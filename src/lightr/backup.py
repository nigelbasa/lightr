"""Backup and restore.

An operator needs one command that captures everything Lightr owns and
one that puts it back. That is what this is: a single archive holding
every row of the database and, optionally, the Maildirs.

Two decisions worth stating, because both cut against instinct:

**Backups are not redacted.** The API masks DKIM private keys,
password hashes, and relay credentials before they cross the wire. A
backup that did the same would restore an install where nobody can log
in and no domain can sign its mail -- a file that looks like a backup
and is not one. So the archive carries the real values, and the safety
is in the file mode (0600) and in saying so plainly rather than in
pretending the secrets are not there.

**A restore refuses a schema it does not recognise.** The archive
records the Alembic revision it was taken at. Loading a 0003 dump into
a 0002 database would half-succeed -- some tables fine, some columns
missing -- and that is the failure that costs someone their evening.
Better to stop and say which revision is needed.
"""

from __future__ import annotations

import io
import json
import logging
import os
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Table, delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr import __version__
from lightr.db import schema

log = logging.getLogger("lightr.backup")

#: Bumped when the archive layout changes incompatibly.
FORMAT_VERSION = 1

MANIFEST_NAME = "manifest.json"
DATABASE_NAME = "database.json"
MAIL_PREFIX = "mail"

#: Owner-only. The archive holds password hashes and private keys.
ARCHIVE_MODE = 0o600


class BackupError(RuntimeError):
    """A backup could not be written, read, or restored."""


@dataclass(slots=True)
class Manifest:
    """What an archive contains, and what it needs to restore into."""

    format: int
    lightr_version: str
    revision: str | None
    created_at: str
    tables: dict[str, int]
    mail_accounts: list[str] = field(default_factory=list)

    @property
    def includes_mail(self) -> bool:
        return bool(self.mail_accounts)

    @property
    def rows(self) -> int:
        return sum(self.tables.values())

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str | bytes) -> Manifest:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BackupError(f"the manifest is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise BackupError("the manifest is not a JSON object")
        try:
            return cls(
                format=int(data["format"]),
                lightr_version=str(data.get("lightr_version", "unknown")),
                revision=data.get("revision"),
                created_at=str(data.get("created_at", "")),
                tables=dict(data.get("tables") or {}),
                mail_accounts=list(data.get("mail_accounts") or []),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BackupError(f"the manifest is missing or malformed: {exc}") from exc


# --------------------------------------------------------------------
# The database
# --------------------------------------------------------------------


def _encode(value: Any) -> Any:
    """Make one column value JSON-safe without losing fidelity.

    Datetimes are written naive, exactly as they are stored -- the Go
    engine wrote naive UTC and this engine kept that, so stamping a
    timezone on the way out would come back as a tz-aware value that
    Postgres refuses to put in a naive column.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID | Path):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        # Queued messages are stored whole since migration 0005. This
        # raised before, which meant the first message sitting in the
        # queue made every backup fail.
        import base64

        return {BINARY_MARKER: base64.b64encode(bytes(value)).decode("ascii")}
    return value


#: How a binary value is written in the JSON dump. A plain string would
#: be indistinguishable from text on the way back in.
BINARY_MARKER = "$base64"


def _decode_row(table: Table, row: dict[str, Any]) -> dict[str, Any]:
    """Turn one JSON row back into column values for this table."""
    unknown = set(row) - set(table.c.keys())
    if unknown:
        raise BackupError(
            f"table {table.name!r} in the archive has column(s) this version does "
            f"not know: {', '.join(sorted(unknown))}. The backup is from a newer "
            f"Lightr; upgrade before restoring it."
        )

    decoded: dict[str, Any] = {}
    for name, value in row.items():
        column = table.c[name]
        if isinstance(value, dict) and set(value) == {BINARY_MARKER}:
            import base64

            try:
                decoded[name] = base64.b64decode(value[BINARY_MARKER], validate=True)
            except (ValueError, TypeError) as exc:
                raise BackupError(
                    f"{table.name}.{name} holds binary data that does not decode"
                ) from exc
        elif isinstance(column.type, DateTime) and isinstance(value, str) and value:
            try:
                decoded[name] = datetime.fromisoformat(value)
            except ValueError as exc:
                raise BackupError(
                    f"{table.name}.{name} is not a timestamp: {value!r}"
                ) from exc
        else:
            decoded[name] = value
    return decoded


async def dump_database(conn: AsyncConnection) -> dict[str, list[dict[str, Any]]]:
    """Every row of every table Lightr owns."""
    data: dict[str, list[dict[str, Any]]] = {}
    for table in schema.metadata.sorted_tables:
        rows = await conn.execute(select(table))
        data[table.name] = [
            {key: _encode(value) for key, value in row._mapping.items()} for row in rows
        ]
    return data


async def count_rows(conn: AsyncConnection) -> dict[str, int]:
    """Row counts per table, for reporting and for emptiness checks."""
    counts: dict[str, int] = {}
    for table in schema.metadata.sorted_tables:
        total = (await conn.execute(select(func.count()).select_from(table))).scalar_one()
        counts[table.name] = int(total)
    return counts


async def load_database(
    conn: AsyncConnection, data: dict[str, list[dict[str, Any]]], *, wipe: bool
) -> dict[str, int]:
    """Insert an archive's rows, optionally clearing what is there first.

    Tables are emptied in reverse dependency order and filled in
    forward order, so foreign keys hold at every point in between.
    """
    if wipe:
        for table in reversed(schema.metadata.sorted_tables):
            await conn.execute(delete(table))

    loaded: dict[str, int] = {}
    for table in schema.metadata.sorted_tables:
        rows = data.get(table.name)
        if not rows:
            continue
        await conn.execute(insert(table), [_decode_row(table, r) for r in rows])
        loaded[table.name] = len(rows)
    return loaded


# --------------------------------------------------------------------
# The archive
# --------------------------------------------------------------------


def _check_readable(directory: Path) -> None:
    """Fail loudly if a Maildir cannot be read in full.

    A backup that silently skipped unreadable mail would look like a
    complete one. Lightr runs as its own user and the mail root is
    group-owned, so this is a real and recoverable mistake.
    """
    try:
        for path in directory.rglob("*"):
            if path.is_file() and not os.access(path, os.R_OK):
                raise BackupError(
                    f"cannot read {path}. Run the backup as root, or as a user in "
                    f"the group that owns the mail directory."
                )
    except PermissionError as exc:
        raise BackupError(f"cannot read {directory}: {exc}") from exc


def write_archive(
    destination: Path,
    manifest: Manifest,
    database: dict[str, list[dict[str, Any]]],
    mail: dict[str, Path] | None = None,
) -> Path:
    """Write the archive, atomically and owner-only."""
    destination = destination.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)

    handle, temporary = tempfile.mkstemp(
        dir=destination.parent, prefix=".lightr-backup-", suffix=".tmp"
    )
    os.close(handle)
    staging = Path(temporary)
    staging.chmod(ARCHIVE_MODE)

    try:
        with tarfile.open(staging, "w:gz") as archive:
            _add_bytes(archive, MANIFEST_NAME, manifest.to_json().encode("utf-8"))
            _add_bytes(
                archive, DATABASE_NAME, json.dumps(database, default=str).encode("utf-8")
            )
            for email, source in sorted((mail or {}).items()):
                _check_readable(source)
                archive.add(str(source), arcname=f"{MAIL_PREFIX}/{email}")
        staging.replace(destination)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise

    destination.chmod(ARCHIVE_MODE)
    return destination


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mtime = int(datetime.now(UTC).timestamp())
    info.mode = ARCHIVE_MODE
    archive.addfile(info, io.BytesIO(payload))


def _open(path: Path) -> tarfile.TarFile:
    try:
        return tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        raise BackupError(f"could not open {path}: {exc}") from exc


def read_manifest(path: Path) -> Manifest:
    with _open(path) as archive:
        try:
            member = archive.extractfile(MANIFEST_NAME)
        except KeyError:
            member = None
        if member is None:
            raise BackupError(f"{path} has no {MANIFEST_NAME}; it is not a Lightr backup")
        manifest = Manifest.from_json(member.read())

    if manifest.format > FORMAT_VERSION:
        raise BackupError(
            f"{path} is a format {manifest.format} archive and this Lightr reads "
            f"format {FORMAT_VERSION}. Upgrade Lightr to restore it."
        )
    return manifest


def read_database(path: Path) -> dict[str, list[dict[str, Any]]]:
    with _open(path) as archive:
        try:
            member = archive.extractfile(DATABASE_NAME)
        except KeyError:
            member = None
        if member is None:
            raise BackupError(f"{path} has no {DATABASE_NAME}")
        try:
            data = json.loads(member.read())
        except json.JSONDecodeError as exc:
            raise BackupError(f"{path} holds an unreadable database dump: {exc}") from exc
    if not isinstance(data, dict):
        raise BackupError(f"{path} holds a database dump of the wrong shape")
    return data


def extract_mail(path: Path, targets: dict[str, Path]) -> dict[str, int]:
    """Restore Maildirs out of an archive into the given directories.

    Members are validated rather than trusted: a tar can name absolute
    paths, ``..`` segments, symlinks, and device nodes, and extracting
    one blindly writes wherever the archive says it should.
    """
    written: dict[str, int] = {}
    with _open(path) as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts
            if len(parts) < 2 or parts[0] != MAIL_PREFIX:
                continue

            email = parts[1]
            target = targets.get(email)
            if target is None:
                continue

            relative = Path(*parts[2:]) if len(parts) > 2 else Path()
            _reject_unsafe_member(member, relative)

            out = target / relative
            if member.isdir():
                out.mkdir(parents=True, exist_ok=True)
                continue

            source = archive.extractfile(member)
            if source is None:  # pragma: no cover - defensive
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(source.read())
            written[email] = written.get(email, 0) + 1
    return written


def _reject_unsafe_member(member: tarfile.TarInfo, relative: Path) -> None:
    if member.issym() or member.islnk():
        raise BackupError(f"the archive contains a link ({member.name}); refusing it")
    if not (member.isfile() or member.isdir()):
        raise BackupError(f"the archive contains a special file ({member.name})")
    if relative.is_absolute() or ".." in relative.parts:
        raise BackupError(f"the archive contains an unsafe path: {member.name}")


# --------------------------------------------------------------------
# The whole job
# --------------------------------------------------------------------


@dataclass(slots=True)
class BackupReport:
    path: Path
    manifest: Manifest
    size_bytes: int


@dataclass(slots=True)
class RestoreReport:
    tables: dict[str, int]
    mail: dict[str, int] = field(default_factory=dict)

    @property
    def rows(self) -> int:
        return sum(self.tables.values())


def default_name(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d-%H%M%S")
    return f"lightr-backup-{stamp}.tar.gz"


async def create(
    conn: AsyncConnection,
    destination: Path,
    *,
    revision: str | None,
    maildirs: dict[str, Path] | None = None,
) -> BackupReport:
    """Take a backup. ``maildirs`` maps address to Maildir root."""
    database = await dump_database(conn)
    manifest = Manifest(
        format=FORMAT_VERSION,
        lightr_version=__version__,
        revision=revision,
        created_at=datetime.now(UTC).isoformat(),
        tables={name: len(rows) for name, rows in database.items()},
        mail_accounts=sorted(maildirs or {}),
    )

    written = write_archive(destination, manifest, database, maildirs)
    return BackupReport(path=written, manifest=manifest, size_bytes=written.stat().st_size)


def check_revision(manifest: Manifest, current: str | None) -> None:
    """Refuse a restore across a schema change."""
    if manifest.revision is None or current is None:
        return
    if manifest.revision != current:
        raise BackupError(
            f"this backup was taken at schema revision {manifest.revision} and the "
            f"database is at {current}. Bring them into line first -- "
            f"lightr migrate --revision {manifest.revision} -- or restore into an "
            f"empty database at the right revision."
        )


async def maildir_targets(
    conn: AsyncConnection, emails: list[str], maildir_root: Path
) -> dict[str, Path]:
    """Where each address's mail belongs, as this database says.

    ``accounts.maildir_path`` wins over the computed layout, because an
    account whose mail was moved has that column pointing at where it
    actually went. A backup reads from there; a restore has to write
    back to the same place, or a recovery quietly puts every mailbox
    somewhere Dovecot is not looking.
    """
    rows = await conn.execute(
        select(
            schema.accounts.c.local_part,
            schema.accounts.c.maildir_path,
            schema.domains.c.name.label("domain_name"),
        ).select_from(schema.accounts.join(schema.domains))
    )
    stored = {
        f"{r.local_part}@{r.domain_name}": r.maildir_path for r in rows
    }

    from lightr.dovecot.maildir import MaildirError, layout_for

    targets: dict[str, Path] = {}
    for email in emails:
        recorded = stored.get(email)
        if recorded:
            targets[email] = Path(recorded)
            continue
        try:
            targets[email] = layout_for(maildir_root, email).root
        except MaildirError:  # pragma: no cover - refused at creation
            log.warning("cannot place mail for %s; skipping it", email)
    return targets


async def restore(
    conn: AsyncConnection,
    path: Path,
    *,
    current_revision: str | None,
    wipe: bool,
    maildir_root: Path | None = None,
    ignore_revision: bool = False,
) -> RestoreReport:
    """Load an archive into this database, and optionally its mail.

    Mail is placed after the rows are loaded, so the destination comes
    from the restored ``accounts.maildir_path`` -- the same source the
    backup read from.
    """
    manifest = read_manifest(path)
    if not ignore_revision:
        check_revision(manifest, current_revision)

    tables = await load_database(conn, read_database(path), wipe=wipe)

    mail: dict[str, int] = {}
    if maildir_root is not None and manifest.mail_accounts:
        targets = await maildir_targets(conn, manifest.mail_accounts, maildir_root)
        for root in targets.values():
            root.mkdir(parents=True, exist_ok=True)
        mail = extract_mail(path, targets)

    return RestoreReport(tables=tables, mail=mail)


__all__ = [
    "ARCHIVE_MODE",
    "DATABASE_NAME",
    "FORMAT_VERSION",
    "MAIL_PREFIX",
    "MANIFEST_NAME",
    "BackupError",
    "BackupReport",
    "Manifest",
    "RestoreReport",
    "check_revision",
    "count_rows",
    "create",
    "default_name",
    "dump_database",
    "extract_mail",
    "load_database",
    "maildir_targets",
    "read_database",
    "read_manifest",
    "restore",
    "write_archive",
]
