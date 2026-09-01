"""Moving mail in and out of a mailbox.

Importing is how an operator migrates onto Lightr: an mbox from a Unix
box, a Maildir from a previous server, a directory of ``.eml`` files
out of an export. Exporting is the other half -- offboarding an
account, or handing someone their mail.

Messages go in through IMAP APPEND rather than by writing files into
the Maildir. Dovecot owns that directory: it keeps index files beside
the mail, and dropping messages in behind its back leaves the indexes
describing a mailbox that no longer exists. APPEND also carries flags
and the original date, which writing files does not.

The mbox dialect on both sides is **mboxrd**: on write, any line
matching ``^>*From `` gains a ``>``; on read, any line matching
``^>+From `` loses one. That pairing is lossless, which the older
``mboxo`` convention is not.
"""

from __future__ import annotations

import logging
import mailbox
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Protocol

log = logging.getLogger("lightr.transfer")

FLAG_SEEN = "\\Seen"
FLAG_ANSWERED = "\\Answered"
FLAG_FLAGGED = "\\Flagged"
FLAG_DELETED = "\\Deleted"
FLAG_DRAFT = "\\Draft"

#: Maildir's single-letter info flags, as Dovecot writes them.
_MAILDIR_FLAGS = {
    "R": FLAG_ANSWERED,
    "S": FLAG_SEEN,
    "T": FLAG_DELETED,
    "D": FLAG_DRAFT,
    "F": FLAG_FLAGGED,
}

_FROM_LINE = re.compile(rb"^>*From ")
_ESCAPED_FROM = re.compile(rb"^>(>*From )")


class TransferError(RuntimeError):
    """Mail could not be read from, or written to, the given source."""


@dataclass(slots=True)
class Message:
    """One message on its way in or out."""

    raw: bytes
    folder: str = "INBOX"
    flags: tuple[str, ...] = ()
    date: datetime | None = None

    @property
    def size(self) -> int:
        return len(self.raw)


@dataclass(slots=True)
class TransferReport:
    """What a transfer moved, and what it could not."""

    messages: int = 0
    bytes_moved: int = 0
    folders: dict[str, int] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)

    def record(self, message: Message) -> None:
        self.messages += 1
        self.bytes_moved += message.size
        self.folders[message.folder] = self.folders.get(message.folder, 0) + 1


# --------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------


def read_eml(path: Path, folder: str = "INBOX") -> Iterator[Message]:
    """One ``.eml`` file, or every ``.eml`` in a directory."""
    if path.is_dir():
        files = sorted(p for p in path.rglob("*") if p.is_file() and _looks_like_eml(p))
        if not files:
            raise TransferError(f"{path} holds no .eml files")
    elif path.is_file():
        files = [path]
    else:
        raise TransferError(f"{path} does not exist")

    for file in files:
        yield Message(raw=file.read_bytes(), folder=folder)


def _looks_like_eml(path: Path) -> bool:
    return path.suffix.lower() in (".eml", ".msg", ".mail")


def read_mbox(path: Path, folder: str = "INBOX") -> Iterator[Message]:
    """Every message in an mbox file."""
    if not path.is_file():
        raise TransferError(f"{path} is not a file")

    try:
        box = mailbox.mbox(str(path), create=False)
    except (OSError, mailbox.Error) as exc:
        raise TransferError(f"could not read {path}: {exc}") from exc

    try:
        for key in box.keys():
            try:
                raw = box.get_bytes(key)
            except (OSError, mailbox.Error) as exc:  # pragma: no cover - corrupt file
                log.warning("skipping an unreadable message in %s: %s", path, exc)
                continue
            yield Message(
                raw=unescape_from_lines(raw),
                folder=folder,
                flags=_flags_from_status(raw),
                date=_date_of(raw),
            )
    finally:
        box.close()


def read_maildir(path: Path, folder: str | None = None) -> Iterator[Message]:
    """Every message in a Maildir, folder structure and flags intact.

    ``folder`` overrides the destination for everything; left unset,
    each Maildir++ subfolder keeps its own name.
    """
    if not (path / "cur").is_dir():
        raise TransferError(f"{path} is not a Maildir (no cur/ directory)")

    try:
        box = mailbox.Maildir(str(path), create=False)
    except (OSError, mailbox.Error) as exc:
        raise TransferError(f"could not read {path}: {exc}") from exc

    yield from _maildir_messages(box, folder or "INBOX", folder)
    for name in box.list_folders():
        sub = box.get_folder(name)
        # Maildir++ writes nesting as dots; IMAP wants a hierarchy.
        yield from _maildir_messages(sub, folder or name.replace(".", "/"), folder)


def _maildir_messages(
    box: mailbox.Maildir, destination: str, override: str | None
) -> Iterator[Message]:
    for key in box.keys():
        try:
            message = box[key]
            raw = box.get_bytes(key)
        except (OSError, KeyError, mailbox.Error) as exc:  # pragma: no cover
            log.warning("skipping an unreadable message: %s", exc)
            continue
        yield Message(
            raw=raw,
            folder=override or destination,
            flags=tuple(
                _MAILDIR_FLAGS[f] for f in message.get_flags() if f in _MAILDIR_FLAGS
            ),
            date=_date_of(raw),
        )


def _flags_from_status(raw: bytes) -> tuple[str, ...]:
    """Read the Status/X-Status headers mbox tools write."""
    head = raw.split(b"\n\n", 1)[0].decode("ascii", "replace")
    flags: list[str] = []
    for line in head.splitlines():
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key == "status" and "R" in value:
            flags.append(FLAG_SEEN)
        elif key == "x-status":
            if "A" in value:
                flags.append(FLAG_ANSWERED)
            if "F" in value:
                flags.append(FLAG_FLAGGED)
            if "D" in value:
                flags.append(FLAG_DELETED)
            if "T" in value:
                flags.append(FLAG_DRAFT)
    return tuple(dict.fromkeys(flags))


def _date_of(raw: bytes) -> datetime | None:
    head = raw.split(b"\n\n", 1)[0].decode("ascii", "replace")
    for line in head.splitlines():
        if line.lower().startswith("date:"):
            try:
                return parsedate_to_datetime(line.split(":", 1)[1].strip())
            except (TypeError, ValueError):
                return None
    return None


# --------------------------------------------------------------------
# mbox escaping
# --------------------------------------------------------------------


def escape_from_lines(raw: bytes) -> bytes:
    """mboxrd quoting: any ``From `` at the start of a line gains a ``>``."""
    return b"\n".join(
        b">" + line if _FROM_LINE.match(line) else line for line in raw.split(b"\n")
    )


def unescape_from_lines(raw: bytes) -> bytes:
    """The inverse: ``>From `` loses one ``>``."""
    return b"\n".join(
        _ESCAPED_FROM.sub(rb"\1", line) if _ESCAPED_FROM.match(line) else line
        for line in raw.split(b"\n")
    )


def to_mbox(messages: Iterable[Message]) -> Iterator[bytes]:
    """Render messages as an mboxrd stream, one chunk per message."""
    for message in messages:
        sender = _envelope_sender(message.raw)
        when = message.date or datetime.now(UTC)
        yield (
            f"From {sender} {when.strftime('%a %b %d %H:%M:%S %Y')}\n".encode("ascii", "replace")
            + escape_from_lines(message.raw).rstrip(b"\n")
            + b"\n\n"
        )


def _envelope_sender(raw: bytes) -> str:
    head = raw.split(b"\n\n", 1)[0].decode("ascii", "replace")
    for line in head.splitlines():
        if line.lower().startswith(("return-path:", "from:")):
            value = line.split(":", 1)[1].strip()
            if "<" in value and ">" in value:
                value = value[value.index("<") + 1 : value.index(">")]
            address = value.split()[0] if value.split() else ""
            if "@" in address:
                return address
    return "MAILER-DAEMON"


# --------------------------------------------------------------------
# The transfer itself
# --------------------------------------------------------------------


class Appender(Protocol):
    """What an import needs of a mailbox: somewhere to put a message."""

    async def append(
        self,
        folder: str,
        raw: bytes,
        *,
        flags: tuple[str, ...] = (),
        date: datetime | None = None,
    ) -> None: ...


async def import_messages(
    mailbox_api: Appender,
    messages: Iterable[Message],
    *,
    dry_run: bool = False,
    limit: int | None = None,
) -> TransferReport:
    """Append messages to a mailbox, reporting what landed.

    One failure does not abort the run. Half an import that names what
    it could not move is more useful than an exception partway through
    with no record of where it stopped.
    """
    report = TransferReport()
    for message in messages:
        if limit is not None and report.messages >= limit:
            break
        if dry_run:
            report.record(message)
            continue
        try:
            await mailbox_api.append(
                message.folder, message.raw, flags=message.flags, date=message.date
            )
        except Exception as exc:
            report.failures.append(f"{message.folder}: {exc}")
            continue
        report.record(message)
    return report


def internaldate(when: datetime | None) -> datetime | None:
    """A date safe to hand IMAP as INTERNALDATE, or None for "server picks".

    imaplib renders a *naive* datetime as local time, which would shift
    every imported message by the server's UTC offset. Anything without
    a zone is therefore stamped UTC before it goes out.
    """
    if when is None:
        return None
    return when if when.tzinfo is not None else when.replace(tzinfo=UTC)


__all__ = [
    "FLAG_ANSWERED",
    "FLAG_DELETED",
    "FLAG_DRAFT",
    "FLAG_FLAGGED",
    "FLAG_SEEN",
    "Appender",
    "Message",
    "TransferError",
    "TransferReport",
    "escape_from_lines",
    "import_messages",
    "internaldate",
    "read_eml",
    "read_maildir",
    "read_mbox",
    "to_mbox",
    "unescape_from_lines",
]
