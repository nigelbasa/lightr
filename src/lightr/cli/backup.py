"""Backup and restore commands.

The Go CLI had no backup at all -- an operator was left with
``sqlite3 .dump`` and a tarball, and no way to know whether the two
were taken at the same moment or belonged together.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from lightr import backup as backups
from lightr.dovecot.maildir import layout_for
from lightr.repo import AccountRepo

from . import output
from .context import confirm, db, fail, state
from .output import Format

app = typer.Typer(no_args_is_help=True, help="Back up and restore everything Lightr owns.")

_PATH_ARG = typer.Argument(help="Archive to read.")


def _revision() -> str | None:
    from lightr.db import migrate as migrations

    try:
        return migrations.current_revision(state.config)
    except Exception:  # pragma: no cover - an unreachable database
        return None


async def _maildirs(refs: list[str] | None) -> dict[str, Path]:
    """Maildir roots for the named accounts, or for every account."""
    cfg = state.config
    async with db() as conn:
        repo = AccountRepo(conn)
        accounts = (
            [await repo.resolve(r) for r in refs]
            if refs
            else await repo.list(limit=100_000)
        )

    roots: dict[str, Path] = {}
    for account in accounts:
        if account.email is None:  # pragma: no cover - list always sets it
            continue
        root = (
            Path(account.maildir_path)
            if account.maildir_path
            else layout_for(cfg.dovecot.maildir_root, account.email).root
        )
        if root.is_dir():
            roots[account.email] = root
        else:
            output.warn(f"{account.email} has no Maildir at {root} yet; skipping it")
    return roots


@app.command("create")
def create(
    destination: Annotated[
        Path | None,
        typer.Argument(help="Where to write the archive. Defaults to the current directory."),
    ] = None,
    include_mail: Annotated[
        bool,
        typer.Option("--include-mail", help="Also archive the Maildirs. This can be large."),
    ] = False,
    account: Annotated[
        list[str] | None,
        typer.Option("--account", help="Limit archived mail to these accounts. Repeatable."),
    ] = None,
) -> None:
    """Take a backup.

    The database is always included; mail is not, because it is
    typically thousands of times larger and most restores only need
    the configuration back.
    """
    import asyncio

    target = destination or Path.cwd() / backups.default_name()
    if target.is_dir():
        target = target / backups.default_name()

    if account and not include_mail:
        fail("--account only applies with --include-mail")

    async def _run() -> backups.BackupReport:
        maildirs = await _maildirs(account) if include_mail else None
        async with db() as conn:
            return await backups.create(
                conn, target, revision=_revision(), maildirs=maildirs
            )

    try:
        report = asyncio.run(_run())
    except backups.BackupError as exc:
        fail(str(exc))

    output.success(
        f"Wrote {report.path} ({output.human_size(report.size_bytes)}, "
        f"{report.manifest.rows} rows"
        + (f", {len(report.manifest.mail_accounts)} mailboxes" if include_mail else "")
        + ")"
    )
    output.warn(
        "This file contains password hashes, DKIM private keys, and relay "
        "credentials. It is written 0600; keep it that way."
    )


@app.command("inspect")
def inspect(
    path: Annotated[Path, _PATH_ARG],
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Show what an archive holds, without restoring it."""
    try:
        manifest = backups.read_manifest(path)
    except backups.BackupError as exc:
        fail(str(exc))

    output.detail(
        {
            "path": str(path),
            "format": manifest.format,
            "lightr_version": manifest.lightr_version,
            "schema_revision": manifest.revision,
            "created_at": manifest.created_at,
            "rows": manifest.rows,
            "includes_mail": manifest.includes_mail,
            "mail_accounts": manifest.mail_accounts,
            "tables": {k: v for k, v in sorted(manifest.tables.items()) if v},
        },
        fmt=fmt,
    )

    current = _revision()
    if manifest.revision and current and manifest.revision != current:
        output.warn(
            f"This database is at revision {current}; the archive is at "
            f"{manifest.revision}. Restoring it will be refused until they match."
        )


@app.command("restore")
def restore(
    path: Annotated[Path, _PATH_ARG],
    include_mail: Annotated[
        bool, typer.Option("--include-mail", help="Also restore the Maildirs.")
    ] = False,
    ignore_revision: Annotated[
        bool,
        typer.Option(
            "--ignore-revision",
            help="Restore even if the schema revisions differ. Rarely right.",
        ),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Restore an archive over this install.

    Replaces everything: the existing rows are deleted first, so the
    result is the archive and nothing else. It asks before doing that.
    """
    import asyncio

    try:
        manifest = backups.read_manifest(path)
    except backups.BackupError as exc:
        fail(str(exc))

    async def _existing() -> int:
        async with db() as conn:
            return sum((await backups.count_rows(conn)).values())

    present = asyncio.run(_existing())
    if present:
        confirm(
            f"Replace the {present} row(s) in this database with the archive?",
            yes=yes,
            detail=(
                f"[yellow]Everything currently in {state.config.database.path or 'the database'} "
                f"will be deleted and replaced by {path}.[/yellow]"
            ),
        )

    async def _run() -> backups.RestoreReport:
        maildirs: dict[str, Path] | None = None
        if include_mail:
            cfg = state.config
            maildirs = {
                email: layout_for(cfg.dovecot.maildir_root, email).root
                for email in manifest.mail_accounts
            }
            for root in maildirs.values():
                root.mkdir(parents=True, exist_ok=True)

        async with db() as conn:
            return await backups.restore(
                conn,
                path,
                current_revision=_revision(),
                wipe=True,
                maildirs=maildirs,
                ignore_revision=ignore_revision,
            )

    try:
        report = asyncio.run(_run())
    except backups.BackupError as exc:
        fail(str(exc))

    output.success(f"Restored {report.rows} row(s) across {len(report.tables)} table(s)")
    if report.mail:
        total = sum(report.mail.values())
        output.success(f"Restored {total} message file(s) into {len(report.mail)} mailbox(es)")
        output.info("Run `lightr dovecot resync <account>` so Dovecot re-indexes them.")
    if include_mail and not manifest.includes_mail:
        output.warn("--include-mail was given, but this archive holds no mail.")


__all__ = ["app"]
