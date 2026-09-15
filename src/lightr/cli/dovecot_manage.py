"""Dovecot commands that treat it as an internal component.

An operator runs these; they do not edit ``dovecot.conf``, hash a
master password, or remember to reload the service.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from lightr.dovecot import config as dovecot_config
from lightr.dovecot.doveadm import Doveadm, DoveadmError
from lightr.dovecot.manage import DovecotManagementError, DovecotManager
from lightr.repo import AccountRepo

from . import output
from .context import confirm, db, run, state
from .output import Format


def _manager() -> DovecotManager:
    return DovecotManager(state.config)


def install(
    reload: Annotated[
        bool, typer.Option("--reload/--no-reload", help="Reload Dovecot afterwards.")
    ] = True,
    conf_dir: Annotated[
        Path | None,
        typer.Option("--conf-dir", help="Write here instead of /etc/dovecot."),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Configure Dovecot completely: keys, config, master user, reload.

    This is the only Dovecot command most installs need. It generates
    everything, checks it with Dovecot's own parser before touching the
    running service, and rolls back if that check fails.
    """
    cfg = state.config
    target = state.config_path or type(cfg).default_path()

    # Anything missing gets generated rather than demanded.
    created: list[str] = []
    if not cfg.dovecot.internal_key:
        cfg.dovecot.internal_key = dovecot_config.generate_internal_key()
        created.append("internal auth key")

    manager = DovecotManager(cfg, conf_dir=conf_dir or Path("/etc/dovecot"))
    if not cfg.dovecot.has_master_user:
        run(manager.ensure_master_user)
        created.append("master user")

    if created:
        cfg.save(target)
        output.info(f"Generated: {', '.join(created)} (saved to {target})")

    confirm(
        "Write Dovecot's configuration and reload it?" if reload
        else "Write Dovecot's configuration?",
        yes=yes,
        detail=(
            f"[yellow]This writes into {manager.conf_dir} and replaces Lightr's "
            "own generated files. It also comments out `!include "
            "auth-system.conf.ext` in conf.d/10-auth.conf, if present, so "
            "logins are not tried against PAM first. Anything already there "
            "is backed up first.[/yellow]"
        ),
    )

    async def _run() -> object:
        return await manager.install(reload=reload)

    try:
        report = run(_run)
    except DovecotManagementError as exc:
        output.stderr.print(f"[red]error[/red] {exc}")
        raise typer.Exit(1) from None

    for change in report.changes:
        if change.action == "written":
            note = f" (backed up to {change.backup.name})" if change.backup else ""
            output.success(f"Wrote {change.path}{note}")
        else:
            output.info(f"Unchanged: {change.path}")

    for warning in report.warnings:
        output.warn(warning)

    if not report.changed:
        output.success("Dovecot is already configured correctly.")
    elif report.reloaded:
        output.success("Dovecot reloaded.")
    elif reload:
        output.warn("Dovecot was not reloaded. Run: systemctl reload dovecot")


def status(
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Show what Lightr can see of Dovecot."""

    async def _run() -> dict[str, object]:
        return await _manager().status()

    info = run(_run)
    output.detail(info, fmt=fmt)

    if not info.get("doveadm_available"):
        output.warn(
            "doveadm was not found. Lightr manages Dovecot directly, so it "
            "must be installed here: apt install dovecot-core"
        )
        raise typer.Exit(1)
    if not info.get("master_user"):
        output.warn("No master user yet. Run: lightr dovecot install")


def quota(
    account: Annotated[
        str | None, typer.Argument(help="One account, or omit for all of them.")
    ] = None,
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Show real mailbox usage, as Dovecot measures it.

    Lightr configures the limit; Dovecot enforces it and is the only
    thing that knows what has actually been used.
    """
    doveadm = Doveadm()

    async def _run() -> list[dict[str, object]]:
        async with db() as conn:
            repo = AccountRepo(conn)
            accounts = (
                [await repo.resolve(account)] if account else await repo.list(limit=10_000)
            )

        rows: list[dict[str, object]] = []
        for record in accounts:
            if record.email is None:
                continue
            try:
                usage = await doveadm.quota_get(record.email)
            except DoveadmError as exc:
                rows.append({"account": record.email, "error": str(exc)})
                continue
            rows.append(
                {
                    "account": record.email,
                    "used": output.human_size(usage.used_bytes),
                    "limit": output.human_size(usage.limit_bytes),
                    "percent": usage.percent,
                    "messages": usage.used_messages,
                    "over": usage.over,
                }
            )
        return rows

    rows = run(_run)
    output.render(
        rows,
        [
            ("account", "ACCOUNT"),
            ("used", "USED"),
            ("limit", "LIMIT"),
            ("percent", "%"),
            ("messages", "MESSAGES"),
        ],
        fmt=fmt,
        empty="No accounts.",
    )

    for row in rows:
        if row.get("over"):
            output.warn(f"{row['account']} is over quota")
        if row.get("error"):
            output.warn(f"{row['account']}: {row['error']}")


def resync(
    account: Annotated[str, typer.Argument(help="Account whose index to rebuild.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Rebuild a mailbox's index. The fix for a corrupt one."""
    confirm(
        f"Rebuild the mailbox index for {account}?",
        yes=yes,
        detail=(
            "[yellow]The mailbox is unavailable while this runs, and clients "
            "may resync.[/yellow]"
        ),
    )

    async def _run() -> str:
        async with db() as conn:
            found = await AccountRepo(conn).resolve(account)
        if found.email is None:
            raise typer.BadParameter(f"no address for {account!r}")
        await Doveadm().force_resync(found.email)
        return found.email

    output.success(f"Rebuilt the index for {run(_run)}")


def index(
    account: Annotated[
        str | None, typer.Argument(help="Mailbox to index. Omit this with --all.")
    ] = None,
    all_accounts: Annotated[
        bool, typer.Option("--all", help="Every mailbox on this server.")
    ] = False,
) -> None:
    """Build the full-text search index for a mailbox.

    Mail is indexed as it arrives once ``dovecot.fts`` is on. Nothing
    indexes what was delivered before that, so until this has run a
    search of an existing mailbox finds none of it.

    Not `resync`: that rebuilds Dovecot's own index files, which is what
    you do to a corrupt mailbox.
    """
    from lightr.config import FtsEngine

    if bool(account) == all_accounts:
        raise typer.BadParameter("name a mailbox, or pass --all")
    if state.config.dovecot.fts is FtsEngine.NONE:
        output.warn(
            "dovecot.fts is none, so nothing will read the index. "
            "Set it, then: lightr dovecot install"
        )

    async def _run() -> tuple[list[str], list[str]]:
        async with db() as conn:
            repo = AccountRepo(conn)
            found = (
                await repo.list() if all_accounts else [await repo.resolve(account or "")]
            )

        doveadm = Doveadm()
        indexed: list[str] = []
        failed: list[str] = []
        for record in found:
            if record.email is None:  # pragma: no cover - resolve always sets it
                continue
            try:
                await doveadm.index(record.email)
            except DoveadmError as exc:
                # One unreadable mailbox must not stop the rest.
                output.warn(f"{record.email}: {exc}")
                failed.append(record.email)
                continue
            indexed.append(record.email)
        return indexed, failed

    indexed, failed = run(_run)
    output.success(f"Indexed {len(indexed)} mailbox(es)")
    if failed:
        raise typer.Exit(1)


__all__ = ["index", "install", "quota", "resync", "status"]
