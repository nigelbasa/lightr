"""The ``lightr`` command.

Deliberately does not import the server stack. A Typer app that pulls
in Starlette and aiosmtpd pays about a second of import time on every
invocation, and most invocations are `list` or `get`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from lightr import __version__, configtemplate

from . import (
    accounts,
    authproviders,
    backup,
    database,
    dovecot,
    mailbox,
    operations,
    output,
    resources,
    webhooks,
)
from .context import db, run, state
from .output import Format

app = typer.Typer(
    name="lightr",
    help="A lightweight mail engine. SMTP, operator APIs, and Dovecot for mailboxes.",
    no_args_is_help=True,
    add_completion=True,
)

app.add_typer(resources.org_app, name="org")
app.add_typer(resources.domain_app, name="domain")
app.add_typer(accounts.app, name="account")
app.add_typer(resources.alias_app, name="alias")
app.add_typer(mailbox.app, name="mailbox")
app.add_typer(dovecot.app, name="dovecot")
app.add_typer(database.app, name="db")
app.add_typer(operations.apikey_app, name="apikey")
app.add_typer(operations.queue_app, name="queue")
app.add_typer(operations.suppression_app, name="suppression")
app.add_typer(webhooks.app, name="webhook")
app.add_typer(authproviders.app, name="auth")
app.add_typer(backup.app, name="backup")


def _version(value: bool) -> None:
    if value:
        output.stdout.print(__version__)
        raise typer.Exit()


@app.callback()
def main(
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Config file. Defaults to /etc/lightr/config.yaml."),
    ] = None,
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Print the version.")
    ] = False,
) -> None:
    """Set global options."""
    state.use(config)


@app.command()
def migrate(
    revision: Annotated[str, typer.Option(help="Target revision.")] = "head",
) -> None:
    """Bring the database schema up to date.

    Safe to run against a database written by the Go engine -- it
    adopts it and adds only what is missing.
    """
    from lightr.db import migrate as migrations

    before = migrations.current_revision(state.config)
    migrations.upgrade(state.config, revision)
    after = migrations.current_revision(state.config)

    if before == after:
        output.info(f"Already at revision {after}. Nothing to do.")
    else:
        output.success(f"Migrated {before or '(empty)'} -> {after}")


@app.command()
def status(
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Show whether the engine's dependencies are reachable."""
    from lightr.db import migrate as migrations
    from lightr.db.engine import create_engine, ping

    cfg = state.config

    async def _run() -> dict[str, object]:
        engine = create_engine(cfg)
        try:
            db_ok = await ping(engine)
        finally:
            await engine.dispose()

        counts: dict[str, int] = {}
        if db_ok:
            try:
                from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

                async with db() as conn:
                    counts = {
                        "organizations": await OrganizationRepo(conn).count(),
                        "domains": len(await DomainRepo(conn).list(limit=10_000)),
                        "accounts": await AccountRepo(conn).count(),
                    }
            except Exception:
                counts = {}

        return {
            "version": __version__,
            "hostname": cfg.server.hostname,
            "database": {
                "driver": str(cfg.database.driver),
                "reachable": db_ok,
                "revision": migrations.current_revision(cfg) if db_ok else None,
                "up_to_date": migrations.is_up_to_date(cfg) if db_ok else False,
            },
            "dovecot": {
                "lmtp": str(cfg.dovecot.lmtp_socket)
                if cfg.dovecot.uses_lmtp_socket
                else f"{cfg.dovecot.lmtp_host}:{cfg.dovecot.lmtp_port}",
                "imap": f"{cfg.dovecot.imap_host}:{cfg.dovecot.imap_port}",
                "maildir_root": str(cfg.dovecot.maildir_root),
                "master_user_configured": cfg.dovecot.has_master_user,
            },
            **({"counts": counts} if counts else {}),
        }

    report = run(_run)
    output.detail(report, fmt=fmt)

    db_state = report["database"]
    assert isinstance(db_state, dict)
    if not db_state["reachable"]:
        output.stderr.print("[red]Database unreachable.[/red] Try: lightr setup")
        raise typer.Exit(1)
    if not db_state["up_to_date"]:
        output.warn("Schema is out of date. Run: lightr migrate")
    if not report["dovecot"]["master_user_configured"]:  # type: ignore[index]
        output.warn(
            "No Dovecot master user configured -- `lightr mailbox` commands will not work."
        )


@app.command()
def preflight(
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Check this machine can actually run Lightr.

    Exits non-zero if something means "cannot work" rather than "will
    work worse". The distinction matters: a missing Dovecot SQL driver
    stops delivery entirely, and reporting that as a warning is how an
    install looks healthy for an hour.
    """
    from lightr import preflight as checks

    report = checks.run(state.config, state.config_path)

    if Format.resolve(fmt) is not Format.TABLE:
        output.detail(
            {
                "ok": report.ok,
                "checks": [
                    {"name": c.name, "level": str(c.level), "detail": c.detail,
                     "fix": c.fix}
                    for c in report.checks
                ],
            },
            fmt=fmt,
        )
    else:
        for check in report.checks:
            if check.level is checks.Level.OK:
                output.success(f"{check.name}: {check.detail}")
            elif check.level is checks.Level.WARN:
                output.warn(f"{check.name}: {check.detail}")
            else:
                output.stderr.print(f"[red]FAIL[/red] {check.name}: {check.detail}")
            if check.fix and check.level is not checks.Level.OK:
                output.stderr.print(f"      {check.fix}")

    if not report.ok:
        output.stderr.print(
            f"\n[red]{len(report.failures)} check(s) mean Lightr cannot work "
            f"on this machine as configured.[/red]"
        )
        raise typer.Exit(1)


@app.command()
def serve() -> None:
    """Run the engine: HTTP API, SMTP, submission, and the sender.

    Refuses to start on an out-of-date schema rather than failing
    later with confusing errors.
    """
    import asyncio
    import logging

    from lightr.db import migrate as migrations
    from lightr.server import Server, ServerError

    cfg = state.config
    logging.basicConfig(
        level=cfg.logging.level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )

    if not migrations.is_up_to_date(cfg):
        output.stderr.print(
            "[red]The database schema is out of date.[/red] Run: lightr migrate"
        )
        raise typer.Exit(1)

    # Refuse rather than start half-working. Every one of these means
    # something an operator would otherwise discover from a user
    # reporting that mail does not arrive.
    from lightr import preflight as checks

    report = checks.run(cfg, state.config_path)
    for warning in report.warnings:
        output.warn(f"{warning.name}: {warning.detail}")
    if not report.ok:
        for failure in report.failures:
            output.stderr.print(f"[red]FAIL[/red] {failure.name}: {failure.detail}")
            if failure.fix:
                output.stderr.print(f"      {failure.fix}")
        output.stderr.print("\nRefusing to start. Run: lightr preflight")
        raise typer.Exit(1)

    # Report drift, do not correct it. Writing Dovecot's configuration
    # from the running service would mean granting the mail engine
    # write access to /etc/dovecot for the life of the process, which
    # is a worse trade than an operator running one command.
    from lightr.dovecot.manage import DovecotManager

    stale = DovecotManager(cfg).drift()
    if stale:
        output.warn(
            f"Dovecot's configuration is out of date ({', '.join(stale)}). "
            "Run: lightr dovecot install"
        )

    try:
        asyncio.run(Server(cfg).serve_forever())
    except ServerError as exc:
        output.stderr.print(f"[red]error[/red] {exc}")
        raise typer.Exit(1) from None
    except KeyboardInterrupt:
        output.info("Stopped.")


@app.command()
def setup(
    hostname: Annotated[
        str | None, typer.Option("--hostname", help="This server's hostname.")
    ] = None,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Where the database and Sieve scripts live."),
    ] = None,
) -> None:
    """Prepare this machine to run Lightr. Safe to run again.

    The package runs this on install, so most operators never type it.
    It writes /etc/lightr/config.yaml if there is nothing there, brings
    the schema up to date, generates the secrets Dovecot needs, and
    configures Dovecot.

    Every step is idempotent and none of them replace a file that
    already exists. There is deliberately no --force: the config file
    holds the keys a running install authenticates with, and the
    command that overwrote it cost an afternoon once already.
    """
    from lightr.config import Config
    from lightr.db import migrate as migrations

    target = state.config_path or Config.default_path()

    if target.exists():
        output.info(f"Using {target}")
    else:
        try:
            configtemplate.write(target)
        except OSError as exc:
            output.stderr.print(f"[red]could not write {target}:[/red] {exc}")
            raise typer.Exit(1) from exc
        output.success(f"Wrote {target}")

    settings: dict[tuple[str, str], object] = {}
    if hostname:
        settings[("server", "hostname")] = hostname
    if data_dir:
        settings[("data_dir", "")] = data_dir.as_posix()
    for name in configtemplate.set_values(target, settings):
        output.success(f"Set {name}")

    # Reload from disk either way: what was just written is the truth.
    state.use(target)
    state.reload()

    cfg = state.config
    migrations.upgrade(cfg)
    output.success("Database schema is up to date")

    # Dovecot is an internal component, so configuring it is part of
    # setting up -- not a second command an operator has to know about,
    # and not one they can forget.
    _configure_dovecot(cfg, target)
    configtemplate.restrict(target)

    if cfg.server.hostname == "localhost":
        output.warn(
            "server.hostname is still 'localhost'. Receivers check it -- set it "
            f"to this server's name in {target}, or run: lightr setup --hostname ..."
        )
    output.info("Next: lightr domain create <your-domain>")


def _configure_dovecot(cfg: object, config_path: Path) -> None:
    """Bring Dovecot in line with this config, reporting what happened.

    Never fatal: mailboxes being unavailable is worth a loud warning,
    but the rest of the engine still works without them.
    """
    import asyncio

    from lightr.dovecot.manage import DovecotManager

    manager = DovecotManager(cfg)  # type: ignore[arg-type]
    report = asyncio.run(manager.reconcile(save_config=config_path))

    if report.generated:
        output.info(f"Generated {', '.join(report.generated)}")
    for change in report.changes:
        if change.action == "written":
            output.success(f"Configured Dovecot: {change.path}")
    if report.reloaded:
        output.success("Dovecot reloaded")
    for warning in report.warnings:
        output.warn(warning)


def entrypoint() -> None:
    """Console-script shim with a last-resort error boundary.

    ``run`` handles failures raised inside a command body, but argument
    validation happens before that -- a rejected password, for
    instance. Without this, those surface as a raw traceback, which is
    exactly the behaviour this rewrite is meant to fix.
    """
    from lightr.apikeys import APIKeyError
    from lightr.auth import PasswordError
    from lightr.authproviders.base import ProviderError
    from lightr.dovecot.mailbox import MailboxError
    from lightr.dovecot.maildir import MaildirError
    from lightr.dovecot.sieve import SieveError

    # sys.exit, not typer.Exit: this is outside Typer's runtime, which
    # is what would normally translate typer.Exit into a status code.
    try:
        app()
    except (
        APIKeyError, PasswordError, ProviderError, MailboxError, MaildirError, SieveError
    ) as exc:
        output.stderr.print(f"[red]error[/red] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        output.stderr.print("\n[dim]Cancelled.[/dim]")
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    entrypoint()
