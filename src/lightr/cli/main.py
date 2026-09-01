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

from lightr import __version__

from . import accounts, backup, dovecot, mailbox, operations, output, resources
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
app.add_typer(operations.apikey_app, name="apikey")
app.add_typer(operations.queue_app, name="queue")
app.add_typer(operations.suppression_app, name="suppression")
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

    database = report["database"]
    assert isinstance(database, dict)
    if not database["reachable"]:
        output.stderr.print("[red]Database unreachable.[/red] Try: lightr init")
        raise typer.Exit(1)
    if not database["up_to_date"]:
        output.warn("Schema is out of date. Run: lightr migrate")
    if not report["dovecot"]["master_user_configured"]:  # type: ignore[index]
        output.warn(
            "No Dovecot master user configured -- `lightr mailbox` commands will not work."
        )


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

    # Reconcile on every start. An install that drifted -- a
    # hand-edited conf, a package upgrade that replaced a file -- comes
    # back into line without anyone noticing it had gone.
    _configure_dovecot(cfg, state.config_path or type(cfg).default_path())

    try:
        asyncio.run(Server(cfg).serve_forever())
    except ServerError as exc:
        output.stderr.print(f"[red]error[/red] {exc}")
        raise typer.Exit(1) from None
    except KeyboardInterrupt:
        output.info("Stopped.")


@app.command()
def init(
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
    hostname: Annotated[
        str | None, typer.Option("--hostname", help="This server's hostname.")
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing config.")] = False,
) -> None:
    """Create a config file and initialise the database."""
    from lightr.config import Config
    from lightr.db import migrate as migrations

    target = state.config_path or Config.default_path()
    if target.exists() and not force:
        output.stderr.print(
            f"[red]{target} already exists.[/red] Pass --force to overwrite it, "
            "or edit it directly."
        )
        raise typer.Exit(1)

    overrides: dict[str, object] = {}
    if data_dir:
        overrides["data_dir"] = str(data_dir)
    if hostname:
        overrides["server"] = {"hostname": hostname}
    cfg = Config.model_validate(overrides)

    try:
        cfg.save(target)
    except OSError as exc:
        output.stderr.print(f"[red]could not write {target}:[/red] {exc}")
        raise typer.Exit(1) from exc

    state.set_config(cfg)
    migrations.upgrade(cfg)

    output.success(f"Wrote {target}")
    output.success(f"Initialised database at {cfg.database.path}")

    # Dovecot is an internal component, so configuring it is part of
    # initialising -- not a second command an operator has to know to
    # run, and not something they can forget.
    _configure_dovecot(cfg, target)

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
    from lightr.dovecot.mailbox import MailboxError
    from lightr.dovecot.maildir import MaildirError
    from lightr.dovecot.sieve import SieveError

    # sys.exit, not typer.Exit: this is outside Typer's runtime, which
    # is what would normally translate typer.Exit into a status code.
    try:
        app()
    except (APIKeyError, PasswordError, MailboxError, MaildirError, SieveError) as exc:
        output.stderr.print(f"[red]error[/red] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        output.stderr.print("\n[dim]Cancelled.[/dim]")
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    entrypoint()
