"""Database commands.

One job, really: getting from the SQLite a fresh install starts with to
a Postgres an operator can back up, without them having to invent a
role, a password, a set of grants and a DSN and get all four into two
config files by hand.
"""

from __future__ import annotations

from typing import Annotated

import typer

from . import output
from .context import confirm, state

app = typer.Typer(no_args_is_help=True, help="Database setup and maintenance.")


@app.command("provision")
def provision(
    role: Annotated[str, typer.Option("--role", help="Postgres role to create.")] = (
        "lightr"
    ),
    database: Annotated[
        str, typer.Option("--database", help="Database to create.")
    ] = "lightr",
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 5432,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Create Lightr's Postgres role and database, and use them.

    Run it as root: it administers Postgres as the postgres system
    user, which is how a Debian-family install is administered locally
    and needs no superuser password.

    The generated password goes into /etc/lightr/config.yaml and is
    printed nowhere. Nobody has to see it, so nobody has to be careful
    with it.

    Safe to run again -- an existing role and database are left alone.
    """
    from lightr.config import Config
    from lightr.db import migrate as migrations
    from lightr.db.provision import ProvisionError, existing_password, write_dsn
    from lightr.db.provision import provision as run_it

    target = state.config_path or Config.default_path()
    if not target.exists():
        output.stderr.print(
            f"[red]{target} does not exist.[/red] Run: lightr setup"
        )
        raise typer.Exit(1)

    cfg = state.config
    confirm(
        f"Create the Postgres role {role!r} and database {database!r}, and point "
        f"Lightr at them?",
        yes=yes,
        detail=(
            "[yellow]The data already in "
            f"{cfg.database.path}[/yellow] is not copied. Use `lightr backup "
            "create` before this and `lightr backup restore` after, or do "
            "this on a fresh install."
        )
        if cfg.database.driver == "sqlite"
        else None,
    )

    try:
        result = run_it(
            role=role,
            database=database,
            host=host,
            port=port,
            known_password=existing_password(cfg.database.dsn),
        )
    except ProvisionError as exc:
        output.stderr.print(f"[red]error[/red] {exc}")
        raise typer.Exit(1) from None

    if result.created_role:
        output.success(f"Created the role {result.role}")
    if result.created_database:
        output.success(f"Created the database {result.database}")
    if result.reset_password:
        output.warn(
            f"The role {result.role} already existed and its password was not "
            "in this config, so a new one was set. Anything else using that "
            "role will need it."
        )
    if not (result.created_role or result.created_database):
        output.info("The role and database were already there.")

    write_dsn(target, result.dsn)
    output.success(f"Wrote the connection string to {target}")

    state.reload()
    migrations.upgrade(state.config)
    output.success("Database schema is up to date")

    # Dovecot reads this database too, through its own userdb conf --
    # which still names the old SQLite file until it is rewritten.
    # Printing "now run this" would leave delivery broken for exactly
    # as long as it took someone to read the line.
    _reconfigure_dovecot(state.config, target)


def _reconfigure_dovecot(cfg: object, config_path: object) -> None:
    """Point Dovecot at the database Lightr now uses.

    Never fatal: the database move succeeded, and saying mailboxes are
    down is more useful than unwinding it.
    """
    import asyncio
    from pathlib import Path

    from lightr.dovecot.manage import DovecotManager

    report = asyncio.run(
        DovecotManager(cfg).reconcile(save_config=Path(str(config_path)))  # type: ignore[arg-type]
    )
    for change in report.changes:
        if change.action == "written":
            output.success(f"Reconfigured Dovecot: {change.path}")
    if report.reloaded:
        output.success("Dovecot reloaded")
    for warning in report.warnings:
        output.warn(warning)


__all__ = ["app"]
