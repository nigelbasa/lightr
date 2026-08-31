"""Dovecot commands: generate its configuration, and check the seams."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from lightr.dovecot import config as dovecot_config
from lightr.dovecot.lmtp import LMTPClient, LMTPError
from lightr.dovecot.maildir import layout_for
from lightr.repo import AccountRepo

from . import output
from .context import confirm, db, run, state
from .output import Format

app = typer.Typer(no_args_is_help=True, help="Configure and check Dovecot.")


@app.command("setup")
def setup(
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing internal key.")
    ] = False,
) -> None:
    """Generate the shared secret Dovecot needs, and save it to the config.

    Run this once per install, before `dovecot config`.
    """
    cfg = state.config
    target = state.config_path or type(cfg).default_path()

    if cfg.dovecot.internal_key and not force:
        output.stderr.print(
            "[yellow]An internal key is already set.[/yellow] "
            "Pass --force to replace it -- Dovecot's Lua script must then be "
            "regenerated, or IMAP logins will start failing."
        )
        raise typer.Exit(1)

    cfg.dovecot.internal_key = dovecot_config.generate_internal_key()
    cfg.save(target)

    output.success(f"Generated an internal key and saved it to {target}")
    output.info("Next: lightr dovecot config --write")


@app.command("config")
def show_config(
    write: Annotated[
        bool, typer.Option("--write", help="Write the files instead of printing them.")
    ] = False,
    out_dir: Annotated[
        Path | None,
        typer.Option("--out-dir", help="Write here instead of the real locations."),
    ] = None,
    api_url: Annotated[
        str | None, typer.Option("--api-url", help="Where Dovecot should reach Lightr.")
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Generate Dovecot's configuration and auth script.

    Prints to stdout by default so the files can be reviewed before
    anything on the system changes.
    """
    try:
        files = dovecot_config.generate(state.config, api_base_url=api_url)
    except dovecot_config.DovecotConfigError as exc:
        output.stderr.print(f"[red]error[/red] {exc}")
        raise typer.Exit(1) from None

    if not write:
        for generated in files:
            output.stderr.print(f"[dim]# --- {generated.path} ---[/dim]")
            output.raw(generated.content)
        output.info("Nothing written. Re-run with --write to install these.")
        return

    targets = [
        (out_dir / generated.path.name if out_dir else generated.path, generated)
        for generated in files
    ]

    existing = [str(path) for path, _ in targets if path.exists()]
    if existing:
        confirm(
            "Overwrite them?",
            yes=yes,
            detail="[yellow]These files already exist:[/yellow]\n  "
            + "\n  ".join(existing),
        )

    for path, generated in targets:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generated.content, encoding="utf-8")
            path.chmod(generated.mode)
        except OSError as exc:
            output.stderr.print(f"[red]could not write {path}:[/red] {exc}")
            raise typer.Exit(1) from exc
        note = " (contains the internal key)" if generated.is_secret else ""
        output.success(f"Wrote {path}{note}")

    output.info("Then: systemctl restart dovecot")


@app.command("check")
def check() -> None:
    """Check that Lightr can reach Dovecot."""
    cfg = state.config
    problems: list[str] = []

    if not cfg.dovecot.internal_key:
        problems.append("dovecot.internal_key is unset -- run: lightr dovecot setup")
    if not cfg.dovecot.has_master_user:
        problems.append(
            "dovecot.master_user/master_password are unset -- "
            "`lightr mailbox` commands will not work"
        )

    lmtp_target = (
        str(cfg.dovecot.lmtp_socket)
        if cfg.dovecot.uses_lmtp_socket
        else f"{cfg.dovecot.lmtp_host}:{cfg.dovecot.lmtp_port}"
    )

    async def _probe() -> str | None:
        client = LMTPClient(cfg.dovecot, timeout=5.0)
        try:
            # An empty recipient list never opens a connection, so probe
            # with a real one that Dovecot will simply reject.
            await client.deliver("", ["probe@invalid"], b"")
        except LMTPError as exc:
            return str(exc)
        return None

    failure = run(_probe)
    reachable = failure is None or "cannot reach" not in failure

    output.detail(
        {
            "lmtp": lmtp_target,
            "lmtp_reachable": reachable,
            "imap": f"{cfg.dovecot.imap_host}:{cfg.dovecot.imap_port}",
            "maildir_root": str(cfg.dovecot.maildir_root),
            "sieve_dir": str(cfg.dovecot.sieve_dir),
            "internal_key_set": bool(cfg.dovecot.internal_key),
            "master_user_set": cfg.dovecot.has_master_user,
        }
    )

    if not reachable:
        problems.append(f"cannot reach Dovecot LMTP at {lmtp_target}")

    for problem in problems:
        output.warn(problem)
    if problems:
        raise typer.Exit(1)
    output.success("Dovecot looks reachable.")


@app.command("provision")
def provision(
    account: Annotated[
        str | None, typer.Argument(help="One account, or omit for all of them.")
    ] = None,
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Create Maildir trees for accounts that have none.

    Dovecot creates a Maildir on first delivery, so this is optional --
    but doing it up front means a new account is selectable in an IMAP
    client immediately, rather than looking broken until its first mail.
    """

    async def _run() -> list[tuple[str, str, bool]]:
        async with db() as conn:
            repo = AccountRepo(conn)
            accounts = (
                [await repo.resolve(account)] if account else await repo.list(limit=10_000)
            )

        results: list[tuple[str, str, bool]] = []
        for record in accounts:
            email = record.email
            if email is None:
                continue
            layout = layout_for(state.config.dovecot.maildir_root, email)
            already = layout.exists()
            if not already:
                layout.create()
            results.append((email, layout.posix, already))
        return results

    results = run(_run)
    created = [r for r in results if not r[2]]

    output.render(
        [{"email": e, "maildir": p, "status": "existed" if a else "created"}
         for e, p, a in results],
        [("email", "ACCOUNT"), ("maildir", "MAILDIR"), ("status", "STATUS")],
        fmt=fmt,
        empty="No accounts to provision.",
    )
    output.success(f"{len(created)} created, {len(results) - len(created)} already present")
