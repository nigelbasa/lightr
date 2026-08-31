"""Account commands, including the password handling the Go CLI lacked.

``account passwd`` exists because the only way to set a password used
to be ``--password`` on create/update, which writes the plaintext into
shell history and into ``ps`` output for every user on the machine.
Passwords here come from a prompt, from stdin, or are generated.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from lightr.auth import (
    PasswordError,
    generate_password,
    hash_password_async,
    validate_password,
)
from lightr.dovecot.maildir import layout_for
from lightr.models import Account, AuthMode
from lightr.repo import AccountRepo, DomainRepo

from . import output
from .context import confirm, db, fail, run, state
from .output import Format

app = typer.Typer(no_args_is_help=True, help="Manage mail accounts.")


def _date_only(value: object) -> str:
    """Trim an ISO timestamp to its date for table display."""
    return str(value).split("T")[0] if value else "-"

COLUMNS = [
    ("email", "EMAIL"),
    ("display_name", "NAME"),
    ("auth_mode", "AUTH"),
    ("quota_bytes", "QUOTA", output.human_size),
    ("created_at", "CREATED", _date_only),
]


@app.command("list")
def list_accounts(
    domain: Annotated[
        str | None, typer.Option("--domain", "-d", help="Limit to one domain.")
    ] = None,
    limit: Annotated[int, typer.Option(help="Maximum rows to return.")] = 100,
    fmt: Annotated[
        Format | None, typer.Option("--format", "-f", help="table, json, or yaml.")
    ] = None,
) -> None:
    """List accounts."""

    async def _run() -> list[Account]:
        async with db() as conn:
            domain_id = None
            if domain:
                domain_id = (await DomainRepo(conn).resolve(domain)).id
            return await AccountRepo(conn).list(domain_id=domain_id, limit=limit)

    rows = run(_run)
    output.render(rows, COLUMNS, fmt=fmt, empty="No accounts yet. Try: lightr account create")


@app.command("get")
def get_account(
    account: Annotated[str, typer.Argument(help="Email address, local part, or id.")],
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Show one account."""

    async def _run() -> Account:
        async with db() as conn:
            return await AccountRepo(conn).resolve(account)

    found = run(_run)
    # Never print the hash, even in JSON: it is a credential.
    data = found.model_dump()
    data["password_hash"] = "(set)" if found.password_hash else None
    data["email"] = found.email
    output.detail(data, fmt=fmt)


@app.command("create")
def create_account(
    email: Annotated[str, typer.Argument(help="Full address, e.g. ops@acme.test")],
    display_name: Annotated[str | None, typer.Option("--display-name")] = None,
    quota: Annotated[
        str | None, typer.Option("--quota", help="Mailbox quota, e.g. 2GB. Omit for unlimited.")
    ] = None,
    external: Annotated[
        bool, typer.Option("--external", help="Authenticate via a configured provider.")
    ] = False,
    external_id: Annotated[str | None, typer.Option("--external-id")] = None,
    generate: Annotated[
        bool, typer.Option("--generate-password", help="Generate a password and print it once.")
    ] = False,
    no_password: Annotated[
        bool, typer.Option("--no-password", help="Create without a password; set it later.")
    ] = False,
) -> None:
    """Create an account.

    Prompts for the password unless --generate-password, --no-password,
    or --external is given. The password is never taken from a flag.
    """
    if "@" not in email:
        raise typer.BadParameter("give the full address, e.g. ops@acme.test")

    password: str | None = None
    if external:
        pass
    elif generate:
        password = generate_password()
    elif not no_password:
        password = _prompt_new_password()

    async def _run() -> tuple[Account, str | None]:
        local_part, domain_name = email.split("@", 1)
        async with db() as conn:
            domain = await DomainRepo(conn).resolve(domain_name)
            account = Account(
                domain_id=domain.id,
                local_part=local_part,
                display_name=display_name,
                auth_mode=AuthMode.EXTERNAL if external else AuthMode.NATIVE,
                external_id=external_id,
                quota_bytes=_parse_size(quota),
            )
            if password is not None:
                account.password_hash = await hash_password_async(password)

            layout = layout_for(state.config.dovecot.maildir_root, f"{local_part}@{domain.name}")
            account.maildir_path = str(layout.root)

            created = await AccountRepo(conn).create(account)
            created.with_domain(domain)
            return created, str(layout.root)

    account, maildir = run(_run)
    output.success(f"Created {account.email}")
    output.info(f"Maildir: {maildir}")
    if generate and password:
        output.secret("Password", password)
    if not account.password_hash and not external:
        output.warn(f"No password set. Run: lightr account passwd {account.email}")


@app.command("passwd")
def set_password(
    account: Annotated[str, typer.Argument(help="Email address, local part, or id.")],
    stdin: Annotated[
        bool, typer.Option("--stdin", help="Read the password from standard input.")
    ] = False,
    generate: Annotated[
        bool, typer.Option("--generate", help="Generate one and print it once.")
    ] = False,
) -> None:
    """Set or reset an account password.

    Reads from a prompt by default. Never accepts the password as a
    command-line flag -- that would leak it into shell history and into
    `ps` output for every user on the machine.
    """
    if stdin and generate:
        raise typer.BadParameter("--stdin and --generate are mutually exclusive")

    if generate:
        password = generate_password()
    elif stdin:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            raise typer.BadParameter("no password on stdin")
        _validate(password)
    else:
        password = _prompt_new_password()

    async def _run() -> str:
        async with db() as conn:
            repo = AccountRepo(conn)
            found = await repo.resolve(account)
            await repo.set_password_hash(found.id, await hash_password_async(password))
            return found.email or account

    email = run(_run)
    output.success(f"Password updated for {email}")
    if generate:
        output.secret("Password", password)


@app.command("update")
def update_account(
    account: Annotated[str, typer.Argument(help="Email address, local part, or id.")],
    display_name: Annotated[str | None, typer.Option("--display-name")] = None,
    quota: Annotated[str | None, typer.Option("--quota", help="e.g. 2GB, or 'none'.")] = None,
    enable: Annotated[bool, typer.Option("--enable", help="Re-enable a disabled account.")] = False,
    disable: Annotated[bool, typer.Option("--disable", help="Block all logins.")] = False,
) -> None:
    """Change account settings. Use `passwd` for the password."""
    if enable and disable:
        raise typer.BadParameter("--enable and --disable are mutually exclusive")

    async def _run() -> str:
        async with db() as conn:
            repo = AccountRepo(conn)
            found = await repo.resolve(account)
            if display_name is not None:
                found.display_name = display_name
            if quota is not None:
                found.quota_bytes = None if quota.lower() == "none" else _parse_size(quota)
            if disable:
                found.auth_mode = AuthMode.DISABLED
            if enable:
                found.auth_mode = AuthMode.NATIVE
            await repo.update(found)
            return found.email or account

    output.success(f"Updated {run(_run)}")


@app.command("delete")
def delete_account(
    account: Annotated[str, typer.Argument(help="Email address, local part, or id.")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation.")] = False,
    purge_mail: Annotated[
        bool, typer.Option("--purge-mail", help="Also delete the Maildir on disk.")
    ] = False,
) -> None:
    """Delete an account."""

    async def _lookup() -> Account:
        async with db() as conn:
            return await AccountRepo(conn).resolve(account)

    found = run(_lookup)
    detail = (
        f"This deletes the account [bold]{found.email}[/bold].\n"
        f"Its mail at {found.maildir_path or '(unknown)'} "
        + ("will also be deleted." if purge_mail else "will be left on disk.")
    )
    confirm(f"Delete {found.email}?", yes=yes, detail=detail)

    async def _run() -> None:
        async with db() as conn:
            await AccountRepo(conn).delete(found.id)

    run(_run)
    output.success(f"Deleted {found.email}")
    if purge_mail and found.maildir_path:
        output.warn(
            f"Mail at {found.maildir_path} was NOT removed -- delete it manually "
            "once you are sure it is not needed."
        )


def _prompt_new_password() -> str:
    password = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
    _validate(password)
    return password


def _validate(password: str) -> None:
    """Validate, reporting failure as advice rather than a traceback.

    This runs before `run()` takes over error handling, so it has to
    do its own translation.
    """
    try:
        validate_password(password)
    except PasswordError as exc:
        fail(str(exc))


_UNITS = {"b": 1, "k": 1024, "kb": 1024, "m": 1024**2, "mb": 1024**2,
          "g": 1024**3, "gb": 1024**3, "t": 1024**4, "tb": 1024**4}


def _parse_size(value: str | None) -> int | None:
    """Parse '2GB' into bytes. Plain digits are already bytes."""
    if value is None:
        return None
    text = value.strip().lower().replace(" ", "")
    if not text or text == "none":
        return None
    if text.isdigit():
        return int(text)
    for suffix in sorted(_UNITS, key=len, reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)]
            try:
                return int(float(number) * _UNITS[suffix])
            except ValueError as exc:
                raise typer.BadParameter(f"{value!r} is not a size, e.g. 2GB") from exc
    raise typer.BadParameter(f"{value!r} is not a size, e.g. 2GB")
