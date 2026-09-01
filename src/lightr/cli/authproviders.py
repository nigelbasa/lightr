"""Offloaded-authentication commands.

The command that earns this group is `lightr auth test`. "Login
failed" is useless to whoever has to fix it; what they need is which
provider was asked, what it said, and whether it answered at all. That
is what `test` prints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from lightr.authproviders import KINDS, AuthProviderRepo, redact
from lightr.models import AuthMode
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

from . import output
from .context import confirm, db, fail, run
from .output import Format

app = typer.Typer(
    no_args_is_help=True,
    help="Offload authentication to LDAP, an HTTP endpoint, or OIDC.",
)

_FORMAT = typer.Option("--format", "-f", help="table, json, or yaml.")
_REF = typer.Argument(help="Provider name or id.")

COLUMNS = [
    ("name", "NAME"),
    ("kind", "TYPE"),
    ("domains", "DOMAINS"),
    ("priority", "PRIORITY"),
    ("enabled", "ENABLED"),
    ("is_default", "DEFAULT"),
]


def _shown(record: Any) -> dict:
    data = output.plain(record)
    assert isinstance(data, dict)
    data["config"] = redact(data.get("config") or {})
    return data


def _parse_settings(pairs: list[str] | None, config_file: Path | None) -> dict[str, Any]:
    """Build a provider config from a file and/or --set key=value.

    A file, because an LDAP config is a dozen fields and nobody wants a
    dozen flags. --set on top of it, because changing one of them
    should not mean editing a file.
    """
    config: dict[str, Any] = {}

    if config_file is not None:
        try:
            parsed = json.loads(config_file.read_text(encoding="utf-8"))
        except OSError as exc:
            fail(f"could not read {config_file}: {exc}")
        except json.JSONDecodeError as exc:
            fail(f"{config_file} is not valid JSON: {exc}")
        if not isinstance(parsed, dict):
            fail(f"{config_file} must hold a JSON object")
        config.update(parsed)

    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        if not sep:
            fail(f"--set expects key=value, got {pair!r}")
        config[key.strip()] = _coerce(value)

    return config


def _coerce(value: str) -> Any:
    """Turn a command-line string into the type it obviously is."""
    lowered = value.strip().lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if value.strip().isdigit():
        return int(value.strip())
    return value


@app.command("list")
def list_providers(
    org: Annotated[str | None, typer.Option("--org")] = None,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """List configured authentication providers, in the order they are asked."""

    async def _run() -> list:
        async with db() as conn:
            org_id = (await OrganizationRepo(conn).resolve(org)).id if org else None
            return [_shown(r) for r in await AuthProviderRepo(conn).list(org_id=org_id)]

    output.render(
        run(_run),
        COLUMNS,
        fmt=fmt,
        empty="No auth providers. Everything authenticates locally.",
    )


@app.command("add")
def add_provider(
    kind: Annotated[
        str, typer.Argument(help=f"One of: {', '.join(sorted(KINDS))}.")
    ],
    name: Annotated[str, typer.Argument(help="A name you will recognise later.")],
    domain: Annotated[
        list[str] | None,
        typer.Option("--domain", help="Domains this answers for. Repeatable."),
    ] = None,
    setting: Annotated[
        list[str] | None,
        typer.Option("--set", help="A config value, as key=value. Repeatable."),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option("--config-file", help="JSON file holding the provider config."),
    ] = None,
    org: Annotated[str | None, typer.Option("--org")] = None,
    priority: Annotated[
        int, typer.Option("--priority", help="Lower is asked first.")
    ] = 100,
    default: Annotated[
        bool,
        typer.Option("--default", help="Answer for any domain no provider names."),
    ] = False,
    sync_groups: Annotated[bool, typer.Option("--sync-groups")] = False,
) -> None:
    """Add an authentication provider.

    \b
    ldap     --set uri=ldaps://dc.corp --set base_dn=ou=people,dc=corp
             --set bind_dn=... --set bind_password=... [--set user_filter=(mail={username})]
    oidc     --set introspection_url=... --set client_id=... --set client_secret=...
             (or --set userinfo_url=...)
    webhook  --set url=https://app.example.com/auth --set secret=...

    An account only uses a provider once it is switched over:
    `lightr auth enable <account>`.
    """
    config = _parse_settings(setting, config_file)

    async def _run():
        async with db() as conn:
            org_id = (await OrganizationRepo(conn).resolve(org)).id if org else None
            for name_ in domain or []:
                # Resolve so a typo'd domain fails here rather than
                # silently matching nothing at login time.
                await DomainRepo(conn).resolve(name_)
            return await AuthProviderRepo(conn).create(
                name,
                kind,
                config,
                org_id=org_id,
                domains=list(domain or []),
                priority=priority,
                is_default=default,
                sync_groups=sync_groups,
            )

    record = run(_run)

    where = ", ".join(record.domains) or ("any domain" if default else "no domain yet")
    output.success(f"Added {kind} provider {record.name} for {where}")
    if not record.domains and not default:
        output.warn(
            "It answers for nothing until you give it --domain or --default. "
            f"Run: lightr auth update {record.name} --domain <your-domain>"
        )


@app.command("get")
def get_provider(
    ref: Annotated[str, _REF],
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Show one provider. Passwords and client secrets are masked."""

    async def _run() -> dict:
        async with db() as conn:
            return _shown(await AuthProviderRepo(conn).resolve(ref))

    output.detail(run(_run), fmt=fmt)


@app.command("update")
def update_provider(
    ref: Annotated[str, _REF],
    domain: Annotated[
        list[str] | None, typer.Option("--domain", help="Replaces the current set.")
    ] = None,
    setting: Annotated[
        list[str] | None,
        typer.Option("--set", help="Merged into the existing config."),
    ] = None,
    priority: Annotated[int | None, typer.Option("--priority")] = None,
    default: Annotated[bool | None, typer.Option("--default/--no-default")] = None,
    enabled: Annotated[bool | None, typer.Option("--enable/--disable")] = None,
) -> None:
    """Change a provider. Only what you name is changed."""
    changes: dict[str, Any] = {}
    if domain:
        changes["domains"] = list(domain)
    if priority is not None:
        changes["priority"] = priority
    if default is not None:
        changes["is_default"] = default
    if enabled is not None:
        changes["enabled"] = enabled

    if not changes and not setting:
        fail("nothing to change -- pass at least one option")

    async def _run() -> str:
        async with db() as conn:
            repo = AuthProviderRepo(conn)
            record = await repo.resolve(ref)
            if setting:
                changes["config"] = {**record.config, **_parse_settings(setting, None)}
            await repo.update(record.id, **changes)
            return record.name

    output.success(f"Updated {run(_run)}")


@app.command("delete")
def delete_provider(
    ref: Annotated[str, _REF],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete a provider.

    Accounts pointed at it keep ``auth_mode = external`` and will stop
    being able to log in, so it says how many.
    """

    async def _count() -> tuple[str, int]:
        async with db() as conn:
            record = await AuthProviderRepo(conn).resolve(ref)
            accounts = await AccountRepo(conn).list(limit=100_000)
            affected = sum(
                1
                for a in accounts
                if a.auth_mode is AuthMode.EXTERNAL
                and (not record.domains or (a.domain_name or "") in record.domains)
            )
            return record.name, affected

    name, affected = run(_count)
    detail = None
    if affected:
        detail = (
            f"[yellow]{affected} account(s) authenticate externally and may have "
            f"nothing left to answer for them.[/yellow]"
        )
    confirm(f"Delete auth provider {name}?", yes=yes, detail=detail)

    async def _run() -> None:
        async with db() as conn:
            repo = AuthProviderRepo(conn)
            await repo.delete((await repo.resolve(ref)).id)

    run(_run)
    output.success(f"Deleted {name}")


@app.command("enable")
def enable_for_account(
    account: Annotated[str, typer.Argument(help="Account to switch over.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Point an account at offloaded authentication.

    Its local password stops being consulted at once -- the provider is
    the only thing that can let it in from then on.
    """
    confirm(
        f"Switch {account} to external authentication?",
        yes=yes,
        detail="[yellow]Its local password will no longer work.[/yellow]",
    )

    async def _run() -> str:
        async with db() as conn:
            repo = AccountRepo(conn)
            found = await repo.resolve(account)
            found.auth_mode = AuthMode.EXTERNAL
            found.password_hash = None
            await repo.update(found)
            return found.email or account

    email = run(_run)
    output.success(f"{email} now authenticates externally")
    output.info(f"Check it works: lightr auth test {email}")


@app.command("local")
def local_for_account(
    account: Annotated[str, typer.Argument(help="Account to switch back.")],
) -> None:
    """Switch an account back to a local password.

    It will have none until one is set, so this is two steps on
    purpose: it does not invent a password nobody asked for.
    """

    async def _run() -> str:
        async with db() as conn:
            repo = AccountRepo(conn)
            found = await repo.resolve(account)
            found.auth_mode = AuthMode.NATIVE
            await repo.update(found)
            return found.email or account

    email = run(_run)
    output.success(f"{email} now authenticates locally")
    output.warn(f"It has no password yet. Run: lightr account passwd {email}")


@app.command("test")
def test_login(
    username: Annotated[str, typer.Argument(help="Address to try, e.g. ops@acme.test")],
    stdin: Annotated[
        bool,
        typer.Option("--stdin", help="Read the password from standard input."),
    ] = False,
) -> None:
    """Try a real login and say exactly what happened.

    Runs the same path SMTP, the API, and Dovecot's passdb all run, so
    a pass here means a mail client will get in too.
    """
    import sys

    # Never a flag: it would land in shell history and in `ps` output
    # for every user on the machine.
    secret = (
        sys.stdin.readline().rstrip("\n")
        if stdin
        else typer.prompt("Password", hide_input=True)
    )

    async def _run():
        from lightr.auth import Authenticator

        async with db() as conn:
            return await Authenticator(conn).authenticate(username, secret)

    result = run(_run)

    if result.ok:
        via = result.provider or "the local password"
        output.success(f"{username} authenticated via {via}")
        return

    assert result.failure is not None
    output.stderr.print(f"[red]error[/red] {username}: {result.failure.value}")
    if result.detail:
        output.stderr.print(f"  {result.detail}")
    if result.temporary:
        output.warn(
            "This is a provider problem, not a wrong password. Dovecot is being "
            "told to try again later rather than that the password is wrong."
        )
    raise typer.Exit(1)


__all__ = ["app"]
