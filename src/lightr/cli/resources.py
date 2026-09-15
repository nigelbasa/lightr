"""Organization, domain, and alias commands."""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from lightr.models import Alias, AliasType, Domain, Organization, SpamPolicy
from lightr.repo import AliasRepo, DomainRepo, OrganizationRepo

from . import output
from .context import confirm, db, run
from .output import Format

org_app = typer.Typer(no_args_is_help=True, help="Manage organizations.")
domain_app = typer.Typer(no_args_is_help=True, help="Manage mail domains.")
alias_app = typer.Typer(no_args_is_help=True, help="Manage address aliases.")

_FORMAT = typer.Option("--format", "-f", help="table, json, or yaml.")


# --------------------------------------------------------------------
# Organizations
# --------------------------------------------------------------------


@org_app.command("list")
def list_orgs(fmt: Annotated[Format | None, _FORMAT] = None) -> None:
    """List organizations."""

    async def _run() -> list[Organization]:
        async with db() as conn:
            return await OrganizationRepo(conn).list()

    output.render(
        run(_run),
        [("name", "NAME"), ("id", "ID"), ("created_at", "CREATED")],
        fmt=fmt,
        empty="No organizations yet. Try: lightr org create",
    )


@org_app.command("get")
def get_org(
    org: Annotated[str, typer.Argument(help="Name or id.")],
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Show one organization."""

    async def _run() -> Organization:
        async with db() as conn:
            return await OrganizationRepo(conn).resolve(org)

    output.detail(run(_run), fmt=fmt)


@org_app.command("create")
def create_org(name: Annotated[str, typer.Argument(help="Organization name.")]) -> None:
    """Create an organization."""

    async def _run() -> Organization:
        async with db() as conn:
            return await OrganizationRepo(conn).create(Organization(name=name))

    created = run(_run)
    output.success(f"Created organization {created.name} ({created.id})")


@org_app.command("rename")
def rename_org(
    org: Annotated[str, typer.Argument(help="Name or id.")],
    name: Annotated[str, typer.Argument(help="The new name.")],
) -> None:
    """Rename an organization."""

    async def _run() -> None:
        async with db() as conn:
            repo = OrganizationRepo(conn)
            await repo.rename((await repo.resolve(org)).id, name)

    run(_run)
    output.success(f"Renamed to {name}")


@org_app.command("delete")
def delete_org(
    org: Annotated[str, typer.Argument(help="Name or id.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete an organization. Its domains must be removed first."""

    async def _lookup() -> Organization:
        async with db() as conn:
            return await OrganizationRepo(conn).resolve(org)

    found = run(_lookup)
    confirm(f"Delete organization {found.name}?", yes=yes)

    async def _run() -> None:
        async with db() as conn:
            await OrganizationRepo(conn).delete(found.id)

    run(_run)
    output.success(f"Deleted {found.name}")


# --------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------

DOMAIN_COLUMNS = [
    ("name", "DOMAIN"),
    ("mail_hostname", "MAIL HOST"),
    ("is_verified", "VERIFIED"),
    ("spam_policy", "SPAM"),
    ("relay_enabled", "RELAY"),
]


@domain_app.command("list")
def list_domains(
    org: Annotated[str | None, typer.Option("--org", help="Limit to one organization.")] = None,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """List domains."""

    async def _run() -> list[Domain]:
        async with db() as conn:
            org_id = (await OrganizationRepo(conn).resolve(org)).id if org else None
            return await DomainRepo(conn).list(org_id=org_id)

    output.render(
        run(_run), DOMAIN_COLUMNS, fmt=fmt, empty="No domains yet. Try: lightr domain create"
    )


@domain_app.command("get")
def get_domain(
    domain: Annotated[str, typer.Argument(help="Domain name, an address, or an id.")],
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Show one domain."""

    async def _run() -> Domain:
        async with db() as conn:
            return await DomainRepo(conn).resolve(domain)

    found = run(_run)
    data = found.model_dump()
    # Never echo credentials or private keys.
    if data.get("dkim_private_key"):
        data["dkim_private_key"] = "(set)"
    if data.get("relay_password"):
        data["relay_password"] = "(set)"
    if data.get("auth_webhook_secret"):
        data["auth_webhook_secret"] = "(set)"
    output.detail(data, fmt=fmt)


@domain_app.command("create")
def create_domain(
    name: Annotated[str, typer.Argument(help="Domain name, e.g. acme.test")],
    org: Annotated[
        str | None, typer.Option("--org", help="Owning organization. Defaults to the only one.")
    ] = None,
    mail_hostname: Annotated[
        str | None, typer.Option("--mail-hostname", help="Public MX hostname, e.g. mail.acme.test")
    ] = None,
    spam_policy: Annotated[SpamPolicy, typer.Option("--spam-policy")] = SpamPolicy.JUNK,
) -> None:
    """Create a domain."""

    async def _run() -> Domain:
        async with db() as conn:
            orgs = OrganizationRepo(conn)
            owner = await orgs.resolve(org) if org else await orgs.default()
            return await DomainRepo(conn).create(
                Domain(
                    org_id=owner.id,
                    name=name,
                    mail_hostname=mail_hostname,
                    spam_policy=spam_policy,
                )
            )

    created = run(_run)
    output.success(f"Created domain {created.name}")
    output.info(f"Next: lightr domain dns {created.name}   # records to publish")


@domain_app.command("delete")
def delete_domain(
    domain: Annotated[str, typer.Argument(help="Domain name or id.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete a domain. Its accounts must be removed first."""

    async def _lookup() -> tuple[Domain, int]:
        async with db() as conn:
            from lightr.repo import AccountRepo

            found = await DomainRepo(conn).resolve(domain)
            return found, await AccountRepo(conn).count(domain_id=found.id)

    found, account_count = run(_lookup)
    if account_count:
        # soft_wrap: a wrapped command is a command the reader cannot copy.
        output.stderr.print(
            f"[red]{found.name} still has {account_count} account(s).[/red]", soft_wrap=True
        )
        output.stderr.print(
            f"Remove them first: lightr account list --domain {found.name}", soft_wrap=True
        )
        raise typer.Exit(1)

    confirm(f"Delete domain {found.name}?", yes=yes)

    async def _run() -> None:
        async with db() as conn:
            await DomainRepo(conn).delete(found.id)

    run(_run)
    output.success(f"Deleted {found.name}")


@domain_app.command("relay")
def domain_relay(
    domain: Annotated[str, typer.Argument(help="Domain name or id.")],
    host: Annotated[
        str | None, typer.Option("--host", help="Smarthost, e.g. smtp.resend.com")
    ] = None,
    port: Annotated[
        int | None, typer.Option("--port", help="587 or 2525 (STARTTLS), 465 (TLS).")
    ] = None,
    username: Annotated[str | None, typer.Option("--username")] = None,
    password_prompt: Annotated[
        bool, typer.Option("--password", help="Prompt for the relay password.")
    ] = False,
    password_stdin: Annotated[
        bool, typer.Option("--password-stdin", help="Read the relay password from stdin.")
    ] = False,
    tls: Annotated[
        bool | None,
        typer.Option("--tls/--no-tls", help="STARTTLS. On by default when a host is set."),
    ] = None,
    skip_verify: Annotated[
        bool | None,
        typer.Option("--skip-verify/--verify", help="Skip checking the relay's certificate."),
    ] = None,
    enable: Annotated[
        bool | None, typer.Option("--enable/--disable", help="Keep the settings, switch use.")
    ] = None,
    clear: Annotated[bool, typer.Option("--clear", help="Remove every relay setting.")] = False,
    test: Annotated[
        bool, typer.Option("--test", help="Connect and log in to the relay; send nothing.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Show or set the smarthost this domain's outgoing mail goes through.

    Receiving is unchanged; mail is still DKIM-signed here as the domain.
    The password is never a flag -- that would put it in shell history
    and in `ps` output -- so it comes from a prompt or from stdin.
    """
    from lightr.mail import relay as relay_tools
    from lightr.mail.sender import Sender

    from .context import state

    if password_prompt and password_stdin:
        raise typer.BadParameter("--password and --password-stdin are mutually exclusive")

    password: str | None = None
    if password_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            raise typer.BadParameter("no password on stdin")
    elif password_prompt:
        password = typer.prompt("Relay password", hide_input=True)

    async def _find() -> Domain:
        async with db() as conn:
            return await DomainRepo(conn).resolve(domain)

    found = run(_find)
    changing = clear or any(
        v is not None for v in (host, port, username, password, tls, skip_verify, enable)
    )

    if changing:
        if clear:
            confirm(f"Remove the relay settings for {found.name}?", yes=yes)
        effective_port = port if port is not None else found.relay_port
        if host is not None and tls is None and effective_port != relay_tools.IMPLICIT_TLS_PORT:
            tls = True
        if host is not None and enable is None:
            enable = True
        change = relay_tools.RelayChange(
            enabled=enable, host=host, port=port, username=username, password=password,
            use_tls=tls, skip_verify=skip_verify, clear=clear,
        )
        try:
            relay_tools.apply(found, change)
        except relay_tools.RelayError as exc:
            raise typer.BadParameter(str(exc)) from exc

        async def _save() -> None:
            async with db() as conn:
                await DomainRepo(conn).update(found)

        run(_save)
        output.success(f"Relay for {found.name} is {'on' if found.relay_enabled else 'off'}")

    output.detail(relay_tools.view(found), fmt=fmt)
    if changing and found.relay_enabled:
        output.info(
            f"Add the provider to {found.name}'s SPF record and publish any records it "
            "asks for. Mail is still signed with this domain's own DKIM key."
        )

    if test:
        helo = Sender(state.config, engine=None).helo_name(found)  # type: ignore[arg-type]

        async def _test() -> str:
            return await relay_tools.test_login(found, local_hostname=helo)

        try:
            output.success(run(_test))
        except relay_tools.RelayError as exc:
            output.stderr.print(f"[red]Relay test failed:[/red] {exc}", soft_wrap=True)
            raise typer.Exit(1) from exc


# --------------------------------------------------------------------
# Aliases
# --------------------------------------------------------------------

ALIAS_COLUMNS = [
    ("source", "SOURCE"),
    ("type", "TYPE"),
    ("destinations", "DESTINATIONS"),
    ("is_active", "ACTIVE"),
]


@alias_app.command("list")
def list_aliases(
    domain: Annotated[str | None, typer.Option("--domain", "-d")] = None,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """List aliases."""

    async def _run() -> list[Alias]:
        async with db() as conn:
            domain_id = (await DomainRepo(conn).resolve(domain)).id if domain else None
            return await AliasRepo(conn).list(domain_id=domain_id)

    output.render(run(_run), ALIAS_COLUMNS, fmt=fmt, empty="No aliases yet.")


@alias_app.command("create")
def create_alias(
    source: Annotated[str, typer.Argument(help="Alias address, e.g. sales@acme.test")],
    destinations: Annotated[
        str, typer.Option("--destinations", "-t", help="Comma-separated addresses.")
    ],
    alias_type: Annotated[AliasType, typer.Option("--type")] = AliasType.FORWARD,
) -> None:
    """Create an alias."""
    if "@" not in source:
        raise typer.BadParameter("give the full alias address, e.g. sales@acme.test")

    async def _run() -> Alias:
        async with db() as conn:
            domain = await DomainRepo(conn).resolve(source.split("@", 1)[1])
            return await AliasRepo(conn).create(
                Alias(
                    domain_id=domain.id,
                    source=source,
                    destinations=destinations,
                    type=alias_type,
                )
            )

    created = run(_run)
    output.success(
        f"Created {created.type} alias {created.source} -> {', '.join(created.destinations)}"
    )


@alias_app.command("delete")
def delete_alias(
    alias: Annotated[str, typer.Argument(help="Alias source or id.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete an alias."""

    async def _lookup() -> Alias:
        async with db() as conn:
            return await AliasRepo(conn).resolve(alias)

    found = run(_lookup)
    confirm(f"Delete alias {found.source}?", yes=yes)

    async def _run() -> None:
        async with db() as conn:
            await AliasRepo(conn).delete(found.id)

    run(_run)
    output.success(f"Deleted alias {found.source}")


@domain_app.command("dns")
def domain_dns(
    domain: Annotated[str, typer.Argument(help="Domain name or id.")],
    fmt: Annotated[Format | None, _FORMAT] = None,
    zone: Annotated[
        bool, typer.Option("--zone", help="Print as zone-file lines.")
    ] = False,
) -> None:
    """Show the DNS records this domain should publish.

    Lightr never pushes records into a DNS provider -- it tells you
    what to publish and then verifies what you did.
    """
    from lightr.mail.dns_records import records_for

    async def _run() -> tuple[Domain, list]:
        async with db() as conn:
            found = await DomainRepo(conn).resolve(domain)
        return found, records_for(
            found.name,
            mail_hostname=found.hostname,
            dkim_selector=found.dkim_selector or "default",
            dkim_public_key=_dkim_public_key(found),
        )

    found, records = run(_run)

    if zone:
        for record in records:
            output.raw(record.as_zone_line())
        return

    output.render(
        [
            {
                "kind": str(r.kind),
                "name": r.name,
                "type": r.type,
                "priority": r.priority,
                "value": r.value,
            }
            for r in records
        ],
        [("kind", "RECORD"), ("name", "NAME"), ("type", "TYPE"), ("value", "VALUE")],
        fmt=fmt,
        empty="No records to publish.",
    )
    if not found.dkim_private_key:
        output.warn(
            f"No DKIM key yet. Run: lightr domain dkim {found.name} --generate"
        )
    output.info(f"Then check with: lightr domain verify {found.name}")


@domain_app.command("verify")
def domain_verify(
    domain: Annotated[str, typer.Argument(help="Domain name or id.")],
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Check the domain's live DNS against what Lightr expects."""
    from lightr.mail.dns_records import verify as verify_dns

    async def _run() -> tuple[Domain, object]:
        async with db() as conn:
            found = await DomainRepo(conn).resolve(domain)
        result = await verify_dns(
            found.name,
            mail_hostname=found.hostname,
            dkim_selector=found.dkim_selector or "default",
            dkim_public_key=_dkim_public_key(found),
        )
        if result.verified and not found.is_verified:
            async with db() as conn:
                found.is_verified = True
                await DomainRepo(conn).update(found)
        return found, result

    found, result = run(_run)

    output.render(
        [
            {
                "record": str(c.kind),
                "state": str(c.state),
                "found": ", ".join(c.found) or None,
                "detail": c.detail or None,
            }
            for c in result.checks
        ],
        [("record", "RECORD"), ("state", "STATE"), ("found", "PUBLISHED")],
        fmt=fmt,
        empty="Nothing to check.",
    )

    if result.verified:
        output.success(f"{found.name} is verified")
        return

    for failure in result.failures:
        output.warn(f"{failure.kind}: {failure.state} -- {failure.detail or ''}".strip())
    output.info(f"See the expected records with: lightr domain dns {found.name}")
    raise typer.Exit(1)


@domain_app.command("dkim")
def domain_dkim(
    domain: Annotated[str, typer.Argument(help="Domain name or id.")],
    generate: Annotated[
        bool, typer.Option("--generate", help="Generate a new key pair.")
    ] = False,
    selector: Annotated[str, typer.Option("--selector")] = "default",
    bits: Annotated[int, typer.Option("--bits", help="Key size.")] = 2048,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Show or generate this domain's DKIM key."""
    from lightr.mail.dkim import generate_key

    async def _show() -> Domain:
        async with db() as conn:
            return await DomainRepo(conn).resolve(domain)

    found = run(_show)

    if not generate:
        if not found.dkim_private_key:
            output.stderr.print(
                f"[yellow]{found.name} has no DKIM key.[/yellow] "
                f"Generate one with: lightr domain dkim {found.name} --generate"
            )
            raise typer.Exit(1)
        public = _dkim_public_key(found)
        output.raw(
            f'{found.dkim_selector or "default"}._domainkey.{found.name}. '
            f'IN TXT "v=DKIM1; k=rsa; p={public}"'
        )
        return

    if found.dkim_private_key:
        confirm(
            f"Replace the DKIM key for {found.name}?",
            yes=yes,
            detail=(
                "[yellow]Mail signed with the old key stops verifying "
                "until the new record propagates.[/yellow]"
            ),
        )

    key = generate_key(selector, bits)

    async def _save() -> None:
        async with db() as conn:
            repo = DomainRepo(conn)
            current = await repo.resolve(domain)
            current.dkim_private_key = key.private_key_pem
            current.dkim_selector = selector
            await repo.update(current)

    run(_save)
    output.success(f"Generated a {bits}-bit DKIM key for {found.name}")
    output.info("Publish this record, then run: lightr domain verify " + found.name)
    output.raw(key.dns_record(found.name))


def _dkim_public_key(domain: Domain) -> str | None:
    """Derive the public key from a stored private key."""
    if not domain.dkim_private_key:
        return None
    try:
        import base64

        from cryptography.hazmat.primitives import serialization

        private = serialization.load_pem_private_key(
            domain.dkim_private_key.encode("ascii"), password=None
        )
        der = private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(der).decode("ascii")
    except Exception:
        return None
