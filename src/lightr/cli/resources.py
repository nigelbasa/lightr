"""Organization, domain, and alias commands."""

from __future__ import annotations

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
