"""API key, queue, and suppression commands.

Operator surfaces for things that go wrong at 3am: which key is being
used, what is stuck in the queue, and why an address stopped receiving
mail.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from typing import Annotated

import click
import typer

from lightr.apikeys import APIKeyRepo, KeyType
from lightr.mail.bounce import BounceRepo
from lightr.mail.queue import Queue, QueueStatus
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

from . import output
from .context import confirm, db, run
from .output import Format

apikey_app = typer.Typer(no_args_is_help=True, help="Manage API keys.")
queue_app = typer.Typer(no_args_is_help=True, help="Inspect the outbound queue.")
suppression_app = typer.Typer(
    no_args_is_help=True, help="Manage the suppression list."
)

_FORMAT = typer.Option("--format", "-f", help="table, json, or yaml.")


# --------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------

KEY_COLUMNS = [
    ("name", "NAME"),
    ("prefix", "PREFIX"),
    ("type", "TYPE"),
    ("active", "ACTIVE"),
    ("usage_count", "USES"),
    ("last_used_at", "LAST USED"),
]


@apikey_app.command("list")
def list_keys(
    org: Annotated[str | None, typer.Option("--org")] = None,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """List API keys. The secrets are not stored and cannot be shown."""

    async def _run() -> list:
        async with db() as conn:
            org_id = (await OrganizationRepo(conn).resolve(org)).id if org else None
            keys = await APIKeyRepo(conn).list(organization_id=org_id)
        return [
            {**k.model_dump(), "key_hash": "(stored)", "scope": k.scope_description()}
            for k in keys
        ]

    output.render(
        run(_run), KEY_COLUMNS, fmt=fmt, empty="No API keys. Try: lightr apikey create"
    )


@apikey_app.command("create")
def create_key(
    name: Annotated[
        str | None,
        typer.Argument(
            help="A name you will recognise later. Omit it to be asked."
        ),
    ] = None,
    key_type: Annotated[KeyType, typer.Option("--type")] = KeyType.ORG,
    org: Annotated[str | None, typer.Option("--org")] = None,
    domain: Annotated[str | None, typer.Option("--domain")] = None,
    account: Annotated[
        str | None, typer.Option("--account", help="For a mailbox-scoped key.")
    ] = None,
    allowed_ip: Annotated[
        list[str] | None,
        typer.Option("--allowed-ip", help="Restrict to an address or CIDR. Repeatable."),
    ] = None,
    expires_in: Annotated[
        int | None, typer.Option("--expires-in", help="Days until it expires.")
    ] = None,
) -> None:
    """Create an API key. The secret is shown once and never again.

    Run it with no arguments to be walked through it: what the key
    should be able to reach, which tenant that is, and when it expires.
    Handing someone a key is the one operator task most likely to be
    done by somebody who has never read this help text.
    """
    if name is None:
        if not interactive():
            output.stderr.print(
                "[red]No name given.[/red] Pass one, or run this in a terminal "
                "to be asked:\n  lightr apikey create <name> --domain example.com"
            )
            raise typer.Exit(1)
        name, key_type, org, domain, account, expires_in = _ask_about_the_key(
            org=org, domain=domain, account=account
        )

    async def _run() -> tuple[object, str]:
        async with db() as conn:
            org_id = None
            domain_id = None
            account_id = None

            if account:
                found = await AccountRepo(conn).resolve(account)
                account_id = found.id
                domain_id = found.domain_id
            if domain:
                domain_id = (await DomainRepo(conn).resolve(domain)).id
            if org:
                org_id = (await OrganizationRepo(conn).resolve(org)).id
            elif key_type is KeyType.ORG:
                org_id = (await OrganizationRepo(conn).default()).id

            return await APIKeyRepo(conn).create(
                name,
                key_type=key_type,
                organization_id=org_id,
                domain_id=domain_id,
                account_id=account_id,
                allowed_ips=list(allowed_ip or []),
                expires_in_days=expires_in,
            )

    key, secret = run(_run)
    # The name, not the id. `scope_description` can only reach for the
    # UUID, and "domain ac82efec-..." tells an operator nothing about
    # which domain they just handed someone a key to.
    scope = account or domain or org or key.scope_description()
    output.success(f"Created {key.name} ({key.prefix}...) for {scope}")
    output.secret("API key", secret)


def interactive() -> bool:
    """Whether there is somebody there to answer a question.

    A separate function so a script that omits the key name gets an
    error rather than a prompt nothing will ever answer.
    """
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):  # pragma: no cover - closed stdin
        return False


#: What each scope means, in the words an operator would use. Shown
#: rather than the enum, because "org" and "domain" only look obvious
#: to whoever wrote the schema.
SCOPES: tuple[tuple[KeyType, str], ...] = (
    (KeyType.ORG, "an organization -- every domain and mailbox it owns"),
    (KeyType.DOMAIN, "one domain -- its mailboxes, and sending as it"),
    (KeyType.ACCOUNT, "one mailbox -- reading it and sending as it"),
    (KeyType.ADMIN, "everything on this server, including other tenants"),
)


def _ask_about_the_key(
    *, org: str | None, domain: str | None, account: str | None
) -> tuple[str, KeyType, str | None, str | None, str | None, int | None]:
    """Walk an operator through creating a key.

    Reads the tenants up front and offers them as a list. Asking
    someone to type an organization name they have not seen is how you
    get a key scoped to a tenant that does not exist -- which fails
    only later, when someone tries to use it.
    """
    tenants = run(_tenants)

    output.stdout.print("What should this key be able to reach?")
    for number, (_, description) in enumerate(SCOPES, start=1):
        output.stdout.print(f"  {number}. {description}")
    choice = typer.prompt("Choose", type=click.IntRange(1, len(SCOPES)), default=2)
    key_type = SCOPES[choice - 1][0]

    if key_type is KeyType.ORG and org is None:
        org = _pick("organization", tenants["organizations"])
    elif key_type is KeyType.DOMAIN and domain is None:
        domain = _pick("domain", tenants["domains"])
    elif key_type is KeyType.ACCOUNT and account is None:
        account = _pick("mailbox", tenants["accounts"])
    elif key_type is KeyType.ADMIN:
        output.warn(
            "An admin key can read and change every tenant on this server. "
            "Scope it to one of them instead unless it is for you."
        )

    subject = account or domain or org or "server"
    name = typer.prompt("A name you will recognise later", default=f"{subject} key")

    expires_in: int | None = None
    if typer.confirm("Should it expire?", default=False):
        expires_in = typer.prompt("Days until it expires", type=int, default=90)

    return name, key_type, org, domain, account, expires_in


async def _tenants() -> dict[str, list[str]]:
    async with db() as conn:
        return {
            "organizations": [
                o.name for o in await OrganizationRepo(conn).list(limit=1000)
            ],
            "domains": [d.name for d in await DomainRepo(conn).list(limit=1000)],
            "accounts": [a.email for a in await AccountRepo(conn).list(limit=1000)],
        }


def _pick(what: str, options: list[str]) -> str:
    """Choose from a list, or type a name if the list is empty."""
    if not options:
        output.warn(f"There are no {what}s yet.")
        return typer.prompt(f"Which {what}")

    if len(options) == 1:
        output.info(f"Using the only {what}: {options[0]}")
        return options[0]

    for number, option in enumerate(options, start=1):
        output.stdout.print(f"  {number}. {option}")
    chosen = typer.prompt(
        f"Which {what}", type=click.IntRange(1, len(options)), default=1
    )
    return options[chosen - 1]


@apikey_app.command("revoke")
def revoke_key(
    key: Annotated[str, typer.Argument(help="Key name, prefix, or id.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Revoke a key. It stops working immediately."""

    async def _lookup() -> object:
        async with db() as conn:
            return await APIKeyRepo(conn).resolve(key)

    found = run(_lookup)
    confirm(
        f"Revoke {found.name} ({found.prefix}...)?",
        yes=yes,
        detail="[yellow]Anything using this key stops working at once.[/yellow]",
    )

    async def _run() -> None:
        async with db() as conn:
            await APIKeyRepo(conn).revoke(found.id)

    run(_run)
    output.success(f"Revoked {found.name}")


@apikey_app.command("rotate")
def rotate_key(
    key: Annotated[str, typer.Argument(help="Key name, prefix, or id.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Replace a key's secret, keeping its name and scope."""

    async def _lookup() -> object:
        async with db() as conn:
            return await APIKeyRepo(conn).resolve(key)

    found = run(_lookup)
    confirm(
        f"Rotate {found.name}?",
        yes=yes,
        detail="[yellow]The old secret stops working immediately.[/yellow]",
    )

    async def _run() -> str:
        async with db() as conn:
            return await APIKeyRepo(conn).rotate(found.id)

    secret = run(_run)
    output.success(f"Rotated {found.name}")
    output.secret("New API key", secret)


@apikey_app.command("delete")
def delete_key(
    key: Annotated[str, typer.Argument(help="Key name, prefix, or id.")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete a key and its usage history."""

    async def _lookup() -> object:
        async with db() as conn:
            return await APIKeyRepo(conn).resolve(key)

    found = run(_lookup)
    confirm(f"Delete {found.name}?", yes=yes)

    async def _run() -> None:
        async with db() as conn:
            await APIKeyRepo(conn).delete(found.id)

    run(_run)
    output.success(f"Deleted {found.name}")


# --------------------------------------------------------------------
# Queue
# --------------------------------------------------------------------

QUEUE_COLUMNS = [
    ("id", "ID"),
    ("from_addr", "FROM"),
    ("to_addrs", "TO"),
    ("subject", "SUBJECT"),
    ("status", "STATUS"),
    ("attempts", "TRIES"),
    ("next_retry", "NEXT TRY"),
]


@queue_app.command("list")
def list_queue(
    status: Annotated[
        QueueStatus | None, typer.Option("--status", help="Filter by status.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """List queued outbound messages."""

    async def _run() -> list:
        async with db() as conn:
            return await Queue(conn).list(status=status, limit=limit)

    output.render(run(_run), QUEUE_COLUMNS, fmt=fmt, empty="The queue is empty.")


@queue_app.command("stats")
def queue_stats(fmt: Annotated[Format | None, _FORMAT] = None) -> None:
    """Count queued messages by status."""

    async def _run() -> dict[str, int]:
        async with db() as conn:
            return await Queue(conn).counts()

    counts = run(_run)
    output.detail(counts or {"pending": 0}, fmt=fmt)

    if counts.get("failed"):
        output.warn(
            f"{counts['failed']} message(s) failed permanently. "
            "Inspect with: lightr queue list --status failed"
        )


@queue_app.command("get")
def get_queued(
    message: Annotated[str, typer.Argument(help="Queue id.")],
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Show one queued message, including why it last failed."""
    from uuid import UUID

    async def _run() -> object:
        try:
            message_id = UUID(message)
        except ValueError as exc:
            raise typer.BadParameter(f"{message!r} is not a queue id") from exc
        async with db() as conn:
            found = await Queue(conn).get(message_id)
        if found is None:
            raise typer.BadParameter(f"no queued message {message}")
        return found

    output.detail(run(_run), fmt=fmt)


@queue_app.command("retry")
def retry_queued(
    message: Annotated[
        str | None, typer.Argument(help="Queue id, or omit for every failed message.")
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Make a message eligible for delivery immediately."""
    from uuid import UUID

    if message is None:
        confirm("Retry every failed message?", yes=yes)

    async def _run() -> int:
        async with db() as conn:
            queue = Queue(conn)
            if message is not None:
                try:
                    await queue.retry_now(UUID(message))
                except ValueError as exc:
                    raise typer.BadParameter(
                        f"{message!r} is not a queue id"
                    ) from exc
                return 1
            failed = await queue.list(status=QueueStatus.FAILED, limit=10_000)
            for item in failed:
                await queue.retry_now(item.id)
            return len(failed)

    count = run(_run)
    output.success(f"{count} message(s) queued for immediate retry")


@queue_app.command("purge")
def purge_queue(
    status: Annotated[QueueStatus, typer.Option("--status")] = QueueStatus.SENT,
    older_than_days: Annotated[int, typer.Option("--older-than", help="In days.")] = 30,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete finished messages older than a cutoff."""
    confirm(
        f"Delete {status} messages older than {older_than_days} days?",
        yes=yes,
        detail="[yellow]This cannot be undone.[/yellow]",
    )

    async def _run() -> int:
        async with db() as conn:
            return await Queue(conn).purge(timedelta(days=older_than_days), status)

    output.success(f"Removed {run(_run)} message(s)")


# --------------------------------------------------------------------
# Suppression
# --------------------------------------------------------------------


@suppression_app.command("list")
def list_suppressed(
    limit: Annotated[int, typer.Option("--limit", "-n")] = 100,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """List addresses Lightr will not send to."""

    async def _run() -> list:
        async with db() as conn:
            return await BounceRepo(conn).list_suppressed(limit=limit)

    output.render(
        run(_run),
        [("email", "ADDRESS"), ("reason", "REASON"), ("created_at", "SINCE")],
        fmt=fmt,
        empty="Nothing is suppressed.",
    )


@suppression_app.command("check")
def check_suppressed(
    email: Annotated[str, typer.Argument(help="Address to check.")],
) -> None:
    """Say whether an address is suppressed, and why.

    The first thing to run when someone reports they stopped receiving
    mail.
    """

    async def _run() -> tuple[bool, list]:
        async with db() as conn:
            repo = BounceRepo(conn)
            suppressed = await repo.is_suppressed(email)
            if not suppressed:
                return False, []
            # Whether it is suppressed and whether we have bounce
            # history are different questions: a manually suppressed
            # address has none. Conflating them would tell an operator
            # the address is fine while mail to it is being dropped.
            return True, await repo.list_bounces(recipient=email, limit=5)

    suppressed, history = run(_run)
    if not suppressed:
        output.success(f"{email} is not suppressed")
        return

    output.stderr.print(f"[yellow]{email} is suppressed.[/yellow]")
    output.render(
        history,
        [
            ("created_at", "WHEN"),
            ("bounce_type", "TYPE"),
            ("diagnostic_code", "DIAGNOSTIC"),
        ],
        fmt=Format.TABLE,
        empty="No bounce history recorded.",
    )
    output.info(f"Allow it again with: lightr suppression remove {email}")


@suppression_app.command("add")
def add_suppression(
    email: Annotated[str, typer.Argument(help="Address to suppress.")],
    reason: Annotated[str, typer.Option("--reason")] = "manual",
) -> None:
    """Stop sending to an address."""

    async def _run() -> None:
        async with db() as conn:
            await BounceRepo(conn).suppress(email, reason=reason)

    run(_run)
    output.success(f"{email} is now suppressed")


@suppression_app.command("remove")
def remove_suppression(
    email: Annotated[str, typer.Argument(help="Address to allow again.")],
) -> None:
    """Allow sending to an address again."""

    async def _run() -> bool:
        async with db() as conn:
            return await BounceRepo(conn).unsuppress(email)

    if run(_run):
        output.success(f"{email} is no longer suppressed")
        return
    output.stderr.print(f"[dim]{email} was not suppressed.[/dim]")
