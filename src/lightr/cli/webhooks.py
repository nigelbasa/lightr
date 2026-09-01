"""Webhook commands.

Delivery, signing, and SSRF vetting already worked; there was no way to
register an endpoint short of writing a row by hand. These commands are
that missing half, plus the one an operator actually reaches for at
3am: `lightr webhook deliveries`, which answers "did they get it?"
"""

from __future__ import annotations

from typing import Annotated

import typer

from lightr.repo import OrganizationRepo
from lightr.webhooks.delivery import VALID_EVENTS, WebhookDeliverer, WebhookRepo

from . import output
from .context import confirm, db, fail, run, state
from .output import Format

app = typer.Typer(no_args_is_help=True, help="Manage webhook endpoints.")

_FORMAT = typer.Option("--format", "-f", help="table, json, or yaml.")
_REF = typer.Argument(help="Webhook name or id.")

COLUMNS = [
    ("name", "NAME"),
    ("url", "URL"),
    ("events", "EVENTS"),
    ("active", "ACTIVE"),
    ("failure_count", "FAILURES"),
    ("last_success", "LAST OK"),
]

DELIVERY_COLUMNS = [
    ("created_at", "WHEN"),
    ("event_type", "EVENT"),
    ("status", "STATUS"),
    ("response_code", "CODE"),
    ("duration_ms", "MS"),
    ("error", "ERROR"),
]


def _shown(hook: object) -> dict:
    """A webhook for display, with the signing secret withheld."""
    data = output.plain(hook)
    assert isinstance(data, dict)
    data["secret"] = "(set)" if data.get("secret") else None
    return data


@app.command("list")
def list_webhooks(
    org: Annotated[str | None, typer.Option("--org")] = None,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """List webhook endpoints."""

    async def _run() -> list:
        async with db() as conn:
            org_id = (await OrganizationRepo(conn).resolve(org)).id if org else None
            return [_shown(h) for h in await WebhookRepo(conn).list(org_id=org_id)]

    output.render(
        run(_run), COLUMNS, fmt=fmt, empty="No webhooks. Try: lightr webhook create"
    )


@app.command("create")
def create_webhook(
    name: Annotated[str, typer.Argument(help="A name you will recognise later.")],
    url: Annotated[str, typer.Argument(help="Where to POST events.")],
    event: Annotated[
        list[str] | None,
        typer.Option(
            "--event",
            help="Subscribe to one event. Repeatable. Every event by default.",
        ),
    ] = None,
    org: Annotated[str | None, typer.Option("--org")] = None,
    description: Annotated[str | None, typer.Option("--description")] = None,
    domain: Annotated[
        str | None, typer.Option("--domain", help="Only fire for this domain.")
    ] = None,
    timeout: Annotated[int, typer.Option("--timeout", help="Seconds.")] = 30,
) -> None:
    """Register a webhook endpoint.

    A signing secret is generated and printed. Every payload is signed
    with it; a receiver that cannot verify a signature has no way to
    tell a real event from anything else that can reach its URL. Unlike
    an API key it is recoverable -- `lightr webhook secret` prints it.
    """

    async def _run():
        async with db() as conn:
            org_id = (await OrganizationRepo(conn).resolve(org)).id if org else None
            return await WebhookRepo(conn).create(
                name,
                url,
                events=list(event or []),
                organization_id=org_id,
                description=description,
                domain_filter=domain,
                timeout=timeout,
            )

    try:
        hook = run(_run)
    except ValueError as exc:  # unknown event, or a URL that is not one
        fail(str(exc))

    output.success(f"Created {hook.name} -> {hook.url} for {', '.join(hook.events)}")
    output.secret("Signing secret", hook.secret, recoverable=True)


@app.command("get")
def get_webhook(
    ref: Annotated[str, _REF],
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Show one webhook."""

    async def _run() -> dict:
        async with db() as conn:
            return _shown(await WebhookRepo(conn).resolve(ref))

    output.detail(run(_run), fmt=fmt)


@app.command("update")
def update_webhook(
    ref: Annotated[str, _REF],
    url: Annotated[str | None, typer.Option("--url")] = None,
    event: Annotated[
        list[str] | None, typer.Option("--event", help="Replaces the current set.")
    ] = None,
    description: Annotated[str | None, typer.Option("--description")] = None,
    domain: Annotated[str | None, typer.Option("--domain")] = None,
    timeout: Annotated[int | None, typer.Option("--timeout")] = None,
    active: Annotated[
        bool | None,
        typer.Option("--enable/--disable", help="Stop or resume delivery."),
    ] = None,
) -> None:
    """Change a webhook. Only what you name is changed."""
    changes: dict[str, object] = {}
    if url is not None:
        changes["url"] = url
    if event:
        changes["events"] = list(event)
    if description is not None:
        changes["description"] = description
    if domain is not None:
        changes["domain_filter"] = domain
    if timeout is not None:
        changes["timeout"] = timeout
    if active is not None:
        changes["active"] = active

    if not changes:
        fail("nothing to change -- pass at least one option")

    async def _run() -> str:
        async with db() as conn:
            repo = WebhookRepo(conn)
            hook = await repo.resolve(ref)
            await repo.update(hook.id, **changes)
            return hook.name

    try:
        name = run(_run)
    except ValueError as exc:
        fail(str(exc))

    output.success(f"Updated {name}: {', '.join(sorted(changes))}")


@app.command("rotate")
def rotate_secret(ref: Annotated[str, _REF]) -> None:
    """Issue a new signing secret.

    The old one stops working immediately, so update the receiver
    before the next event fires.
    """

    async def _run() -> str:
        async with db() as conn:
            repo = WebhookRepo(conn)
            hook = await repo.resolve(ref)
            return await repo.rotate_secret(hook.id)

    output.secret("Signing secret", run(_run), recoverable=True)


@app.command("secret")
def show_secret(ref: Annotated[str, _REF]) -> None:
    """Print a webhook's signing secret.

    It is recoverable, unlike an API key: HMAC needs the secret itself,
    so it is stored rather than hashed. The API never returns it; this
    command does, because someone who can run it already has the
    database.
    """

    async def _run() -> str:
        async with db() as conn:
            return (await WebhookRepo(conn).resolve(ref)).secret

    output.secret("Signing secret", run(_run), recoverable=True)


@app.command("test")
def test_webhook(ref: Annotated[str, _REF]) -> None:
    """Send a test event and report what the receiver said.

    Exercises the real path -- URL vetting, signing, timeout -- so a
    pass here means the next real event will work too.
    """

    async def _run():
        async with db() as conn:
            repo = WebhookRepo(conn)
            hook = await repo.resolve(ref)
            deliverer = WebhookDeliverer(
                allow_private=state.config.webhook.allow_private
            )
            attempt = await deliverer.deliver(
                hook, "ping",
                {"webhook": hook.name, "message": "This is a test from Lightr."},
            )
            await repo.record(hook.id, "ping", {}, attempt)
            return hook, attempt

    hook, attempt = run(_run)

    if attempt.ok:
        output.success(
            f"{hook.name} accepted the test: HTTP {attempt.status_code} "
            f"in {attempt.duration_ms}ms"
        )
        return

    detail = attempt.error or f"HTTP {attempt.status_code}: {attempt.body[:200]}"
    output.stderr.print(f"[red]error[/red] {hook.name} did not accept the test: {detail}")
    if not attempt.retryable:
        output.info("That is not a transient failure; the URL or the receiver is wrong.")
    raise typer.Exit(1)


@app.command("deliveries")
def list_deliveries(
    ref: Annotated[str, _REF],
    limit: Annotated[int, typer.Option("--limit")] = 20,
    fmt: Annotated[Format | None, _FORMAT] = None,
) -> None:
    """Recent delivery attempts, newest first.

    The answer to "did they get it?", which is the only question
    anyone asks about a webhook.
    """

    async def _run() -> tuple[dict, list]:
        async with db() as conn:
            repo = WebhookRepo(conn)
            hook = await repo.resolve(ref)
            return (
                await repo.stats(hook.id),
                await repo.deliveries(hook.id, limit=limit),
            )

    stats, deliveries = run(_run)
    output.render(
        deliveries,
        DELIVERY_COLUMNS,
        fmt=fmt,
        empty="No deliveries yet. Try: lightr webhook test",
    )
    if stats and Format.resolve(fmt) is Format.TABLE:
        output.info(", ".join(f"{k}: {v}" for k, v in sorted(stats.items())))


@app.command("delete")
def delete_webhook(
    ref: Annotated[str, _REF],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete a webhook and its delivery history."""
    confirm(f"Delete webhook {ref}?", yes=yes)

    async def _run() -> str:
        async with db() as conn:
            repo = WebhookRepo(conn)
            hook = await repo.resolve(ref)
            await repo.delete(hook.id)
            return hook.name

    output.success(f"Deleted {run(_run)}")


@app.command("events")
def list_events(fmt: Annotated[Format | None, _FORMAT] = None) -> None:
    """The events a webhook may subscribe to."""
    output.render(
        [{"event": e} for e in sorted(VALID_EVENTS)],
        [("event", "EVENT")],
        fmt=fmt,
    )


__all__ = ["app"]
