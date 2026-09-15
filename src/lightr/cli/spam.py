"""Spam-checking commands."""

from __future__ import annotations

from typing import Annotated

import typer

from . import output
from .context import run, state
from .output import Format

app = typer.Typer(no_args_is_help=True, help="Spam checking and blocklists.")


@app.command("lists")
def lists(
    zone: Annotated[
        list[str] | None,
        typer.Option("--zone", help="Check this address list instead of the configured ones."),
    ] = None,
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Check that each configured blocklist actually answers.

    Asks every list for its fixed test entries. A list that refuses --
    most often because this server's DNS goes through a public resolver
    -- is not used, and says so here rather than silently doing nothing.
    """
    from lightr.mail.reputation import probe

    spam = state.config.spam
    targets = (
        [(z, "address") for z in zone]
        if zone
        else [(z, "address") for z in spam.dnsbl_zones]
        + [(z, "domain") for z in spam.domain_blocklist_zones]
    )
    if not targets:
        output.warn(
            "No blocklists are configured. Add dnsbl_zones and "
            "domain_blocklist_zones under spam: in /etc/lightr/config.yaml."
        )
        raise typer.Exit(0)

    async def _probe_all() -> list:
        return [await probe(z, kind) for z, kind in targets]

    results = run(_probe_all)
    output.render(
        results,
        [("zone", "List"), ("kind", "Checks"), ("status", "Status"), ("detail", "Detail")],
        fmt=fmt,
    )
    if any(r.status != "working" for r in results):
        raise typer.Exit(1)
