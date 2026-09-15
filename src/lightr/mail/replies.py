"""Reply routing for forwarded mail.

When Lightr forwards a message off the server it hands out a token
address on the alias's own domain -- ``reply+<token>@acme.test`` -- and
records who the message was really from. The token does two jobs:

**The envelope sender of every forward.** Forwarding with the original
sender's address fails SPF at the destination: ``example.test`` never
authorised this server. Using an address on our own domain passes, and
a bounce comes back here instead of to a stranger who never sent to
the forwarding destination.

**The Reply-To of a bridged copy.** Someone reading ``alice@acme.test``
mail from their own inbox elsewhere can press reply. The reply arrives
at the token, and Lightr sends it on to the original sender -- from
``alice@acme.test``, with the forwarding stripped out, so the person
who wrote in sees a reply from the address they wrote to and nothing
about where alice actually reads her mail.

This follows the Go engine's end-to-end test for bridges: a Reply-To
token on the mirrored copy, and a reply to that token reaching the
original sender with its subject intact.

Tokens are random, stored, and expire. Stateless SRS would avoid the
table, but a bridge reply needs the original sender, recipients and
destinations looked up anyway, so there is nothing to gain by encoding
half of it into the address.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email import message_from_bytes
from email.message import Message
from email.policy import SMTP as SMTP_POLICY
from email.utils import formataddr, getaddresses, parseaddr
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema

#: The local part every token address starts with.
REPLY_PREFIX = "reply+"

#: Hex, not url-safe base64: routing lowercases every address, so a
#: token with capitals in it would never be found again.
TOKEN_BYTES = 12
_TOKEN = re.compile(rf"^{re.escape(REPLY_PREFIX)}([0-9a-f]{{{TOKEN_BYTES * 2}}})$")

#: How long a token keeps working. Long enough for a reply to a
#: holiday backlog, short enough that the table does not grow forever.
RETENTION = timedelta(days=30)

#: Headers removed from a reply before it goes back to the original
#: sender. They describe the path through the bridge destination's
#: mail provider -- which is exactly what the bridge exists to hide --
#: or are signatures that would no longer verify once From changes.
STRIPPED_FROM_REPLIES = (
    "Received",
    "Return-Path",
    "Sender",
    "Reply-To",
    "Delivered-To",
    "X-Original-To",
    "DKIM-Signature",
    "ARC-Seal",
    "ARC-Message-Signature",
    "ARC-Authentication-Results",
    "Authentication-Results",
    "X-Google-DKIM-Signature",
    "X-Gm-Message-State",
    "X-Received",
    "Cc",
    "Bcc",
)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class RouteKind(StrEnum):
    #: A copy of a bridge alias's mail. Replies to it are relayed.
    BRIDGE = "bridge"
    #: A plain forward. The token is only an envelope sender, so only
    #: bounces are expected back.
    FORWARD = "forward"


@dataclass(slots=True)
class ReplyRoute:
    token: str
    alias_id: UUID
    domain_id: UUID | None
    local_address: str
    original_from: str
    destinations: list[str] = field(default_factory=list)
    account_id: UUID | None = None
    original_to: str | None = None
    original_cc: str | None = None
    kind: RouteKind = RouteKind.BRIDGE
    created_at: datetime = field(default_factory=_now)

    def address(self, domain_name: str) -> str:
        return reply_address(self.token, domain_name)

    @property
    def expired(self) -> bool:
        return self.created_at < _now() - RETENTION

    def accepts_reply_from(self, *senders: str) -> bool:
        """Whether a reply really came from where the copy was sent.

        Checks the envelope sender or the From header. Some providers
        rewrite the envelope of their users' mail, so the envelope
        alone would refuse real replies; the header alone is forgeable.
        Either is enough here because the token itself is the secret --
        it only ever appeared in the copy sent to these destinations.
        """
        allowed = {d.strip().lower() for d in self.destinations}
        return any(s and s.strip().lower() in allowed for s in senders)


def new_token() -> str:
    return secrets.token_hex(TOKEN_BYTES)


def reply_address(token: str, domain_name: str) -> str:
    return f"{REPLY_PREFIX}{token}@{domain_name}"


def token_from(local_part: str) -> str | None:
    """The token in a local part, or None if it is not a token address."""
    match = _TOKEN.match(local_part.strip().lower())
    return match.group(1) if match else None


def reply_target(message: Message, envelope_from: str) -> str:
    """Where the original sender wants replies.

    Their Reply-To if they set one, then their From, then the envelope
    -- the same order a mail client uses when someone presses reply.
    """
    for header in ("Reply-To", "From"):
        value = message.get(header)
        if value:
            addresses = [a for _, a in getaddresses([str(value)]) if "@" in a]
            if addresses:
                return addresses[0].lower()
    return envelope_from.strip().lower()


def header_address(message: Message, header: str = "From") -> str:
    _, address = parseaddr(str(message.get(header, "") or ""))
    return address.lower()


def for_bridge(message: Message, reply_to: str) -> Message:
    """The copy sent to a bridge destination: Reply-To points back here."""
    copy = _copy(message)
    del copy["Reply-To"]
    copy["Reply-To"] = reply_to
    return copy


def clean_reply(message: Message, route: ReplyRoute) -> Message:
    """A reply from a bridge destination, made ready for the original
    sender.

    From becomes the alias address, keeping the display name the replier
    used; To becomes the original sender. The headers that trace the
    reply's path through the replier's own provider are removed, along
    with anything Lightr itself stamped on the way in. The body is not
    touched -- a quoted copy of the original is the replier's to keep.
    """
    from lightr.mail.headers import CONTROLLED_HEADERS

    copy = _copy(message)
    display_name, _ = parseaddr(str(copy.get("From", "") or ""))

    for header in (*STRIPPED_FROM_REPLIES, *CONTROLLED_HEADERS, "From", "To"):
        del copy[header]

    copy["From"] = formataddr((display_name, route.local_address))
    copy["To"] = route.original_from
    return copy


def _copy(message: Message) -> Message:
    """An independent copy: the local delivery keeps the original."""
    return message_from_bytes(message.as_bytes(), policy=SMTP_POLICY)


class ReplyRouteRepo:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(
        self,
        *,
        alias_id: UUID,
        domain_id: UUID,
        local_address: str,
        destinations: list[str],
        original_from: str,
        kind: RouteKind,
        account_id: UUID | None = None,
        original_to: str | None = None,
        original_cc: str | None = None,
    ) -> ReplyRoute:
        route = ReplyRoute(
            token=new_token(),
            alias_id=alias_id,
            domain_id=domain_id,
            account_id=account_id,
            local_address=local_address.lower(),
            destinations=[d.lower() for d in destinations],
            original_from=original_from.lower(),
            original_to=original_to,
            original_cc=original_cc,
            kind=kind,
        )
        await self._conn.execute(
            insert(schema.alias_reply_routes).values(
                token=route.token,
                alias_id=str(route.alias_id),
                domain_id=str(route.domain_id) if route.domain_id else None,
                account_id=str(route.account_id) if route.account_id else None,
                local_address=route.local_address,
                bridge_destinations=json.dumps(route.destinations),
                original_from=route.original_from,
                original_to=route.original_to,
                original_cc=route.original_cc,
                kind=str(route.kind),
                created_at=route.created_at,
            )
        )
        return route

    async def get(self, token: str) -> ReplyRoute | None:
        """A live route. An expired one is as good as absent."""
        row = (
            await self._conn.execute(
                select(schema.alias_reply_routes).where(
                    schema.alias_reply_routes.c.token == token.lower()
                )
            )
        ).first()
        if row is None:
            return None
        route = _to_model(row._mapping)
        return None if route.expired else route

    async def sweep(self, older_than: timedelta = RETENTION) -> int:
        result = await self._conn.execute(
            delete(schema.alias_reply_routes).where(
                schema.alias_reply_routes.c.created_at < _now() - older_than
            )
        )
        return int(result.rowcount or 0)


def _to_model(mapping: Any) -> ReplyRoute:
    data = dict(mapping)
    try:
        destinations = json.loads(data.get("bridge_destinations") or "[]")
    except json.JSONDecodeError:
        destinations = []
    return ReplyRoute(
        token=data["token"],
        alias_id=UUID(str(data["alias_id"])),
        domain_id=UUID(str(data["domain_id"])) if data.get("domain_id") else None,
        account_id=UUID(str(data["account_id"])) if data.get("account_id") else None,
        local_address=data["local_address"],
        destinations=destinations if isinstance(destinations, list) else [],
        original_from=data["original_from"],
        original_to=data.get("original_to"),
        original_cc=data.get("original_cc"),
        kind=RouteKind(data.get("kind") or RouteKind.BRIDGE),
        created_at=data["created_at"],
    )


__all__ = [
    "REPLY_PREFIX",
    "RETENTION",
    "ReplyRoute",
    "ReplyRouteRepo",
    "RouteKind",
    "clean_reply",
    "for_bridge",
    "header_address",
    "new_token",
    "reply_address",
    "reply_target",
    "token_from",
]
