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
from email.message import EmailMessage, Message
from email.policy import SMTP as SMTP_POLICY
from email.utils import formataddr, formatdate, getaddresses, make_msgid, parseaddr
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


#: The first and last lines of the header card a forwarded copy opens
#: with, in its text part. A reply quotes them, and the lines between
#: them are what comes out again before the reply is relayed.
FORWARD_MARKER = "---------- Forwarded by Lightr ----------"
ORIGINAL_MARKER = "---------- Original message ----------"
#: The caption of the card's HTML table, which is how that table is
#: found again inside a quoted reply.
HTML_MARKER = "Forwarded by Lightr"
#: In the Message-ID of every wrapped copy, so a reply's References can
#: be cleaned of it: the original sender never saw that message.
FORWARD_ID_TAG = "lightr-fwd"

_QUOTE_PREFIX = re.compile(r"^[\s>]*")
_TABLE_TAG = re.compile(r"<(/?)table\b[^>]*>", re.IGNORECASE)
_BODY_TAG = re.compile(r"<body\b[^>]*>", re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")


def wrap_forward(message: Message, *, alias_address: str, reply_to: str) -> EmailMessage:
    """The copy of a message that leaves the server for an alias.

    Sent as the alias, not as the original sender: a relay such as
    Resend refuses mail whose From is a domain it has not verified, and
    the receiver's DMARC check fails a stranger's domain sent from our
    IP. Who really wrote it goes in a header card at the top of the body,
    and Reply-To says where an answer goes -- the reply token for a
    bridge, the original sender for a plain forward. The original body
    and its attachments follow the card unchanged.
    """
    from html import escape

    name, sender = parseaddr(str(message.get("From", "") or ""))
    domain_name = alias_address.rsplit("@", 1)[-1]
    shown = name or sender or "someone"

    wrapped = EmailMessage(policy=SMTP_POLICY)
    for value in message.get_all("Received") or []:
        wrapped["Received"] = " ".join(str(value).split())
    wrapped["From"] = formataddr((f"{shown} via {domain_name}", alias_address))
    wrapped["To"] = _one_line(message.get("To")) or alias_address
    wrapped["Reply-To"] = reply_to
    wrapped["Subject"] = _one_line(message.get("Subject"))
    wrapped["Date"] = _one_line(message.get("Date")) or formatdate(localtime=True)
    wrapped["Message-ID"] = make_msgid(idstring=FORWARD_ID_TAG, domain=domain_name)
    original_id = _one_line(message.get("Message-ID"))
    references = " ".join(
        v for v in (_one_line(message.get("References")), original_id) if v
    )
    if references:
        wrapped["References"] = references
    if in_reply_to := _one_line(message.get("In-Reply-To")):
        wrapped["In-Reply-To"] = in_reply_to

    fields = [
        (label, _one_line(message.get(label)))
        for label in ("From", "Date", "Subject", "To", "Cc")
    ]
    fields = [(label, value) for label, value in fields if value]
    hint = f"Reply to this message to answer {shown}."

    text_part, html_part = _bodies(message)
    original_text = text_part.get_content() if text_part is not None else (
        _html_to_text(html_part.get_content()) if html_part is not None else ""
    )
    card_text = "\n".join(
        [FORWARD_MARKER, *(f"{label}: {value}" for label, value in fields), hint,
         ORIGINAL_MARKER, ""]
    )
    wrapped.set_content(card_text + "\n" + original_text)

    rows = "<br>".join(
        f"<b>{escape(label)}:</b> {escape(value)}" for label, value in fields
    )
    card_html = (
        '<table role="presentation" cellpadding="0" cellspacing="0" '
        'style="border:1px solid #d9dde3;border-radius:8px;margin:0 0 16px;'
        "width:100%;max-width:640px;font-family:Arial,Helvetica,sans-serif;"
        'font-size:13px;color:#3c4043">'
        '<tr><td style="padding:10px 14px;border-bottom:1px solid #e8eaed;'
        f'font-weight:bold;color:#1a73e8">{HTML_MARKER}</td></tr>'
        f'<tr><td style="padding:10px 14px;line-height:1.5">{rows}'
        f'<div style="margin-top:6px;color:#5f6368">{escape(hint)}</div>'
        "</td></tr></table>"
    )
    if html_part is not None:
        original_html = html_part.get_content()
        body = _BODY_TAG.search(original_html)
        html = (
            original_html[: body.end()] + card_html + original_html[body.end():]
            if body else card_html + original_html
        )
    else:
        html = (
            f"{card_html}<div style=\"white-space:pre-wrap\">"
            f"{escape(original_text)}</div>"
        )
    wrapped.add_alternative(html, subtype="html")

    chosen = {id(p) for p in (text_part, html_part) if p is not None}
    for part in message.walk():
        if part.is_multipart() or id(part) in chosen:
            continue
        maintype, _, subtype = part.get_content_type().partition("/")
        wrapped.add_attachment(
            part.get_payload(decode=True) or b"",
            maintype=maintype, subtype=subtype,
            filename=part.get_filename() or "attachment",
        )
        if content_id := part.get("Content-ID"):
            attached = wrapped.get_payload()[-1]
            attached["Content-ID"] = str(content_id)
    return wrapped


def clean_reply(message: Message, route: ReplyRoute) -> Message:
    """A reply from a bridge destination, made ready for the original
    sender.

    From becomes the alias address, keeping the display name the replier
    used; To becomes the original sender. The headers that trace the
    reply's path through the replier's own provider are removed, along
    with anything Lightr itself stamped on the way in.

    In the body, the reply keeps what the replier wrote and the original
    message they quoted. Only the forward's header card comes out, and
    the token address, wherever a mail client quoted it, becomes the
    alias. A card that cannot be found -- a client that mangled the
    quote -- leaves the body as it was: a reply with some Lightr text in
    it beats a reply that never arrives.
    """
    from lightr.mail.headers import CONTROLLED_HEADERS

    copy = _copy(message)
    display_name, _ = parseaddr(str(copy.get("From", "") or ""))

    for header in (*STRIPPED_FROM_REPLIES, *CONTROLLED_HEADERS, "From", "To"):
        del copy[header]

    copy["From"] = formataddr((display_name, route.local_address))
    copy["To"] = route.original_from

    token_address = reply_address(route.token, route.local_address.rsplit("@", 1)[-1])
    _unwrap_bodies(copy, token_address=token_address, alias_address=route.local_address)
    _drop_forward_ids(copy)
    return copy


def _one_line(value: object) -> str:
    return " ".join(str(value or "").split())


def _bodies(message: Message) -> tuple[Any, Any]:
    get_body = getattr(message, "get_body", None)
    if get_body is None:  # pragma: no cover - always an EmailMessage here
        return None, None
    return get_body(preferencelist=("plain",)), get_body(preferencelist=("html",))


def _html_to_text(html: str) -> str:
    from html import unescape

    return unescape(_HTML_TAG.sub("", html))


def _unwrap_bodies(message: Message, *, token_address: str, alias_address: str) -> None:
    token = re.compile(re.escape(token_address), re.IGNORECASE)
    for part in message.walk():
        if part.is_multipart() or part.get_filename():
            continue
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (KeyError, LookupError):  # an unknown charset: leave it be
            continue
        stripped = (
            strip_card_text(content) if content_type == "text/plain"
            else strip_card_html(content)
        )
        stripped = token.sub(alias_address, stripped)
        if stripped != content:
            part.set_content(stripped, subtype=content_type.split("/")[1])


def strip_card_text(text: str) -> str:
    """Remove a quoted header card from a plain-text reply."""
    lines = text.splitlines(keepends=True)

    def bare(line: str) -> str:
        return _QUOTE_PREFIX.sub("", line).strip()

    start = next((i for i, line in enumerate(lines) if bare(line) == FORWARD_MARKER), None)
    if start is None:
        return text
    end = next(
        (j for j in range(start + 1, len(lines)) if bare(lines[j]) == ORIGINAL_MARKER), None
    )
    if end is None:
        return text
    return "".join(lines[:start] + lines[end + 1:])


def strip_card_html(html: str) -> str:
    """Remove a quoted header card from an HTML reply."""
    at = html.find(HTML_MARKER)
    if at < 0:
        return html
    start = html.lower().rfind("<table", 0, at)
    if start < 0:
        return html
    depth = 0
    for tag in _TABLE_TAG.finditer(html, start):
        depth += -1 if tag.group(1) else 1
        if depth == 0:
            return html[:start] + html[tag.end():]
    return html


def _drop_forward_ids(message: Message) -> None:
    """Take the wrapped copy's Message-ID out of a reply's threading.

    The original sender never saw that message; the original's own ID,
    carried in the copy's References, is what threads for them.
    """
    references = [
        ref for ref in _one_line(message.get("References")).split()
        if FORWARD_ID_TAG not in ref
    ]
    in_reply_to = _one_line(message.get("In-Reply-To"))
    del message["References"]
    if references:
        message["References"] = " ".join(references)
    if FORWARD_ID_TAG in in_reply_to or not in_reply_to:
        del message["In-Reply-To"]
        if references:
            message["In-Reply-To"] = references[-1]


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
    "FORWARD_ID_TAG",
    "FORWARD_MARKER",
    "HTML_MARKER",
    "ORIGINAL_MARKER",
    "REPLY_PREFIX",
    "RETENTION",
    "ReplyRoute",
    "ReplyRouteRepo",
    "RouteKind",
    "clean_reply",
    "header_address",
    "new_token",
    "reply_address",
    "reply_target",
    "strip_card_html",
    "strip_card_text",
    "token_from",
    "wrap_forward",
]
