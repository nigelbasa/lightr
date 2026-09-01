"""Parsing bounces, and suppressing addresses that produce them.

A bounce is how a remote server says an address is dead. Without
parsing them, an engine keeps mailing the same dead addresses forever,
which is one of the fastest ways to lose sending reputation.

The classification that matters is hard versus soft:

* **hard** -- the address does not exist, or the domain does not.
  Suppress it; sending again cannot succeed and actively hurts.
* **soft** -- a full mailbox, a greylist, a temporary outage. Do not
  suppress: the address is fine and will accept mail later.

Getting that backwards is expensive in both directions, so anything
ambiguous is treated as soft. Suppressing a live address silently stops
mail the user expects; retrying a dead one costs only a little
reputation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email import message_from_bytes
from email.message import Message
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema


class BounceType(StrEnum):
    HARD = "hard"
    SOFT = "soft"
    COMPLAINT = "complaint"  # a feedback-loop report, not a delivery failure
    UNKNOWN = "unknown"

    @property
    def should_suppress(self) -> bool:
        """Only hard bounces and complaints stop future sending."""
        return self in (BounceType.HARD, BounceType.COMPLAINT)


#: RFC 3463 enhanced status codes that mean "this address is dead".
#: 5.1.1 no such mailbox, 5.1.2 no such domain, 5.1.3 bad syntax,
#: 5.1.6 mailbox moved, 5.2.1 mailbox disabled.
HARD_STATUS = frozenset({"5.1.1", "5.1.2", "5.1.3", "5.1.6", "5.2.1", "5.4.4"})

#: Codes that are explicitly temporary even though they are 5.x-adjacent.
#: 5.2.2 is a full mailbox -- permanent by class, but the address is
#: alive and suppressing it would be wrong.
SOFT_STATUS = frozenset({"4.2.2", "5.2.2", "4.4.1", "4.4.7", "4.7.1", "4.2.0"})

_STATUS = re.compile(r"\b([45]\.\d{1,3}\.\d{1,3})\b")
_SMTP_CODE = re.compile(r"\b([45]\d{2})\b")
_ANGLE_ADDRESS = re.compile(r"<([^<>@\s]+@[^<>@\s]+)>")

# Phrases that identify a hard failure when no status code is present.
_HARD_PHRASES = (
    "user unknown",
    "no such user",
    "no such recipient",
    "recipient not found",
    "unknown recipient",
    "does not exist",
    "invalid recipient",
    "address rejected",
    "mailbox unavailable",
    "no mailbox here",
    "unrouteable address",
)

_SOFT_PHRASES = (
    "mailbox full",
    "over quota",
    "quota exceeded",
    "insufficient storage",
    "try again later",
    "greylist",
    "temporarily deferred",
    "temporary failure",
    "connection timed out",
)


@dataclass(slots=True)
class Bounce:
    """One parsed delivery failure."""

    recipient: str
    bounce_type: BounceType
    status: str | None = None
    diagnostic: str | None = None
    remote_mta: str | None = None
    original_message_id: str | None = None

    @property
    def should_suppress(self) -> bool:
        return self.bounce_type.should_suppress


def classify(status: str | None, diagnostic: str | None) -> BounceType:
    """Decide whether a failure is permanent.

    Status codes are authoritative when present; the diagnostic text is
    a fallback, because plenty of servers still send prose.
    """
    if status:
        if status in SOFT_STATUS:
            return BounceType.SOFT
        if status in HARD_STATUS:
            return BounceType.HARD
        if status.startswith("4"):
            return BounceType.SOFT
        if status.startswith("5"):
            return BounceType.HARD

    if diagnostic:
        lowered = diagnostic.lower()
        # Soft is checked first: "mailbox full" also contains phrases
        # that look permanent.
        if any(phrase in lowered for phrase in _SOFT_PHRASES):
            return BounceType.SOFT
        if any(phrase in lowered for phrase in _HARD_PHRASES):
            return BounceType.HARD

        code_match = _SMTP_CODE.search(diagnostic)
        if code_match:
            return (
                BounceType.SOFT
                if code_match.group(1).startswith("4")
                else BounceType.HARD
            )

    # Unrecognised: treat as soft. Suppressing a live address silently
    # stops mail a user expects, which is worse than one more retry.
    return BounceType.UNKNOWN


def parse(raw: bytes) -> list[Bounce]:
    """Extract failures from a bounce message.

    Prefers the machine-readable ``message/delivery-status`` part
    (RFC 3464). Falls back to scanning the text when a server sends
    only prose, which many still do.
    """
    message = message_from_bytes(raw)

    if _is_complaint(message):
        return _parse_complaint(message)

    bounces = _parse_delivery_status(message)
    if bounces:
        return bounces
    return _parse_prose(message)


def _is_complaint(message: Message) -> bool:
    """Whether this is an ARF feedback-loop report rather than a bounce."""
    if message.get_content_type() == "multipart/report":
        if message.get_param("report-type", "").lower() == "feedback-report":
            return True
    return any(
        part.get_content_type() == "message/feedback-report"
        for part in message.walk()
    )


def _parse_complaint(message: Message) -> list[Bounce]:
    """A spam complaint. The recipient asked not to receive this."""
    recipients: list[str] = []
    for part in message.walk():
        if part.get_content_type() != "message/feedback-report":
            continue
        # Like delivery-status, an ARF report's fields are headers as
        # far as the email parser is concerned, not body text.
        for fields in _status_blocks(part):
            if address := fields.get("original-rcpt-to"):
                recipients.append(_clean_address(address))
        for line in _part_text(part).splitlines():
            name, _, value = line.partition(":")
            if name.strip().lower() == "original-rcpt-to":
                recipients.append(_clean_address(value))

    if not recipients:
        # Fall back to the embedded original message's To header.
        for part in message.walk():
            if part.get_content_type() == "message/rfc822":
                for sub in part.walk():
                    if sub.get("To"):
                        recipients.append(_clean_address(sub["To"]))
                        break

    return [
        Bounce(recipient=address, bounce_type=BounceType.COMPLAINT)
        for address in dict.fromkeys(a for a in recipients if a)
    ]


def _parse_delivery_status(message: Message) -> list[Bounce]:
    """Parse RFC 3464 per-recipient delivery-status fields."""
    bounces: list[Bounce] = []
    original_id = _original_message_id(message)

    for part in message.walk():
        if part.get_content_type() != "message/delivery-status":
            continue

        for fields in _status_blocks(part):
            recipient = _clean_address(
                fields.get("final-recipient") or fields.get("original-recipient") or ""
            )
            if not recipient:
                continue
            if fields.get("action", "").lower().startswith("deliver"):
                continue  # a success report, not a failure

            status = fields.get("status")
            diagnostic = fields.get("diagnostic-code")
            bounces.append(
                Bounce(
                    recipient=recipient,
                    bounce_type=classify(status, diagnostic),
                    status=status,
                    diagnostic=diagnostic,
                    remote_mta=_strip_type(fields.get("remote-mta")),
                    original_message_id=original_id,
                )
            )
    return bounces


def _status_blocks(part: Message) -> list[dict[str, str]]:
    """The per-recipient field groups inside a delivery-status part.

    RFC 3464 formats these as header blocks, and Python's email parser
    therefore exposes each block as a sub-Message whose *headers* carry
    the fields -- its body is empty. Reading the body would silently
    find nothing, which is exactly the bug this replaced.

    Falls back to parsing raw text for the case where the part did not
    come through the structured parser.
    """
    payload = part.get_payload()

    if isinstance(payload, list):
        blocks = [
            {k.lower(): str(v).strip() for k, v in sub.items()} for sub in payload
        ]
        if any(blocks):
            return [b for b in blocks if b]

    if isinstance(payload, str):
        return [f for block in payload.split("\n\n") if (f := _fields(block))]

    return []


def _parse_prose(message: Message) -> list[Bounce]:
    """Last resort: find an address and a reason in the body text."""
    body = ""
    for part in message.walk():
        if part.get_content_type() == "text/plain":
            body = _part_text(part)
            break
    if not body:
        return []

    addresses = _ANGLE_ADDRESS.findall(body)
    if not addresses:
        return []

    status_match = _STATUS.search(body)
    status = status_match.group(1) if status_match else None

    return [
        Bounce(
            recipient=address.lower(),
            bounce_type=classify(status, body),
            status=status,
            diagnostic=body[:500].strip(),
            original_message_id=_original_message_id(message),
        )
        for address in dict.fromkeys(addresses)
    ]


def _fields(block: str) -> dict[str, str]:
    """Parse ``Name: value`` lines into a lowercase-keyed mapping."""
    out: dict[str, str] = {}
    current: str | None = None
    for line in block.splitlines():
        if line[:1] in (" ", "\t") and current:
            out[current] += " " + line.strip()
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        current = name.strip().lower()
        out[current] = value.strip()
    return out


def _clean_address(value: str) -> str:
    """Strip an address type prefix and any angle brackets."""
    text = value.strip()
    if ";" in text:
        text = text.split(";", 1)[1]
    text = text.strip().strip("<>").strip()
    return text.lower()


def _strip_type(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(";", 1)[-1].strip() or None


def _original_message_id(message: Message) -> str | None:
    """The Message-ID of whatever bounced."""
    for part in message.walk():
        if part.get_content_type() in ("message/rfc822", "text/rfc822-headers"):
            for sub in part.walk():
                if sub.get("Message-ID"):
                    return str(sub["Message-ID"]).strip()
    return None


def _part_text(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        return payload
    # A container part: flatten its children.
    return "\n\n".join(_part_text(sub) for sub in part.get_payload() or [])


class BounceRepo:
    """Recording bounces and maintaining the suppression list."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def record(
        self, bounce: Bounce, *, org_id: UUID, domain_id: UUID
    ) -> bool:
        """Store a bounce, suppressing the address if it is permanent.

        Returns whether the address was suppressed.
        """
        await self._conn.execute(
            insert(schema.bounces).values(
                id=str(uuid4()),
                org_id=str(org_id),
                domain_id=str(domain_id),
                original_msg_id=bounce.original_message_id,
                recipient_email=bounce.recipient,
                bounce_type=str(bounce.bounce_type),
                diagnostic_code=(bounce.diagnostic or "")[:1000] or None,
                remote_mta=bounce.remote_mta,
                created_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )

        if not bounce.should_suppress:
            return False
        await self.suppress(
            bounce.recipient,
            reason=f"{bounce.bounce_type}: {bounce.status or 'no status'}",
            org_id=org_id,
        )
        return True

    async def suppress(
        self, email: str, *, reason: str, org_id: UUID | None = None
    ) -> None:
        """Add an address to the suppression list, idempotently."""
        address = email.strip().lower()
        if await self.is_suppressed(address):
            return
        await self._conn.execute(
            insert(schema.suppression_list).values(
                email=address,
                reason=reason[:255],
                org_id=str(org_id) if org_id else None,
                created_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )

    async def unsuppress(self, email: str) -> bool:
        """Remove an address. Returns whether anything was removed."""
        result = await self._conn.execute(
            delete(schema.suppression_list).where(
                schema.suppression_list.c.email == email.strip().lower()
            )
        )
        return bool(result.rowcount)

    async def is_suppressed(self, email: str) -> bool:
        row = (
            await self._conn.execute(
                select(schema.suppression_list.c.email).where(
                    schema.suppression_list.c.email == email.strip().lower()
                )
            )
        ).first()
        return row is not None

    async def list_suppressed(self, limit: int = 100) -> list[dict[str, object]]:
        rows = await self._conn.execute(
            select(schema.suppression_list)
            .order_by(schema.suppression_list.c.created_at.desc())
            .limit(limit)
        )
        return [dict(r._mapping) for r in rows]

    async def list_bounces(
        self, recipient: str | None = None, limit: int = 100
    ) -> list[dict[str, object]]:
        stmt = (
            select(schema.bounces)
            .order_by(schema.bounces.c.created_at.desc())
            .limit(limit)
        )
        if recipient:
            stmt = stmt.where(
                schema.bounces.c.recipient_email == recipient.strip().lower()
            )
        rows = await self._conn.execute(stmt)
        return [dict(r._mapping) for r in rows]


__all__ = [
    "HARD_STATUS",
    "SOFT_STATUS",
    "Bounce",
    "BounceRepo",
    "BounceType",
    "classify",
    "parse",
]
