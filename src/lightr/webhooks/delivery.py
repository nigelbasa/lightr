"""Delivering webhook events.

Events are queued and delivered with retries rather than sent inline,
for the same reason outbound mail is: a slow endpoint must not hold a
mail transaction open, and a failed delivery should be retried rather
than lost.

Every payload is signed. A receiver that cannot verify a signature has
no way to tell a real event from anything else that can reach its URL,
so the signature is not optional -- a webhook with no secret gets one
generated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema
from lightr.webhooks.ssrf import SSRFError, vet

log = logging.getLogger("lightr.webhooks")

SIGNATURE_HEADER = "X-Lightr-Signature"
TIMESTAMP_HEADER = "X-Lightr-Timestamp"
EVENT_HEADER = "X-Lightr-Event"
DELIVERY_HEADER = "X-Lightr-Delivery"

#: How long a signature stays valid. Bounding this is what stops a
#: captured request being replayed indefinitely.
SIGNATURE_TOLERANCE = timedelta(minutes=5)

RETRY_DELAYS = (
    timedelta(seconds=30),
    timedelta(minutes=5),
    timedelta(minutes=30),
    timedelta(hours=2),
    timedelta(hours=12),
)


class Event(StrEnum):
    MAIL_RECEIVED = "mail.received"
    MAIL_DELIVERED = "mail.delivered"
    MAIL_REJECTED = "mail.rejected"
    MAIL_SENT = "mail.sent"
    MAIL_BOUNCED = "mail.bounced"
    ACCOUNT_CREATED = "account.created"
    ACCOUNT_DELETED = "account.deleted"
    DOMAIN_VERIFIED = "domain.verified"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEFERRED = "deferred"


@dataclass(slots=True)
class Attempt:
    """The result of one delivery attempt."""

    ok: bool
    status_code: int | None = None
    body: str = ""
    error: str = ""
    duration_ms: int = 0

    @property
    def retryable(self) -> bool:
        """Whether trying again could succeed.

        A 4xx means the receiver understood and refused; repeating it
        will not help. 5xx and transport errors are worth retrying.
        """
        if self.status_code is None:
            return True  # transport failure
        if 200 <= self.status_code < 300:
            return False
        return self.status_code >= 500 or self.status_code == 429


def sign(secret: str, timestamp: str, payload: bytes) -> str:
    """The signature for a payload.

    Signs the timestamp *and* the body together. Signing only the body
    would let a captured request be replayed forever.
    """
    message = timestamp.encode("ascii") + b"." + payload
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify(
    secret: str,
    signature: str,
    timestamp: str,
    payload: bytes,
    *,
    tolerance: timedelta = SIGNATURE_TOLERANCE,
) -> bool:
    """Verify a signature, in constant time, within the time window.

    Provided so receivers can be tested against the real implementation
    rather than a description of it.
    """
    try:
        sent_at = datetime.fromtimestamp(int(timestamp), tz=UTC)
    except (ValueError, OSError, OverflowError):
        return False

    if abs(datetime.now(UTC) - sent_at) > tolerance:
        return False

    return hmac.compare_digest(sign(secret, timestamp, payload), signature)


@dataclass(slots=True)
class Webhook:
    """A configured endpoint."""

    id: UUID
    name: str
    url: str
    secret: str
    events: list[str] = field(default_factory=list)
    active: bool = True
    max_retries: int = 5
    timeout: int = 30
    organization_id: UUID | None = None
    domain_filter: str | None = None

    def wants(self, event: Event | str) -> bool:
        if not self.active:
            return False
        return not self.events or str(event) in self.events or "*" in self.events


class WebhookDeliverer:
    """Sends one event to one endpoint."""

    def __init__(self, *, allow_private: bool = False) -> None:
        self._allow_private = allow_private

    async def deliver(
        self, webhook: Webhook, event: Event | str, payload: dict[str, Any]
    ) -> Attempt:
        """Attempt one delivery. Never raises."""
        try:
            target = vet(webhook.url, allow_private=self._allow_private)
        except SSRFError as exc:
            # Not retryable: the URL itself is the problem.
            return Attempt(ok=False, status_code=400, error=str(exc))

        body = json.dumps(
            {
                "event": str(event),
                "timestamp": datetime.now(UTC).isoformat(),
                "data": payload,
            },
            default=str,
        ).encode("utf-8")

        timestamp = str(int(datetime.now(UTC).timestamp()))
        delivery_id = str(uuid4())
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "lightr-webhooks/1",
            SIGNATURE_HEADER: sign(webhook.secret, timestamp, body),
            TIMESTAMP_HEADER: timestamp,
            EVENT_HEADER: str(event),
            DELIVERY_HEADER: delivery_id,
            # Connecting by address means the Host header has to carry
            # the real name, or the receiver cannot route it.
            "Host": target.host,
        }

        try:
            import httpx
        except ImportError:  # pragma: no cover - depends on install
            return Attempt(ok=False, error="httpx is not installed")

        started = datetime.now(UTC)
        try:
            async with httpx.AsyncClient(
                timeout=webhook.timeout,
                # Following redirects would undo the SSRF check: the
                # redirect target is chosen by the receiver.
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    target.connect_url, content=body, headers=headers
                )
        except Exception as exc:
            elapsed = int((datetime.now(UTC) - started).total_seconds() * 1000)
            return Attempt(ok=False, error=str(exc), duration_ms=elapsed)

        elapsed = int((datetime.now(UTC) - started).total_seconds() * 1000)
        return Attempt(
            ok=200 <= response.status_code < 300,
            status_code=response.status_code,
            body=response.text[:500],
            duration_ms=elapsed,
        )


def next_retry_at(attempts: int, *, now: datetime | None = None) -> datetime:
    moment = now or datetime.now(UTC).replace(tzinfo=None)
    index = min(max(attempts - 1, 0), len(RETRY_DELAYS) - 1)
    return moment + RETRY_DELAYS[index]


class WebhookRepo:
    """Stored webhooks and their delivery log."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def list_for(
        self, event: Event | str, *, org_id: UUID | None = None
    ) -> list[Webhook]:
        """Every active webhook that wants this event."""
        stmt = select(schema.webhooks).where(schema.webhooks.c.active.is_(True))
        if org_id is not None:
            stmt = stmt.where(
                (schema.webhooks.c.organization_id == str(org_id))
                | (schema.webhooks.c.organization_id.is_(None))
            )
        rows = await self._conn.execute(stmt)
        hooks = [_to_model(r._mapping) for r in rows]
        return [h for h in hooks if h.wants(event)]

    async def record(
        self,
        webhook_id: UUID,
        event: Event | str,
        payload: dict[str, Any],
        attempt: Attempt,
    ) -> UUID:
        """Log a delivery attempt."""
        event_id = uuid4()
        now = datetime.now(UTC).replace(tzinfo=None)
        status = DeliveryStatus.DELIVERED if attempt.ok else (
            DeliveryStatus.DEFERRED if attempt.retryable else DeliveryStatus.FAILED
        )

        await self._conn.execute(
            insert(schema.webhook_events).values(
                id=str(event_id),
                webhook_id=str(webhook_id),
                event_type=str(event),
                payload=json.dumps(payload, default=str)[:10_000],
                status=str(status),
                attempts=1,
                next_retry=None if attempt.ok else next_retry_at(1, now=now),
                response_code=attempt.status_code,
                response_body=attempt.body or None,
                error=(attempt.error or None),
                created_at=now,
                delivered_at=now if attempt.ok else None,
                duration_ms=attempt.duration_ms,
            )
        )

        await self._conn.execute(
            update(schema.webhooks)
            .where(schema.webhooks.c.id == str(webhook_id))
            .values(
                **(
                    {"last_success": now, "failure_count": 0}
                    if attempt.ok
                    else {
                        "last_failure": now,
                        "failure_count": schema.webhooks.c.failure_count + 1,
                    }
                ),
                updated_at=now,
            )
        )
        return event_id

    async def stats(self, webhook_id: UUID) -> dict[str, int]:
        from sqlalchemy import func

        rows = await self._conn.execute(
            select(schema.webhook_events.c.status, func.count())
            .where(schema.webhook_events.c.webhook_id == str(webhook_id))
            .group_by(schema.webhook_events.c.status)
        )
        return {r[0]: int(r[1]) for r in rows}


def _to_model(mapping: Any) -> Webhook:
    data = dict(mapping)
    events = data.get("events")
    if isinstance(events, str):
        try:
            events = json.loads(events)
        except json.JSONDecodeError:
            events = [e.strip() for e in events.split(",") if e.strip()]
    return Webhook(
        id=UUID(data["id"]),
        name=data["name"],
        url=data["url"],
        secret=data.get("secret") or "",
        events=list(events or []),
        active=bool(data.get("active", True)),
        max_retries=int(data.get("max_retries") or 5),
        timeout=int(data.get("timeout") or 30),
        organization_id=(
            UUID(data["organization_id"]) if data.get("organization_id") else None
        ),
        domain_filter=data.get("domain_filter"),
    )


__all__ = [
    "DELIVERY_HEADER",
    "EVENT_HEADER",
    "SIGNATURE_HEADER",
    "SIGNATURE_TOLERANCE",
    "TIMESTAMP_HEADER",
    "Attempt",
    "DeliveryStatus",
    "Event",
    "Webhook",
    "WebhookDeliverer",
    "WebhookRepo",
    "next_retry_at",
    "sign",
    "verify",
]
