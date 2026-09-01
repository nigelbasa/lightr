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
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema
from lightr.webhooks.ssrf import SSRFError, check_url, vet

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
    description: str | None = None
    failure_count: int = 0
    last_success: datetime | None = None
    last_failure: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

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


#: What an operator may subscribe to. "*" means every event, including
#: ones added later.
VALID_EVENTS = frozenset({str(e) for e in Event}) | {"*"}


def validate_events(events: list[str] | None) -> list[str]:
    """Check an event subscription, or default it to everything.

    Strict on purpose: a typo in an event name would otherwise be a
    webhook that is configured, looks healthy, and never fires.
    """
    if not events:
        return ["*"]
    unknown = [e for e in events if e not in VALID_EVENTS]
    if unknown:
        raise ValueError(
            f"unknown event(s): {', '.join(unknown)}. Valid events are "
            f"{', '.join(sorted(VALID_EVENTS))}"
        )
    return list(dict.fromkeys(events))


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

    # -- management -------------------------------------------------------

    async def create(
        self,
        name: str,
        url: str,
        *,
        events: list[str] | None = None,
        secret: str | None = None,
        organization_id: UUID | None = None,
        description: str | None = None,
        domain_filter: str | None = None,
        timeout: int = 30,
        max_retries: int = 5,
        active: bool = True,
    ) -> Webhook:
        """Register an endpoint, generating a signing secret if needed.

        The URL's scheme, host, and port are checked here so a mistake
        is reported when it is made rather than at the first event.
        Resolution is deliberately *not* checked: a receiver that is
        not in DNS yet is an ordinary state, and the delivery path
        vets the address again anyway.
        """
        check_url(url)
        chosen = validate_events(events)

        # A receiver that cannot verify a signature has no way to tell a
        # real event from anything else that can reach its URL, so a
        # webhook without a secret gets one rather than going unsigned.
        signing_secret = secret or secrets.token_urlsafe(32)
        now = datetime.now(UTC).replace(tzinfo=None)
        webhook = Webhook(
            id=uuid4(),
            name=name,
            url=url.strip(),
            secret=signing_secret,
            events=chosen,
            active=active,
            max_retries=max_retries,
            timeout=timeout,
            organization_id=organization_id,
            domain_filter=domain_filter,
            description=description,
            created_at=now,
            updated_at=now,
        )

        await self._conn.execute(
            insert(schema.webhooks).values(
                id=str(webhook.id),
                name=webhook.name,
                description=description,
                url=webhook.url,
                method="POST",
                secret=signing_secret,
                auth_type="none",
                events=json.dumps(chosen),
                organization_id=str(organization_id) if organization_id else None,
                domain_filter=domain_filter,
                max_retries=max_retries,
                timeout=timeout,
                active=active,
                created_at=now,
                updated_at=now,
            )
        )
        return webhook

    async def list(
        self, *, org_id: UUID | None = None, limit: int = 100
    ) -> list[Webhook]:
        stmt = (
            select(schema.webhooks).order_by(schema.webhooks.c.name).limit(limit)
        )
        if org_id is not None:
            stmt = stmt.where(
                (schema.webhooks.c.organization_id == str(org_id))
                | (schema.webhooks.c.organization_id.is_(None))
            )
        rows = await self._conn.execute(stmt)
        return [_to_model(r._mapping) for r in rows]

    async def resolve(self, ref: str) -> Webhook:
        """Find a webhook by id or name.

        Name as well as id, because every other object in this engine
        is addressable by the thing a human wrote down.
        """
        from lightr.repo import AmbiguousReferenceError, NotFoundError, _as_uuid

        table = schema.webhooks
        if (as_uuid := _as_uuid(ref)) is not None:
            row = (
                await self._conn.execute(select(table).where(table.c.id == str(as_uuid)))
            ).first()
            if row is None:
                raise NotFoundError("webhook", ref)
            return _to_model(row._mapping)

        rows = (
            await self._conn.execute(select(table).where(table.c.name == ref))
        ).fetchall()
        if not rows:
            raise NotFoundError("webhook", ref, "try `lightr webhook list`")
        if len(rows) > 1:
            raise AmbiguousReferenceError(
                "webhook", ref, [str(r._mapping["id"]) for r in rows]
            )
        return _to_model(rows[0]._mapping)

    async def update(self, webhook_id: UUID, **values: Any) -> None:
        """Change a webhook. Only the fields given are touched."""
        if values.get("url"):
            check_url(values["url"])
        if "events" in values:
            values["events"] = json.dumps(validate_events(values["events"]))

        allowed = {
            "name", "description", "url", "secret", "events", "domain_filter",
            "max_retries", "timeout", "active",
        }
        changes = {k: v for k, v in values.items() if k in allowed}
        if not changes:
            return

        await self._conn.execute(
            update(schema.webhooks)
            .where(schema.webhooks.c.id == str(webhook_id))
            .values(**changes, updated_at=datetime.now(UTC).replace(tzinfo=None))
        )

    async def rotate_secret(self, webhook_id: UUID) -> str:
        secret = secrets.token_urlsafe(32)
        await self.update(webhook_id, secret=secret)
        return secret

    async def delete(self, webhook_id: UUID) -> None:
        await self._conn.execute(
            delete(schema.webhook_events).where(
                schema.webhook_events.c.webhook_id == str(webhook_id)
            )
        )
        await self._conn.execute(
            delete(schema.webhooks).where(schema.webhooks.c.id == str(webhook_id))
        )

    async def deliveries(
        self, webhook_id: UUID, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        """The recent delivery log, newest first.

        This is the answer to "did they get it?", which is the only
        question anyone asks about a webhook.
        """
        rows = await self._conn.execute(
            select(schema.webhook_events)
            .where(schema.webhook_events.c.webhook_id == str(webhook_id))
            .order_by(schema.webhook_events.c.created_at.desc())
            .limit(limit)
        )
        return [dict(r._mapping) for r in rows]

    async def stats(self, webhook_id: UUID) -> dict[str, int]:
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
        description=data.get("description"),
        failure_count=int(data.get("failure_count") or 0),
        last_success=data.get("last_success"),
        last_failure=data.get("last_failure"),
        created_at=data.get("created_at"),
        updated_at=data.get("updated_at"),
    )


__all__ = [
    "DELIVERY_HEADER",
    "EVENT_HEADER",
    "SIGNATURE_HEADER",
    "SIGNATURE_TOLERANCE",
    "TIMESTAMP_HEADER",
    "VALID_EVENTS",
    "Attempt",
    "DeliveryStatus",
    "Event",
    "Webhook",
    "WebhookDeliverer",
    "WebhookRepo",
    "next_retry_at",
    "sign",
    "validate_events",
    "verify",
]
