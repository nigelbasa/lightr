"""The outbound queue.

Mail that leaves the server goes through here rather than being sent
inline, so a slow or temporarily unreachable remote MTA cannot hold an
SMTP transaction open, and so a failed send is retried instead of lost.

Two rules drive the design:

* **A message is never delivered twice.** Claiming a row before sending
  it is what makes that true when more than one sender runs.
* **A permanent failure must not be retried.** A 5xx is the remote
  server saying "never"; retrying it wastes reputation and delays the
  bounce the sender is waiting for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema

#: Backoff between attempts. Roughly exponential, capped so a message
#: is not still being retried a week later.
RETRY_DELAYS = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=30),
    timedelta(hours=2),
    timedelta(hours=8),
)

DEFAULT_MAX_ATTEMPTS = 5


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class QueueStatus(StrEnum):
    PENDING = "pending"
    SENDING = "sending"  # claimed by a sender
    SENT = "sent"
    FAILED = "failed"  # permanently; a bounce is owed
    DEFERRED = "deferred"  # transient failure, will retry


@dataclass(slots=True)
class QueuedMessage:
    """One message waiting to leave."""

    id: UUID
    org_id: UUID
    domain_id: UUID
    from_addr: str
    to_addrs: list[str]
    subject: str
    body: str
    status: QueueStatus
    attempts: int
    max_attempts: int
    next_retry: datetime
    last_error: str | None = None
    raw: bytes | None = None
    envelope_from: str | None = None

    @property
    def sender(self) -> str:
        """The SMTP envelope sender: rewritten for a forward, else From."""
        return self.envelope_from or self.from_addr

    @property
    def exhausted(self) -> bool:
        return self.attempts >= self.max_attempts


def classify_failure(code: int) -> QueueStatus:
    """Whether a send failure should be retried.

    4xx is the remote server saying "not now"; 5xx is "never". Retrying
    a 5xx burns sending reputation and delays the bounce.
    """
    return QueueStatus.DEFERRED if 400 <= code < 500 else QueueStatus.FAILED


def next_retry_at(attempts: int, *, now: datetime | None = None) -> datetime:
    """When to try again after ``attempts`` failures."""
    moment = now or _now()
    index = min(max(attempts - 1, 0), len(RETRY_DELAYS) - 1)
    return moment + RETRY_DELAYS[index]


class Queue:
    """Persistent outbound queue over ``email_queue``."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def enqueue(
        self,
        *,
        org_id: UUID,
        domain_id: UUID,
        from_addr: str,
        to_addrs: list[str],
        subject: str,
        body: str,
        html_body: str | None = None,
        headers: dict[str, str] | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        raw: bytes | None = None,
        envelope_from: str | None = None,
    ) -> UUID:
        """Add a message. Returns its queue id.

        Pass ``raw`` whenever there is a real message to send -- anything
        from a mail client, anything forwarded. ``subject`` and ``body``
        are then only for listing the queue.
        """
        if not to_addrs:
            raise ValueError("a queued message needs at least one recipient")

        message_id = uuid4()
        now = _now()
        await self._conn.execute(
            insert(schema.email_queue).values(
                id=str(message_id),
                org_id=str(org_id),
                domain_id=str(domain_id),
                from_addr=from_addr,
                to_addrs=json.dumps(to_addrs),
                subject=subject,
                body=body,
                html_body=html_body,
                headers=json.dumps(headers or {}),
                raw=raw,
                envelope_from=envelope_from,
                status=str(QueueStatus.PENDING),
                attempts=0,
                max_attempts=max_attempts,
                next_retry=now,
                created_at=now,
                updated_at=now,
            )
        )
        return message_id

    async def claim(self, limit: int = 10) -> list[QueuedMessage]:
        """Take messages that are due, marking them as ours.

        The claim is what stops two senders delivering the same message
        twice. It is a single UPDATE ... WHERE status = 'pending', so
        whichever sender's write lands first wins and the other sees no
        rows.
        """
        now = _now()
        due = (
            await self._conn.execute(
                select(schema.email_queue.c.id)
                .where(
                    and_(
                        schema.email_queue.c.status.in_(
                            [str(QueueStatus.PENDING), str(QueueStatus.DEFERRED)]
                        ),
                        schema.email_queue.c.next_retry <= now,
                    )
                )
                .order_by(schema.email_queue.c.next_retry)
                .limit(limit)
            )
        ).fetchall()

        claimed: list[QueuedMessage] = []
        for row in due:
            message_id = row._mapping["id"]
            result = await self._conn.execute(
                update(schema.email_queue)
                .where(
                    and_(
                        schema.email_queue.c.id == message_id,
                        schema.email_queue.c.status.in_(
                            [str(QueueStatus.PENDING), str(QueueStatus.DEFERRED)]
                        ),
                    )
                )
                .values(status=str(QueueStatus.SENDING), updated_at=now)
            )
            if result.rowcount:
                message = await self.get(UUID(message_id))
                if message is not None:
                    claimed.append(message)
        return claimed

    async def get(self, message_id: UUID) -> QueuedMessage | None:
        row = (
            await self._conn.execute(
                select(schema.email_queue).where(
                    schema.email_queue.c.id == str(message_id)
                )
            )
        ).first()
        return _to_model(row._mapping) if row else None

    async def mark_sent(self, message_id: UUID) -> None:
        now = _now()
        await self._conn.execute(
            update(schema.email_queue)
            .where(schema.email_queue.c.id == str(message_id))
            .values(
                status=str(QueueStatus.SENT),
                delivered_at=now,
                updated_at=now,
                last_error=None,
            )
        )

    async def mark_failed(
        self, message_id: UUID, *, code: int, error: str
    ) -> QueueStatus:
        """Record a failure and decide what happens next.

        Returns the status the message ended up in, so a caller can
        raise a bounce when it is terminal.
        """
        message = await self.get(message_id)
        if message is None:
            raise LookupError(f"no queued message {message_id}")

        attempts = message.attempts + 1
        outcome = classify_failure(code)

        if outcome is QueueStatus.DEFERRED and attempts >= message.max_attempts:
            # Out of retries: a transient failure becomes permanent.
            outcome = QueueStatus.FAILED

        now = _now()
        await self._conn.execute(
            update(schema.email_queue)
            .where(schema.email_queue.c.id == str(message_id))
            .values(
                status=str(outcome),
                attempts=attempts,
                last_error=error[:1000],
                next_retry=next_retry_at(attempts, now=now),
                updated_at=now,
            )
        )
        return outcome

    async def release(self, message_id: UUID) -> None:
        """Un-claim a message, e.g. when a sender is shutting down."""
        await self._conn.execute(
            update(schema.email_queue)
            .where(
                and_(
                    schema.email_queue.c.id == str(message_id),
                    schema.email_queue.c.status == str(QueueStatus.SENDING),
                )
            )
            .values(status=str(QueueStatus.PENDING), updated_at=_now())
        )

    async def list(
        self, status: QueueStatus | None = None, limit: int = 100
    ) -> list[QueuedMessage]:
        stmt = (
            select(schema.email_queue)
            .order_by(schema.email_queue.c.created_at.desc())
            .limit(limit)
        )
        if status is not None:
            stmt = stmt.where(schema.email_queue.c.status == str(status))
        rows = await self._conn.execute(stmt)
        return [_to_model(r._mapping) for r in rows]

    async def retry_now(self, message_id: UUID) -> None:
        """Make a deferred or failed message eligible immediately."""
        await self._conn.execute(
            update(schema.email_queue)
            .where(schema.email_queue.c.id == str(message_id))
            .values(
                status=str(QueueStatus.PENDING),
                next_retry=_now(),
                updated_at=_now(),
            )
        )

    async def purge(self, older_than: timedelta, status: QueueStatus) -> int:
        """Delete finished messages older than a cutoff. Returns the count."""
        from sqlalchemy import delete

        cutoff = _now() - older_than
        result = await self._conn.execute(
            delete(schema.email_queue).where(
                and_(
                    schema.email_queue.c.status == str(status),
                    schema.email_queue.c.updated_at < cutoff,
                )
            )
        )
        return int(result.rowcount or 0)

    async def counts(self) -> dict[str, int]:
        from sqlalchemy import func

        rows = await self._conn.execute(
            select(schema.email_queue.c.status, func.count())
            .group_by(schema.email_queue.c.status)
        )
        return {r[0]: int(r[1]) for r in rows}


def _to_model(mapping: Any) -> QueuedMessage:
    data = dict(mapping)
    return QueuedMessage(
        id=UUID(data["id"]),
        org_id=UUID(data["org_id"]),
        domain_id=UUID(data["domain_id"]),
        from_addr=data["from_addr"],
        to_addrs=json.loads(data["to_addrs"]) if data.get("to_addrs") else [],
        subject=data.get("subject") or "",
        body=data.get("body") or "",
        status=QueueStatus(data["status"]),
        attempts=int(data.get("attempts") or 0),
        max_attempts=int(data.get("max_attempts") or DEFAULT_MAX_ATTEMPTS),
        next_retry=data["next_retry"],
        last_error=data.get("last_error"),
        raw=bytes(data["raw"]) if data.get("raw") is not None else None,
        envelope_from=data.get("envelope_from"),
    )


__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "RETRY_DELAYS",
    "Queue",
    "QueueStatus",
    "QueuedMessage",
    "classify_failure",
    "next_retry_at",
]
