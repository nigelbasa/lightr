"""The outbound queue: claiming, retrying, and giving up."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.db import schema
from lightr.mail.queue import (
    RETRY_DELAYS,
    Queue,
    QueueStatus,
    classify_failure,
    next_retry_at,
)
from lightr.models import Domain, Organization
from lightr.repo import DomainRepo, OrganizationRepo


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


@pytest_asyncio.fixture
async def scope(conn: AsyncConnection) -> dict:
    org = await OrganizationRepo(conn).create(Organization(name="Acme"))
    domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
    return {"org": org, "domain": domain}


@pytest.fixture
def queue(conn: AsyncConnection) -> Queue:
    return Queue(conn)


async def _enqueue(queue: Queue, scope: dict, **overrides):
    payload = {
        "org_id": scope["org"].id,
        "domain_id": scope["domain"].id,
        "from_addr": "ops@acme.test",
        "to_addrs": ["someone@external.test"],
        "subject": "Hello",
        "body": "Body.",
    }
    payload.update(overrides)
    return await queue.enqueue(**payload)


class TestEnqueue:
    async def test_message_starts_pending_and_due(
        self, queue: Queue, scope: dict
    ) -> None:
        message_id = await _enqueue(queue, scope)
        message = await queue.get(message_id)

        assert message is not None
        assert message.status is QueueStatus.PENDING
        assert message.attempts == 0

    async def test_recipients_round_trip(self, queue: Queue, scope: dict) -> None:
        message_id = await _enqueue(queue, scope, to_addrs=["a@x.test", "b@y.test"])
        message = await queue.get(message_id)
        assert message is not None
        assert message.to_addrs == ["a@x.test", "b@y.test"]

    async def test_no_recipients_is_rejected(self, queue: Queue, scope: dict) -> None:
        with pytest.raises(ValueError, match="at least one recipient"):
            await _enqueue(queue, scope, to_addrs=[])


class TestClaiming:
    async def test_claim_returns_due_messages(self, queue: Queue, scope: dict) -> None:
        await _enqueue(queue, scope)
        claimed = await queue.claim()
        assert len(claimed) == 1
        assert claimed[0].status is QueueStatus.SENDING

    async def test_a_claimed_message_is_not_claimed_again(
        self, queue: Queue, scope: dict
    ) -> None:
        """This is what stops two senders delivering one message twice."""
        await _enqueue(queue, scope)

        first = await queue.claim()
        second = await queue.claim()

        assert len(first) == 1
        assert second == []

    async def test_claim_respects_the_limit(self, queue: Queue, scope: dict) -> None:
        for _ in range(5):
            await _enqueue(queue, scope)
        assert len(await queue.claim(limit=2)) == 2

    async def test_messages_not_yet_due_are_skipped(
        self, queue: Queue, scope: dict, conn: AsyncConnection
    ) -> None:
        from datetime import UTC, datetime

        message_id = await _enqueue(queue, scope)
        future = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1)
        await conn.execute(
            update(schema.email_queue)
            .where(schema.email_queue.c.id == str(message_id))
            .values(next_retry=future)
        )
        assert await queue.claim() == []

    async def test_release_makes_it_claimable_again(
        self, queue: Queue, scope: dict
    ) -> None:
        message_id = await _enqueue(queue, scope)
        await queue.claim()

        await queue.release(message_id)

        assert len(await queue.claim()) == 1

    async def test_due_order_is_oldest_first(self, queue: Queue, scope: dict) -> None:
        first = await _enqueue(queue, scope, subject="first")
        await _enqueue(queue, scope, subject="second")

        claimed = await queue.claim(limit=1)
        assert claimed[0].id == first


class TestFailureClassification:
    @pytest.mark.parametrize("code", [421, 450, 451, 452])
    def test_4xx_is_retried(self, code: int) -> None:
        assert classify_failure(code) is QueueStatus.DEFERRED

    @pytest.mark.parametrize("code", [550, 551, 552, 553, 554])
    def test_5xx_is_permanent(self, code: int) -> None:
        """Retrying a 5xx burns reputation and delays the bounce."""
        assert classify_failure(code) is QueueStatus.FAILED

    async def test_transient_failure_defers(self, queue: Queue, scope: dict) -> None:
        message_id = await _enqueue(queue, scope)
        outcome = await queue.mark_failed(message_id, code=451, error="try later")

        assert outcome is QueueStatus.DEFERRED
        message = await queue.get(message_id)
        assert message is not None
        assert message.attempts == 1
        assert message.last_error == "try later"

    async def test_permanent_failure_does_not_retry(
        self, queue: Queue, scope: dict
    ) -> None:
        message_id = await _enqueue(queue, scope)
        outcome = await queue.mark_failed(message_id, code=550, error="no such user")

        assert outcome is QueueStatus.FAILED
        assert await queue.claim() == []

    async def test_running_out_of_attempts_becomes_permanent(
        self, queue: Queue, scope: dict
    ) -> None:
        message_id = await _enqueue(queue, scope, max_attempts=2)

        assert await queue.mark_failed(message_id, code=451, error="x") is (
            QueueStatus.DEFERRED
        )
        assert await queue.mark_failed(message_id, code=451, error="x") is (
            QueueStatus.FAILED
        )

    async def test_error_text_is_truncated(self, queue: Queue, scope: dict) -> None:
        message_id = await _enqueue(queue, scope)
        await queue.mark_failed(message_id, code=451, error="x" * 5000)

        message = await queue.get(message_id)
        assert message is not None
        assert message.last_error is not None
        assert len(message.last_error) <= 1000

    async def test_unknown_message_raises(self, queue: Queue) -> None:
        with pytest.raises(LookupError):
            await queue.mark_failed(uuid4(), code=451, error="x")


class TestBackoff:
    def test_delays_increase(self) -> None:
        assert list(RETRY_DELAYS) == sorted(RETRY_DELAYS)

    def test_first_attempt_uses_the_shortest_delay(self) -> None:
        from datetime import UTC, datetime

        now = datetime.now(UTC).replace(tzinfo=None)
        assert next_retry_at(1, now=now) == now + RETRY_DELAYS[0]

    def test_delay_is_capped(self) -> None:
        """A message must not end up scheduled a month out."""
        from datetime import UTC, datetime

        now = datetime.now(UTC).replace(tzinfo=None)
        assert next_retry_at(99, now=now) == now + RETRY_DELAYS[-1]

    def test_zero_attempts_is_handled(self) -> None:
        from datetime import UTC, datetime

        now = datetime.now(UTC).replace(tzinfo=None)
        assert next_retry_at(0, now=now) == now + RETRY_DELAYS[0]


class TestLifecycle:
    async def test_mark_sent_clears_the_error(
        self, queue: Queue, scope: dict
    ) -> None:
        message_id = await _enqueue(queue, scope)
        await queue.mark_failed(message_id, code=451, error="temporary")
        await queue.mark_sent(message_id)

        message = await queue.get(message_id)
        assert message is not None
        assert message.status is QueueStatus.SENT
        assert message.last_error is None

    async def test_sent_messages_are_not_reclaimed(
        self, queue: Queue, scope: dict
    ) -> None:
        message_id = await _enqueue(queue, scope)
        await queue.mark_sent(message_id)
        assert await queue.claim() == []

    async def test_retry_now_makes_a_failed_message_eligible(
        self, queue: Queue, scope: dict
    ) -> None:
        message_id = await _enqueue(queue, scope)
        await queue.mark_failed(message_id, code=550, error="permanent")

        await queue.retry_now(message_id)

        assert len(await queue.claim()) == 1

    async def test_counts_by_status(self, queue: Queue, scope: dict) -> None:
        sent = await _enqueue(queue, scope)
        await _enqueue(queue, scope)
        await queue.mark_sent(sent)

        counts = await queue.counts()
        assert counts["sent"] == 1
        assert counts["pending"] == 1

    async def test_purge_removes_only_old_finished_messages(
        self, queue: Queue, scope: dict, conn: AsyncConnection
    ) -> None:
        from datetime import UTC, datetime

        old = await _enqueue(queue, scope)
        recent = await _enqueue(queue, scope)
        await queue.mark_sent(old)
        await queue.mark_sent(recent)

        await conn.execute(
            update(schema.email_queue)
            .where(schema.email_queue.c.id == str(old))
            .values(updated_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=40))
        )

        removed = await queue.purge(timedelta(days=30), QueueStatus.SENT)

        assert removed == 1
        assert await queue.get(old) is None
        assert await queue.get(recent) is not None

    async def test_purge_leaves_pending_alone(
        self, queue: Queue, scope: dict
    ) -> None:
        await _enqueue(queue, scope)
        assert await queue.purge(timedelta(seconds=0), QueueStatus.SENT) == 0
