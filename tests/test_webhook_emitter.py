"""Emitting webhook events from the delivery path.

The property that matters: mail delivery must not wait on, or fail
because of, a webhook receiver. The mail is the product; the
notification is not.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncEngine
from tests.test_smtp import FakeLMTP, _raw

from lightr.config import Config
from lightr.db import schema
from lightr.mail.smtp import LightrHandler
from lightr.models import Account, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo
from lightr.webhooks.delivery import Attempt, Event
from lightr.webhooks.emitter import Emitter


class RecordingDeliverer:
    """Stands in for the HTTP client and records what it was asked to send."""

    def __init__(self, *, ok: bool = True, delay: float = 0.0) -> None:
        self.ok = ok
        self.delay = delay
        self.calls: list[tuple[str, dict]] = []

    async def deliver(self, webhook, event, payload):
        if self.delay:
            await asyncio.sleep(self.delay)
        self.calls.append((str(event), payload))
        return Attempt(ok=self.ok, status_code=200 if self.ok else 500)


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        await AccountRepo(conn).create(Account(domain_id=domain.id, local_part="ops"))

        now = datetime.now(UTC).replace(tzinfo=None)
        await conn.execute(
            insert(schema.webhooks).values(
                id=str(uuid4()),
                name="ops-hook",
                url="http://hooks.example.test/lightr",
                secret="s3cret",
                events=json.dumps(["*"]),
                active=True,
                created_at=now,
                updated_at=now,
            )
        )


@pytest_asyncio.fixture
async def handler(
    cfg: Config, engine: AsyncEngine, world: None
) -> AsyncIterator[LightrHandler]:
    h = LightrHandler(cfg, engine)
    h.lmtp = FakeLMTP()  # type: ignore[assignment]
    yield h
    await h.webhooks.drain()


class TestEmissionFromDelivery:
    async def test_a_delivered_message_emits(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        recorder = RecordingDeliverer()
        handler.webhooks._deliverer = recorder  # type: ignore[attr-defined]

        await handler.deliver(
            mail_from="sender@example.test",
            recipients=["ops@acme.test"],
            raw=_raw("Hello"),
        )
        await handler.webhooks.drain()

        assert [c[0] for c in recorder.calls] == [str(Event.MAIL_RECEIVED)]
        assert recorder.calls[0][1]["to"] == ["ops@acme.test"]

    async def test_a_rejection_emits(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        recorder = RecordingDeliverer()
        handler.webhooks._deliverer = recorder  # type: ignore[attr-defined]

        await handler.deliver(
            mail_from="sender@example.test",
            recipients=["ghost@acme.test"],
            raw=_raw(),
        )
        await handler.webhooks.drain()

        assert [c[0] for c in recorder.calls] == [str(Event.MAIL_REJECTED)]
        assert recorder.calls[0][1]["reason"] == "no_such_mailbox"

    async def test_the_payload_carries_the_subject(
        self, handler: LightrHandler
    ) -> None:
        recorder = RecordingDeliverer()
        handler.webhooks._deliverer = recorder  # type: ignore[attr-defined]

        await handler.deliver(
            mail_from="s@example.test",
            recipients=["ops@acme.test"],
            raw=_raw("Invoice 42"),
        )
        await handler.webhooks.drain()

        assert recorder.calls[0][1]["subject"] == "Invoice 42"


class TestDeliveryIsNotBlocked:
    async def test_a_slow_receiver_does_not_delay_the_mail(
        self, handler: LightrHandler
    ) -> None:
        """The point of fire-and-forget."""
        handler.webhooks._deliverer = RecordingDeliverer(delay=0.5)  # type: ignore[attr-defined]

        started = asyncio.get_running_loop().time()
        await handler.deliver(
            mail_from="s@example.test", recipients=["ops@acme.test"], raw=_raw()
        )
        elapsed = asyncio.get_running_loop().time() - started

        assert elapsed < 0.3, "delivery waited on the webhook"
        await handler.webhooks.drain()

    async def test_a_failing_receiver_does_not_fail_the_mail(
        self, handler: LightrHandler
    ) -> None:
        handler.webhooks._deliverer = RecordingDeliverer(ok=False)  # type: ignore[attr-defined]

        outcome = await handler.deliver(
            mail_from="s@example.test", recipients=["ops@acme.test"], raw=_raw()
        )
        await handler.webhooks.drain()

        assert outcome.ok
        assert outcome.delivered == ["ops@acme.test"]

    async def test_a_raising_deliverer_does_not_reach_the_mail_path(
        self, handler: LightrHandler
    ) -> None:
        class Exploding:
            async def deliver(self, *args, **kwargs):
                raise RuntimeError("boom")

        handler.webhooks._deliverer = Exploding()  # type: ignore[attr-defined]

        outcome = await handler.deliver(
            mail_from="s@example.test", recipients=["ops@acme.test"], raw=_raw()
        )
        await handler.webhooks.drain()

        assert outcome.ok


class TestRecording:
    async def test_the_attempt_is_logged(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        handler.webhooks._deliverer = RecordingDeliverer()  # type: ignore[attr-defined]

        await handler.deliver(
            mail_from="s@example.test", recipients=["ops@acme.test"], raw=_raw()
        )
        await handler.webhooks.drain()

        async with engine.begin() as conn:
            rows = (await conn.execute(select(schema.webhook_events))).fetchall()
        assert len(rows) == 1
        assert rows[0]._mapping["status"] == "delivered"


class TestDraining:
    async def test_drain_waits_for_in_flight_deliveries(
        self, cfg: Config, engine: AsyncEngine, world: None
    ) -> None:
        """Without this, a restart silently drops events that were
        already in flight."""
        emitter = Emitter(engine)
        recorder = RecordingDeliverer(delay=0.1)
        emitter._deliverer = recorder  # type: ignore[attr-defined]

        emitter.emit(Event.MAIL_RECEIVED, {"to": "ops@acme.test"})
        await emitter.drain()

        assert len(recorder.calls) == 1

    async def test_drain_with_nothing_in_flight_is_harmless(
        self, cfg: Config, engine: AsyncEngine
    ) -> None:
        await Emitter(engine).drain()

    async def test_no_webhooks_means_no_work(
        self, cfg: Config, engine: AsyncEngine
    ) -> None:
        """No hooks configured: nothing is attempted."""
        emitter = Emitter(engine)
        recorder = RecordingDeliverer()
        emitter._deliverer = recorder  # type: ignore[attr-defined]

        emitter.emit(Event.MAIL_RECEIVED, {})
        await emitter.drain()

        assert recorder.calls == []


class TestConcurrencyBound:
    def test_there_is_a_cap(self) -> None:
        """A burst of mail to a slow endpoint must not open an
        unbounded number of connections."""
        from lightr.webhooks.emitter import MAX_CONCURRENT

        assert 1 <= MAX_CONCURRENT <= 50

    async def test_tasks_are_held_while_in_flight(
        self, cfg: Config, engine: AsyncEngine, world: None
    ) -> None:
        """A task with no strong reference can be garbage-collected
        mid-flight, dropping the event silently."""
        emitter = Emitter(engine)
        emitter._deliverer = RecordingDeliverer(delay=0.2)  # type: ignore[attr-defined]

        emitter.emit(Event.MAIL_RECEIVED, {})
        assert emitter._tasks

        await emitter.drain()


@pytest.fixture(autouse=True)
def _quiet_webhook_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("CRITICAL", logger="lightr.webhooks")
