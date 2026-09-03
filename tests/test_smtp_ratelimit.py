"""Per-address limits on the receive listener.

Inbound SMTP is the one port that has to accept connections from
strangers, so the only thing available is to make a stranger's flood
cost them time. 421 is the code for that -- "not now, come back" --
which a real sender retries and a flood does not.

The refusal happens at EHLO, before a message is in memory. Refusing at
DATA would mean the server had already read the thing it did not want.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config
from lightr.mail.smtp import LightrHandler


class FakeSession:
    """Enough of aiosmtpd's Session for the handler to read a peer."""

    def __init__(self, address: str = "203.0.113.9") -> None:
        self.peer = (address, 40000)
        self.host_name = ""
        self.ssl = None
        self.authenticated = False


@pytest_asyncio.fixture
async def receive(cfg: Config, engine: AsyncEngine) -> AsyncIterator[LightrHandler]:
    cfg.limits.smtp_sessions_per_minute = 3
    handler = LightrHandler(cfg, engine, require_auth=False)
    yield handler
    await handler.webhooks.drain()


async def greet(handler: LightrHandler, session: FakeSession) -> str:
    responses = await handler.handle_EHLO(
        None, session, None, "sender.example", ["250-ok"]
    )
    return responses[-1]


class TestSessionLimit:
    async def test_a_flood_from_one_address_is_turned_away(
        self, receive: LightrHandler
    ) -> None:
        session = FakeSession()
        results = [await greet(receive, session) for _ in range(5)]

        assert results[0] == "250-ok"
        assert any(r.startswith("421") for r in results)

    async def test_it_is_a_transient_refusal_not_a_rejection(
        self, receive: LightrHandler
    ) -> None:
        """A 5xx here would tell a legitimate sender to give up and
        bounce the mail. Being busy is not the same as refusing it."""
        session = FakeSession()
        results = [await greet(receive, session) for _ in range(6)]

        refusals = [r for r in results if not r.startswith("250")]
        assert refusals
        assert all(r.startswith("4") for r in refusals)

    async def test_one_noisy_sender_does_not_block_everyone(
        self, receive: LightrHandler
    ) -> None:
        """The limit is per address. A shared bucket would let one
        misbehaving sender stop the server accepting any mail at all."""
        noisy = FakeSession("203.0.113.9")
        for _ in range(6):
            await greet(receive, noisy)

        assert await greet(receive, FakeSession("198.51.100.4")) == "250-ok"

    async def test_the_helo_name_is_still_recorded(
        self, receive: LightrHandler
    ) -> None:
        """It goes into Received headers and the delivery record."""
        session = FakeSession()
        await greet(receive, session)

        assert session.host_name == "sender.example"


class TestSubmissionIsNotLimitedByAddress:
    async def test_an_authenticated_listener_has_no_address_limit(
        self, cfg: Config, engine: AsyncEngine
    ) -> None:
        """Submission is authenticated, so the budget belongs to the
        account. Limiting it by address would punish an office behind
        one NAT."""
        cfg.limits.smtp_sessions_per_minute = 1
        handler = LightrHandler(cfg, engine, require_auth=True)
        try:
            session = FakeSession()
            results = [await greet(handler, session) for _ in range(10)]

            assert all(r == "250-ok" for r in results)
        finally:
            await handler.webhooks.drain()


class TestMessageLimit:
    async def test_a_sender_past_its_hourly_budget_is_asked_to_wait(
        self, cfg: Config, engine: AsyncEngine
    ) -> None:
        """Sessions and messages are counted separately: one connection
        can carry many messages, so a session limit alone bounds
        nothing."""

        class FakeEnvelope:
            def __init__(self) -> None:
                self.mail_from = "sender@example.test"
                self.rcpt_tos = ["ops@acme.test"]
                self.content = b"Subject: hi\r\n\r\nbody\r\n"
                self.mail_options: list[str] = []

        cfg.limits.smtp_sessions_per_minute = 1000
        cfg.limits.smtp_messages_per_hour = 1
        handler = LightrHandler(cfg, engine, require_auth=False)
        try:
            session = FakeSession()
            first = await handler.handle_DATA(None, session, FakeEnvelope())
            second = await handler.handle_DATA(None, session, FakeEnvelope())

            assert not first.startswith("421")
            assert second.startswith("421")
        finally:
            await handler.webhooks.drain()


class TestZeroMeansUnlimited:
    async def test_a_limit_of_zero_does_not_refuse_every_message(
        self, cfg: Config, engine: AsyncEngine
    ) -> None:
        """An operator who sets a limit to nothing means "stop limiting
        this". Reading it as capacity zero would refuse the entire
        inbound mail flow."""
        cfg.limits.smtp_sessions_per_minute = 0
        handler = LightrHandler(cfg, engine, require_auth=False)
        try:
            session = FakeSession()
            results = [await greet(handler, session) for _ in range(50)]

            assert all(r == "250-ok" for r in results)
        finally:
            await handler.webhooks.drain()
