"""Bounces arriving over SMTP.

A bounce comes from a null sender. Recording it is what keeps the
suppression list current -- without this the engine keeps mailing dead
addresses and burns sending reputation.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine
from tests.test_bounce import HARD_DSN, SOFT_DSN
from tests.test_smtp import FakeLMTP

from lightr.config import Config
from lightr.mail.bounce import BounceRepo
from lightr.mail.smtp import LightrHandler
from lightr.models import Account, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        await AccountRepo(conn).create(
            Account(domain_id=domain.id, local_part="postmaster")
        )


@pytest_asyncio.fixture
async def handler(
    cfg: Config, engine: AsyncEngine, world: None
) -> AsyncIterator[LightrHandler]:
    h = LightrHandler(cfg, engine)
    h.lmtp = FakeLMTP()  # type: ignore[assignment]
    yield h
    await h.webhooks.drain()


class TestBounceIngestion:
    async def test_null_sender_bounce_suppresses(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        await handler.deliver(
            mail_from="",  # the RFC signal for a bounce
            recipients=["postmaster@acme.test"],
            raw=HARD_DSN,
        )

        async with engine.begin() as conn:
            assert await BounceRepo(conn).is_suppressed("ghost@example.test")

    async def test_soft_bounce_does_not_suppress(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        await handler.deliver(
            mail_from="", recipients=["postmaster@acme.test"], raw=SOFT_DSN
        )

        async with engine.begin() as conn:
            assert not await BounceRepo(conn).is_suppressed("full@example.test")

    async def test_the_bounce_is_still_delivered(
        self, handler: LightrHandler
    ) -> None:
        """The postmaster should still receive it -- parsing is in
        addition to delivery, not instead of it."""
        outcome = await handler.deliver(
            mail_from="", recipients=["postmaster@acme.test"], raw=HARD_DSN
        )
        assert outcome.delivered == ["postmaster@acme.test"]

    async def test_ordinary_mail_is_not_parsed_as_a_bounce(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        """A message with a real sender must not touch the suppression
        list, however DSN-shaped its body looks."""
        await handler.deliver(
            mail_from="someone@example.test",
            recipients=["postmaster@acme.test"],
            raw=HARD_DSN,
        )

        async with engine.begin() as conn:
            assert not await BounceRepo(conn).is_suppressed("ghost@example.test")

    async def test_bounce_is_attributed_to_the_only_domain(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        await handler.deliver(
            mail_from="", recipients=["postmaster@acme.test"], raw=HARD_DSN
        )

        async with engine.begin() as conn:
            recorded = await BounceRepo(conn).list_bounces()
        assert len(recorded) == 1
        assert recorded[0]["recipient_email"] == "ghost@example.test"

    async def test_malformed_bounce_does_not_break_delivery(
        self, handler: LightrHandler
    ) -> None:
        """A bounce is third-party input; a bad one must not stop the
        message reaching a human who can look at it."""
        outcome = await handler.deliver(
            mail_from="",
            recipients=["postmaster@acme.test"],
            raw=b"\xff\xfe not even a message",
        )
        assert outcome.delivered == ["postmaster@acme.test"]

    async def test_bounce_for_an_unroutable_recipient_is_still_parsed(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Even when we cannot deliver the bounce anywhere, the
        suppression it implies still matters."""
        await handler.deliver(
            mail_from="", recipients=["nobody@acme.test"], raw=HARD_DSN
        )

        async with engine.begin() as conn:
            assert await BounceRepo(conn).is_suppressed("ghost@example.test")
