"""Bridges, reply tokens, and the envelope sender of forwards.

The requirement comes from the Go engine's end-to-end test: mail to a
bridge alias lands in the local mailbox *and* a copy goes to the
bridge destination with a Reply-To token; a reply sent to that token
reaches the original sender with its subject intact.

On top of that, what the user asked for: the reply is "cleaned of the
Lightr forward" -- it arrives from the address the original sender
wrote to, with nothing in it about where that mailbox is really read.

And one the Go test did not cover: a forward that keeps the original
sender as its envelope sender fails SPF at the destination, so every
forward's envelope sender is a token address on our own domain.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from email import message_from_bytes
from email.message import EmailMessage

import pytest_asyncio
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config
from lightr.db import schema
from lightr.dovecot.lmtp import DeliveryResult, RecipientStatus
from lightr.mail import replies
from lightr.mail.queue import Queue, QueuedMessage
from lightr.mail.routing import Disposition, Router
from lightr.mail.smtp import LightrHandler
from lightr.models import Account, Alias, AliasType, Domain, Organization
from lightr.repo import AccountRepo, AliasRepo, DomainRepo, OrganizationRepo

BRIDGE_DESTINATION = "alice.personal@example.net"
ORIGINAL_SENDER = "customer@example.org"


class RecordingLMTP:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], bytes]] = []

    async def deliver(self, sender, recipients, message):
        payload = message if isinstance(message, bytes) else message.as_bytes()
        self.calls.append((list(recipients), payload))
        return DeliveryResult(statuses=[RecipientStatus(r, 250, "ok") for r in recipients])


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        alice = await AccountRepo(conn).create(
            Account(domain_id=domain.id, local_part="alice")
        )
        aliases = AliasRepo(conn)
        # Same name as the account: a bridge mirrors into that mailbox.
        bridge = await aliases.create(
            Alias(domain_id=domain.id, source="alice", type=AliasType.BRIDGE,
                  destinations=[BRIDGE_DESTINATION])
        )
        await aliases.create(
            Alias(domain_id=domain.id, source="info",
                  destinations=["someone@external.test"])
        )
    return {"domain": domain, "alice": alice, "bridge": bridge}


@pytest_asyncio.fixture
async def receive(
    cfg: Config, engine: AsyncEngine, world: dict
) -> AsyncIterator[LightrHandler]:
    cfg.spam.enabled = False
    handler = LightrHandler(cfg, engine)
    handler.lmtp = RecordingLMTP()  # type: ignore[assignment]
    yield handler
    await handler.webhooks.drain()


def _inbound(subject: str = "Order 1234", *, to: str = "alice@acme.test") -> bytes:
    message = EmailMessage()
    message["From"] = f"A Customer <{ORIGINAL_SENDER}>"
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = "<order-1234@example.org>"
    message.set_content("Where is my order?")
    message.add_attachment(b"receipt", maintype="application", subtype="pdf",
                           filename="receipt.pdf")
    return message.as_bytes()


def _reply_from_bridge(token_address: str, *, sender: str = BRIDGE_DESTINATION) -> bytes:
    message = EmailMessage()
    message["Received"] = "from mail-sor-f41.personal-provider.example by mx.example.net"
    message["Received"] = "from [10.0.0.7] by smtp.personal-provider.example"
    message["DKIM-Signature"] = "v=1; a=rsa-sha256; d=example.net; s=x; b=abc"
    message["Return-Path"] = f"<{sender}>"
    message["From"] = f"Alice <{sender}>"
    message["To"] = token_address
    message["Cc"] = "someone.else@example.net"
    message["Subject"] = "Re: Order 1234"
    message["In-Reply-To"] = "<order-1234@example.org>"
    message["References"] = "<order-1234@example.org>"
    message.set_content("It shipped yesterday.")
    return message.as_bytes()


async def _queued(engine: AsyncEngine) -> list[QueuedMessage]:
    async with engine.begin() as conn:
        return await Queue(conn).list()


async def _bridge_a_message(receive: LightrHandler, engine: AsyncEngine) -> str:
    """Send mail to the bridge and return the token address it handed out."""
    await receive.deliver(
        mail_from=ORIGINAL_SENDER, recipients=["alice@acme.test"], raw=_inbound()
    )
    (copy,) = await _queued(engine)
    assert copy.raw is not None
    reply_to = message_from_bytes(copy.raw)["Reply-To"]
    assert reply_to
    async with engine.begin() as conn:
        await conn.execute(schema.email_queue.delete())
    return str(reply_to)


class TestTheBridgeFires:
    async def test_mail_to_a_bridge_lands_locally_and_is_copied_out(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """The router returned LOCAL for any address with an account,
        and a bridge always shares its name with one -- so no bridge
        could ever fire."""
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["alice@acme.test"], raw=_inbound()
        )

        lmtp: RecordingLMTP = receive.lmtp  # type: ignore[assignment]
        assert [c[0] for c in lmtp.calls] == [["alice@acme.test"]]
        assert [q.to_addrs for q in await _queued(engine)] == [[BRIDGE_DESTINATION]]

    async def test_a_plain_forward_with_an_accounts_name_is_still_ignored(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        """The mailbox still wins over a forward of the same name."""
        async with engine.begin() as conn:
            bridge = await AliasRepo(conn).resolve(str(world["bridge"].id))
            bridge.type = AliasType.FORWARD
            await AliasRepo(conn).update(bridge)
            route = await Router(conn).route("alice@acme.test")

        assert route.disposition is Disposition.LOCAL

    async def test_the_copy_carries_a_reply_token(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        token_address = await _bridge_a_message(receive, engine)

        local, domain = token_address.split("@")
        assert domain == "acme.test"
        assert replies.token_from(local) is not None

    async def test_the_local_copy_does_not(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """The token is for replies from the bridge destination. Alice
        replying from her own mailbox should reach the customer
        directly."""
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["alice@acme.test"], raw=_inbound()
        )

        lmtp: RecordingLMTP = receive.lmtp  # type: ignore[assignment]
        local_copy = message_from_bytes(lmtp.calls[0][1])
        assert local_copy["Reply-To"] is None

    async def test_the_copy_is_whole(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["alice@acme.test"], raw=_inbound()
        )

        (copy,) = await _queued(engine)
        assert copy.raw is not None
        assert b"receipt.pdf" in copy.raw


class TestForwardsPassSPF:
    async def test_a_forward_is_sent_from_our_domain(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Sent with the customer's address as the envelope, the
        destination checks example.org's SPF, which never authorised
        this server."""
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["info@acme.test"],
            raw=_inbound(to="info@acme.test"),
        )

        (copy,) = await _queued(engine)
        assert copy.sender.endswith("@acme.test")
        assert copy.sender.startswith(replies.REPLY_PREFIX)

    async def test_the_from_header_is_left_alone(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Only the envelope changes. The person reading the forward
        still sees who wrote it."""
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["info@acme.test"],
            raw=_inbound(to="info@acme.test"),
        )

        (copy,) = await _queued(engine)
        assert copy.raw is not None
        parsed = message_from_bytes(copy.raw)
        assert ORIGINAL_SENDER in str(parsed["From"])
        assert parsed["Reply-To"] is None


class TestARepliesGoesBackToTheOriginalSender:
    async def test_the_reply_is_queued_to_the_original_sender(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        token_address = await _bridge_a_message(receive, engine)

        outcome = await receive.deliver(
            mail_from=BRIDGE_DESTINATION, recipients=[token_address],
            raw=_reply_from_bridge(token_address),
        )

        assert outcome.smtp_response().startswith("250")
        (reply,) = await _queued(engine)
        assert reply.to_addrs == [ORIGINAL_SENDER]

    async def test_it_comes_from_the_address_the_customer_wrote_to(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        token_address = await _bridge_a_message(receive, engine)

        await receive.deliver(
            mail_from=BRIDGE_DESTINATION, recipients=[token_address],
            raw=_reply_from_bridge(token_address),
        )

        (reply,) = await _queued(engine)
        assert reply.raw is not None
        parsed = message_from_bytes(reply.raw)
        assert "alice@acme.test" in str(parsed["From"])
        assert str(parsed["To"]) == ORIGINAL_SENDER
        assert reply.sender == "alice@acme.test"

    async def test_nothing_in_it_reveals_where_alice_reads_mail(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """The part the user asked for: cleaned of the forward."""
        token_address = await _bridge_a_message(receive, engine)

        await receive.deliver(
            mail_from=BRIDGE_DESTINATION, recipients=[token_address],
            raw=_reply_from_bridge(token_address),
        )

        (reply,) = await _queued(engine)
        assert reply.raw is not None
        headers = reply.raw.split(b"\r\n\r\n", 1)[0].decode()
        assert BRIDGE_DESTINATION not in headers
        assert "personal-provider" not in headers
        assert "someone.else@example.net" not in headers
        assert replies.REPLY_PREFIX not in headers

    async def test_the_conversation_still_threads(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        token_address = await _bridge_a_message(receive, engine)

        await receive.deliver(
            mail_from=BRIDGE_DESTINATION, recipients=[token_address],
            raw=_reply_from_bridge(token_address),
        )

        (reply,) = await _queued(engine)
        assert reply.raw is not None
        parsed = message_from_bytes(reply.raw)
        assert parsed["Subject"] == "Re: Order 1234"
        assert parsed["In-Reply-To"] == "<order-1234@example.org>"

    async def test_it_goes_to_the_customers_reply_to_if_they_set_one(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Where the customer asked for replies, not where they sent from."""
        message = message_from_bytes(_inbound())
        message["Reply-To"] = "orders@example.org"
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["alice@acme.test"],
            raw=message.as_bytes(),
        )
        (copy,) = await _queued(engine)
        assert copy.raw is not None
        token_address = str(message_from_bytes(copy.raw)["Reply-To"])
        async with engine.begin() as conn:
            await conn.execute(schema.email_queue.delete())

        await receive.deliver(
            mail_from=BRIDGE_DESTINATION, recipients=[token_address],
            raw=_reply_from_bridge(token_address),
        )

        (reply,) = await _queued(engine)
        assert reply.to_addrs == ["orders@example.org"]


class TestATokenIsNotAnOpenRelay:
    async def test_a_stranger_cannot_use_a_token(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Anyone who sees a token could otherwise mail the customer
        from alice@acme.test."""
        token_address = await _bridge_a_message(receive, engine)

        outcome = await receive.deliver(
            mail_from="attacker@evil.test", recipients=[token_address],
            raw=_reply_from_bridge(token_address, sender="attacker@evil.test"),
        )

        assert outcome.smtp_response().startswith("550")
        assert await _queued(engine) == []

    async def test_an_unknown_token_looks_like_any_unknown_address(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        fake = replies.reply_address("0" * 24, "acme.test")

        outcome = await receive.deliver(
            mail_from=BRIDGE_DESTINATION, recipients=[fake],
            raw=_reply_from_bridge(fake),
        )

        assert outcome.smtp_response() == "550 5.1.1 No such user here"

    async def test_a_plain_forward_token_does_not_relay_replies(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Its token is only an envelope sender. An autoresponder
        answering it must not become mail to the customer."""
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["info@acme.test"],
            raw=_inbound(to="info@acme.test"),
        )
        (copy,) = await _queued(engine)
        token_address = copy.sender
        async with engine.begin() as conn:
            await conn.execute(schema.email_queue.delete())

        outcome = await receive.deliver(
            mail_from="someone@external.test", recipients=[token_address],
            raw=_reply_from_bridge(token_address, sender="someone@external.test"),
        )

        assert outcome.smtp_response().startswith("550")
        assert await _queued(engine) == []

    async def test_an_expired_token_stops_working(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        token_address = await _bridge_a_message(receive, engine)
        async with engine.begin() as conn:
            await conn.execute(
                update(schema.alias_reply_routes).values(
                    created_at=replies._now() - replies.RETENTION - timedelta(days=1)
                )
            )

        outcome = await receive.deliver(
            mail_from=BRIDGE_DESTINATION, recipients=[token_address],
            raw=_reply_from_bridge(token_address),
        )

        assert outcome.smtp_response().startswith("550")

    async def test_a_spam_reply_is_not_relayed(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        from lightr.mail import headers as header_tools
        from lightr.mail.routing import Route

        token_address = await _bridge_a_message(receive, engine)
        async with engine.begin() as conn:
            route = await Router(conn).route(token_address)
        assert isinstance(route, Route)

        outcome = await receive._relay_replies(
            [route], mail_from=BRIDGE_DESTINATION,
            message=message_from_bytes(_reply_from_bridge(token_address)),
            analysis=header_tools.Analysis(is_spam=True, score=9.0),
            outcome=__import__("lightr.mail.smtp", fromlist=["x"]).DeliveryOutcome(),
        )

        assert await _queued(engine) == []
        assert outcome == ["alice@acme.test"]  # into the mailbox, for Junk


class TestBounces:
    async def test_a_bounce_of_a_bridged_copy_reaches_alice(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """So she can see the address her mail goes to has stopped
        working."""
        token_address = await _bridge_a_message(receive, engine)
        lmtp: RecordingLMTP = receive.lmtp  # type: ignore[assignment]
        lmtp.calls.clear()

        outcome = await receive.deliver(
            mail_from="", recipients=[token_address],
            raw=b"Subject: Undelivered Mail Returned to Sender\r\n\r\nno such user\r\n",
        )

        assert outcome.smtp_response().startswith("250")
        assert [c[0] for c in lmtp.calls] == [["alice@acme.test"]]
        assert await _queued(engine) == []

    async def test_a_bounce_of_a_plain_forward_is_accepted_not_bounced(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Nobody local to give it to. Refusing it would bounce a
        bounce, which is how backscatter starts."""
        await receive.deliver(
            mail_from=ORIGINAL_SENDER, recipients=["info@acme.test"],
            raw=_inbound(to="info@acme.test"),
        )
        (copy,) = await _queued(engine)
        async with engine.begin() as conn:
            await conn.execute(schema.email_queue.delete())

        outcome = await receive.deliver(
            mail_from="", recipients=[copy.sender],
            raw=b"Subject: Delivery Status Notification\r\n\r\nfailed\r\n",
        )

        assert outcome.smtp_response().startswith("250")
        assert await _queued(engine) == []


class TestTokens:
    def test_tokens_survive_the_router_lowercasing_addresses(self) -> None:
        token = replies.new_token()

        assert token == token.lower()
        assert replies.token_from(f"{replies.REPLY_PREFIX}{token}".upper()) == token

    def test_an_ordinary_local_part_is_not_a_token(self) -> None:
        assert replies.token_from("reply") is None
        assert replies.token_from("reply+short") is None
        assert replies.token_from("alice") is None

    async def test_the_sweep_removes_only_expired_tokens(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        await _bridge_a_message(receive, engine)
        await _bridge_a_message(receive, engine)
        async with engine.begin() as conn:
            (first, *_rest) = (
                await conn.execute(schema.alias_reply_routes.select())
            ).fetchall()
            await conn.execute(
                update(schema.alias_reply_routes)
                .where(schema.alias_reply_routes.c.token == first.token)
                .values(created_at=replies._now() - timedelta(days=60))
            )

        from lightr.mail.sender import Sender

        removed = await Sender(receive.cfg, engine).sweep()

        assert removed == 1
        async with engine.begin() as conn:
            remaining = (await conn.execute(schema.alias_reply_routes.select())).fetchall()
        assert len(remaining) == 1


class TestSubmissionRequiresALogin:
    async def test_mail_from_is_refused_before_authentication(
        self, cfg: Config, engine: AsyncEngine, world: dict
    ) -> None:
        """The sender check only runs for an authenticated session. That
        is safe only because MAIL FROM is refused before one exists."""
        handler = LightrHandler(cfg, engine, require_auth=True)
        try:

            class Session:
                authenticated = False

            class Envelope:
                def __init__(self) -> None:
                    self.mail_from = None
                    self.mail_options: list[str] = []

            reply = await handler.handle_MAIL(
                None, Session(), Envelope(), "ceo@acme.test", []
            )

            assert reply.startswith("530")
        finally:
            await handler.webhooks.drain()
