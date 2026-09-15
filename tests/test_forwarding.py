"""Forwarding, and mail leaving the server whole.

Two bugs this file exists for:

* **Forwarding was a no-op that reported success.** Routing worked out
  where an alias's mail should go, the outcome said "forwarded", the
  sender got a 250 -- and nothing was queued. The test for it checked
  the outcome, so it passed.
* **Everything that left the server was rebuilt from subject and body.**
  A mail client's attachments, HTML part and headers never reached the
  recipient.

So these tests look at what was actually queued and what actually goes
out on the wire, not at what the code said it did.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from email import message_from_bytes
from email.message import EmailMessage

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config
from lightr.dovecot.lmtp import DeliveryResult, RecipientStatus
from lightr.mail import headers as header_tools
from lightr.mail.queue import Queue, QueuedMessage, QueueStatus
from lightr.mail.routing import Disposition, Route
from lightr.mail.sender import Sender
from lightr.mail.smtp import MAX_HOPS, DeliveryOutcome, LightrHandler
from lightr.models import Account, Alias, Domain, Organization
from lightr.repo import AccountRepo, AliasRepo, DomainRepo, OrganizationRepo


class RecordingLMTP:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], bytes]] = []

    async def deliver(self, sender, recipients, message):
        payload = message if isinstance(message, bytes) else message.as_bytes()
        self.calls.append((sender, list(recipients), payload))
        return DeliveryResult(
            statuses=[RecipientStatus(r, 250, "ok") for r in recipients]
        )


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        await AccountRepo(conn).create(Account(domain_id=domain.id, local_part="ops"))
        aliases = AliasRepo(conn)
        await aliases.create(
            Alias(domain_id=domain.id, source="out",
                  destinations=["someone@external.test"])
        )
        await aliases.create(
            Alias(domain_id=domain.id, source="both",
                  destinations=["ops@acme.test", "someone@external.test"])
        )
    return {"org": org, "domain": domain}


@pytest_asyncio.fixture
async def receive(
    cfg: Config, engine: AsyncEngine, world: dict
) -> AsyncIterator[LightrHandler]:
    cfg.spam.enabled = False  # no DNS in tests; spam is exercised directly below
    handler = LightrHandler(cfg, engine)
    handler.lmtp = RecordingLMTP()  # type: ignore[assignment]
    yield handler
    await handler.webhooks.drain()


def _with_attachment(subject: str = "Quarterly figures") -> bytes:
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "out@acme.test"
    message["Subject"] = subject
    message["Message-ID"] = "<figures@example.test>"
    message.set_content("Plain text.")
    message.add_alternative("<p>HTML <b>part</b>.</p>", subtype="html")
    message.add_attachment(
        b"%PDF-1.4 not really a pdf", maintype="application",
        subtype="pdf", filename="figures.pdf",
    )
    return message.as_bytes()


async def _queued(engine: AsyncEngine) -> list[QueuedMessage]:
    async with engine.begin() as conn:
        return await Queue(conn).list()


class TestForwardsAreActuallySent:
    async def test_an_external_forward_is_queued(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        await receive.deliver(
            mail_from="sender@example.test", recipients=["out@acme.test"],
            raw=_with_attachment(),
        )

        queued = await _queued(engine)
        assert [q.to_addrs for q in queued] == [["someone@external.test"]]

    async def test_the_forward_is_signed_as_the_alias_domain(
        self, receive: LightrHandler, engine: AsyncEngine, world: dict
    ) -> None:
        """The sender's domain is not ours, so it cannot be the one the
        forward is attributed to. It used to be -- and a message from a
        domain we do not host was logged and dropped."""
        await receive.deliver(
            mail_from="sender@example.test", recipients=["out@acme.test"],
            raw=_with_attachment(),
        )

        (queued,) = await _queued(engine)
        assert queued.domain_id == world["domain"].id

    async def test_a_local_destination_goes_to_dovecot_not_the_queue(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Queuing it would send it out to our own MX and back."""
        outcome = await receive.deliver(
            mail_from="sender@example.test", recipients=["both@acme.test"],
            raw=_with_attachment(),
        )

        lmtp: RecordingLMTP = receive.lmtp  # type: ignore[assignment]
        assert [c[1] for c in lmtp.calls] == [["ops@acme.test"]]
        assert [q.to_addrs for q in await _queued(engine)] == [
            ["someone@external.test"]
        ]
        assert outcome.delivered == ["ops@acme.test"]

    async def test_the_sender_is_not_told_success_for_a_dropped_forward(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """What `forwarded` reports must be what was queued."""
        outcome = await receive.deliver(
            mail_from="sender@example.test", recipients=["out@acme.test"],
            raw=_with_attachment(),
        )

        queued = [a for q in await _queued(engine) for a in q.to_addrs]
        assert outcome.forwarded == queued

    async def test_a_forward_leaves_without_our_analysis(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """A forwarded copy reached Gmail carrying X-Spam-Score,
        X-Lightr-Has-Attachment and our Authentication-Results. The local
        copy of a bridge keeps them; the copy that leaves must not."""
        raw = _with_attachment().replace(
            b"Subject:", b"X-Spam-Score: -10.0\r\nSubject:", 1
        )
        await receive.deliver(
            mail_from="sender@example.test", recipients=["both@acme.test"], raw=raw,
        )

        (queued,) = await _queued(engine)
        assert queued.raw is not None
        sent = message_from_bytes(queued.raw)
        for name in header_tools.CONTROLLED_HEADERS:
            assert name not in sent, name
        assert sent["Received"] is not None

        lmtp: RecordingLMTP = receive.lmtp  # type: ignore[assignment]
        (_, _, local_payload) = lmtp.calls[0]
        local = message_from_bytes(local_payload)
        assert local[header_tools.HEADER_AUTH_RESULTS] is not None


class TestTheMessageLeavesWhole:
    async def test_attachments_survive_forwarding(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        await receive.deliver(
            mail_from="sender@example.test", recipients=["out@acme.test"],
            raw=_with_attachment(),
        )

        (queued,) = await _queued(engine)
        assert queued.raw is not None
        parsed = message_from_bytes(queued.raw)
        filenames = [p.get_filename() for p in parsed.walk() if p.get_filename()]
        content_types = {p.get_content_type() for p in parsed.walk()}
        assert filenames == ["figures.pdf"]
        assert "text/html" in content_types

    async def test_the_wire_form_is_the_queued_message(
        self, cfg: Config, engine: AsyncEngine, world: dict
    ) -> None:
        """The sender used to rebuild every message from subject and a
        plain-text body, whatever had been queued."""
        raw = _with_attachment()
        async with engine.begin() as conn:
            await Queue(conn).enqueue(
                org_id=world["org"].id, domain_id=world["domain"].id,
                from_addr="ops@acme.test", to_addrs=["someone@external.test"],
                subject="Quarterly figures", body="Plain text.", raw=raw,
            )
            (queued,) = await Queue(conn).list()

        wire = Sender(cfg, engine)._compose(queued, world["domain"])

        assert b"figures.pdf" in wire
        assert b"text/html" in wire

    async def test_a_message_queued_without_raw_still_composes(
        self, cfg: Config, engine: AsyncEngine, world: dict
    ) -> None:
        """Rows queued before migration 0005 have no raw message."""
        async with engine.begin() as conn:
            await Queue(conn).enqueue(
                org_id=world["org"].id, domain_id=world["domain"].id,
                from_addr="ops@acme.test", to_addrs=["someone@external.test"],
                subject="Old row", body="Body only.",
            )
            (queued,) = await Queue(conn).list()

        wire = Sender(cfg, engine)._compose(queued, world["domain"])

        assert b"Subject: Old row" in wire
        assert b"Body only." in wire

    async def test_the_envelope_sender_can_differ_from_the_header(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        """A forward rewritten with SRS keeps the original From header
        and uses a sender our domain authorises."""
        async with engine.begin() as conn:
            await Queue(conn).enqueue(
                org_id=world["org"].id, domain_id=world["domain"].id,
                from_addr="sender@example.test", to_addrs=["someone@external.test"],
                subject="s", body="b", raw=b"Subject: s\r\n\r\nb\r\n",
                envelope_from="SRS0=abcd=xy=example.test=sender@acme.test",
            )
            (queued,) = await Queue(conn).list()

        assert queued.from_addr == "sender@example.test"
        assert queued.sender == "SRS0=abcd=xy=example.test=sender@acme.test"
        assert queued.status is QueueStatus.PENDING


class TestWhatIsNotForwarded:
    async def test_spam_is_not_relayed_off_the_server(
        self, receive: LightrHandler, engine: AsyncEngine, world: dict
    ) -> None:
        """Relaying junk outward spends this server's reputation on it,
        and receivers blocklist forwarders for exactly that."""
        message = message_from_bytes(_with_attachment())
        outcome = DeliveryOutcome()

        route = Route(
            recipient="both@acme.test",
            disposition=Disposition.ALIAS_FORWARD,
            domain_id=world["domain"].id,
        )
        local = await receive._forward(
            [(route, "someone@external.test"), (route, "ops@acme.test")],
            mail_from="sender@example.test",
            message=message,
            analysis=header_tools.Analysis(is_spam=True, score=9.0),
            outcome=outcome,
        )

        assert await _queued(engine) == []
        assert outcome.forwarded == []
        # It still lands locally, where the Junk rules can file it.
        assert local == ["ops@acme.test"]

    async def test_a_looping_message_is_refused_permanently(
        self, receive: LightrHandler, engine: AsyncEngine
    ) -> None:
        """Alias expansion catches loops inside Lightr. Two forwards
        pointing at each other across two providers only show up as a
        pile of Received headers."""
        hops = "".join(
            f"Received: from hop{n}.example.test by hop{n + 1}.example.test\r\n"
            for n in range(MAX_HOPS)
        )
        raw = (hops + "Subject: round and round\r\n\r\nbody\r\n").encode()

        outcome = await receive.deliver(
            mail_from="sender@example.test", recipients=["out@acme.test"], raw=raw,
        )

        assert outcome.smtp_response().startswith("554")
        assert await _queued(engine) == []


class TestSubmissionCannotLoseMail:
    @pytest.fixture
    def submission(self, cfg: Config, engine: AsyncEngine, world: dict):
        handler = LightrHandler(cfg, engine, require_auth=True)
        handler.lmtp = RecordingLMTP()  # type: ignore[assignment]
        return handler

    async def test_an_unqueueable_send_is_refused_not_accepted(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        """It used to log a warning and answer 250. The client showed
        the mail as sent; nothing was."""
        outcome = await submission.deliver(
            mail_from="someone@not-ours.test",
            recipients=["friend@external.test"],
            raw=_with_attachment(),
        )

        assert outcome.smtp_response().startswith("5")
        assert await _queued(engine) == []
        await submission.webhooks.drain()
