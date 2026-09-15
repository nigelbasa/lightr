"""SMTP receive and submission behaviour."""

from __future__ import annotations

from collections.abc import AsyncIterator
from email.message import EmailMessage

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.auth import hash_password
from lightr.config import Config
from lightr.dovecot.lmtp import DeliveryResult, RecipientStatus
from lightr.dovecot.sieve import HEADER_SPAM_SCORE
from lightr.mail.routing import RejectReason
from lightr.mail.smtp import DeliveryOutcome, LightrHandler
from lightr.models import Account, Alias, Domain, Organization
from lightr.repo import AccountRepo, AliasRepo, DomainRepo, OrganizationRepo

FAST_ROUNDS = 4


class FakeLMTP:
    """Records what would have gone to Dovecot."""

    def __init__(self, *, fail: bool = False, refuse: set[str] | None = None) -> None:
        self.fail = fail
        self.refuse = refuse or set()
        self.calls: list[tuple[str, list[str], bytes]] = []

    async def deliver(self, sender, recipients, message):
        from lightr.dovecot.lmtp import LMTPError

        payload = message if isinstance(message, bytes) else message.as_bytes()
        self.calls.append((sender, list(recipients), payload))
        if self.fail:
            raise LMTPError("cannot reach Dovecot LMTP at /run/dovecot/lmtp")
        return DeliveryResult(
            statuses=[
                RecipientStatus(r, 550 if r in self.refuse else 250, "x")
                for r in recipients
            ]
        )


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        accounts = AccountRepo(conn)
        await accounts.create(
            Account(
                domain_id=domain.id,
                local_part="ops",
                password_hash=hash_password("correct-horse", rounds=FAST_ROUNDS),
            )
        )
        await accounts.create(Account(domain_id=domain.id, local_part="team"))
        await AliasRepo(conn).create(
            Alias(domain_id=domain.id, source="out",
                  destinations=["someone@external.test"])
        )


@pytest.fixture
def lmtp() -> FakeLMTP:
    return FakeLMTP()


@pytest_asyncio.fixture
async def handler(
    cfg: Config, engine: AsyncEngine, world: None, lmtp: FakeLMTP
) -> AsyncIterator[LightrHandler]:
    h = LightrHandler(cfg, engine)
    h.lmtp = lmtp  # type: ignore[assignment]
    yield h
    # Webhook emission is fire-and-forget; without this its tasks
    # outlive the test's event loop and raise in a worker thread.
    await h.webhooks.drain()


def _raw(subject: str = "Hello", *, spam_header: bool = False) -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg["To"] = "ops@acme.test"
    msg["Subject"] = subject
    if spam_header:
        msg[HEADER_SPAM_SCORE] = "0.0"
    msg.set_content("Body text.")
    return msg.as_bytes()


class TestLocalDelivery:
    async def test_message_reaches_lmtp(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        outcome = await handler.deliver(
            mail_from="sender@example.test",
            recipients=["ops@acme.test"],
            raw=_raw(),
            remote_ip="203.0.113.5",
            helo="mx.example.test",
        )

        assert outcome.ok
        assert outcome.delivered == ["ops@acme.test"]
        assert lmtp.calls[0][1] == ["ops@acme.test"]

    async def test_several_recipients_in_one_transaction(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        outcome = await handler.deliver(
            mail_from="s@example.test",
            recipients=["ops@acme.test", "team@acme.test"],
            raw=_raw(),
        )
        assert sorted(outcome.delivered) == ["ops@acme.test", "team@acme.test"]
        assert len(lmtp.calls) == 1  # one LMTP transaction, not two

    async def test_analysis_headers_are_added(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        await handler.deliver(
            mail_from="s@example.test", recipients=["ops@acme.test"], raw=_raw()
        )
        payload = lmtp.calls[0][2]
        assert b"X-Spam-Score:" in payload
        assert b"Authentication-Results:" in payload

    async def test_forged_spam_header_is_replaced(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        """A sender must not be able to pre-mark themselves as clean."""
        await handler.deliver(
            mail_from="s@example.test",
            recipients=["ops@acme.test"],
            raw=_raw(spam_header=True),
        )
        payload = lmtp.calls[0][2].decode()
        assert payload.count("X-Spam-Score:") == 1

    async def test_received_header_records_the_hop(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        await handler.deliver(
            mail_from="s@example.test",
            recipients=["ops@acme.test"],
            raw=_raw(),
            remote_ip="203.0.113.5",
            helo="mx.example.test",
        )
        payload = lmtp.calls[0][2].decode()
        assert "Received:" in payload
        assert "203.0.113.5" in payload


class TestRejections:
    async def test_unknown_mailbox_is_not_delivered(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        outcome = await handler.deliver(
            mail_from="s@example.test", recipients=["ghost@acme.test"], raw=_raw()
        )
        assert not outcome.ok
        assert outcome.rejected[0][1] is RejectReason.NO_SUCH_MAILBOX
        assert lmtp.calls == []

    async def test_relay_attempt_is_refused(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        """The check that keeps the server off blocklists."""
        outcome = await handler.deliver(
            mail_from="s@example.test", recipients=["victim@elsewhere.test"], raw=_raw()
        )
        assert outcome.rejected[0][1] is RejectReason.NOT_LOCAL_DOMAIN
        assert "550" in outcome.smtp_response()

    async def test_alias_forwards_without_local_delivery(
        self, handler: LightrHandler, lmtp: FakeLMTP, engine: AsyncEngine
    ) -> None:
        """This used to assert only `outcome.forwarded` -- and the
        outcome said "forwarded" while nothing was queued. Every message
        to a forwarding alias was accepted and dropped, and this test
        passed. So it checks the queue, not the report."""
        from lightr.mail.queue import Queue

        outcome = await handler.deliver(
            mail_from="s@example.test", recipients=["out@acme.test"], raw=_raw()
        )

        assert outcome.forwarded == ["someone@external.test"]
        assert lmtp.calls == []
        async with engine.begin() as conn:
            queued = await Queue(conn).list()
        assert [q.to_addrs for q in queued] == [["someone@external.test"]]


class TestPartialFailure:
    async def test_valid_recipient_still_gets_the_message(
        self, handler: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        outcome = await handler.deliver(
            mail_from="s@example.test",
            recipients=["ops@acme.test", "ghost@acme.test"],
            raw=_raw(),
        )
        assert outcome.delivered == ["ops@acme.test"]
        assert outcome.rejected[0][0] == "ghost@acme.test"

    async def test_partial_success_reports_250(
        self, handler: LightrHandler
    ) -> None:
        """Reporting failure would make the sender retry and duplicate
        the copy that already arrived."""
        outcome = await handler.deliver(
            mail_from="s@example.test",
            recipients=["ops@acme.test", "ghost@acme.test"],
            raw=_raw(),
        )
        assert outcome.smtp_response().startswith("250")

    async def test_dovecot_down_is_transient(
        self, cfg: Config, engine: AsyncEngine, world: None
    ) -> None:
        """4xx so the sender retries once the store is back, rather
        than bouncing mail that was never anyone's fault."""
        handler = LightrHandler(cfg, engine)
        handler.lmtp = FakeLMTP(fail=True)  # type: ignore[assignment]

        outcome = await handler.deliver(
            mail_from="s@example.test", recipients=["ops@acme.test"], raw=_raw()
        )
        assert outcome.smtp_response().startswith("451")
        assert outcome.error is not None


class TestSMTPResponses:
    def test_clean_success(self) -> None:
        assert DeliveryOutcome(delivered=["a@b.test"]).smtp_response() == "250 2.0.0 OK"

    def test_error_wins_over_everything(self) -> None:
        outcome = DeliveryOutcome(delivered=["a@b.test"], error="store down")
        assert outcome.smtp_response().startswith("451")

    def test_all_rejected_reports_the_first_reason(self) -> None:
        outcome = DeliveryOutcome(
            rejected=[("a@b.test", RejectReason.NOT_LOCAL_DOMAIN)]
        )
        assert "Relay access denied" in outcome.smtp_response()

    def test_alias_loop_is_transient(self) -> None:
        outcome = DeliveryOutcome(rejected=[("a@b.test", RejectReason.ALIAS_LOOP)])
        assert outcome.smtp_response().startswith("451")

    def test_no_recipients_at_all(self) -> None:
        assert DeliveryOutcome().smtp_response().startswith("550")


class TestAuthentication:
    async def test_correct_credentials_succeed(
        self, handler: LightrHandler
    ) -> None:
        from aiosmtpd.smtp import LoginPassword

        session = type("S", (), {"ssl": object()})()
        result = await handler.authenticate(
            None, session, None, "PLAIN",
            LoginPassword(b"ops@acme.test", b"correct-horse"),
        )
        assert result.success

    async def test_wrong_password_fails(self, handler: LightrHandler) -> None:
        from aiosmtpd.smtp import LoginPassword

        session = type("S", (), {"ssl": object()})()
        result = await handler.authenticate(
            None, session, None, "PLAIN", LoginPassword(b"ops@acme.test", b"nope")
        )
        assert not result.success

    async def test_plaintext_auth_is_refused_without_tls(
        self, handler: LightrHandler
    ) -> None:
        """require_tls_for_auth defaults on; sending credentials in the
        clear must not be possible by accident."""
        from aiosmtpd.smtp import LoginPassword

        session = type("S", (), {"ssl": None})()
        result = await handler.authenticate(
            None, session, None, "PLAIN",
            LoginPassword(b"ops@acme.test", b"correct-horse"),
        )
        assert not result.success

    async def test_plaintext_auth_allowed_when_configured(
        self, cfg: Config, engine: AsyncEngine, world: None
    ) -> None:
        from aiosmtpd.smtp import LoginPassword

        cfg.security.require_tls_for_auth = False
        handler = LightrHandler(cfg, engine)

        session = type("S", (), {"ssl": None})()
        result = await handler.authenticate(
            None, session, None, "PLAIN",
            LoginPassword(b"ops@acme.test", b"correct-horse"),
        )
        assert result.success

    async def test_unsupported_mechanism_is_not_handled(
        self, handler: LightrHandler
    ) -> None:
        result = await handler.authenticate(None, None, None, "OAUTHBEARER", None)
        assert not result.success
        assert not result.handled


class TestSubmissionRelay:
    """An authenticated user may mail anyone; :25 may not relay at all.

    That difference is the entire reason for a separate :587.
    """

    @pytest_asyncio.fixture
    async def submission(
        self, cfg: Config, engine: AsyncEngine, world: None, lmtp: FakeLMTP
    ):
        h = LightrHandler(cfg, engine, require_auth=True)
        h.lmtp = lmtp  # type: ignore[assignment]
        yield h
        await h.webhooks.drain()

    async def test_external_recipients_are_queued_not_refused(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        outcome = await submission.deliver(
            mail_from="ops@acme.test",
            recipients=["someone@external.test"],
            raw=_raw(),
        )

        assert outcome.ok
        assert outcome.forwarded == ["someone@external.test"]

        from lightr.mail.queue import Queue

        async with engine.begin() as conn:
            queued = await Queue(conn).list()
        assert [q.to_addrs for q in queued] == [["someone@external.test"]]

    async def test_receive_still_refuses_to_relay(
        self, handler: LightrHandler, engine: AsyncEngine
    ) -> None:
        """The check that keeps the server off blocklists."""
        outcome = await handler.deliver(
            mail_from="stranger@example.test",
            recipients=["victim@elsewhere.test"],
            raw=_raw(),
        )

        assert outcome.rejected[0][1] is RejectReason.NOT_LOCAL_DOMAIN

        from lightr.mail.queue import Queue

        async with engine.begin() as conn:
            assert await Queue(conn).list() == []

    async def test_local_recipients_still_go_to_dovecot(
        self, submission: LightrHandler, lmtp: FakeLMTP
    ) -> None:
        outcome = await submission.deliver(
            mail_from="ops@acme.test", recipients=["team@acme.test"], raw=_raw()
        )
        assert outcome.delivered == ["team@acme.test"]

    async def test_a_mixed_message_splits_correctly(
        self, submission: LightrHandler, lmtp: FakeLMTP, engine: AsyncEngine
    ) -> None:
        outcome = await submission.deliver(
            mail_from="ops@acme.test",
            recipients=["team@acme.test", "someone@external.test"],
            raw=_raw(),
        )

        assert outcome.delivered == ["team@acme.test"]
        assert outcome.forwarded == ["someone@external.test"]

    async def test_submitted_mail_leaves_without_our_analysis(
        self, submission: LightrHandler, lmtp: FakeLMTP, engine: AsyncEngine
    ) -> None:
        """Gmail received X-Spam-Score, X-Lightr-Has-Attachment and an
        Authentication-Results saying dkim=none, stamped by us on mail we
        were sending. The local copy keeps the analysis; the queued copy
        must not carry it, forged or ours, but keeps the trace headers."""
        from email import message_from_bytes

        from lightr.mail.headers import CONTROLLED_HEADERS
        from lightr.mail.queue import Queue

        outcome = await submission.deliver(
            mail_from="ops@acme.test",
            recipients=["team@acme.test", "someone@external.test"],
            raw=_raw(spam_header=True),
            remote_ip="203.0.113.5",
            helo="laptop.example.test",
        )
        assert outcome.forwarded == ["someone@external.test"]

        async with engine.begin() as conn:
            (queued,) = await Queue(conn).list()
        assert queued.raw is not None
        sent = message_from_bytes(queued.raw)
        for name in CONTROLLED_HEADERS:
            assert name not in sent, name
        assert sent["Received"] and sent["Message-ID"] and sent["Date"]

        (_, _, local_payload) = lmtp.calls[0]
        local = message_from_bytes(local_payload)
        assert local[HEADER_SPAM_SCORE] is not None
        assert local["Message-ID"] == sent["Message-ID"]

    async def test_an_unknown_sender_domain_is_not_queued(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        """We cannot attribute or sign mail from a domain we do not
        host, so it is not queued."""
        await submission.deliver(
            mail_from="someone@notours.test",
            recipients=["out@external.test"],
            raw=_raw(),
        )

        from lightr.mail.queue import Queue

        async with engine.begin() as conn:
            assert await Queue(conn).list() == []
