"""Bounce parsing and suppression.

The hard/soft distinction is the thing worth testing hardest: getting
it backwards either silently stops mail a user expects, or keeps
mailing dead addresses and burns sending reputation.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.mail.bounce import Bounce, BounceRepo, BounceType, classify, parse
from lightr.models import Domain, Organization
from lightr.repo import DomainRepo, OrganizationRepo

HARD_DSN = b"""From: MAILER-DAEMON@mx.example.test
To: ops@acme.test
Subject: Undelivered Mail Returned to Sender
Content-Type: multipart/report; report-type=delivery-status; boundary="B"

--B
Content-Type: text/plain

This is the mail system at host mx.example.test.

--B
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.test

Final-Recipient: rfc822; ghost@example.test
Original-Recipient: rfc822;ghost@example.test
Action: failed
Status: 5.1.1
Remote-MTA: dns; mail.example.test
Diagnostic-Code: smtp; 550 5.1.1 <ghost@example.test>: Recipient address
 rejected: User unknown in local recipient table

--B
Content-Type: message/rfc822

Message-ID: <original@acme.test>
Subject: The original

--B--
"""

SOFT_DSN = b"""From: MAILER-DAEMON@mx.example.test
To: ops@acme.test
Subject: Delivery delayed
Content-Type: multipart/report; report-type=delivery-status; boundary="B"

--B
Content-Type: message/delivery-status

Final-Recipient: rfc822; full@example.test
Action: failed
Status: 5.2.2
Diagnostic-Code: smtp; 552 5.2.2 Mailbox full

--B--
"""

MULTI_DSN = b"""From: MAILER-DAEMON@mx.example.test
Content-Type: multipart/report; report-type=delivery-status; boundary="B"

--B
Content-Type: message/delivery-status

Final-Recipient: rfc822; ghost@example.test
Action: failed
Status: 5.1.1

Final-Recipient: rfc822; busy@example.test
Action: failed
Status: 4.4.1

--B--
"""

PROSE_BOUNCE = b"""From: postmaster@old.example.test
To: ops@acme.test
Subject: Returned mail
Content-Type: text/plain

Your message could not be delivered to <nobody@old.example.test>.
550 5.1.1 User unknown
"""

COMPLAINT = b"""From: feedback@isp.test
To: ops@acme.test
Subject: FW: complaint
Content-Type: multipart/report; report-type=feedback-report; boundary="B"

--B
Content-Type: message/feedback-report

Feedback-Type: abuse
User-Agent: SomeISP/1.0
Original-Rcpt-To: annoyed@isp.test

--B--
"""


class TestClassification:
    @pytest.mark.parametrize("status", ["5.1.1", "5.1.2", "5.1.3", "5.2.1"])
    def test_dead_address_codes_are_hard(self, status: str) -> None:
        assert classify(status, None) is BounceType.HARD

    @pytest.mark.parametrize("status", ["4.2.2", "4.4.1", "4.7.1"])
    def test_4xx_is_soft(self, status: str) -> None:
        assert classify(status, None) is BounceType.SOFT

    def test_full_mailbox_is_soft_despite_being_5xx(self) -> None:
        """5.2.2 is permanent by class, but the address is alive --
        suppressing it would silently stop wanted mail."""
        assert classify("5.2.2", "552 Mailbox full") is BounceType.SOFT

    def test_unknown_5xx_defaults_to_hard(self) -> None:
        assert classify("5.9.9", None) is BounceType.HARD

    def test_prose_user_unknown_is_hard(self) -> None:
        assert classify(None, "550 User unknown") is BounceType.HARD

    def test_prose_quota_is_soft(self) -> None:
        assert classify(None, "Over quota, try again later") is BounceType.SOFT

    def test_soft_phrases_win_over_hard_ones(self) -> None:
        """'mailbox full' and 'mailbox unavailable' both appear; the
        soft reading must win."""
        text = "552 mailbox full; mailbox unavailable right now"
        assert classify(None, text) is BounceType.SOFT

    def test_bare_smtp_code_is_used(self) -> None:
        assert classify(None, "421 service unavailable") is BounceType.SOFT
        assert classify(None, "551 nope") is BounceType.HARD

    def test_nothing_recognisable_is_unknown_not_hard(self) -> None:
        """Anything ambiguous must not suppress."""
        result = classify(None, "something went wrong")
        assert result is BounceType.UNKNOWN
        assert not result.should_suppress

    def test_only_hard_and_complaint_suppress(self) -> None:
        assert BounceType.HARD.should_suppress
        assert BounceType.COMPLAINT.should_suppress
        assert not BounceType.SOFT.should_suppress
        assert not BounceType.UNKNOWN.should_suppress


class TestDSNParsing:
    def test_hard_bounce(self) -> None:
        bounces = parse(HARD_DSN)
        assert len(bounces) == 1
        assert bounces[0].recipient == "ghost@example.test"
        assert bounces[0].bounce_type is BounceType.HARD
        assert bounces[0].status == "5.1.1"

    def test_diagnostic_and_mta_are_captured(self) -> None:
        bounce = parse(HARD_DSN)[0]
        assert bounce.diagnostic is not None
        assert "User unknown" in bounce.diagnostic
        assert bounce.remote_mta == "mail.example.test"

    def test_folded_diagnostic_is_joined(self) -> None:
        """The Diagnostic-Code spans two lines in the fixture."""
        assert "local recipient table" in (parse(HARD_DSN)[0].diagnostic or "")

    def test_original_message_id_is_recovered(self) -> None:
        assert parse(HARD_DSN)[0].original_message_id == "<original@acme.test>"

    def test_full_mailbox_is_not_suppressed(self) -> None:
        bounce = parse(SOFT_DSN)[0]
        assert bounce.bounce_type is BounceType.SOFT
        assert not bounce.should_suppress

    def test_multiple_recipients_are_classified_separately(self) -> None:
        bounces = {b.recipient: b.bounce_type for b in parse(MULTI_DSN)}
        assert bounces["ghost@example.test"] is BounceType.HARD
        assert bounces["busy@example.test"] is BounceType.SOFT

    def test_address_type_prefix_is_stripped(self) -> None:
        assert parse(HARD_DSN)[0].recipient == "ghost@example.test"

    def test_garbage_input_does_not_raise(self) -> None:
        assert parse(b"not a real message at all") == []


class TestProseParsing:
    def test_address_and_reason_are_found(self) -> None:
        bounces = parse(PROSE_BOUNCE)
        assert len(bounces) == 1
        assert bounces[0].recipient == "nobody@old.example.test"
        assert bounces[0].bounce_type is BounceType.HARD

    def test_status_code_in_prose_is_extracted(self) -> None:
        assert parse(PROSE_BOUNCE)[0].status == "5.1.1"

    def test_text_without_an_address_yields_nothing(self) -> None:
        raw = b"Subject: hi\nContent-Type: text/plain\n\nno addresses here\n"
        assert parse(raw) == []


class TestComplaints:
    def test_feedback_report_is_a_complaint(self) -> None:
        bounces = parse(COMPLAINT)
        assert len(bounces) == 1
        assert bounces[0].bounce_type is BounceType.COMPLAINT
        assert bounces[0].recipient == "annoyed@isp.test"

    def test_complaints_suppress(self) -> None:
        """Someone marking mail as spam must stop receiving it."""
        assert parse(COMPLAINT)[0].should_suppress


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


@pytest_asyncio.fixture
async def scope(conn: AsyncConnection) -> dict:
    org = await OrganizationRepo(conn).create(Organization(name="Acme"))
    domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
    return {"org": org, "domain": domain}


class TestSuppression:
    async def test_hard_bounce_suppresses(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        repo = BounceRepo(conn)
        bounce = parse(HARD_DSN)[0]

        suppressed = await repo.record(
            bounce, org_id=scope["org"].id, domain_id=scope["domain"].id
        )

        assert suppressed
        assert await repo.is_suppressed("ghost@example.test")

    async def test_soft_bounce_does_not_suppress(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        repo = BounceRepo(conn)
        bounce = parse(SOFT_DSN)[0]

        suppressed = await repo.record(
            bounce, org_id=scope["org"].id, domain_id=scope["domain"].id
        )

        assert not suppressed
        assert not await repo.is_suppressed("full@example.test")

    async def test_bounce_is_recorded_either_way(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        repo = BounceRepo(conn)
        await repo.record(
            parse(SOFT_DSN)[0], org_id=scope["org"].id, domain_id=scope["domain"].id
        )
        assert len(await repo.list_bounces()) == 1

    async def test_suppression_is_idempotent(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        """A second bounce for the same address must not fail on the
        primary key."""
        repo = BounceRepo(conn)
        bounce = parse(HARD_DSN)[0]

        await repo.record(bounce, org_id=scope["org"].id, domain_id=scope["domain"].id)
        await repo.record(bounce, org_id=scope["org"].id, domain_id=scope["domain"].id)

        assert len(await repo.list_suppressed()) == 1
        assert len(await repo.list_bounces()) == 2

    async def test_unsuppress(self, conn: AsyncConnection, scope: dict) -> None:
        repo = BounceRepo(conn)
        await repo.suppress("ghost@example.test", reason="hard")

        assert await repo.unsuppress("ghost@example.test")
        assert not await repo.is_suppressed("ghost@example.test")

    async def test_unsuppress_reports_when_nothing_matched(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        assert not await BounceRepo(conn).unsuppress("never@seen.test")

    async def test_addresses_are_matched_case_insensitively(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        repo = BounceRepo(conn)
        await repo.suppress("Ghost@Example.Test", reason="hard")
        assert await repo.is_suppressed("ghost@example.test")

    async def test_suppression_blocks_delivery(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        """The end-to-end point of all this: the router must refuse."""
        from lightr.mail.routing import RejectReason, Router
        from lightr.models import Account
        from lightr.repo import AccountRepo

        await AccountRepo(conn).create(
            Account(domain_id=scope["domain"].id, local_part="ops")
        )
        await BounceRepo(conn).suppress("ops@acme.test", reason="hard")

        route = await Router(conn).route("ops@acme.test")
        assert route.reason is RejectReason.SUPPRESSED

    async def test_long_diagnostics_are_truncated(
        self, conn: AsyncConnection, scope: dict
    ) -> None:
        repo = BounceRepo(conn)
        await repo.record(
            Bounce(
                recipient="x@y.test",
                bounce_type=BounceType.HARD,
                diagnostic="x" * 5000,
            ),
            org_id=scope["org"].id,
            domain_id=scope["domain"].id,
        )
        stored = (await repo.list_bounces())[0]
        assert len(str(stored["diagnostic_code"])) <= 1000
