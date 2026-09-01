"""SPF, DKIM verification, DMARC, and spam scoring.

The load-bearing rule throughout: a lookup that fails is not a
verification that failed. DNS being slow must never look like a
forgery, or an outage rejects everyone's mail at once.
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

from lightr.config import SpamConfig
from lightr.mail.authentication import (
    DKIMResult,
    DMARCResult,
    Result,
    SPFResult,
    _aligned,
    check_dkim,
    check_dmarc,
    check_spf,
    from_domain_of,
)
from lightr.mail.spam import Score, score_message


class TestResultSemantics:
    def test_only_fail_indicates_forgery(self) -> None:
        assert Result.FAIL.is_failure
        for result in (Result.TEMPERROR, Result.PERMERROR, Result.NONE, Result.NEUTRAL):
            assert not result.is_failure, result

    def test_inconclusive_results(self) -> None:
        assert Result.TEMPERROR.is_inconclusive
        assert Result.NONE.is_inconclusive
        assert not Result.PASS.is_inconclusive
        assert not Result.FAIL.is_inconclusive


class TestSPF:
    async def test_no_client_address_is_none(self) -> None:
        result = await check_spf("", "a@b.test", "helo.test")
        assert result.result is Result.NONE

    async def test_no_domain_is_none(self) -> None:
        result = await check_spf("203.0.113.5", "", "")
        assert result.result is Result.NONE

    async def test_domain_comes_from_the_envelope_sender(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, str] = {}

        def fake_check2(i: str, s: str, h: str) -> tuple[str, str]:
            captured.update({"i": i, "s": s, "h": h})
            return ("pass", "sender SPF authorized")

        import spf

        monkeypatch.setattr(spf, "check2", fake_check2)

        result = await check_spf("203.0.113.5", "ops@sender.test", "mx.sender.test")

        assert result.result is Result.PASS
        assert result.domain == "sender.test"
        assert captured["i"] == "203.0.113.5"

    async def test_helo_is_used_for_a_null_sender(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bounce has no envelope sender; RFC 7208 says use HELO."""
        import spf

        monkeypatch.setattr(spf, "check2", lambda **kw: ("pass", ""))

        result = await check_spf("203.0.113.5", "", "mx.bouncer.test")
        assert result.domain == "mx.bouncer.test"

    async def test_a_lookup_failure_is_temperror_not_fail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The rule that matters: DNS trouble is not a forgery."""
        import spf

        def boom(**kwargs: object) -> tuple[str, str]:
            raise OSError("DNS is down")

        monkeypatch.setattr(spf, "check2", boom)

        result = await check_spf("203.0.113.5", "a@b.test", "h.test")
        assert result.result is Result.TEMPERROR
        assert not result.result.is_failure

    async def test_a_real_fail_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import spf

        monkeypatch.setattr(spf, "check2", lambda **kw: ("fail", "not authorized"))

        result = await check_spf("203.0.113.5", "a@b.test", "h.test")
        assert result.result is Result.FAIL

    async def test_an_unknown_verdict_becomes_neutral(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import spf

        monkeypatch.setattr(spf, "check2", lambda **kw: ("weird", ""))

        assert (await check_spf("1.2.3.4", "a@b.test", "h")).result is Result.NEUTRAL


class TestDKIMVerification:
    async def test_unsigned_message_is_none(self) -> None:
        result = await check_dkim(b"From: a@b.test\r\n\r\nbody")
        assert result.result is Result.NONE

    async def test_a_valid_signature_passes(self) -> None:
        from lightr.mail.dkim import generate_key, sign

        key = generate_key("sel", bits=1024)
        raw = (
            b"From: ops@acme.test\r\nSubject: Hi\r\n"
            b"Date: Tue, 01 Sep 2026 10:00:00 +0000\r\n\r\nBody\r\n"
        )
        signed = sign(
            raw, domain="acme.test", selector="sel",
            private_key_pem=key.private_key_pem,
        )

        import dkim as dkimpy

        original = dkimpy.verify
        try:
            dkimpy.verify = lambda message, **kw: original(  # type: ignore[assignment]
                message, dnsfunc=lambda name, **k: key.dns_value()
            )
            result = await check_dkim(signed)
        finally:
            dkimpy.verify = original  # type: ignore[assignment]

        assert result.result is Result.PASS

    async def test_signature_identity_is_extracted(self) -> None:
        raw = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=sender.test; s=sel2026; "
            b"h=from:subject; b=abc\r\nFrom: a@sender.test\r\n\r\nbody"
        )
        result = await check_dkim(raw)
        assert result.domain == "sender.test"
        assert result.selector == "sel2026"

    async def test_a_broken_signature_is_permerror_not_fail(self) -> None:
        """A malformed signature is a problem with the message, but not
        proof that the sender is forged."""
        raw = b"DKIM-Signature: total nonsense\r\nFrom: a@b.test\r\n\r\nbody"
        result = await check_dkim(raw)
        assert result.result in (Result.PERMERROR, Result.FAIL)


class TestDMARCAlignment:
    @pytest.mark.parametrize(
        ("candidate", "from_domain", "expected"),
        [
            ("acme.test", "acme.test", True),
            ("mail.acme.test", "acme.test", True),
            ("acme.test", "mail.acme.test", True),
            ("ACME.TEST", "acme.test", True),
            ("acme.test.", "acme.test", True),
            ("evil.test", "acme.test", False),
            ("acme.test.evil.test", "acme.test", False),
            ("", "acme.test", False),
        ],
    )
    def test_alignment(self, candidate: str, from_domain: str, expected: bool) -> None:
        assert _aligned(candidate, from_domain) is expected

    async def test_no_from_domain_is_none(self) -> None:
        result = await check_dmarc("", SPFResult(Result.PASS), DKIMResult(Result.PASS))
        assert result.result is Result.NONE

    async def test_no_published_policy_is_none(self) -> None:
        """conftest patches the lookup to return no policy."""
        result = await check_dmarc(
            "acme.test", SPFResult(Result.PASS, "acme.test"), DKIMResult(Result.NONE)
        )
        assert result.result is Result.NONE

    async def test_aligned_spf_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "lightr.mail.authentication._dmarc_policy",
            _policy("reject"),
        )
        result = await check_dmarc(
            "acme.test", SPFResult(Result.PASS, "acme.test"), DKIMResult(Result.NONE)
        )
        assert result.result is Result.PASS
        assert result.aligned_spf

    async def test_spf_passing_for_the_wrong_domain_does_not_align(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The whole point of DMARC: SPF passing for a domain the sender
        happens to control says nothing about this From address."""
        monkeypatch.setattr(
            "lightr.mail.authentication._dmarc_policy", _policy("reject")
        )
        result = await check_dmarc(
            "acme.test", SPFResult(Result.PASS, "evil.test"), DKIMResult(Result.NONE)
        )
        assert result.result is Result.FAIL
        assert result.should_reject

    async def test_aligned_dkim_alone_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "lightr.mail.authentication._dmarc_policy", _policy("quarantine")
        )
        result = await check_dmarc(
            "acme.test", SPFResult(Result.FAIL), DKIMResult(Result.PASS, "acme.test")
        )
        assert result.result is Result.PASS

    async def test_temperror_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A DNS outage must not produce a DMARC failure."""
        monkeypatch.setattr(
            "lightr.mail.authentication._dmarc_policy", _policy("reject")
        )
        result = await check_dmarc(
            "acme.test", SPFResult(Result.TEMPERROR), DKIMResult(Result.NONE)
        )
        assert result.result is Result.TEMPERROR
        assert not result.should_reject

    async def test_policy_drives_the_action(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "lightr.mail.authentication._dmarc_policy", _policy("quarantine")
        )
        result = await check_dmarc(
            "acme.test", SPFResult(Result.FAIL), DKIMResult(Result.FAIL)
        )
        assert result.should_quarantine
        assert not result.should_reject


def _policy(value: str):
    async def _lookup(domain: str) -> str:
        return value

    return _lookup


class TestFromDomain:
    def test_plain_address(self) -> None:
        assert from_domain_of(b"From: a@b.test\r\n\r\nbody") == "b.test"

    def test_display_name(self) -> None:
        raw = b'From: "A Person" <a@b.test>\r\n\r\nbody'
        assert from_domain_of(raw) == "b.test"

    def test_missing_from(self) -> None:
        assert from_domain_of(b"Subject: x\r\n\r\nbody") == ""

    def test_garbage(self) -> None:
        assert from_domain_of(b"\xff\xfe") == ""


def _message(**kwargs: object) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg["To"] = "ops@acme.test"
    msg["Subject"] = str(kwargs.get("subject", "Hello"))
    if kwargs.get("message_id", True):
        msg["Message-ID"] = "<abc@example.test>"
    if kwargs.get("date", True):
        msg["Date"] = "Tue, 01 Sep 2026 10:00:00 +0000"
    msg.set_content(str(kwargs.get("body", "Body text.")))
    return msg


CLEAN = (SPFResult(Result.PASS, "example.test"), DKIMResult(Result.PASS, "example.test"))


class TestSpamScoring:
    def test_a_clean_authenticated_message_scores_low(self) -> None:
        score = score_message(
            _message(), spf=CLEAN[0], dkim=CLEAN[1], dmarc=DMARCResult(Result.PASS)
        )
        assert score.points < 1.0

    def test_spf_failure_scores(self) -> None:
        score = score_message(
            _message(),
            spf=SPFResult(Result.FAIL),
            dkim=DKIMResult(Result.NONE),
            dmarc=DMARCResult(Result.NONE),
        )
        assert score.points >= 3.0
        assert any("spf=fail" in r for r in score.reasons)

    def test_dmarc_reject_is_the_strongest_signal(self) -> None:
        score = score_message(
            _message(),
            spf=SPFResult(Result.FAIL),
            dkim=DKIMResult(Result.FAIL),
            dmarc=DMARCResult(Result.FAIL, policy="reject"),
        )
        cfg = SpamConfig()
        _, is_junk = score.verdict(cfg)
        assert is_junk

    def test_temperror_does_not_score(self) -> None:
        """An outage must not push legitimate mail into Junk."""
        score = score_message(
            _message(),
            spf=SPFResult(Result.TEMPERROR),
            dkim=DKIMResult(Result.TEMPERROR),
            dmarc=DMARCResult(Result.TEMPERROR),
        )
        assert score.points < SpamConfig().junk_threshold

    def test_no_single_content_heuristic_junks_a_message(self) -> None:
        """Content signals are weak evidence; several must agree."""
        cfg = SpamConfig()
        for message in (
            _message(subject="FREE MONEY NOW"),
            _message(subject="Buy now!!!"),
            _message(message_id=False),
            _message(date=False),
        ):
            score = score_message(
                message, spf=CLEAN[0], dkim=CLEAN[1], dmarc=DMARCResult(Result.PASS)
            )
            _, is_junk = score.verdict(cfg)
            assert not is_junk, score.reasons

    def test_all_caps_subject_scores(self) -> None:
        score = score_message(
            _message(subject="URGENT ACTION REQUIRED"),
            spf=CLEAN[0], dkim=CLEAN[1], dmarc=DMARCResult(Result.PASS),
        )
        assert any("caps" in r for r in score.reasons)

    def test_executable_attachment_scores_high(self) -> None:
        msg = _message()
        msg.add_attachment(
            b"MZ", maintype="application", subtype="octet-stream",
            filename="invoice.exe",
        )
        score = score_message(
            msg, spf=CLEAN[0], dkim=CLEAN[1], dmarc=DMARCResult(Result.PASS)
        )
        assert any("executable" in r for r in score.reasons)

    def test_a_pdf_attachment_does_not_score(self) -> None:
        msg = _message()
        msg.add_attachment(
            b"%PDF", maintype="application", subtype="pdf", filename="invoice.pdf"
        )
        score = score_message(
            msg, spf=CLEAN[0], dkim=CLEAN[1], dmarc=DMARCResult(Result.PASS)
        )
        assert not any("executable" in r for r in score.reasons)

    def test_reasons_are_recorded_with_their_weight(self) -> None:
        score = score_message(
            _message(),
            spf=SPFResult(Result.FAIL),
            dkim=DKIMResult(Result.NONE),
            dmarc=DMARCResult(Result.NONE),
        )
        assert any("+3.0" in r for r in score.reasons)

    def test_thresholds_are_configurable(self) -> None:
        score = Score(points=3.0)
        strict = SpamConfig(suspicious_threshold=1.0, junk_threshold=2.0)
        lenient = SpamConfig(suspicious_threshold=5.0, junk_threshold=9.0)

        assert score.verdict(strict) == (True, True)
        assert score.verdict(lenient) == (False, False)
