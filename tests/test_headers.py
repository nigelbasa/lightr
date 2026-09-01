"""Headers Lightr injects for Sieve to test against."""

from __future__ import annotations

from email.message import EmailMessage

import pytest

from lightr.dovecot.sieve import (
    HEADER_AUTH_RESULTS,
    HEADER_HAS_ATTACHMENT,
    HEADER_SPAM_FLAG,
    HEADER_SPAM_SCORE,
)
from lightr.mail.headers import (
    Analysis,
    AuthResults,
    add_received,
    apply,
    ensure_date,
    ensure_message_id,
    has_attachment,
    strip_controlled,
)


def _message(*, attachment: bool = False, inline: bool = False) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg["To"] = "ops@acme.test"
    msg["Subject"] = "Hello"
    msg.set_content("Body.")
    if attachment:
        msg.add_attachment(b"data", maintype="application", subtype="pdf",
                           filename="doc.pdf")
    if inline:
        msg.add_attachment(b"img", maintype="image", subtype="png",
                           filename="logo.png", disposition="inline")
    return msg


class TestForgedHeaders:
    """An external sender must not be able to opt out of filtering."""

    def test_inbound_spam_score_is_stripped(self) -> None:
        msg = _message()
        msg[HEADER_SPAM_SCORE] = "0.0"

        apply(msg, Analysis(score=9.5, is_spam=True), "mail.acme.test")

        assert msg.get_all(HEADER_SPAM_SCORE) == ["9.5"]

    def test_repeated_forged_headers_are_all_removed(self) -> None:
        msg = _message()
        for _ in range(3):
            msg[HEADER_SPAM_FLAG] = "NO"

        apply(msg, Analysis(score=9.9, is_spam=True), "mail.acme.test")

        assert msg.get_all(HEADER_SPAM_FLAG) == ["YES"]

    def test_forged_auth_results_are_replaced(self) -> None:
        msg = _message()
        msg[HEADER_AUTH_RESULTS] = "mail.acme.test; spf=pass; dkim=pass; dmarc=pass"

        apply(
            msg,
            Analysis(auth=AuthResults(spf="fail", dkim="fail", dmarc="fail")),
            "mail.acme.test",
        )

        results = msg.get_all(HEADER_AUTH_RESULTS)
        assert results is not None
        assert len(results) == 1
        assert "spf=fail" in results[0]

    def test_strip_reports_what_it_removed(self) -> None:
        msg = _message()
        msg[HEADER_SPAM_SCORE] = "0"
        msg[HEADER_HAS_ATTACHMENT] = "no"

        removed = strip_controlled(msg)

        assert set(removed) == {HEADER_SPAM_SCORE, HEADER_HAS_ATTACHMENT}


class TestAnalysisHeaders:
    def test_score_is_written_to_one_decimal(self) -> None:
        msg = _message()
        apply(msg, Analysis(score=4.25), "mail.acme.test")
        assert msg[HEADER_SPAM_SCORE] == "4.2"

    def test_flag_reflects_the_verdict(self) -> None:
        clean, spam = _message(), _message()
        apply(clean, Analysis(score=0.1, is_spam=False), "h")
        apply(spam, Analysis(score=8.0, is_spam=True), "h")

        assert clean[HEADER_SPAM_FLAG] == "NO"
        assert spam[HEADER_SPAM_FLAG] == "YES"

    def test_reasons_are_recorded_when_present(self) -> None:
        msg = _message()
        apply(msg, Analysis(score=6.0, is_spam=True, reasons=["dnsbl", "no spf"]), "h")
        assert msg["X-Lightr-Spam-Reasons"] == "dnsbl, no spf"

    def test_no_reasons_header_when_clean(self) -> None:
        msg = _message()
        apply(msg, Analysis(), "h")
        assert "X-Lightr-Spam-Reasons" not in msg

    def test_attachment_flag(self) -> None:
        msg = _message()
        apply(msg, Analysis(has_attachment=True), "h")
        assert msg[HEADER_HAS_ATTACHMENT] == "yes"


class TestAttachmentDetection:
    def test_plain_message_has_none(self) -> None:
        assert has_attachment(_message()) is False

    def test_real_attachment_is_detected(self) -> None:
        assert has_attachment(_message(attachment=True)) is True

    def test_inline_image_is_not_an_attachment(self) -> None:
        """An inline logo is not what a filter rule means."""
        assert has_attachment(_message(inline=True)) is False


class TestAuthResultsRendering:
    def test_includes_the_hostname_first(self) -> None:
        rendered = AuthResults().render("mail.acme.test")
        assert rendered.startswith("mail.acme.test;")

    def test_all_three_mechanisms_appear(self) -> None:
        rendered = AuthResults(spf="pass", dkim="pass", dmarc="pass").render("h")
        for fragment in ("spf=pass", "dkim=pass", "dmarc=pass"):
            assert fragment in rendered

    def test_smtp_mailfrom_is_included_when_known(self) -> None:
        rendered = AuthResults(spf="pass", mail_from="a@b.test").render("h")
        assert "smtp.mailfrom=a@b.test" in rendered

    def test_sieve_can_match_the_rendered_form(self) -> None:
        """The Sieve generator tests for 'spf=fail'; the rendered
        header must contain exactly that."""
        from lightr.dovecot.sieve import Condition, Field, Operator, compile_condition

        rendered = AuthResults(spf="fail").render("mail.acme.test")
        test, _ = compile_condition(Condition(Field.SPF_RESULT, Operator.EQUALS, "fail"))

        fragment = test.split('"')[-2]
        assert fragment in rendered


class TestEnvelopeHeaders:
    def test_received_is_prepended(self) -> None:
        msg = _message()
        add_received(
            msg, hostname="mail.acme.test", remote_ip="203.0.113.5",
            helo="mx.example.test", recipient="ops@acme.test",
        )
        assert msg.items()[0][0] == "Received"

    def test_received_names_the_recipient_and_source(self) -> None:
        msg = _message()
        add_received(
            msg, hostname="mail.acme.test", remote_ip="203.0.113.5",
            helo="mx.example.test", recipient="ops@acme.test",
        )
        value = msg["Received"]
        assert "203.0.113.5" in value
        assert "ops@acme.test" in value
        assert "mail.acme.test" in value

    def test_message_id_is_added_when_missing(self) -> None:
        msg = EmailMessage()
        msg.set_content("x")
        ensure_message_id(msg, "acme.test")
        assert msg["Message-ID"].endswith("@acme.test>")

    def test_existing_message_id_is_kept(self) -> None:
        msg = _message()
        msg["Message-ID"] = "<original@elsewhere.test>"
        ensure_message_id(msg, "acme.test")
        assert msg["Message-ID"] == "<original@elsewhere.test>"

    def test_date_is_added_when_missing(self) -> None:
        msg = EmailMessage()
        msg.set_content("x")
        ensure_date(msg)
        assert msg["Date"]

    @pytest.mark.parametrize("header", ["From", "To", "Subject"])
    def test_original_headers_survive(self, header: str) -> None:
        msg = _message()
        apply(msg, Analysis(score=1.0), "h")
        assert msg[header]
