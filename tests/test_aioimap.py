"""Parsing IMAP responses from Dovecot.

The wire parsing is the part that can silently produce wrong data, so
it is tested against real Dovecot response shapes. Connection handling
is exercised only for its error messages -- a live Dovecot is not
available in the suite.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from lightr.dovecot.aioimap import (
    AioIMAPClient,
    _as_lines,
    _parse_date,
    _parse_headers,
    _parse_internaldate,
    _parse_summaries,
    _quote,
)
from lightr.dovecot.mailbox import IMAPProtocol, MailboxError


class TestProtocolConformance:
    def test_client_satisfies_the_mailbox_protocol(self) -> None:
        """The adapter and the real client must stay in step."""
        assert isinstance(AioIMAPClient("127.0.0.1"), IMAPProtocol)


class TestMailboxNameQuoting:
    def test_plain_name(self) -> None:
        assert _quote("INBOX") == '"INBOX"'

    def test_name_with_a_space(self) -> None:
        assert _quote("Sent Items") == '"Sent Items"'

    def test_quotes_are_escaped(self) -> None:
        assert _quote('Odd"Name') == '"Odd\\"Name"'

    def test_backslashes_are_escaped(self) -> None:
        assert _quote("a\\b") == '"a\\\\b"'


class TestLineNormalisation:
    def test_bytes_and_str_are_mixed_safely(self) -> None:
        assert _as_lines([b"one", "two"]) == ["one", "two"]

    def test_undecodable_bytes_do_not_raise(self) -> None:
        assert _as_lines([b"\xff\xfe"]) == ["��"]

    def test_none_is_empty(self) -> None:
        assert _as_lines(None) == []


class TestSummaryParsing:
    #: A realistic Dovecot FETCH response for two messages.
    LINES: ClassVar[list[str]] = [
        "1 FETCH (UID 4821 FLAGS (\\Seen) RFC822.SIZE 2048 "
        'INTERNALDATE "01-Sep-2026 10:30:00 +0000" BODY[HEADER.FIELDS '
        "(FROM TO SUBJECT DATE)] {84}",
        "From: Billing <billing@example.test>",
        "To: ops@acme.test",
        "Subject: Invoice 42",
        "Date: Tue, 01 Sep 2026 10:30:00 +0000",
        ")",
        "2 FETCH (UID 4822 FLAGS () RFC822.SIZE 1024 "
        'INTERNALDATE "01-Sep-2026 11:00:00 +0000" BODY[HEADER.FIELDS '
        "(FROM TO SUBJECT DATE)] {60}",
        "From: someone@example.test",
        "To: ops@acme.test",
        "Subject: Hello",
        ")",
    ]

    def test_both_messages_are_parsed(self) -> None:
        summaries = _parse_summaries(self.LINES, "INBOX")
        assert [s.uid for s in summaries] == [4821, 4822]

    def test_headers_are_extracted(self) -> None:
        first = _parse_summaries(self.LINES, "INBOX")[0]
        assert first.subject == "Invoice 42"
        assert "billing@example.test" in first.from_
        assert first.to == "ops@acme.test"

    def test_size_and_flags(self) -> None:
        summaries = _parse_summaries(self.LINES, "INBOX")
        assert summaries[0].size == 2048
        assert summaries[0].seen is True
        assert summaries[1].seen is False

    def test_folder_is_recorded(self) -> None:
        assert _parse_summaries(self.LINES, "Archive")[0].folder == "Archive"

    def test_date_comes_from_the_header(self) -> None:
        first = _parse_summaries(self.LINES, "INBOX")[0]
        assert first.date is not None
        assert first.date.year == 2026

    def test_internaldate_is_the_fallback(self) -> None:
        """The second message has no Date header."""
        second = _parse_summaries(self.LINES, "INBOX")[1]
        assert second.date is not None

    def test_empty_response_is_empty(self) -> None:
        assert _parse_summaries([], "INBOX") == []

    def test_unrecognised_lines_are_ignored(self) -> None:
        """Servers emit untagged responses a strict parser would trip
        on; a listing that omits noise beats one that raises."""
        noisy = ["* OK [UIDVALIDITY 1] Ok", *self.LINES, "* 2 EXISTS"]
        assert len(_parse_summaries(noisy, "INBOX")) == 2

    def test_encoded_subject_is_decoded(self) -> None:
        lines = [
            "1 FETCH (UID 1 FLAGS () RFC822.SIZE 10 BODY[HEADER.FIELDS (SUBJECT)] {10}",
            "Subject: =?utf-8?B?SGVsbG8gV29ybGQ=?=",
            ")",
        ]
        assert _parse_summaries(lines, "INBOX")[0].subject == "Hello World"

    def test_message_without_headers_still_yields_a_summary(self) -> None:
        lines = ["1 FETCH (UID 7 FLAGS (\\Seen) RFC822.SIZE 5)"]
        summaries = _parse_summaries(lines, "INBOX")
        assert len(summaries) == 1
        assert summaries[0].uid == 7
        assert summaries[0].subject == ""


class TestHeaderParsing:
    def test_keys_are_lowercased(self) -> None:
        headers = _parse_headers("From: a@b.test\nSubject: Hi")
        assert headers["from"] == "a@b.test"
        assert headers["subject"] == "Hi"

    def test_folded_headers_are_joined(self) -> None:
        headers = _parse_headers("Subject: a very\n long subject")
        assert "long subject" in headers["subject"]

    def test_empty_blob(self) -> None:
        assert _parse_headers("") == {}


class TestDateParsing:
    def test_rfc2822_date(self) -> None:
        parsed = _parse_date("Tue, 01 Sep 2026 10:30:00 +0000")
        assert parsed is not None
        assert parsed.day == 1

    @pytest.mark.parametrize("bad", [None, "", "not a date"])
    def test_bad_dates_yield_none(self, bad: str | None) -> None:
        assert _parse_date(bad) is None

    def test_internaldate_format(self) -> None:
        line = 'FETCH (INTERNALDATE "01-Sep-2026 10:30:00 +0000")'
        parsed = _parse_internaldate(line)
        assert parsed is not None
        assert parsed.month == 9

    def test_missing_internaldate(self) -> None:
        assert _parse_internaldate("FETCH (UID 1)") is None

    def test_malformed_internaldate(self) -> None:
        assert _parse_internaldate('FETCH (INTERNALDATE "nonsense")') is None


class TestConnectionErrors:
    async def test_unreachable_server_says_where(self) -> None:
        client = AioIMAPClient("127.0.0.1", port=1, timeout=2)
        with pytest.raises(MailboxError, match="cannot reach Dovecot IMAP"):
            await client.login("ops@acme.test*master", "secret")

    async def test_logout_without_a_connection_is_harmless(self) -> None:
        await AioIMAPClient("127.0.0.1").logout()
