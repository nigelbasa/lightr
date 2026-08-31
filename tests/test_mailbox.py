"""Mailbox reads through Dovecot, against a fake IMAP client."""

from __future__ import annotations

from email.message import EmailMessage

import pytest

from lightr.dovecot.mailbox import (
    FLAG_FLAGGED,
    FLAG_SEEN,
    Folder,
    Mailbox,
    MailboxError,
    MessageNotFoundError,
    MessageSummary,
    build_search_criteria,
    decode_mime_header,
    extract_attachment,
    parse_message,
)


def _raw(subject: str = "Hello", *, attachment: bool = False, html: bool = False) -> bytes:
    msg = EmailMessage()
    msg["From"] = "Sender <sender@example.test>"
    msg["To"] = "ops@acme.test"
    msg["Subject"] = subject
    msg["Date"] = "Tue, 01 Sep 2026 10:30:00 +0000"
    msg.set_content("Plain body.")
    if html:
        msg.add_alternative("<p>Rich body.</p>", subtype="html")
    if attachment:
        msg.add_attachment(
            b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="invoice.pdf"
        )
    return msg.as_bytes()


class FakeIMAP:
    """An in-memory stand-in for Dovecot."""

    def __init__(self) -> None:
        self.messages: dict[str, dict[int, tuple[bytes, set[str]]]] = {
            "INBOX": {
                1: (_raw("First"), {FLAG_SEEN}),
                2: (_raw("Second"), set()),
                3: (_raw("Third", attachment=True), set()),
            },
            "Trash": {},
        }
        self.moved: list[tuple[str, int, str]] = []
        self.expunged: list[tuple[str, int]] = []

    async def login(self, username: str, password: str) -> None: ...
    async def logout(self) -> None: ...

    async def list_folders(self) -> list[Folder]:
        return [
            Folder("Sent", 0, 0, 1),
            Folder("INBOX", len(self.messages["INBOX"]), 2, 1),
            Folder("Archive", 0, 0, 1),
        ]

    async def select(self, folder: str) -> Folder:
        return Folder(folder, len(self.messages.get(folder, {})), 0, 1)

    async def search(self, folder: str, criteria: str) -> list[int]:
        uids = sorted(self.messages.get(folder, {}))
        if "UNSEEN" in criteria:
            uids = [u for u in uids if FLAG_SEEN not in self.messages[folder][u][1]]
        return uids

    async def fetch_summaries(self, folder: str, uids: list[int]) -> list[MessageSummary]:
        out = []
        for uid in uids:
            raw, flags = self.messages[folder][uid]
            detail = parse_message(raw, uid, folder, frozenset(flags))
            out.append(
                MessageSummary(
                    uid=uid,
                    folder=folder,
                    subject=detail.subject,
                    from_=detail.from_,
                    to=detail.to,
                    date=detail.date,
                    size=len(raw),
                    flags=frozenset(flags),
                )
            )
        return out

    async def fetch_raw(self, folder: str, uid: int) -> bytes:
        entry = self.messages.get(folder, {}).get(uid)
        return entry[0] if entry else b""

    async def store_flags(
        self, folder: str, uid: int, flags: list[str], *, add: bool
    ) -> None:
        current = self.messages[folder][uid][1]
        if add:
            current.update(flags)
        else:
            current.difference_update(flags)

    async def move(self, folder: str, uid: int, destination: str) -> None:
        self.moved.append((folder, uid, destination))
        entry = self.messages[folder].pop(uid)
        self.messages.setdefault(destination, {})[uid] = entry

    async def expunge(self, folder: str, uid: int) -> None:
        self.expunged.append((folder, uid))
        self.messages[folder].pop(uid, None)


@pytest.fixture
def imap() -> FakeIMAP:
    return FakeIMAP()


@pytest.fixture
def mailbox(imap: FakeIMAP) -> Mailbox:
    return Mailbox(imap)


class TestFolders:
    async def test_inbox_sorts_first(self, mailbox: Mailbox) -> None:
        names = [f.name for f in await mailbox.folders()]
        assert names[0] == "INBOX"

    async def test_remaining_folders_are_alphabetical(self, mailbox: Mailbox) -> None:
        names = [f.name for f in await mailbox.folders()]
        assert names[1:] == ["Archive", "Sent"]


class TestListing:
    async def test_newest_first(self, mailbox: Mailbox) -> None:
        uids = [m.uid for m in await mailbox.list()]
        assert uids == [3, 2, 1]

    async def test_limit_and_offset(self, mailbox: Mailbox) -> None:
        page = await mailbox.list(limit=1, offset=1)
        assert [m.uid for m in page] == [2]

    async def test_unread_filter(self, mailbox: Mailbox) -> None:
        unread = await mailbox.list(criteria=build_search_criteria(unread=True))
        assert [m.uid for m in unread] == [3, 2]

    async def test_flags_surface_as_booleans(self, mailbox: Mailbox) -> None:
        by_uid = {m.uid: m for m in await mailbox.list()}
        assert by_uid[1].seen is True
        assert by_uid[2].seen is False

    async def test_empty_folder_returns_empty(self, mailbox: Mailbox) -> None:
        assert await mailbox.list("Trash") == []


class TestFetching:
    async def test_subject_and_body(self, mailbox: Mailbox) -> None:
        detail = await mailbox.get("INBOX", 1)
        assert detail.subject == "First"
        assert "Plain body." in detail.text

    async def test_missing_uid_raises(self, mailbox: Mailbox) -> None:
        with pytest.raises(MessageNotFoundError, match="uid 99"):
            await mailbox.get("INBOX", 99)

    async def test_attachments_are_listed(self, mailbox: Mailbox) -> None:
        detail = await mailbox.get("INBOX", 3)
        assert detail.has_attachments
        assert detail.attachments[0].filename == "invoice.pdf"
        assert detail.attachments[0].content_type == "application/pdf"

    async def test_attachment_bytes_can_be_extracted(self, mailbox: Mailbox) -> None:
        detail = await mailbox.get("INBOX", 3)
        index = detail.attachments[0].index

        filename, content_type, payload = await mailbox.attachment("INBOX", 3, index)

        assert filename == "invoice.pdf"
        assert content_type == "application/pdf"
        assert payload.startswith(b"%PDF")

    async def test_bad_attachment_index_is_reported(self, mailbox: Mailbox) -> None:
        with pytest.raises(MailboxError, match="no attachment at index"):
            await mailbox.attachment("INBOX", 3, 99)


class TestMimeHandling:
    def test_rfc2047_subject_is_decoded(self) -> None:
        encoded = "=?utf-8?B?SGVsbG8gV29ybGQ=?="
        assert decode_mime_header(encoded) == "Hello World"

    def test_undecodable_header_falls_back_to_raw(self) -> None:
        assert decode_mime_header("=?bogus-charset?q?x?=") == "=?bogus-charset?q?x?="

    def test_empty_header_is_empty_string(self) -> None:
        assert decode_mime_header(None) == ""

    def test_html_and_text_alternatives_are_separated(self) -> None:
        detail = parse_message(_raw(html=True), 1, "INBOX", frozenset())
        assert "Plain body." in detail.text
        assert "Rich body." in detail.html

    def test_attachment_is_not_treated_as_body(self) -> None:
        detail = parse_message(_raw(attachment=True), 1, "INBOX", frozenset())
        assert "%PDF" not in detail.text

    def test_date_is_parsed(self) -> None:
        detail = parse_message(_raw(), 1, "INBOX", frozenset())
        assert detail.date is not None
        assert detail.date.year == 2026

    def test_malformed_date_yields_none(self) -> None:
        raw = b"From: a@b.test\r\nDate: not-a-date\r\nSubject: x\r\n\r\nbody"
        assert parse_message(raw, 1, "INBOX", frozenset()).date is None

    def test_extract_attachment_out_of_range(self) -> None:
        with pytest.raises(MailboxError):
            extract_attachment(_raw(), 42)


class TestFlagsAndMoves:
    async def test_mark_seen(self, mailbox: Mailbox, imap: FakeIMAP) -> None:
        await mailbox.mark("INBOX", 2, seen=True)
        assert FLAG_SEEN in imap.messages["INBOX"][2][1]

    async def test_mark_unseen(self, mailbox: Mailbox, imap: FakeIMAP) -> None:
        await mailbox.mark("INBOX", 1, seen=False)
        assert FLAG_SEEN not in imap.messages["INBOX"][1][1]

    async def test_flagging(self, mailbox: Mailbox, imap: FakeIMAP) -> None:
        await mailbox.mark("INBOX", 1, flagged=True)
        assert FLAG_FLAGGED in imap.messages["INBOX"][1][1]

    async def test_delete_moves_to_trash_by_default(
        self, mailbox: Mailbox, imap: FakeIMAP
    ) -> None:
        """Deleting must be recoverable unless explicitly told otherwise."""
        await mailbox.delete("INBOX", 1)

        assert imap.moved == [("INBOX", 1, "Trash")]
        assert imap.expunged == []
        assert 1 in imap.messages["Trash"]

    async def test_expunge_is_opt_in(self, mailbox: Mailbox, imap: FakeIMAP) -> None:
        await mailbox.delete("INBOX", 1, expunge=True)

        assert imap.expunged == [("INBOX", 1)]
        assert 1 not in imap.messages["INBOX"]


class TestSearchCriteria:
    def test_no_filters_is_all(self) -> None:
        assert build_search_criteria() == "ALL"

    def test_unread(self) -> None:
        assert build_search_criteria(unread=True) == "UNSEEN"

    def test_combined_terms(self) -> None:
        criteria = build_search_criteria(sender="billing@", unread=True)
        assert criteria == 'UNSEEN FROM "billing@"'

    def test_iso_date_becomes_imap_date(self) -> None:
        assert build_search_criteria(since="2026-08-01") == "SINCE 01-Aug-2026"

    def test_bad_date_gives_a_useful_message(self) -> None:
        with pytest.raises(MailboxError, match="YYYY-MM-DD"):
            build_search_criteria(since="last tuesday")

    def test_quotes_in_terms_are_escaped(self) -> None:
        criteria = build_search_criteria(subject='say "hi"')
        assert criteria == 'SUBJECT "say \\"hi\\""'
