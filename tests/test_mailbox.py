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
        self.user_folders: list[str] = []
        self.appended: list[tuple[str, bytes, tuple[str, ...]]] = []
        #: What THREAD would return per folder. Unset means every
        #: message is its own conversation, which is what a server
        #: without THREAD reports.
        self.thread_groups: dict[str, list[list[int]]] = {}

    async def login(self, username: str, password: str) -> None: ...
    async def logout(self) -> None: ...

    async def list_folders(self) -> list[Folder]:
        return [
            Folder("Sent", 0, 0, 1),
            Folder("INBOX", len(self.messages["INBOX"]), 2, 1),
            Folder("Archive", 0, 0, 1),
            *(Folder(name, 0, 0, 1) for name in self.user_folders),
        ]

    async def create_folder(self, name: str) -> None:
        if name in self.user_folders:
            raise MailboxError(f"could not create folder {name!r}: already exists")
        self.user_folders.append(name)
        self.messages.setdefault(name, {})

    async def rename_folder(self, name: str, new_name: str) -> None:
        if name not in self.user_folders:
            raise MailboxError(f"could not rename {name!r}: no such folder")
        self.user_folders[self.user_folders.index(name)] = new_name
        self.messages[new_name] = self.messages.pop(name, {})

    async def delete_folder(self, name: str) -> None:
        if name not in self.user_folders:
            raise MailboxError(f"could not delete folder {name!r}: no such folder")
        self.user_folders.remove(name)
        self.messages.pop(name, None)

    async def append(self, folder, raw, *, flags=(), date=None) -> None:
        self.appended.append((folder, raw, tuple(flags)))
        box = self.messages.setdefault(folder, {})
        box[max(box, default=0) + 1] = (raw, set(flags))

    async def select(self, folder: str) -> Folder:
        return Folder(folder, len(self.messages.get(folder, {})), 0, 1)

    async def search(self, folder: str, criteria: str) -> list[int]:
        uids = sorted(self.messages.get(folder, {}))
        if "UNSEEN" in criteria:
            uids = [u for u in uids if FLAG_SEEN not in self.messages[folder][u][1]]
        return uids

    async def thread(self, folder: str, criteria: str = "ALL") -> list[list[int]]:
        """Group as Dovecot does: the criteria filters, the grouping stays."""
        matched = set(await self.search(folder, criteria))
        groups = self.thread_groups.get(folder)
        if groups is None:
            return [[uid] for uid in sorted(matched)]
        return [
            [uid for uid in group if uid in matched]
            for group in groups
            if any(uid in matched for uid in group)
        ]

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

    async def store_flags(self, folder, uid, flags, *, add) -> None:
        for one in _uids(uid):
            current = self.messages[folder][one][1]
            if add:
                current.update(flags)
            else:
                current.difference_update(flags)

    async def move(self, folder, uid, destination) -> None:
        for one in _uids(uid):
            self.moved.append((folder, one, destination))
            entry = self.messages[folder].pop(one)
            self.messages.setdefault(destination, {})[one] = entry

    async def expunge(self, folder, uid) -> None:
        for one in _uids(uid):
            self.expunged.append((folder, one))
            self.messages[folder].pop(one, None)


def _uids(uid: int | list[int]) -> list[int]:
    return [uid] if isinstance(uid, int) else list(uid)


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


class TestThreading:
    """Conversations, as Dovecot's THREAD groups them.

    The property that matters is that the page is a page of *threads*:
    windowing by message would cut a conversation across two pages, and
    a client showing the second half of a conversation with no first
    half looks broken.
    """

    async def test_without_server_grouping_each_message_stands_alone(
        self, mailbox: Mailbox
    ) -> None:
        """A server with no THREAD renders as the plain list it was."""
        threads = await mailbox.threads()
        assert [t.uids for t in threads] == [[3], [2], [1]]

    async def test_grouped_messages_arrive_as_one_thread(
        self, imap: FakeIMAP, mailbox: Mailbox
    ) -> None:
        imap.thread_groups["INBOX"] = [[1, 2], [3]]

        threads = await mailbox.threads()
        assert [t.uids for t in threads] == [[3], [1, 2]]

    async def test_most_recently_active_first(
        self, imap: FakeIMAP, mailbox: Mailbox
    ) -> None:
        """A conversation's position is its newest message, not its
        oldest -- a reply brings the whole thread back to the top."""
        imap.thread_groups["INBOX"] = [[1, 3], [2]]

        assert [t.uids for t in await mailbox.threads()] == [[1, 3], [2]]

    async def test_the_window_counts_threads_not_messages(
        self, imap: FakeIMAP, mailbox: Mailbox
    ) -> None:
        imap.thread_groups["INBOX"] = [[1, 2], [3]]

        page = await mailbox.threads(limit=1)
        assert [t.uids for t in page] == [[3]]

    async def test_offset_never_splits_a_conversation(
        self, imap: FakeIMAP, mailbox: Mailbox
    ) -> None:
        imap.thread_groups["INBOX"] = [[1, 2], [3]]

        page = await mailbox.threads(limit=1, offset=1)
        assert [t.uids for t in page] == [[1, 2]]

    async def test_a_filter_narrows_within_a_thread(
        self, imap: FakeIMAP, mailbox: Mailbox
    ) -> None:
        """Message 1 is read; the conversation still appears, with only
        the unread message in it."""
        imap.thread_groups["INBOX"] = [[1, 2], [3]]

        threads = await mailbox.threads(criteria=build_search_criteria(unread=True))
        assert [t.uids for t in threads] == [[3], [2]]

    async def test_an_empty_folder_has_no_threads(self, mailbox: Mailbox) -> None:
        assert await mailbox.threads("Trash") == []

    async def test_an_offset_past_the_end_is_empty(self, mailbox: Mailbox) -> None:
        assert await mailbox.threads(offset=99) == []

    async def test_a_message_that_vanished_is_dropped_not_left_as_a_gap(
        self,
    ) -> None:
        """THREAD and FETCH are two round trips; a message can be
        expunged between them."""

        class Gappy(FakeIMAP):
            async def thread(self, folder, criteria="ALL"):  # type: ignore[override]
                return [[1, 99]]

            async def fetch_summaries(self, folder, uids):  # type: ignore[override]
                present = [u for u in uids if u in self.messages[folder]]
                return await super().fetch_summaries(folder, present)

        threads = await Mailbox(Gappy()).threads()
        assert [t.uids for t in threads] == [[1]]


class TestThreadSummary:
    """What a client shows on one row of a threaded inbox."""

    @pytest.fixture
    def thread(self, imap: FakeIMAP, mailbox: Mailbox):
        imap.thread_groups["INBOX"] = [[1, 2]]

        async def _first():
            return (await mailbox.threads())[0]

        return _first

    async def test_the_subject_comes_from_the_opening_message(self, thread) -> None:
        """Replies carry "Re:", and some clients rewrite the subject
        partway through."""
        assert (await thread()).subject == "First"

    async def test_the_root_identifies_the_conversation(self, thread) -> None:
        assert (await thread()).root == 1

    async def test_the_latest_message_is_last(self, thread) -> None:
        assert (await thread()).latest.uid == 2

    async def test_unseen_counts_only_the_unread(self, thread) -> None:
        """Message 1 is read, message 2 is not."""
        assert (await thread()).unseen == 1

    async def test_the_date_is_the_newest_in_the_thread(self, thread) -> None:
        found = await thread()
        assert found.date == max(m.date for m in found.messages if m.date)

    async def test_participants_are_unique_and_in_order(self, thread) -> None:
        """Both messages are from the same sender; it is listed once."""
        assert (await thread()).participants == ["Sender <sender@example.test>"]

    async def test_size_is_the_whole_conversation(self, thread) -> None:
        found = await thread()
        assert found.size == sum(m.size for m in found.messages)

    async def test_length_is_the_message_count(self, thread) -> None:
        assert len(await thread()) == 2


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

    async def test_deleting_from_trash_is_permanent(
        self, mailbox: Mailbox, imap: FakeIMAP
    ) -> None:
        """Moving Trash to Trash would leave the message undeletable."""
        await mailbox.delete("INBOX", 1)
        await mailbox.delete("Trash", 1)

        assert imap.expunged == [("Trash", 1)]
        assert imap.messages["Trash"] == {}

    async def test_answered_and_draft_flags(
        self, mailbox: Mailbox, imap: FakeIMAP
    ) -> None:
        await mailbox.mark("INBOX", 2, answered=True, draft=True)
        assert {"\\Answered", "\\Draft"} <= imap.messages["INBOX"][2][1]

        await mailbox.mark("INBOX", 2, answered=False)
        assert "\\Answered" not in imap.messages["INBOX"][2][1]
        assert "\\Draft" in imap.messages["INBOX"][2][1]


class TestBulk:
    async def test_several_messages_at_once(
        self, mailbox: Mailbox, imap: FakeIMAP
    ) -> None:
        await mailbox.mark("INBOX", [2, 3], seen=True, flagged=True)
        for uid in (2, 3):
            assert {FLAG_SEEN, FLAG_FLAGGED} <= imap.messages["INBOX"][uid][1]

    async def test_bulk_move(self, mailbox: Mailbox, imap: FakeIMAP) -> None:
        await mailbox.move("INBOX", [1, 2], "Archive")
        assert set(imap.messages["Archive"]) == {1, 2}

    async def test_emptying_a_folder(self, mailbox: Mailbox, imap: FakeIMAP) -> None:
        await mailbox.delete("INBOX", [1, 2])

        assert await mailbox.empty("Trash") == 2
        assert imap.messages["Trash"] == {}

    async def test_emptying_an_empty_folder(self, mailbox: Mailbox) -> None:
        assert await mailbox.empty("Trash") == 0


class TestFolderManagement:
    async def test_create_rename_delete(
        self, mailbox: Mailbox, imap: FakeIMAP
    ) -> None:
        await mailbox.create_folder("Receipts")
        await mailbox.rename_folder("Receipts", "Receipts/2026")
        assert "Receipts/2026" in [f.name for f in await mailbox.folders()]

        await mailbox.delete_folder("Receipts/2026")
        assert "Receipts/2026" not in [f.name for f in await mailbox.folders()]

    @pytest.mark.parametrize("name", ["INBOX", "inbox", "Sent", "Trash", "Junk"])
    async def test_system_folders_cannot_be_deleted(
        self, mailbox: Mailbox, name: str
    ) -> None:
        """Junk is where the spam rules file mail; deleting it would
        make every spam delivery fail."""
        with pytest.raises(MailboxError, match="system folder"):
            await mailbox.delete_folder(name)

    async def test_system_folders_cannot_be_renamed(self, mailbox: Mailbox) -> None:
        with pytest.raises(MailboxError, match="system folder"):
            await mailbox.rename_folder("Sent", "Outbox")

    @pytest.mark.parametrize(
        "name", ["", " padded", "star*", "per%cent", "/lead", "trail/", "a//b", "bad\x07"]
    )
    async def test_names_imap_would_misread_are_refused(
        self, mailbox: Mailbox, name: str
    ) -> None:
        with pytest.raises(MailboxError):
            await mailbox.create_folder(name)


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
