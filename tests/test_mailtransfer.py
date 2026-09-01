"""Importing and exporting mail.

Migration is the moment an operator has the least patience for a tool
that loses things, so these tests are about fidelity: the bytes that
go in are the bytes that come out, flags survive, and folder structure
survives.
"""

from __future__ import annotations

import mailbox as stdlib_mailbox
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lightr import mailtransfer as transfer

# Maildir writes flags into the filename after a colon. NTFS reads a
# colon as an alternate-data-stream marker and refuses the name, so the
# flag assertions cannot run there. Lightr ships for Linux; this is the
# test host disagreeing with the target, not a gap in the feature.
maildir_flags = pytest.mark.skipif(
    os.name == "nt", reason="Maildir flag suffixes need a colon in the filename"
)

MESSAGE = b"""\
From: sender@example.test
To: ops@acme.test
Subject: Quarterly report
Date: Tue, 01 Sep 2026 09:00:00 +0000

Attached.
"""


class FakeMailbox:
    """Somewhere to append to, without a Dovecot."""

    def __init__(self) -> None:
        self.appended: list[tuple[str, bytes, tuple[str, ...], datetime | None]] = []
        self.fail_on: str | None = None

    async def append(
        self,
        folder: str,
        raw: bytes,
        *,
        flags: tuple[str, ...] = (),
        date: datetime | None = None,
    ) -> None:
        if self.fail_on is not None and folder == self.fail_on:
            raise RuntimeError("no such folder")
        self.appended.append((folder, raw, flags, date))


# --------------------------------------------------------------------
# mboxrd quoting
# --------------------------------------------------------------------


class TestFromQuoting:
    def test_a_from_line_in_a_body_is_quoted(self) -> None:
        """Unquoted, it would split one message into two on read."""
        assert transfer.escape_from_lines(b"body\nFrom here on\n") == (
            b"body\n>From here on\n"
        )

    def test_quoting_round_trips(self) -> None:
        original = b"a\nFrom x\n>From y\n>>From z\nend\n"
        assert transfer.unescape_from_lines(transfer.escape_from_lines(original)) == original

    def test_a_line_merely_starting_with_from_is_untouched(self) -> None:
        assert transfer.escape_from_lines(b"Fromage\n") == b"Fromage\n"


# --------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------


@pytest.fixture
def mbox_file(tmp_path: Path) -> Path:
    path = tmp_path / "archive.mbox"
    box = stdlib_mailbox.mbox(str(path))
    for subject in ("One", "Two"):
        box.add(MESSAGE.replace(b"Quarterly report", subject.encode()))
    box.close()
    return path


@pytest.fixture
def maildir(tmp_path: Path) -> Path:
    root = tmp_path / "Maildir"
    box = stdlib_mailbox.Maildir(str(root))
    inbox = stdlib_mailbox.MaildirMessage(MESSAGE)
    if os.name != "nt":
        inbox.set_flags("S")
    box.add(inbox)

    sent = box.add_folder("Sent")
    sent.add(stdlib_mailbox.MaildirMessage(MESSAGE.replace(b"Attached.", b"Sent one.")))
    box.close()
    return root


class TestReadingMbox:
    def test_every_message_is_found(self, mbox_file: Path) -> None:
        assert len(list(transfer.read_mbox(mbox_file))) == 2

    def test_the_body_survives(self, mbox_file: Path) -> None:
        first = next(iter(transfer.read_mbox(mbox_file)))
        assert b"Attached." in first.raw

    def test_the_date_header_is_kept(self, mbox_file: Path) -> None:
        first = next(iter(transfer.read_mbox(mbox_file)))
        assert first.date is not None
        assert first.date.year == 2026

    def test_a_missing_file_says_so(self, tmp_path: Path) -> None:
        with pytest.raises(transfer.TransferError):
            list(transfer.read_mbox(tmp_path / "nope.mbox"))

    def test_status_headers_become_flags(self, tmp_path: Path) -> None:
        path = tmp_path / "read.mbox"
        box = stdlib_mailbox.mbox(str(path))
        box.add(b"Status: RO\nX-Status: A\nSubject: hi\n\nbody\n")
        box.close()

        message = next(iter(transfer.read_mbox(path)))
        assert transfer.FLAG_SEEN in message.flags
        assert transfer.FLAG_ANSWERED in message.flags


class TestReadingMaildir:
    def test_folders_are_preserved(self, maildir: Path) -> None:
        folders = {m.folder for m in transfer.read_maildir(maildir)}
        assert folders == {"INBOX", "Sent"}

    @maildir_flags
    def test_flags_are_preserved(self, maildir: Path) -> None:
        inbox = [m for m in transfer.read_maildir(maildir) if m.folder == "INBOX"]
        assert transfer.FLAG_SEEN in inbox[0].flags

    def test_a_folder_override_collapses_everything(self, maildir: Path) -> None:
        folders = {m.folder for m in transfer.read_maildir(maildir, "Archive")}
        assert folders == {"Archive"}

    def test_a_plain_directory_is_not_a_maildir(self, tmp_path: Path) -> None:
        with pytest.raises(transfer.TransferError, match="not a Maildir"):
            list(transfer.read_maildir(tmp_path))


class TestReadingEml:
    def test_a_single_file(self, tmp_path: Path) -> None:
        path = tmp_path / "one.eml"
        path.write_bytes(MESSAGE)
        assert [m.raw for m in transfer.read_eml(path)] == [MESSAGE]

    def test_a_directory_of_files(self, tmp_path: Path) -> None:
        for name in ("a.eml", "b.eml", "notes.txt"):
            (tmp_path / name).write_bytes(MESSAGE)
        assert len(list(transfer.read_eml(tmp_path))) == 2

    def test_a_directory_with_nothing_in_it_says_so(self, tmp_path: Path) -> None:
        with pytest.raises(transfer.TransferError, match=r"no \.eml"):
            list(transfer.read_eml(tmp_path))


# --------------------------------------------------------------------
# Importing
# --------------------------------------------------------------------


class TestImport:
    async def test_messages_are_appended(self, mbox_file: Path) -> None:
        box = FakeMailbox()
        report = await transfer.import_messages(box, transfer.read_mbox(mbox_file))

        assert report.messages == 2
        assert len(box.appended) == 2
        assert report.folders == {"INBOX": 2}

    async def test_folders_go_with_them(self, maildir: Path) -> None:
        box = FakeMailbox()
        await transfer.import_messages(box, transfer.read_maildir(maildir))

        assert {folder for folder, _, _, _ in box.appended} == {"INBOX", "Sent"}

    @maildir_flags
    async def test_flags_go_with_them(self, maildir: Path) -> None:
        box = FakeMailbox()
        await transfer.import_messages(box, transfer.read_maildir(maildir))

        by_folder = {folder: flags for folder, _, flags, _ in box.appended}
        assert transfer.FLAG_SEEN in by_folder["INBOX"]

    async def test_a_dry_run_appends_nothing(self, mbox_file: Path) -> None:
        box = FakeMailbox()
        report = await transfer.import_messages(
            box, transfer.read_mbox(mbox_file), dry_run=True
        )

        assert report.messages == 2
        assert box.appended == []

    async def test_a_limit_stops_early(self, mbox_file: Path) -> None:
        box = FakeMailbox()
        report = await transfer.import_messages(
            box, transfer.read_mbox(mbox_file), limit=1
        )
        assert report.messages == 1

    async def test_one_failure_does_not_abandon_the_rest(self, maildir: Path) -> None:
        """Half an import that names what it could not move beats an
        exception partway through with no record of where it stopped."""
        box = FakeMailbox()
        box.fail_on = "Sent"

        report = await transfer.import_messages(box, transfer.read_maildir(maildir))

        assert report.messages == 1
        assert len(report.failures) == 1
        assert "Sent" in report.failures[0]


# --------------------------------------------------------------------
# Exporting
# --------------------------------------------------------------------


class TestExport:
    def test_each_message_gets_a_from_line(self) -> None:
        chunks = list(transfer.to_mbox([transfer.Message(raw=MESSAGE)]))
        assert chunks[0].startswith(b"From sender@example.test ")

    def test_an_exported_mbox_reads_back_identically(self, tmp_path: Path) -> None:
        """The round trip that matters: out of Lightr, into any other
        mail tool, and back."""
        body = MESSAGE + b"\nFrom the desk of someone\n"
        path = tmp_path / "out.mbox"
        path.write_bytes(b"".join(transfer.to_mbox([transfer.Message(raw=body)])))

        read_back = list(transfer.read_mbox(path))

        assert len(read_back) == 1
        assert read_back[0].raw.rstrip(b"\n") == body.rstrip(b"\n")

    def test_a_message_with_no_sender_still_exports(self) -> None:
        chunk = next(iter(transfer.to_mbox([transfer.Message(raw=b"Subject: x\n\nbody\n")])))
        assert chunk.startswith(b"From MAILER-DAEMON ")


class TestInternaldate:
    def test_a_naive_datetime_is_stamped_utc(self) -> None:
        """imaplib renders a naive datetime as local time, which would
        shift every imported message by the server's offset."""
        stamped = transfer.internaldate(datetime(2026, 1, 1, 12, 0, 0))
        assert stamped is not None
        assert stamped.tzinfo is UTC

    def test_an_aware_datetime_is_left_alone(self) -> None:
        original = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert transfer.internaldate(original) is original

    def test_none_means_the_server_picks(self) -> None:
        assert transfer.internaldate(None) is None
