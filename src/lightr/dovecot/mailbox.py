"""Reading mailboxes through Dovecot.

Under the Go engine the mailbox API read rows out of a ``messages``
table. Dovecot owns the store now, so reads go over IMAP instead. That
costs a round trip but buys correctness for free: flags, UIDs, folder
state and search all come from Dovecot rather than from a second copy
that can drift.

One adapter, two callers -- the REST ``/v1/mailbox/*`` routes and the
``lightr mailbox`` command group -- so they cannot disagree.

The IMAP wire work is delegated to a client object satisfying
``IMAPProtocol``; the real one wraps aioimaplib, and tests supply a
fake. Keeping the protocol narrow is what makes that possible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Protocol, runtime_checkable

# Flags Dovecot reports that we surface as booleans.
FLAG_SEEN = "\\Seen"
FLAG_FLAGGED = "\\Flagged"
FLAG_ANSWERED = "\\Answered"
FLAG_DRAFT = "\\Draft"
FLAG_DELETED = "\\Deleted"


class MailboxError(RuntimeError):
    """A mailbox operation failed."""


class MessageNotFoundError(MailboxError):
    def __init__(self, uid: int, folder: str) -> None:
        super().__init__(f"no message with uid {uid} in {folder!r}")
        self.uid = uid
        self.folder = folder


@dataclass(frozen=True, slots=True)
class Folder:
    name: str
    messages: int
    unseen: int
    uidvalidity: int

    @property
    def is_inbox(self) -> bool:
        return self.name.upper() == "INBOX"


@dataclass(frozen=True, slots=True)
class Attachment:
    """One attachment part of a message."""

    index: int
    filename: str
    content_type: str
    size: int


@dataclass(slots=True)
class MessageSummary:
    """What a message list shows, without fetching the body."""

    uid: int
    folder: str
    subject: str
    from_: str
    to: str
    date: datetime | None
    size: int
    flags: frozenset[str] = field(default_factory=frozenset)

    @property
    def seen(self) -> bool:
        return FLAG_SEEN in self.flags

    @property
    def flagged(self) -> bool:
        return FLAG_FLAGGED in self.flags

    @property
    def answered(self) -> bool:
        return FLAG_ANSWERED in self.flags


@dataclass(slots=True)
class MessageDetail(MessageSummary):
    """A fetched message, with body and attachment metadata."""

    text: str = ""
    html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    raw: bytes = b""

    @property
    def has_attachments(self) -> bool:
        return bool(self.attachments)


@dataclass(slots=True)
class Thread:
    """One conversation, its messages oldest first.

    Deliberately flat. Dovecot's THREAD response is a tree describing
    who replied to whom, but no client Lightr serves renders that tree
    -- they show a conversation and the messages in it, in order.
    """

    uids: list[int]
    messages: list[MessageSummary]

    def __len__(self) -> int:
        return len(self.messages)

    @property
    def root(self) -> int:
        """The UID a client uses to identify the conversation."""
        return self.uids[0]

    @property
    def latest(self) -> MessageSummary:
        return self.messages[-1]

    @property
    def subject(self) -> str:
        """The conversation's subject: the first message that has one.

        Replies carry "Re:" and some clients rewrite the subject
        mid-thread, so the opening message is the one that named it.
        """
        return next((m.subject for m in self.messages if m.subject), "")

    @property
    def participants(self) -> list[str]:
        """Everyone who wrote, in the order they first did."""
        return list(dict.fromkeys(m.from_ for m in self.messages if m.from_))

    @property
    def date(self) -> datetime | None:
        dates = [m.date for m in self.messages if m.date is not None]
        return max(dates) if dates else None

    @property
    def unseen(self) -> int:
        return sum(1 for m in self.messages if not m.seen)

    @property
    def flagged(self) -> bool:
        return any(m.flagged for m in self.messages)

    @property
    def size(self) -> int:
        return sum(m.size for m in self.messages)


#: `list` inside the Mailbox class body resolves to `Mailbox.list`, the
#: method, so a `list[...]` return annotation written there is not a
#: type at all. Naming the shape out here keeps it one.
ThreadList = list[Thread]


@runtime_checkable
class IMAPProtocol(Protocol):
    """The narrow slice of IMAP the mailbox adapter needs."""

    async def login(self, username: str, password: str) -> None: ...
    async def logout(self) -> None: ...
    async def list_folders(self) -> list[Folder]: ...
    async def select(self, folder: str) -> Folder: ...
    async def search(self, folder: str, criteria: str) -> list[int]: ...
    async def thread(self, folder: str, criteria: str = "ALL") -> list[list[int]]: ...
    async def fetch_summaries(self, folder: str, uids: list[int]) -> list[MessageSummary]: ...
    async def fetch_raw(self, folder: str, uid: int) -> bytes: ...
    async def append(
        self,
        folder: str,
        raw: bytes,
        *,
        flags: tuple[str, ...] = (),
        date: datetime | None = None,
    ) -> None: ...
    async def store_flags(
        self, folder: str, uid: int | list[int], flags: list[str], *, add: bool
    ) -> None: ...
    async def move(self, folder: str, uid: int | list[int], destination: str) -> None: ...
    async def expunge(self, folder: str, uid: int | list[int]) -> None: ...
    async def create_folder(self, name: str) -> None: ...
    async def rename_folder(self, name: str, new_name: str) -> None: ...
    async def delete_folder(self, name: str) -> None: ...


def decode_mime_header(value: str | None) -> str:
    """Decode an RFC 2047 encoded header into readable text."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except (UnicodeDecodeError, LookupError, ValueError):
        return value


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


def parse_message(raw: bytes, uid: int, folder: str, flags: frozenset[str]) -> MessageDetail:
    """Turn a fetched RFC 822 message into a MessageDetail.

    Uses the stdlib email package, which is genuinely good at this --
    it is the one place the Python port is simpler than the Go one,
    where MIME walking was hand-written.
    """
    parsed: Message = message_from_bytes(raw)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for index, part in enumerate(parsed.walk()):
        if part.get_content_maintype() == "multipart":
            continue

        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        if disposition == "attachment" or (filename and disposition != "inline"):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    index=index,
                    filename=decode_mime_header(filename) or f"part-{index}",
                    content_type=part.get_content_type(),
                    size=len(payload),
                )
            )
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            decoded = payload.decode(charset, errors="replace")
        except LookupError:
            decoded = payload.decode("utf-8", errors="replace")

        if part.get_content_type() == "text/html":
            html_parts.append(decoded)
        elif part.get_content_type() == "text/plain":
            text_parts.append(decoded)

    return MessageDetail(
        uid=uid,
        folder=folder,
        subject=decode_mime_header(parsed.get("Subject")),
        from_=decode_mime_header(parsed.get("From")),
        to=decode_mime_header(parsed.get("To")),
        date=_parse_date(parsed.get("Date")),
        size=len(raw),
        flags=flags,
        text="\n".join(text_parts),
        html="\n".join(html_parts),
        attachments=attachments,
        raw=raw,
    )


def extract_attachment(raw: bytes, index: int) -> tuple[str, str, bytes]:
    """Pull one attachment's filename, type, and bytes out of a message."""
    parsed = message_from_bytes(raw)
    for position, part in enumerate(parsed.walk()):
        if position != index:
            continue
        payload = part.get_payload(decode=True) or b""
        filename = decode_mime_header(part.get_filename()) or f"part-{index}"
        return filename, part.get_content_type(), payload
    raise MailboxError(f"no attachment at index {index}")


def build_search_criteria(
    *,
    unread: bool = False,
    flagged: bool = False,
    sender: str | None = None,
    recipient: str | None = None,
    subject: str | None = None,
    since: str | None = None,
    before: str | None = None,
    text: str | None = None,
) -> str:
    """Build an IMAP SEARCH string from the CLI/API filter options.

    The Go engine's SEARCH ignored its criteria entirely and returned
    every message. Dovecot implements it properly, so these filters do
    what they say.
    """
    terms: list[str] = []
    if unread:
        terms.append("UNSEEN")
    if flagged:
        terms.append("FLAGGED")
    if sender:
        terms.append(f'FROM "{_escape(sender)}"')
    if recipient:
        terms.append(f'TO "{_escape(recipient)}"')
    if subject:
        terms.append(f'SUBJECT "{_escape(subject)}"')
    if since:
        terms.append(f"SINCE {_imap_date(since)}")
    if before:
        terms.append(f"BEFORE {_imap_date(before)}")
    if text:
        terms.append(f'TEXT "{_escape(text)}"')
    return " ".join(terms) if terms else "ALL"


_IMAP_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)


def _imap_date(value: str) -> str:
    """Convert an ISO date to IMAP's DD-Mon-YYYY form."""
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise MailboxError(
            f"{value!r} is not a date -- use YYYY-MM-DD, e.g. 2026-08-01"
        ) from exc
    return f"{parsed.day:02d}-{_IMAP_MONTHS[parsed.month - 1]}-{parsed.year}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


class Mailbox:
    """Mailbox operations for one authenticated account."""

    def __init__(self, client: IMAPProtocol) -> None:
        self._client = client

    async def folders(self) -> list[Folder]:
        folders = await self._client.list_folders()
        # INBOX first, then alphabetical -- how every mail client shows it.
        return sorted(folders, key=lambda f: (not f.is_inbox, f.name.lower()))

    async def list(
        self,
        folder: str = "INBOX",
        *,
        limit: int = 50,
        offset: int = 0,
        criteria: str = "ALL",
    ) -> list[MessageSummary]:
        uids = await self._client.search(folder, criteria)
        # Newest first: IMAP returns ascending UIDs, and UIDs are
        # monotonic under Dovecot, so reversing is chronological.
        window = list(reversed(uids))[offset : offset + limit]
        if not window:
            return []
        summaries = await self._client.fetch_summaries(folder, window)
        order = {uid: position for position, uid in enumerate(window)}
        return sorted(summaries, key=lambda m: order.get(m.uid, 0))

    async def threads(
        self,
        folder: str = "INBOX",
        *,
        limit: int = 50,
        offset: int = 0,
        criteria: str = "ALL",
    ) -> ThreadList:
        """Conversations in a folder, most recently active first.

        The window is applied to threads, not to messages: paging by UID
        would cut a conversation in half across two pages. THREAD
        returns the whole structure in one cheap round trip, so only the
        messages actually on this page are fetched.

        Ordered by highest UID, which is the same "UIDs are monotonic
        under Dovecot" assumption `list` makes, so the two orderings
        agree about what "newest" means.
        """
        groups = await self._client.thread(folder, criteria)
        ordered = sorted(
            (sorted(group) for group in groups if group),
            key=lambda uids: uids[-1],
            reverse=True,
        )
        window = ordered[offset : offset + limit]
        if not window:
            return []

        summaries = await self._client.fetch_summaries(
            folder, [uid for group in window for uid in group]
        )
        by_uid = {summary.uid: summary for summary in summaries}

        threads: list[Thread] = []
        for group in window:
            # A message that vanished between THREAD and FETCH is
            # dropped rather than left as a gap in the conversation.
            messages = [by_uid[uid] for uid in group if uid in by_uid]
            if messages:
                threads.append(
                    Thread(uids=[m.uid for m in messages], messages=messages)
                )
        return threads

    async def get(self, folder: str, uid: int) -> MessageDetail:
        raw = await self._client.fetch_raw(folder, uid)
        if not raw:
            raise MessageNotFoundError(uid, folder)
        summaries = await self._client.fetch_summaries(folder, [uid])
        flags = summaries[0].flags if summaries else frozenset()
        return parse_message(raw, uid, folder, flags)

    async def raw(self, folder: str, uid: int) -> bytes:
        """One message exactly as it was delivered.

        Export works from this rather than from a parsed message: a
        re-serialised MIME tree is not byte-identical to what arrived,
        and an exported mailbox should be the original mail.
        """
        raw = await self._client.fetch_raw(folder, uid)
        if not raw:
            raise MessageNotFoundError(uid, folder)
        return raw

    async def append(
        self,
        folder: str,
        raw: bytes,
        *,
        flags: tuple[str, ...] = (),
        date: datetime | None = None,
    ) -> None:
        """Add a message to a folder, keeping its flags and date.

        This is how mail is imported. Writing files into the Maildir
        directly would leave Dovecot's indexes describing a mailbox
        that no longer matches what is on disk.
        """
        await self._client.append(folder, raw, flags=flags, date=date)

    async def attachment(self, folder: str, uid: int, index: int) -> tuple[str, str, bytes]:
        raw = await self._client.fetch_raw(folder, uid)
        if not raw:
            raise MessageNotFoundError(uid, folder)
        return extract_attachment(raw, index)

    async def mark(
        self,
        folder: str,
        uid: int | list[int],
        *,
        seen: bool | None = None,
        flagged: bool | None = None,
        answered: bool | None = None,
        draft: bool | None = None,
    ) -> None:
        """Set or clear flags on one message or several.

        Grouped by direction so a bulk "read and flagged" is two round
        trips, not one per flag per message.
        """
        wanted = {
            FLAG_SEEN: seen,
            FLAG_FLAGGED: flagged,
            FLAG_ANSWERED: answered,
            FLAG_DRAFT: draft,
        }
        adding = [flag for flag, on in wanted.items() if on is True]
        removing = [flag for flag, on in wanted.items() if on is False]
        if adding:
            await self._client.store_flags(folder, uid, adding, add=True)
        if removing:
            await self._client.store_flags(folder, uid, removing, add=False)

    async def move(self, folder: str, uid: int | list[int], destination: str) -> None:
        await self._client.move(folder, uid, destination)

    async def delete(
        self, folder: str, uid: int | list[int], *, expunge: bool = False
    ) -> None:
        """Move to Trash, or expunge outright.

        Defaults to Trash: an operator running `lightr mailbox delete`
        almost never means 'destroy irrecoverably'. Deleting what is
        already in Trash removes it for good -- moving it to where it
        already is would make it undeletable.
        """
        if expunge or folder == TRASH:
            await self._client.store_flags(folder, uid, [FLAG_DELETED], add=True)
            await self._client.expunge(folder, uid)
        else:
            await self._client.move(folder, uid, TRASH)

    async def empty(self, folder: str) -> int:
        """Permanently remove everything in a folder. Returns how many."""
        uids = await self._client.search(folder, "ALL")
        if uids:
            await self._client.store_flags(folder, uids, [FLAG_DELETED], add=True)
            await self._client.expunge(folder, uids)
        return len(uids)

    async def create_folder(self, name: str) -> None:
        _check_folder_name(name)
        await self._client.create_folder(name)

    async def rename_folder(self, name: str, new_name: str) -> None:
        _refuse_special(name, "renamed")
        _check_folder_name(new_name)
        await self._client.rename_folder(name, new_name)

    async def delete_folder(self, name: str) -> None:
        _refuse_special(name, "deleted")
        await self._client.delete_folder(name)


#: Folders every mailbox has. Mail clients find them by special-use
#: flag, and Lightr files into them by name -- Junk from the spam
#: rules, Sent from submission -- so they are not the user's to remove.
SPECIAL_FOLDERS = ("INBOX", "Sent", "Drafts", "Trash", "Junk", "Archive")
TRASH = "Trash"


def _refuse_special(name: str, verb: str) -> None:
    if name.upper() == "INBOX" or name in SPECIAL_FOLDERS:
        raise MailboxError(f"{name} is a system folder and cannot be {verb}")


def _check_folder_name(name: str) -> None:
    """Refuse names IMAP would read as something else.

    `/` is the hierarchy separator, so it is allowed (it makes a
    subfolder); `*` and `%` are LIST wildcards and control characters
    have no business in a folder name.
    """
    if not name or not name.strip() or name != name.strip():
        raise MailboxError("a folder name cannot be empty or padded with spaces")
    if len(name) > 200:
        raise MailboxError("a folder name can be at most 200 characters")
    if any(c in name for c in "*%") or any(ord(c) < 32 for c in name):
        raise MailboxError("a folder name cannot contain *, % or control characters")
    if name.startswith("/") or name.endswith("/") or "//" in name:
        raise MailboxError("a folder name cannot start or end with / or contain //")
    if name.upper() == "INBOX" or name in SPECIAL_FOLDERS:
        raise MailboxError(f"{name} already exists")


__all__ = [
    "SPECIAL_FOLDERS",
    "Attachment",
    "Folder",
    "IMAPProtocol",
    "Mailbox",
    "MailboxError",
    "MessageDetail",
    "MessageNotFoundError",
    "MessageSummary",
    "Thread",
    "build_search_criteria",
    "decode_mime_header",
    "extract_attachment",
    "parse_message",
]
