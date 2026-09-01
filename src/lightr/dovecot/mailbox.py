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


@runtime_checkable
class IMAPProtocol(Protocol):
    """The narrow slice of IMAP the mailbox adapter needs."""

    async def login(self, username: str, password: str) -> None: ...
    async def logout(self) -> None: ...
    async def list_folders(self) -> list[Folder]: ...
    async def select(self, folder: str) -> Folder: ...
    async def search(self, folder: str, criteria: str) -> list[int]: ...
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
        self, folder: str, uid: int, flags: list[str], *, add: bool
    ) -> None: ...
    async def move(self, folder: str, uid: int, destination: str) -> None: ...
    async def expunge(self, folder: str, uid: int) -> None: ...


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

    async def mark(self, folder: str, uid: int, *, seen: bool | None = None,
                   flagged: bool | None = None) -> None:
        if seen is not None:
            await self._client.store_flags(folder, uid, [FLAG_SEEN], add=seen)
        if flagged is not None:
            await self._client.store_flags(folder, uid, [FLAG_FLAGGED], add=flagged)

    async def move(self, folder: str, uid: int, destination: str) -> None:
        await self._client.move(folder, uid, destination)

    async def delete(self, folder: str, uid: int, *, expunge: bool = False) -> None:
        """Move to Trash, or expunge outright.

        Defaults to Trash: an operator running `lightr mailbox delete`
        almost never means 'destroy irrecoverably'.
        """
        if expunge:
            await self._client.store_flags(folder, uid, [FLAG_DELETED], add=True)
            await self._client.expunge(folder, uid)
        else:
            await self._client.move(folder, uid, "Trash")


__all__ = [
    "Attachment",
    "Folder",
    "IMAPProtocol",
    "Mailbox",
    "MailboxError",
    "MessageDetail",
    "MessageNotFoundError",
    "MessageSummary",
    "build_search_criteria",
    "decode_mime_header",
    "extract_attachment",
    "parse_message",
]
