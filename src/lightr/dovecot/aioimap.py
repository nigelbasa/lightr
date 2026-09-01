"""The real IMAP client, over aioimaplib.

Implements ``IMAPProtocol`` against a live Dovecot. Everything that
parses an IMAP response lives here, so the rest of the engine works in
terms of Folder and MessageSummary and never sees the wire format.

The parsing is defensive on purpose: IMAP servers are free to include
untagged responses, ordering, and literal forms that a strict parser
would trip on, and a mailbox listing that raises is worse than one that
omits a field.
"""

from __future__ import annotations

import logging
import re
from email.utils import parsedate_to_datetime
from typing import Any

from lightr.dovecot.mailbox import (
    Folder,
    MailboxError,
    MessageSummary,
    decode_mime_header,
)

log = logging.getLogger("lightr.imap")

DEFAULT_TIMEOUT = 30

# LIST response: (\HasNoChildren \Sent) "/" "Sent"
_LIST_LINE = re.compile(
    r'\((?P<flags>[^)]*)\)\s+"?(?P<sep>[^"\s]*)"?\s+"?(?P<name>[^"]+)"?\s*$'
)

# STATUS response: "INBOX" (MESSAGES 12 UNSEEN 3 UIDVALIDITY 1)
_STATUS_ITEM = re.compile(r"(\w+)\s+(\d+)")

# A UID inside a FETCH response.
_UID = re.compile(r"\bUID\s+(\d+)")
_SIZE = re.compile(r"\bRFC822\.SIZE\s+(\d+)")
_FLAGS = re.compile(r"\bFLAGS\s+\(([^)]*)\)")
_INTERNALDATE = re.compile(r'\bINTERNALDATE\s+"([^"]+)"')


class AioIMAPClient:
    """An IMAP connection to Dovecot, scoped to one mailbox."""

    def __init__(
        self,
        host: str,
        port: int = 143,
        *,
        use_tls: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._host = host
        self._port = port
        self._use_tls = use_tls
        self._timeout = timeout
        self._client: Any = None
        self._selected: str | None = None

    # -- connection -----------------------------------------------------

    async def _connect(self) -> Any:
        if self._client is not None:
            return self._client

        try:
            import aioimaplib
        except ImportError as exc:  # pragma: no cover - depends on install
            raise MailboxError(
                "reading mailboxes needs aioimaplib: pip install 'lightr[imap]'"
            ) from exc

        factory = (
            aioimaplib.IMAP4_SSL if self._use_tls else aioimaplib.IMAP4
        )
        try:
            client = factory(host=self._host, port=self._port, timeout=self._timeout)
            await client.wait_hello_from_server()
        except Exception as exc:
            raise MailboxError(
                f"cannot reach Dovecot IMAP at {self._host}:{self._port}: {exc}"
            ) from exc

        self._client = client
        return client

    async def login(self, username: str, password: str) -> None:
        client = await self._connect()
        response = await client.login(username, password)
        if response.result != "OK":
            raise MailboxError(
                "Dovecot refused the master-user login. Check "
                "dovecot.master_user and dovecot.master_password, and the "
                "matching passdb entry in Dovecot."
            )

    async def logout(self) -> None:
        if self._client is None:
            return
        try:
            await self._client.logout()
        except Exception:
            log.debug("IMAP logout failed", exc_info=True)
        finally:
            self._client = None
            self._selected = None

    # -- folders --------------------------------------------------------

    async def list_folders(self) -> list[Folder]:
        client = await self._connect()
        response = await client.list('""', "*")
        if response.result != "OK":
            raise MailboxError("could not list folders")

        folders: list[Folder] = []
        for line in _as_lines(response.lines):
            match = _LIST_LINE.search(line)
            if match is None:
                continue
            name = match.group("name")
            if "\\Noselect" in match.group("flags"):
                continue
            try:
                folders.append(await self.select_status(name))
            except MailboxError:
                # A folder that vanished between LIST and STATUS should
                # not break the whole listing.
                log.debug("skipping unreadable folder %s", name)
        return folders

    async def select_status(self, folder: str) -> Folder:
        """STATUS a folder without selecting it."""
        client = await self._connect()
        response = await client.status(
            _quote(folder), "(MESSAGES UNSEEN UIDVALIDITY)"
        )
        if response.result != "OK":
            raise MailboxError(f"could not read status of {folder!r}")

        values = {}
        for line in _as_lines(response.lines):
            values.update(
                {k.upper(): int(v) for k, v in _STATUS_ITEM.findall(line)}
            )
        return Folder(
            name=folder,
            messages=values.get("MESSAGES", 0),
            unseen=values.get("UNSEEN", 0),
            uidvalidity=values.get("UIDVALIDITY", 0),
        )

    async def select(self, folder: str) -> Folder:
        client = await self._connect()
        response = await client.select(_quote(folder))
        if response.result != "OK":
            raise MailboxError(f"no such folder: {folder}")
        self._selected = folder
        return await self.select_status(folder)

    async def _ensure_selected(self, folder: str) -> Any:
        client = await self._connect()
        if self._selected != folder:
            await self.select(folder)
        return client

    # -- messages -------------------------------------------------------

    async def search(self, folder: str, criteria: str) -> list[int]:
        client = await self._ensure_selected(folder)
        response = await client.uid_search(criteria or "ALL")
        if response.result != "OK":
            raise MailboxError(f"search failed in {folder!r}: {criteria}")

        uids: list[int] = []
        for line in _as_lines(response.lines):
            uids.extend(int(token) for token in line.split() if token.isdigit())
        return uids

    async def fetch_summaries(
        self, folder: str, uids: list[int]
    ) -> list[MessageSummary]:
        if not uids:
            return []

        client = await self._ensure_selected(folder)
        uid_set = ",".join(str(u) for u in uids)
        response = await client.uid(
            "fetch",
            uid_set,
            "(UID FLAGS RFC822.SIZE INTERNALDATE "
            "BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE)])",
        )
        if response.result != "OK":
            raise MailboxError(f"could not fetch messages from {folder!r}")

        return _parse_summaries(response.lines, folder)

    async def fetch_raw(self, folder: str, uid: int) -> bytes:
        client = await self._ensure_selected(folder)
        response = await client.uid("fetch", str(uid), "(BODY.PEEK[])")
        if response.result != "OK":
            return b""

        # The body arrives as a literal: the largest bytes chunk.
        chunks = [line for line in response.lines if isinstance(line, bytes | bytearray)]
        if not chunks:
            return b""
        return bytes(max(chunks, key=len))

    async def store_flags(
        self, folder: str, uid: int, flags: list[str], *, add: bool
    ) -> None:
        client = await self._ensure_selected(folder)
        operation = "+FLAGS" if add else "-FLAGS"
        response = await client.uid(
            "store", str(uid), operation, f"({' '.join(flags)})"
        )
        if response.result != "OK":
            raise MailboxError(f"could not update flags on message {uid}")

    async def move(self, folder: str, uid: int, destination: str) -> None:
        client = await self._ensure_selected(folder)

        response = await client.uid("move", str(uid), _quote(destination))
        if response.result == "OK":
            return

        # MOVE (RFC 6851) is not universal. Fall back to the older
        # COPY + \Deleted + EXPUNGE, which every server supports.
        copied = await client.uid("copy", str(uid), _quote(destination))
        if copied.result != "OK":
            raise MailboxError(
                f"could not move message {uid} to {destination!r} -- "
                "does that folder exist?"
            )
        await self.store_flags(folder, uid, ["\\Deleted"], add=True)
        await self.expunge(folder, uid)

    async def expunge(self, folder: str, uid: int) -> None:
        client = await self._ensure_selected(folder)

        # UID EXPUNGE (RFC 4315) removes only this message. Plain
        # EXPUNGE would remove every \Deleted message in the folder,
        # which is not what deleting one message means.
        response = await client.uid("expunge", str(uid))
        if response.result != "OK":
            raise MailboxError(
                f"could not expunge message {uid}; the server may not "
                "support UIDPLUS"
            )


def _quote(name: str) -> str:
    """Quote a mailbox name for the wire."""
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _as_lines(lines: Any) -> list[str]:
    """Normalise aioimaplib's mixed bytes/str lines to text."""
    out: list[str] = []
    for line in lines or []:
        if isinstance(line, bytes | bytearray):
            out.append(bytes(line).decode("utf-8", "replace"))
        else:
            out.append(str(line))
    return out


def _parse_summaries(lines: Any, folder: str) -> list[MessageSummary]:
    """Turn a FETCH response into summaries.

    Pairs each metadata line with the header block that follows it.
    """
    summaries: list[MessageSummary] = []
    text_lines = _as_lines(lines)

    pending: dict[str, Any] | None = None
    header_blob: list[str] = []

    def flush() -> None:
        nonlocal pending, header_blob
        if pending is None:
            return
        headers = _parse_headers("\n".join(header_blob))
        summaries.append(
            MessageSummary(
                uid=pending["uid"],
                folder=folder,
                subject=decode_mime_header(headers.get("subject")),
                from_=decode_mime_header(headers.get("from")),
                to=decode_mime_header(headers.get("to")),
                date=_parse_date(headers.get("date")) or pending.get("internaldate"),
                size=pending.get("size", 0),
                flags=frozenset(pending.get("flags", ())),
            )
        )
        pending = None
        header_blob = []

    for line in text_lines:
        uid_match = _UID.search(line)
        if uid_match and "FETCH" in line.upper():
            flush()
            size_match = _SIZE.search(line)
            flags_match = _FLAGS.search(line)
            pending = {
                "uid": int(uid_match.group(1)),
                "size": int(size_match.group(1)) if size_match else 0,
                "flags": tuple(flags_match.group(1).split()) if flags_match else (),
                "internaldate": _parse_internaldate(line),
            }
            continue
        if pending is not None and line.strip() not in (")", ""):
            header_blob.append(line)

    flush()
    return summaries


def _parse_headers(blob: str) -> dict[str, str]:
    """Parse a small header block into a lowercase-keyed mapping."""
    from email.parser import Parser

    parsed = Parser().parsestr(blob, headersonly=True)
    return {k.lower(): v for k, v in parsed.items()}


def _parse_date(value: str | None) -> Any:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


def _parse_internaldate(line: str) -> Any:
    match = _INTERNALDATE.search(line)
    if match is None:
        return None
    from datetime import datetime

    try:
        return datetime.strptime(match.group(1), "%d-%b-%Y %H:%M:%S %z")
    except ValueError:
        return None


__all__ = ["DEFAULT_TIMEOUT", "AioIMAPClient"]
