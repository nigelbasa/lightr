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

import contextlib
import logging
import re
from collections.abc import AsyncIterator
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

#: How often an IDLE is re-entered. Under the 29 minutes RFC 2177 tells
#: a client to stay inside one, and under Dovecot's own imap_idle_notify
#: interval, so a dropped connection is noticed rather than waited on.
IDLE_REFRESH = 600.0

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

    async def create_folder(self, name: str) -> None:
        client = await self._connect()
        response = await client.create(_quote(name))
        if response.result != "OK":
            raise MailboxError(f"could not create folder {name!r}: {_detail(response)}")
        # Subscribed, or most clients will not show it.
        await client.subscribe(_quote(name))

    async def rename_folder(self, name: str, new_name: str) -> None:
        client = await self._connect()
        response = await client.rename(_quote(name), _quote(new_name))
        if response.result != "OK":
            raise MailboxError(
                f"could not rename {name!r} to {new_name!r}: {_detail(response)}"
            )
        await client.subscribe(_quote(new_name))
        if self._selected == name:
            self._selected = None

    async def delete_folder(self, name: str) -> None:
        client = await self._connect()
        if self._selected == name:
            # Dovecot refuses to delete the selected mailbox.
            await client.close()
            self._selected = None
        response = await client.delete(_quote(name))
        if response.result != "OK":
            raise MailboxError(f"could not delete folder {name!r}: {_detail(response)}")

    async def select(self, folder: str) -> Folder:
        client = await self._connect()
        response = await client.select(_quote(folder))
        if response.result != "OK":
            raise MailboxError(f"no such folder: {folder}")
        self._selected = folder
        return await self.select_status(folder)

    async def idle(
        self, folder: str, *, timeout: float = IDLE_REFRESH
    ) -> AsyncIterator[list[str]]:
        """Yield Dovecot's untagged pushes for a folder, as they arrive.

        IDLE is how a client hears about mail without polling. The
        connection is re-entered every ``timeout`` seconds because a
        server is entitled to drop an IDLE that has run too long -- the
        RFC says 29 minutes -- and because a refresh proves the socket is
        still alive.

        The caller ends it by closing the generator (leaving the ``async
        for``, or cancelling the task); the IDLE is stopped and the
        connection is left usable.
        """
        client = await self._ensure_selected(folder)
        try:
            while True:
                await client.idle_start(timeout=timeout)
                try:
                    lines = _as_lines(await client.wait_server_push(timeout=timeout))
                except TimeoutError:
                    lines = []
                finally:
                    if client.has_pending_idle():
                        client.idle_done()
                if lines:
                    yield lines
        finally:
            with contextlib.suppress(Exception):
                if client.has_pending_idle():
                    client.idle_done()

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

    async def thread(self, folder: str, criteria: str = "ALL") -> list[list[int]]:
        """Group a folder's messages into conversations, server-side.

        Dovecot does this with THREAD (RFC 5256), which follows
        References and In-Reply-To properly -- the thing a client cannot
        do well from summaries, because it would need every message's
        headers to find out which two of them are related.

        aioimaplib's ``uid()`` refuses anything but COPY, FETCH, EXPUNGE
        and STORE, so the command is built and executed directly. The
        criteria replaces THREAD's search key, so it is the same string
        SEARCH takes, and it goes across as one argument -- splitting it
        would break a quoted value containing a space.

        A server without THREAD leaves every message on its own, which
        renders as the plain list a client would otherwise have shown.
        Bad criteria still raise, because the fallback runs them through
        SEARCH, which refuses them.
        """
        client = await self._ensure_selected(folder)
        try:
            from aioimaplib import Command
        except ImportError as exc:  # pragma: no cover - depends on install
            raise MailboxError(
                "threading needs aioimaplib: pip install 'lightr[imap]'"
            ) from exc

        command = Command(
            "THREAD",
            client.protocol.new_tag(),
            "REFERENCES",
            "UTF-8",
            criteria or "ALL",
            prefix="UID",
            loop=client.protocol.loop,
        )
        try:
            response = await client.protocol.execute(command)
        except Exception as exc:
            log.debug("UID THREAD failed in %s: %s", folder, exc)
            response = None

        if response is None or response.result != "OK":
            return [[uid] for uid in await self.search(folder, criteria)]
        return _parse_threads(response.lines)

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
        self, folder: str, uid: int | list[int], flags: list[str], *, add: bool
    ) -> None:
        client = await self._ensure_selected(folder)
        operation = "+FLAGS" if add else "-FLAGS"
        response = await client.uid(
            "store", _uid_set(uid), operation, f"({' '.join(flags)})"
        )
        if response.result != "OK":
            raise MailboxError(f"could not update flags on message {uid}")

    async def move(self, folder: str, uid: int | list[int], destination: str) -> None:
        client = await self._ensure_selected(folder)

        response = await client.uid("move", _uid_set(uid), _quote(destination))
        if response.result == "OK":
            return

        # MOVE (RFC 6851) is not universal. Fall back to the older
        # COPY + \Deleted + EXPUNGE, which every server supports.
        copied = await client.uid("copy", _uid_set(uid), _quote(destination))
        if copied.result != "OK":
            raise MailboxError(
                f"could not move message {uid} to {destination!r} -- "
                "does that folder exist?"
            )
        await self.store_flags(folder, uid, ["\\Deleted"], add=True)
        await self.expunge(folder, uid)

    async def append(
        self,
        folder: str,
        raw: bytes,
        *,
        flags: tuple[str, ...] = (),
        date: Any = None,
    ) -> None:
        """APPEND a message into a folder, creating the folder if needed.

        Importing into a folder the mailbox does not have yet is the
        normal case -- a Maildir being migrated carries folder names
        this server has never seen -- so a missing folder is created
        rather than reported as an error.
        """
        client = await self._connect()

        if folder.upper() != "INBOX":
            # CREATE on an existing folder is a no-op error; ignore it
            # rather than round-tripping a LIST for every message.
            await client.create(_quote(folder))

        response = await client.append(
            raw,
            mailbox=_quote(folder),
            flags=" ".join(flags) if flags else None,
            date=date,
        )
        if response.result != "OK":
            raise MailboxError(
                f"could not append a message to {folder!r}: "
                f"{' '.join(_as_lines(response.lines))[:200]}"
            )

    async def expunge(self, folder: str, uid: int | list[int]) -> None:
        client = await self._ensure_selected(folder)

        # UID EXPUNGE (RFC 4315) removes only these messages. Plain
        # EXPUNGE would remove every \Deleted message in the folder,
        # which is not what deleting one message means.
        response = await client.uid("expunge", _uid_set(uid))
        if response.result != "OK":
            raise MailboxError(
                f"could not expunge message {uid}; the server may not "
                "support UIDPLUS"
            )


def _uid_set(uid: int | list[int]) -> str:
    """One UID, or several as a comma-separated set -- one round trip
    for a bulk action rather than one per message."""
    if isinstance(uid, int):
        return str(uid)
    if not uid:
        raise MailboxError("no messages given")
    return ",".join(str(int(u)) for u in uid)


def _detail(response: Any) -> str:
    return " ".join(_as_lines(response.lines))[:200]


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


def _parse_threads(lines: Any) -> list[list[int]]:
    """Flatten a THREAD response into one list of UIDs per conversation.

    The wire form nests: ``((2)(3))(1)(4 5)`` is three conversations,
    the first of them a reply to a message and the third a pair. The
    nesting describes who replied to whom, which no caller here needs --
    a thread is its messages, and their order comes from their UIDs.
    """
    threads: list[list[int]] = []
    for line in _as_lines(lines):
        text = line.strip()
        if text.upper().startswith("THREAD"):
            text = text[len("THREAD"):].lstrip()
        if not text.startswith("("):
            # "Thread completed (0.10 secs)." and any other commentary.
            continue

        depth = 0
        current: list[int] = []
        digits = ""
        for char in text:
            if char.isdigit():
                digits += char
                continue
            if digits:
                current.append(int(digits))
                digits = ""
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(depth - 1, 0)
                if depth == 0 and current:
                    threads.append(current)
                    current = []
        if digits:
            current.append(int(digits))
        if current:
            threads.append(current)
    return threads


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
