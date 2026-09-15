"""Live mailbox updates over a WebSocket.

A client that wants to know about new mail either polls or holds an IMAP
connection open. This is the third way: one socket per device, carrying
the same events IMAP's IDLE carries, as JSON.

Two things shape the implementation.

**A WebSocket is not covered by the HTTP middleware.** Everything else
is authenticated in one place, in ``create_app``; Starlette's
``BaseHTTPMiddleware`` never sees a socket. So this endpoint
authenticates itself, and does it before ``accept()`` where the client
sent a header. Browsers cannot set headers on a WebSocket, so a token in
the first message is accepted too -- never in the query string, which
nginx writes to its access log.

**A socket lives for hours; a database transaction must not.** The key
is verified and the account read in one short transaction, which is then
closed. What stays open is one IMAP connection, which is what Dovecot is
built to hold.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from starlette.websockets import WebSocket, WebSocketDisconnect

from lightr.apikeys import APIKeyRepo, Permission
from lightr.models import Account

log = logging.getLogger("lightr.api.events")

PATH = "/v1/mailbox/events"

#: Sockets one mailbox may hold at once. Each is an IMAP connection, and
#: Dovecot allows 20 per user per address; this leaves room for the
#: user's own mail apps.
MAX_SOCKETS_PER_ACCOUNT = 5

#: How long a client has to send its token when it did not send a header.
AUTH_TIMEOUT = 10.0

#: Sent when nothing has happened, so a proxy does not decide the
#: connection is idle and close it.
HEARTBEAT = 30.0

#: How many messages of a folder are watched for changes.
WINDOW = 50

#: Used when the IMAP client cannot IDLE.
POLL_INTERVAL = 30.0

# Close codes, in the 4000-4999 range applications own.
CLOSE_UNAUTHORIZED = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_TOO_MANY = 4429
CLOSE_MAILBOX_GONE = 4404


async def events(websocket: WebSocket) -> None:
    """Serve one client's live view of one mailbox."""
    token = _token_from_headers(websocket)
    if token is None:
        await websocket.accept()
        token = await _token_from_first_message(websocket)
        if token is None:
            await websocket.close(CLOSE_UNAUTHORIZED, "send {\"token\": \"...\"} first")
            return
        accepted = True
    else:
        accepted = False

    resolved = await _resolve(websocket, token)
    if resolved is None:
        if accepted:
            await websocket.close(CLOSE_UNAUTHORIZED, "invalid or expired token")
        else:
            await websocket.close(CLOSE_UNAUTHORIZED)
        return
    account, problem = resolved
    if problem is not None:
        if not accepted:
            await websocket.close(problem[0], problem[1])
        else:
            await websocket.close(problem[0], problem[1])
        return
    assert account is not None

    email = account.email or ""
    counts: dict[str, int] = websocket.app.state.__dict__.setdefault("event_sockets", {})
    if counts.get(email, 0) >= MAX_SOCKETS_PER_ACCOUNT:
        if not accepted:
            await websocket.accept()
        await websocket.close(CLOSE_TOO_MANY, "too many open event sockets")
        return
    if not accepted:
        await websocket.accept()
    counts[email] = counts.get(email, 0) + 1

    try:
        await _serve(websocket, account)
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("event socket for %s failed", email)
        with contextlib.suppress(Exception):
            await websocket.close(1011, "internal error")
    finally:
        counts[email] = max(0, counts.get(email, 1) - 1)
        if not counts[email]:
            counts.pop(email, None)


def _token_from_headers(websocket: WebSocket) -> str | None:
    if key := websocket.headers.get("x-api-key"):
        return key.strip()
    scheme, _, value = websocket.headers.get("authorization", "").partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value.strip() else None


async def _token_from_first_message(websocket: WebSocket) -> str | None:
    try:
        async with asyncio.timeout(AUTH_TIMEOUT):
            message = await websocket.receive_json()
    except (TimeoutError, WebSocketDisconnect, ValueError):
        return None
    token = message.get("token") if isinstance(message, dict) else None
    return token.strip() if isinstance(token, str) and token.strip() else None


async def _resolve(
    websocket: WebSocket, token: str
) -> tuple[Account | None, tuple[int, str] | None] | None:
    """The account this token may watch, in one short transaction."""
    from lightr.repo import AccountRepo, NotFoundError

    engine = websocket.app.state.engine
    client = websocket.client.host if websocket.client else None
    async with engine.begin() as conn:
        key = await APIKeyRepo(conn).verify(token, ip=client)
        if key is None:
            return None
        if not key.allows(Permission.MAILBOX) or key.account_id is None:
            return None, (CLOSE_FORBIDDEN, "this key does not open a mailbox")
        try:
            account = await AccountRepo(conn).resolve(str(key.account_id))
        except (NotFoundError, LookupError):
            return None, (CLOSE_MAILBOX_GONE, "that mailbox no longer exists")
    return account, None


async def _serve(websocket: WebSocket, account: Account) -> None:
    from lightr.cli.imap_client import _connect
    from lightr.dovecot.mailbox import Mailbox

    cfg = websocket.app.state.config
    client = await _connect(cfg, account.email or "")
    mailbox = Mailbox(client)
    folder = "INBOX"
    try:
        await _send(websocket, {
            "type": "ready",
            "mailbox": account.email,
            "folder": folder,
            "folders": [_folder(f) for f in await mailbox.folders()],
        })
        view = await _snapshot(mailbox, folder)
        await _loop(websocket, client, mailbox, folder, view, account.email or "")
    finally:
        with contextlib.suppress(Exception):
            await client.logout()


async def _loop(
    websocket: WebSocket,
    client: Any,
    mailbox: Any,
    folder: str,
    view: dict[int, frozenset[str]],
    email: str,
) -> None:
    """Wait on the client and on Dovecot at the same time."""
    stream = _watch(client, folder)
    incoming = asyncio.create_task(websocket.receive())
    changes = asyncio.create_task(anext(stream))  # type: ignore[arg-type]
    try:
        while True:
            done, _ = await asyncio.wait(
                {incoming, changes},
                timeout=HEARTBEAT,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                await _send(websocket, {"type": "heartbeat"})
                continue

            if changes in done:
                changes.result()
                view = await _emit(websocket, mailbox, folder, view)
                changes = asyncio.create_task(anext(stream))  # type: ignore[arg-type]

            if incoming in done:
                message = incoming.result()
                if message.get("type") == "websocket.disconnect":
                    return
                wanted = await _handle(websocket, mailbox, message, folder)
                if wanted is not None and wanted != folder:
                    folder = wanted
                    changes.cancel()
                    with contextlib.suppress(Exception):
                        await stream.aclose()
                    stream = _watch(client, folder)
                    view = await _snapshot(mailbox, folder)
                    await _send(websocket, {
                        "type": "ready", "mailbox": email, "folder": folder,
                        "folders": [_folder(f) for f in await mailbox.folders()],
                    })
                    changes = asyncio.create_task(anext(stream))  # type: ignore[arg-type]
                incoming = asyncio.create_task(websocket.receive())
    finally:
        for task in (incoming, changes):
            task.cancel()
        with contextlib.suppress(Exception):
            await stream.aclose()


async def _handle(
    websocket: WebSocket, mailbox: Any, message: dict[str, Any], folder: str
) -> str | None:
    """Act on one client message. Returns a folder to switch to, or None."""
    import json

    raw = message.get("text")
    if not raw:
        return None
    try:
        body = json.loads(raw)
    except ValueError:
        await _send(websocket, {"type": "error", "error": "expected JSON"})
        return None
    if not isinstance(body, dict):
        await _send(websocket, {"type": "error", "error": "expected a JSON object"})
        return None

    kind = body.get("type")
    if kind == "ping":
        await _send(websocket, {"type": "pong"})
    elif kind == "watch":
        wanted = body.get("folder")
        if not isinstance(wanted, str) or not wanted.strip():
            await _send(websocket, {"type": "error", "error": "watch needs a folder"})
            return None
        return wanted.strip()
    elif kind == "refresh":
        return folder
    else:
        await _send(websocket, {"type": "error", "error": f"unknown message: {kind!r}"})
    return None


async def _watch(client: Any, folder: str) -> AsyncIterator[list[str]]:
    """Dovecot's pushes for a folder, or a poll when IDLE is unavailable."""
    idle = getattr(client, "idle", None)
    if idle is None:
        while True:
            await asyncio.sleep(POLL_INTERVAL)
            yield []
        return
    async for lines in idle(folder):
        yield lines


async def _snapshot(mailbox: Any, folder: str) -> dict[int, frozenset[str]]:
    return {m.uid: m.flags for m in await mailbox.list(folder, limit=WINDOW)}


async def _emit(
    websocket: WebSocket, mailbox: Any, folder: str, before: dict[int, frozenset[str]]
) -> dict[int, frozenset[str]]:
    """Send what changed in the watched window since the last look."""
    from lightr.api.mailbox import _summary

    summaries = await mailbox.list(folder, limit=WINDOW)
    after = {m.uid: m.flags for m in summaries}

    arrived = [_summary(m) for m in summaries if m.uid not in before]
    changed = [
        _summary(m) for m in summaries
        if m.uid in before and before[m.uid] != m.flags
    ]
    # A UID can leave the window two ways: it was deleted, or newer mail
    # pushed it off the end. Only a full window can have pushed anything
    # off, so only then is the oldest visible UID a floor -- otherwise
    # deleting the oldest message in a small mailbox went unreported.
    floor = min(after, default=0) if len(after) >= WINDOW else 0
    removed = sorted(uid for uid in before if uid not in after and uid >= floor)

    if arrived or changed or removed:
        status = await mailbox.folders()
        here = next((f for f in status if f.name == folder), None)
        await _send(websocket, {
            "type": "update",
            "folder": folder,
            "new": arrived,
            "changed": changed,
            "removed": removed,
            "status": _folder(here) if here is not None else None,
        })
    return after


async def _send(websocket: WebSocket, payload: dict[str, Any]) -> None:
    """Send one frame, encoding what the HTTP side encodes.

    Starlette's send_json is plain json.dumps, which refuses the
    datetime in a message summary -- the socket died with "Object of
    type datetime is not JSON serializable" the first time one arrived.
    """
    from lightr.api.app import json_default

    await websocket.send_text(json.dumps(payload, default=json_default))


def _folder(folder: Any) -> dict[str, Any]:
    return {
        "name": folder.name,
        "messages": folder.messages,
        "unseen": folder.unseen,
        "uidvalidity": folder.uidvalidity,
    }


__all__ = ["MAX_SOCKETS_PER_ACCOUNT", "PATH", "events"]
