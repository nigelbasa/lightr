"""The live-updates socket.

Driven through the ASGI protocol directly rather than through a threaded
test client: the socket, the fake Dovecot and the database then share one
event loop, which is the arrangement production runs in. A test client
that spawns its own loop hid exactly this class of bug until a cutover
found it on port 25.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine
from tests.test_mailbox import FLAG_SEEN, FakeIMAP, _raw

from lightr.api.app import create_app
from lightr.api.events import (
    CLOSE_FORBIDDEN,
    CLOSE_TOO_MANY,
    CLOSE_UNAUTHORIZED,
    MAX_SOCKETS_PER_ACCOUNT,
    PATH,
)
from lightr.apikeys import APIKeyRepo, KeyType
from lightr.cli import imap_client
from lightr.config import Config
from lightr.models import Account, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo


class IdlingIMAP(FakeIMAP):
    """A fake Dovecot whose IDLE the test drives."""

    def __init__(self) -> None:
        super().__init__()
        self.pushes: asyncio.Queue[list[str]] = asyncio.Queue()
        self.idled: list[str] = []

    async def idle(self, folder: str, *, timeout: float = 600.0) -> AsyncIterator[list[str]]:
        self.idled.append(folder)
        while True:
            yield await self.pushes.get()

    def deliver(self, subject: str, folder: str = "INBOX") -> int:
        box = self.messages.setdefault(folder, {})
        uid = max(box, default=0) + 1
        box[uid] = (_raw(subject), set())
        self.pushes.put_nowait([f"{len(box)} EXISTS"])
        return uid


class Socket:
    """One WebSocket connection, spoken as ASGI."""

    def __init__(self, app: Any, headers: dict[str, str] | None = None) -> None:
        self._app = app
        self._headers = [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ]
        self._to_app: asyncio.Queue[dict] = asyncio.Queue()
        self._from_app: asyncio.Queue[dict] = asyncio.Queue()
        self._task: asyncio.Task | None = None

    async def __aenter__(self) -> Socket:
        scope = {
            "type": "websocket", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "scheme": "ws", "path": PATH, "raw_path": PATH.encode(), "query_string": b"",
            "root_path": "", "headers": [(b"host", b"test"), *self._headers],
            "client": ("203.0.113.9", 4444), "server": ("test", 80), "subprotocols": [],
            "state": {},
        }
        self._task = asyncio.create_task(
            self._app(scope, self._to_app.get, self._from_app.put)
        )
        await self._to_app.put({"type": "websocket.connect"})
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._to_app.put({"type": "websocket.disconnect", "code": 1000})
        if self._task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._task, timeout=5)

    async def next(self, timeout: float = 5.0) -> dict:
        return await asyncio.wait_for(self._from_app.get(), timeout)

    async def accepted(self) -> dict:
        """The accept frame, or the close frame that came instead."""
        return await self.next()

    async def json(self, timeout: float = 5.0) -> dict:
        while True:
            message = await self.next(timeout)
            if message["type"] == "websocket.close":
                raise AssertionError(f"closed: {message}")
            if message["type"] == "websocket.send" and message.get("text"):
                return json.loads(message["text"])

    async def send(self, payload: dict) -> None:
        await self._to_app.put({"type": "websocket.receive", "text": json.dumps(payload)})

    async def until(self, kind: str, timeout: float = 5.0) -> dict:
        while True:
            message = await self.json(timeout)
            if message["type"] == kind:
                return message


@pytest.fixture
def imap() -> IdlingIMAP:
    return IdlingIMAP()


@pytest.fixture(autouse=True)
def fake_dovecot(imap: IdlingIMAP) -> AsyncIterator[None]:
    imap_client.set_client_factory(lambda cfg, email: imap)
    yield
    imap_client.set_client_factory(None)


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        ops = await AccountRepo(conn).create(Account(domain_id=domain.id, local_part="ops"))
        keys = APIKeyRepo(conn)
        _, mailbox_key = await keys.create(
            "ops-mailbox", key_type=KeyType.ACCOUNT, account_id=ops.id
        )
        _, org_key = await keys.create("org-wide", organization_id=org.id)
    return {"mailbox_key": mailbox_key, "org_key": org_key}


@pytest.fixture
def app(cfg: Config, engine: AsyncEngine) -> Any:
    return create_app(cfg, engine=engine)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestGettingIn:
    async def test_a_socket_without_a_token_is_closed(self, app: Any, world: dict) -> None:
        async with Socket(app) as socket:
            assert (await socket.accepted())["type"] == "websocket.accept"
            await socket.send({"hello": "there"})  # anything but a token
            closed = await socket.next()

        assert closed["type"] == "websocket.close"
        assert closed["code"] == CLOSE_UNAUTHORIZED

    async def test_a_bad_token_never_gets_accepted(self, app: Any, world: dict) -> None:
        async with Socket(app, bearer("lk_not-a-key")) as socket:
            closed = await socket.next()

        assert closed["type"] == "websocket.close"
        assert closed["code"] == CLOSE_UNAUTHORIZED

    async def test_an_operator_key_does_not_open_a_mailbox(
        self, app: Any, world: dict
    ) -> None:
        async with Socket(app, bearer(world["org_key"])) as socket:
            closed = await socket.next()

        assert closed["code"] == CLOSE_FORBIDDEN

    async def test_a_header_token_is_ready_straight_away(
        self, app: Any, world: dict
    ) -> None:
        async with Socket(app, bearer(world["mailbox_key"])) as socket:
            assert (await socket.accepted())["type"] == "websocket.accept"
            ready = await socket.json()

        assert ready["type"] == "ready"
        assert ready["mailbox"] == "ops@acme.test"
        assert ready["folder"] == "INBOX"
        assert "INBOX" in [f["name"] for f in ready["folders"]]

    async def test_a_browser_can_send_the_token_in_the_first_message(
        self, app: Any, world: dict
    ) -> None:
        """Browsers cannot set headers on a WebSocket, and a token in the
        query string would be written to nginx's access log."""
        async with Socket(app) as socket:
            assert (await socket.accepted())["type"] == "websocket.accept"
            await socket.send({"token": world["mailbox_key"]})
            ready = await socket.json()

        assert ready["type"] == "ready"

    async def test_one_mailbox_cannot_hold_every_socket(
        self, app: Any, world: dict
    ) -> None:
        open_sockets = []
        try:
            for _ in range(MAX_SOCKETS_PER_ACCOUNT):
                socket = await Socket(app, bearer(world["mailbox_key"])).__aenter__()
                open_sockets.append(socket)
                await socket.accepted()
                await socket.json()

            async with Socket(app, bearer(world["mailbox_key"])) as extra:
                await extra.accepted()
                closed = await extra.next()
            assert closed["code"] == CLOSE_TOO_MANY
        finally:
            for socket in open_sockets:
                await socket.__aexit__()


class TestWhatItPushes:
    async def test_new_mail_arrives_as_an_update(
        self, app: Any, world: dict, imap: IdlingIMAP
    ) -> None:
        async with Socket(app, bearer(world["mailbox_key"])) as socket:
            await socket.accepted()
            await socket.json()
            imap.deliver("Invoice 9")

            update = await socket.until("update")

        assert update["folder"] == "INBOX"
        assert [m["subject"] for m in update["new"]] == ["Invoice 9"]
        assert update["status"]["name"] == "INBOX"

    async def test_a_flag_change_and_a_deletion_are_reported(
        self, app: Any, world: dict, imap: IdlingIMAP
    ) -> None:
        async with Socket(app, bearer(world["mailbox_key"])) as socket:
            await socket.accepted()
            await socket.json()

            imap.messages["INBOX"][2][1].add(FLAG_SEEN)
            imap.pushes.put_nowait(["2 FETCH (FLAGS (\\Seen))"])
            changed = await socket.until("update")

            imap.messages["INBOX"].pop(1)
            imap.pushes.put_nowait(["1 EXPUNGE"])
            removed = await socket.until("update")

        assert [m["uid"] for m in changed["changed"]] == [2]
        assert changed["changed"][0]["seen"] is True
        assert removed["removed"] == [1]

    async def test_a_client_can_watch_another_folder(
        self, app: Any, world: dict, imap: IdlingIMAP
    ) -> None:
        async with Socket(app, bearer(world["mailbox_key"])) as socket:
            await socket.accepted()
            await socket.json()

            await socket.send({"type": "watch", "folder": "Trash"})
            ready = await socket.until("ready")

        assert ready["folder"] == "Trash"
        assert imap.idled == ["INBOX", "Trash"]

    async def test_ping_is_answered(self, app: Any, world: dict) -> None:
        async with Socket(app, bearer(world["mailbox_key"])) as socket:
            await socket.accepted()
            await socket.json()
            await socket.send({"type": "ping"})

            assert (await socket.json())["type"] == "pong"

    async def test_nonsense_is_refused_without_closing(
        self, app: Any, world: dict
    ) -> None:
        async with Socket(app, bearer(world["mailbox_key"])) as socket:
            await socket.accepted()
            await socket.json()
            await socket.send({"type": "explode"})
            error = await socket.json()
            await socket.send({"type": "ping"})

            assert error["type"] == "error"
            assert (await socket.json())["type"] == "pong"
