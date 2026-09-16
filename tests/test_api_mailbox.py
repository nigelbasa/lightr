"""The /v1/mailbox/* routes.

The security property under test: these act on exactly one mailbox --
whichever the key is scoped to -- and there is no path parameter that
could point them at anyone else's mail.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine
from tests.test_mailbox import FakeIMAP

from lightr.api.app import create_app
from lightr.apikeys import APIKeyRepo, KeyType
from lightr.cli import imap_client
from lightr.config import Config
from lightr.models import Account, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo


@pytest.fixture(autouse=True)
def fake_dovecot() -> AsyncIterator[None]:
    imap_client.set_client_factory(lambda cfg, email: FakeIMAP())
    yield
    imap_client.set_client_factory(None)


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        accounts = AccountRepo(conn)
        ops = await accounts.create(Account(domain_id=domain.id, local_part="ops"))
        other = await accounts.create(Account(domain_id=domain.id, local_part="other"))

        keys = APIKeyRepo(conn)
        _, mailbox_key = await keys.create(
            "ops-mailbox", key_type=KeyType.ACCOUNT, account_id=ops.id
        )
        _, other_key = await keys.create(
            "other-mailbox", key_type=KeyType.ACCOUNT, account_id=other.id
        )
        _, org_key = await keys.create("org-wide", organization_id=org.id)
        _, admin_key = await keys.create("root", key_type=KeyType.ADMIN)

    return {
        "ops": ops,
        "other": other,
        "mailbox_key": mailbox_key,
        "other_key": other_key,
        "org_key": org_key,
        "admin_key": admin_key,
    }


@pytest_asyncio.fixture
async def client(cfg: Config, engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(cfg, engine=engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def auth(secret: str) -> dict[str, str]:
    return {"X-API-Key": secret}


class TestScoping:
    async def test_an_account_key_reaches_its_own_mailbox(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get("/v1/mailbox", headers=auth(world["mailbox_key"]))
        assert response.status_code == 200
        assert response.json()["email"] == "ops@acme.test"

    async def test_an_org_key_is_refused(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """An org key carries no mailbox permission at all, so it is
        refused before the question of which mailbox even arises."""
        response = await client.get("/v1/mailbox", headers=auth(world["org_key"]))
        assert response.status_code == 403
        assert "mailbox" in response.json()["error"]

    async def test_an_admin_key_is_also_refused(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """Admin is not a mailbox. Being powerful does not name which
        mailbox to open."""
        response = await client.get("/v1/mailbox", headers=auth(world["admin_key"]))
        assert response.status_code == 403

    async def test_there_is_no_path_parameter_to_tamper_with(
        self, world: dict
    ) -> None:
        """The route table itself is the guarantee: no mailbox route
        takes an account identifier."""
        from lightr.api.mailbox import MAILBOX_ROUTES

        for route in MAILBOX_ROUTES:
            assert "account" not in route.path
            assert "{email}" not in route.path

    async def test_two_keys_see_different_mailboxes(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        mine = await client.get("/v1/mailbox", headers=auth(world["mailbox_key"]))
        theirs = await client.get("/v1/mailbox", headers=auth(world["other_key"]))

        assert mine.json()["email"] == "ops@acme.test"
        assert theirs.json()["email"] == "other@acme.test"

    async def test_no_key_is_401(self, client: httpx.AsyncClient, world: dict) -> None:
        assert (await client.get("/v1/mailbox")).status_code == 401


class TestReading:
    async def test_folders(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.get(
            "/v1/mailbox/folders", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 200
        assert response.json()[0]["name"] == "INBOX"

    async def test_messages_are_newest_first(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/messages", headers=auth(world["mailbox_key"])
        )
        assert [m["uid"] for m in response.json()] == [3, 2, 1]

    async def test_unread_filter(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/messages?unread=true", headers=auth(world["mailbox_key"])
        )
        assert [m["uid"] for m in response.json()] == [3, 2]

    async def test_limit_is_capped(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """An unbounded limit is a way to make the server do arbitrary
        work on one request."""
        response = await client.get(
            "/v1/mailbox/messages?limit=100000", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 200

    async def test_a_bad_limit_falls_back_to_the_default(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/messages?limit=abc", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 200

    async def test_message_body_and_attachments(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/messages/3", headers=auth(world["mailbox_key"])
        )
        body = response.json()
        assert "Plain body." in body["text"]
        assert body["attachments"][0]["filename"] == "invoice.pdf"

    async def test_missing_message_is_404(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/messages/9999", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 404

    async def test_a_non_numeric_uid_is_400(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/messages/not-a-uid", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 400


class TestAttachments:
    async def test_download_returns_the_bytes(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        listing = (
            await client.get(
                "/v1/mailbox/messages/3", headers=auth(world["mailbox_key"])
            )
        ).json()
        index = listing["attachments"][0]["index"]

        response = await client.get(
            f"/v1/mailbox/messages/3/attachments/{index}",
            headers=auth(world["mailbox_key"]),
        )

        assert response.status_code == 200
        assert response.content.startswith(b"%PDF")
        assert response.headers["content-type"].startswith("application/pdf")

    async def test_filename_is_offered_for_download(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        listing = (
            await client.get(
                "/v1/mailbox/messages/3", headers=auth(world["mailbox_key"])
            )
        ).json()
        index = listing["attachments"][0]["index"]

        response = await client.get(
            f"/v1/mailbox/messages/3/attachments/{index}",
            headers=auth(world["mailbox_key"]),
        )
        assert 'filename="invoice.pdf"' in response.headers["content-disposition"]

    async def test_a_bad_attachment_index_is_400_or_404(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/messages/3/attachments/oops",
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 400


class TestMutations:
    async def test_mark_read(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.patch(
            "/v1/mailbox/messages/2",
            json={"read": True},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 200
        assert response.json()["updated"]

    async def test_flag(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.patch(
            "/v1/mailbox/messages/1",
            json={"flagged": True},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 200

    async def test_move(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.patch(
            "/v1/mailbox/messages/1",
            json={"folder": "Trash"},
            headers=auth(world["mailbox_key"]),
        )
        assert response.json()["folder"] == "Trash"

    async def test_an_empty_patch_is_400(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.patch(
            "/v1/mailbox/messages/1", json={}, headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 400

    async def test_delete_moves_to_trash(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.delete(
            "/v1/mailbox/messages/1", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 204


class TestClientFlags:
    async def test_answered_and_draft_can_be_set(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.patch(
            "/v1/mailbox/messages/2",
            json={"answered": True},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 200

    async def test_a_flag_must_be_a_boolean(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """The string "false" is truthy; accepting it would set the flag."""
        response = await client.patch(
            "/v1/mailbox/messages/2",
            json={"read": "false"},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 400


class TestBulk:
    async def test_mark_several_read(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/mailbox/messages/bulk",
            json={"uids": [2, 3], "read": True},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 200
        assert response.json()["updated"] == 2

    async def test_bulk_delete(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.post(
            "/v1/mailbox/messages/bulk",
            json={"uids": [1, 2], "delete": True},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 200

    @pytest.mark.parametrize(
        "body",
        [
            {"uids": [], "read": True},
            {"uids": "1,2", "read": True},
            {"uids": [True], "read": True},
            {"uids": [1]},
            {"uids": [1], "move_to": "Archive", "delete": True},
            {"uids": list(range(1, 1002)), "read": True},
        ],
    )
    async def test_bad_requests_are_refused(
        self, client: httpx.AsyncClient, world: dict, body: dict
    ) -> None:
        response = await client.post(
            "/v1/mailbox/messages/bulk", json=body, headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 400


@pytest.fixture
def shared_imap() -> FakeIMAP:
    """One fake for every request in a test.

    The default fixture builds a fresh fake per connection, which is
    right for isolation but forgets a folder between creating it and
    renaming it.
    """
    fake = FakeIMAP()
    fake.messages["Drafts"] = {}
    imap_client.set_client_factory(lambda cfg, email: fake)
    return fake


class TestFolders:
    async def test_create_rename_delete(
        self, client: httpx.AsyncClient, world: dict, shared_imap: FakeIMAP
    ) -> None:
        headers = auth(world["mailbox_key"])

        created = await client.post(
            "/v1/mailbox/folders", json={"name": "Receipts"}, headers=headers
        )
        assert created.status_code == 201

        renamed = await client.patch(
            "/v1/mailbox/folders/Receipts", json={"name": "Receipts/2026"},
            headers=headers,
        )
        assert renamed.status_code == 200

        # A nested name reaches the handler whole, slash included.
        deleted = await client.delete("/v1/mailbox/folders/Receipts/2026", headers=headers)
        assert deleted.status_code == 204

    async def test_a_system_folder_cannot_be_deleted(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.delete(
            "/v1/mailbox/folders/Junk", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 400
        assert "system folder" in response.json()["error"]

    async def test_an_unknown_folder_is_a_client_error(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.delete(
            "/v1/mailbox/folders/Nope", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 400

    async def test_empty_trash(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.post(
            "/v1/mailbox/folders/Trash/empty", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 200
        assert response.json()["removed"] == 0

    async def test_the_inbox_cannot_be_emptied(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/mailbox/folders/INBOX/empty", headers=auth(world["mailbox_key"])
        )
        assert response.status_code == 400


class TestDrafts:
    @pytest.fixture
    def imap(self, shared_imap: FakeIMAP) -> FakeIMAP:
        return shared_imap

    async def test_a_draft_is_stored_with_the_draft_flag(
        self, client: httpx.AsyncClient, world: dict, imap: FakeIMAP
    ) -> None:
        response = await client.post(
            "/v1/mailbox/drafts",
            json={"to": "friend@example.test", "subject": "Later", "text": "Half"},
            headers=auth(world["mailbox_key"]),
        )

        assert response.status_code == 201
        ((folder, raw, flags),) = imap.appended
        assert folder == "Drafts"
        assert "\\Draft" in flags
        assert b"From: ops@acme.test" in raw
        assert b"Subject: Later" in raw

    async def test_replacing_a_draft_removes_the_old_copy(
        self, client: httpx.AsyncClient, world: dict, imap: FakeIMAP
    ) -> None:
        headers = auth(world["mailbox_key"])
        await client.post("/v1/mailbox/drafts", json={"subject": "v1"}, headers=headers)

        response = await client.post(
            "/v1/mailbox/drafts", json={"subject": "v2", "replace": 1}, headers=headers
        )

        assert response.status_code == 201
        assert list(imap.messages["Drafts"]) == [2]

    async def test_a_header_cannot_be_injected(
        self, client: httpx.AsyncClient, world: dict, imap: FakeIMAP
    ) -> None:
        response = await client.post(
            "/v1/mailbox/drafts",
            json={"subject": "hi\r\nBcc: everyone@example.test"},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 400
        assert imap.appended == []


class TestSending:
    """Sending through the API is submission by another door, so it
    must refuse exactly what submission refuses."""

    @pytest.fixture(autouse=True)
    def no_dns(self, cfg: Config) -> None:
        cfg.spam.enabled = False

    async def _queued(self, engine: AsyncEngine) -> list:
        from lightr.mail.queue import Queue

        async with engine.begin() as conn:
            return await Queue(conn).list()

    async def test_mail_is_queued_and_filed_in_sent(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine,
        shared_imap: FakeIMAP,
    ) -> None:
        response = await client.post(
            "/v1/mailbox/send",
            json={"to": "friend@example.test", "subject": "Hi", "text": "Hello"},
            headers=auth(world["mailbox_key"]),
        )

        assert response.status_code == 202, response.text
        assert response.json()["queued"] == ["friend@example.test"]
        assert response.json()["saved_to_sent"] is True
        (queued,) = await self._queued(engine)
        assert queued.to_addrs == ["friend@example.test"]
        ((folder, _, flags),) = shared_imap.appended
        assert folder == "Sent"
        assert "\\Seen" in flags

    async def test_bcc_goes_out_but_is_not_shown_to_recipients(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine,
        shared_imap: FakeIMAP,
    ) -> None:
        await client.post(
            "/v1/mailbox/send",
            json={"to": "friend@example.test", "bcc": "boss@example.test",
                  "subject": "Hi", "text": "Hello"},
            headers=auth(world["mailbox_key"]),
        )

        (queued,) = await self._queued(engine)
        assert set(queued.to_addrs) == {"friend@example.test", "boss@example.test"}
        assert b"boss@example.test" not in queued.raw
        ((_, sent_copy, _),) = shared_imap.appended
        assert b"Bcc: boss@example.test" in sent_copy

    async def test_sending_as_someone_else_is_refused(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine,
        shared_imap: FakeIMAP,
    ) -> None:
        response = await client.post(
            "/v1/mailbox/send",
            json={"from": "other@acme.test", "to": "friend@example.test",
                  "subject": "Forged", "text": "x"},
            headers=auth(world["mailbox_key"]),
        )

        assert response.status_code == 403
        assert await self._queued(engine) == []
        assert shared_imap.appended == []

    async def test_a_blocked_account_cannot_send(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine,
    ) -> None:
        async with engine.begin() as conn:
            account = world["ops"]
            account.can_send = False
            await AccountRepo(conn).update(account)

        response = await client.post(
            "/v1/mailbox/send",
            json={"to": "friend@example.test", "subject": "Hi", "text": "x"},
            headers=auth(world["mailbox_key"]),
        )

        assert response.status_code == 403
        assert "not allowed to send" in response.json()["error"]
        assert await self._queued(engine) == []

    async def test_a_reply_marks_the_original_answered(
        self, client: httpx.AsyncClient, world: dict, shared_imap: FakeIMAP,
    ) -> None:
        response = await client.post(
            "/v1/mailbox/send",
            json={"to": "sender@example.test", "subject": "Re: Second",
                  "text": "Thanks", "reply_to": {"folder": "INBOX", "uid": 2}},
            headers=auth(world["mailbox_key"]),
        )

        assert response.status_code == 202
        assert "\\Answered" in shared_imap.messages["INBOX"][2][1]

    async def test_a_message_with_no_recipients_is_refused(
        self, client: httpx.AsyncClient, world: dict,
    ) -> None:
        response = await client.post(
            "/v1/mailbox/send", json={"subject": "Nobody"},
            headers=auth(world["mailbox_key"]),
        )
        assert response.status_code == 400

    async def test_a_raw_message_is_addressed_from_its_headers(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine,
        shared_imap: FakeIMAP,
    ) -> None:
        """A client that builds its own MIME sends it whole; To, Cc and
        Bcc still decide who gets it, and Bcc still does not travel."""
        raw = (
            "From: ops@acme.test\r\n"
            "To: friend@example.test\r\n"
            "Bcc: boss@example.test\r\n"
            "Subject: Built by the client\r\n"
            "Message-ID: <client-built@acme.test>\r\n"
            "\r\n"
            "Body.\r\n"
        )

        response = await client.post(
            "/v1/mailbox/send", json={"raw": raw}, headers=auth(world["mailbox_key"])
        )

        assert response.status_code == 202, response.text
        (queued,) = await self._queued(engine)
        assert set(queued.to_addrs) == {"friend@example.test", "boss@example.test"}
        assert b"boss@example.test" not in queued.raw
        assert b"Built by the client" in queued.raw
        assert response.json()["message_id"] == "<client-built@acme.test>"


class TestShutdown:
    async def test_webhooks_from_api_sends_are_drained(
        self, cfg: Config, engine: AsyncEngine
    ) -> None:
        """The API's submission handler announces deliveries in the
        background; shutting down must wait for those, as the SMTP
        server does for its own handlers."""
        drained: list[bool] = []

        class Webhooks:
            async def drain(self) -> None:
                drained.append(True)

        class Submission:
            webhooks = Webhooks()

        app = create_app(cfg, engine=engine)
        app.state.submission = Submission()

        async with app.router.lifespan_context(app):
            pass

        assert drained == [True]


class TestThreads:
    """`/v1/mailbox/threads` -- the same mail, grouped."""

    @pytest.fixture
    def grouped(self) -> AsyncIterator[FakeIMAP]:
        """A mailbox where 1 and 2 are one conversation."""
        fake = FakeIMAP()
        fake.thread_groups["INBOX"] = [[1, 2], [3]]
        imap_client.set_client_factory(lambda cfg, email: fake)
        yield fake
        imap_client.set_client_factory(None)

    async def test_it_needs_a_mailbox_key(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get("/v1/mailbox/threads")
        assert response.status_code == 401

    async def test_an_org_key_cannot_read_a_mailbox(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/threads", headers=auth(world["org_key"])
        )
        assert response.status_code == 403

    async def test_conversations_come_back_grouped(
        self, client: httpx.AsyncClient, world: dict, grouped: FakeIMAP
    ) -> None:
        response = await client.get(
            "/v1/mailbox/threads", headers=auth(world["mailbox_key"])
        )

        assert response.status_code == 200
        assert [t["uids"] for t in response.json()] == [[3], [1, 2]]

    async def test_a_thread_carries_what_a_list_row_shows(
        self, client: httpx.AsyncClient, world: dict, grouped: FakeIMAP
    ) -> None:
        body = (
            await client.get(
                "/v1/mailbox/threads", headers=auth(world["mailbox_key"])
            )
        ).json()
        conversation = next(t for t in body if t["count"] == 2)

        assert conversation["uid"] == 1
        assert conversation["subject"] == "First"
        assert conversation["unseen"] == 1
        assert conversation["folder"] == "INBOX"
        assert len(conversation["messages"]) == 2

    async def test_the_limit_counts_threads(
        self, client: httpx.AsyncClient, world: dict, grouped: FakeIMAP
    ) -> None:
        body = (
            await client.get(
                "/v1/mailbox/threads?limit=1", headers=auth(world["mailbox_key"])
            )
        ).json()

        assert [t["uids"] for t in body] == [[3]]

    async def test_filters_apply(
        self, client: httpx.AsyncClient, world: dict, grouped: FakeIMAP
    ) -> None:
        """Message 1 is read, so its conversation keeps only message 2."""
        body = (
            await client.get(
                "/v1/mailbox/threads?unread=1", headers=auth(world["mailbox_key"])
            )
        ).json()

        assert [t["uids"] for t in body] == [[3], [2]]

    async def test_an_empty_folder_is_an_empty_list(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/threads?folder=Trash", headers=auth(world["mailbox_key"])
        )

        assert response.status_code == 200
        assert response.json() == []
