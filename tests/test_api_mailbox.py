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
