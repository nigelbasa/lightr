"""The webhook management routes.

Two failures matter more than the rest of this surface: handing a
signing secret to a key that should not have it, and letting one tenant
see or edit another's endpoints. Both get their own tests.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.api.app import create_app
from lightr.apikeys import APIKeyRepo, KeyType
from lightr.config import Config
from lightr.models import Organization
from lightr.repo import OrganizationRepo
from lightr.webhooks.delivery import WebhookRepo


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    """Two organizations, each with its own webhook, plus a global one."""
    async with engine.begin() as conn:
        orgs, keys = OrganizationRepo(conn), APIKeyRepo(conn)
        acme = await orgs.create(Organization(name="Acme"))
        globex = await orgs.create(Organization(name="Globex"))

        hooks = WebhookRepo(conn)
        await hooks.create(
            "acme-hook", "https://acme.example.test/h", organization_id=acme.id
        )
        await hooks.create(
            "globex-hook", "https://globex.example.test/h", organization_id=globex.id
        )
        # No organization: the operator's own, not a tenant's.
        await hooks.create("server-hook", "https://ops.example.test/h")

        _, admin_secret = await keys.create("root", key_type=KeyType.ADMIN)
        _, acme_secret = await keys.create("acme-ci", organization_id=acme.id)

    return {"admin_key": admin_secret, "acme_key": acme_secret}


@pytest_asyncio.fixture
async def client(cfg: Config, engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(cfg, engine=engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def auth(secret: str) -> dict[str, str]:
    return {"X-API-Key": secret}


class TestSecrets:
    async def test_a_listing_never_carries_the_signing_secret(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """It is stored in the clear because HMAC needs it, which is
        exactly why it must not be readable over the wire: it would let
        the holder forge every event this server sends."""
        response = await client.get("/v1/webhooks", headers=auth(world["admin_key"]))

        assert response.status_code == 200
        for hook in response.json():
            assert hook["secret"] == "(set)"

    async def test_a_get_never_carries_it_either(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/webhooks/acme-hook", headers=auth(world["admin_key"])
        )
        assert response.json()["secret"] == "(set)"

    async def test_creation_returns_it_once(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """A receiver cannot verify anything without it, so it is shown
        exactly once, at the moment there is somewhere to put it."""
        response = await client.post(
            "/v1/webhooks",
            headers=auth(world["admin_key"]),
            json={"name": "new", "url": "https://new.example.test/h"},
        )

        assert response.status_code == 201
        assert len(response.json()["secret"]) >= 32

    async def test_rotation_returns_the_new_one(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/webhooks/acme-hook/rotate", headers=auth(world["admin_key"])
        )
        assert len(response.json()["secret"]) >= 32


class TestScoping:
    async def test_a_scoped_key_sees_only_its_own(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get("/v1/webhooks", headers=auth(world["acme_key"]))

        names = {h["name"] for h in response.json()}
        assert names == {"acme-hook"}

    async def test_a_scoped_key_cannot_read_another_tenants(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/webhooks/globex-hook", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_a_scoped_key_cannot_read_the_operators_own(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """A webhook with no organization belongs to whoever runs the
        server, not to any tenant on it."""
        response = await client.get(
            "/v1/webhooks/server-hook", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_a_scoped_key_cannot_delete_another_tenants(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.delete(
            "/v1/webhooks/globex-hook", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_what_a_scoped_key_creates_lands_in_its_own_org(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        await client.post(
            "/v1/webhooks",
            headers=auth(world["acme_key"]),
            json={"name": "theirs", "url": "https://theirs.example.test/h"},
        )

        listed = await client.get("/v1/webhooks", headers=auth(world["acme_key"]))
        assert {h["name"] for h in listed.json()} == {"acme-hook", "theirs"}

    async def test_an_admin_key_sees_everything(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get("/v1/webhooks", headers=auth(world["admin_key"]))
        assert len(response.json()) == 3


class TestCRUD:
    async def test_addressable_by_name(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """No route should force the caller to know a UUID."""
        response = await client.get(
            "/v1/webhooks/acme-hook", headers=auth(world["admin_key"])
        )
        assert response.status_code == 200

    async def test_an_unknown_webhook_is_404(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/webhooks/nope", headers=auth(world["admin_key"])
        )
        assert response.status_code == 404

    async def test_a_patch_changes_only_what_it_names(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.patch(
            "/v1/webhooks/acme-hook",
            headers=auth(world["admin_key"]),
            json={"url": "https://moved.example.test/h"},
        )

        assert response.status_code == 200
        assert response.json()["url"] == "https://moved.example.test/h"
        assert response.json()["name"] == "acme-hook"

    async def test_a_bad_url_is_400_not_500(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/webhooks",
            headers=auth(world["admin_key"]),
            json={"name": "bad", "url": "file:///etc/passwd"},
        )
        assert response.status_code == 400
        assert "scheme" in response.json()["error"]

    async def test_a_misspelt_event_is_400(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/webhooks",
            headers=auth(world["admin_key"]),
            json={
                "name": "typo",
                "url": "https://x.example.test/h",
                "events": ["mail.recieved"],
            },
        )
        assert response.status_code == 400

    async def test_missing_fields_are_named(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/webhooks", headers=auth(world["admin_key"]), json={"name": "x"}
        )
        assert response.status_code == 400
        assert "url" in response.json()["error"]

    async def test_delete_removes_it(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        assert (
            await client.delete(
                "/v1/webhooks/acme-hook", headers=auth(world["admin_key"])
            )
        ).status_code == 204

        remaining = await client.get("/v1/webhooks", headers=auth(world["admin_key"]))
        assert "acme-hook" not in {h["name"] for h in remaining.json()}


class TestDeliveries:
    async def test_the_log_is_readable(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        from lightr.webhooks.delivery import Attempt

        async with engine.begin() as conn:
            repo = WebhookRepo(conn)
            hook = await repo.resolve("acme-hook")
            await repo.record(hook.id, "mail.sent", {}, Attempt(ok=True, status_code=200))

        response = await client.get(
            "/v1/webhooks/acme-hook/deliveries", headers=auth(world["admin_key"])
        )

        assert response.status_code == 200
        assert response.json()["stats"]["delivered"] == 1
        assert len(response.json()["deliveries"]) == 1


class TestTestFire:
    async def test_an_unreachable_receiver_reports_502_not_success(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """The point of a test fire is to find out it does not work."""
        response = await client.post(
            "/v1/webhooks/acme-hook/test", headers=auth(world["admin_key"])
        )

        assert response.status_code == 502
        assert response.json()["ok"] is False

    async def test_a_failed_test_is_recorded(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        await client.post(
            "/v1/webhooks/acme-hook/test", headers=auth(world["admin_key"])
        )

        log = await client.get(
            "/v1/webhooks/acme-hook/deliveries", headers=auth(world["admin_key"])
        )
        assert log.json()["deliveries"][0]["event_type"] == "ping"


@pytest.fixture(autouse=True)
def _no_real_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test fires must not leave the machine."""
    import socket

    def refuse(*args: object, **kwargs: object):
        raise socket.gaierror("blocked in tests")

    monkeypatch.setattr("lightr.webhooks.ssrf.socket.getaddrinfo", refuse)
