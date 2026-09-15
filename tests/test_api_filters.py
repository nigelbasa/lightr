"""The /v1/mailbox/filters routes.

What matters: a rule that will not compile is never stored, a change
that cannot be installed is rolled back, and one mailbox's key never
sees or touches another's rules.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine
from tests.test_sieve_install import NoDoveadm

from lightr.api.app import create_app
from lightr.apikeys import APIKeyRepo, KeyType
from lightr.config import Config
from lightr.dovecot.sieve_install import script_path
from lightr.models import Account, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        accounts = AccountRepo(conn)
        ops = await accounts.create(Account(domain_id=domain.id, local_part="ops"))
        other = await accounts.create(Account(domain_id=domain.id, local_part="other"))
        keys = APIKeyRepo(conn)
        _, mine = await keys.create("ops", key_type=KeyType.ACCOUNT, account_id=ops.id)
        _, theirs = await keys.create(
            "other", key_type=KeyType.ACCOUNT, account_id=other.id
        )
        _, org_key = await keys.create("org", organization_id=org.id)
    return {"mine": mine, "theirs": theirs, "org_key": org_key}


@pytest_asyncio.fixture
async def client(cfg: Config, engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(cfg, engine=engine)
    app.state.doveadm = NoDoveadm()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def auth(secret: str) -> dict[str, str]:
    return {"X-API-Key": secret}


RECEIPTS = {
    "name": "Receipts",
    "conditions": [{"field": "from", "operator": "contains", "value": "bank.test"}],
    "actions": [{"type": "file_into", "value": "Receipts"}],
}


def _installed(cfg: Config) -> str:
    return script_path(cfg.dovecot.sieve_dir, "ops@acme.test").read_text()


class TestCreating:
    async def test_a_rule_is_stored_and_installed(
        self, client: httpx.AsyncClient, world: dict, cfg: Config
    ) -> None:
        response = await client.post(
            "/v1/mailbox/filters", json=RECEIPTS, headers=auth(world["mine"])
        )

        assert response.status_code == 201, response.text
        rule = response.json()
        assert rule["name"] == "Receipts"
        assert rule["conditions"] == RECEIPTS["conditions"]
        assert '"Receipts"' in _installed(cfg)

    async def test_an_unknown_operator_is_refused_and_not_stored(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        bad = {**RECEIPTS, "conditions": [
            {"field": "from", "operator": "sounds_like", "value": "x"}
        ]}
        response = await client.post(
            "/v1/mailbox/filters", json=bad, headers=auth(world["mine"])
        )

        assert response.status_code == 400
        listing = await client.get("/v1/mailbox/filters", headers=auth(world["mine"]))
        assert listing.json() == []

    async def test_redirect_is_not_available(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """It would send mail off the server past everything forwarding
        does to stay deliverable."""
        rule = {**RECEIPTS, "actions": [
            {"type": "redirect", "value": "me@elsewhere.test"}
        ]}
        response = await client.post(
            "/v1/mailbox/filters", json=rule, headers=auth(world["mine"])
        )

        assert response.status_code == 400
        assert "forwarding" in response.json()["error"]

    async def test_unknown_fields_are_refused(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/mailbox/filters", json={**RECEIPTS, "account_id": "someone-else"},
            headers=auth(world["mine"]),
        )
        assert response.status_code == 400

    async def test_a_change_that_cannot_be_installed_is_rolled_back(
        self, client: httpx.AsyncClient, world: dict, cfg: Config, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("")
        cfg.dovecot.sieve_dir = blocker

        response = await client.post(
            "/v1/mailbox/filters", json=RECEIPTS, headers=auth(world["mine"])
        )

        assert response.status_code == 502
        listing = await client.get("/v1/mailbox/filters", headers=auth(world["mine"]))
        assert listing.json() == []


class TestChanging:
    async def _create(self, client: httpx.AsyncClient, key: str) -> str:
        response = await client.post("/v1/mailbox/filters", json=RECEIPTS,
                                     headers=auth(key))
        return response.json()["id"]

    async def test_patch_keeps_what_it_does_not_mention(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        rule_id = await self._create(client, world["mine"])

        response = await client.patch(
            f"/v1/mailbox/filters/{rule_id}", json={"name": "Bank"},
            headers=auth(world["mine"]),
        )

        assert response.status_code == 200, response.text
        assert response.json()["name"] == "Bank"
        assert response.json()["actions"] == RECEIPTS["actions"]

    async def test_switching_a_rule_off_reinstalls_the_script(
        self, client: httpx.AsyncClient, world: dict, cfg: Config
    ) -> None:
        rule_id = await self._create(client, world["mine"])

        await client.patch(
            f"/v1/mailbox/filters/{rule_id}", json={"is_active": False},
            headers=auth(world["mine"]),
        )

        assert "No active rules" in _installed(cfg)

    async def test_delete(self, client: httpx.AsyncClient, world: dict, cfg: Config) -> None:
        rule_id = await self._create(client, world["mine"])

        response = await client.delete(
            f"/v1/mailbox/filters/{rule_id}", headers=auth(world["mine"])
        )

        assert response.status_code == 204
        assert "No active rules" in _installed(cfg)

    async def test_the_script_can_be_read(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        await self._create(client, world["mine"])

        response = await client.get(
            "/v1/mailbox/filters/script", headers=auth(world["mine"])
        )

        assert response.status_code == 200
        assert "fileinto" in response.text


class TestScoping:
    async def test_another_mailbox_cannot_see_or_touch_a_rule(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        created = await client.post(
            "/v1/mailbox/filters", json=RECEIPTS, headers=auth(world["mine"])
        )
        rule_id = created.json()["id"]
        theirs = auth(world["theirs"])

        assert (await client.get("/v1/mailbox/filters", headers=theirs)).json() == []
        assert (
            await client.get(f"/v1/mailbox/filters/{rule_id}", headers=theirs)
        ).status_code == 404
        assert (
            await client.patch(f"/v1/mailbox/filters/{rule_id}", json={"name": "x"},
                               headers=theirs)
        ).status_code == 404
        assert (
            await client.delete(f"/v1/mailbox/filters/{rule_id}", headers=theirs)
        ).status_code == 404

        mine = await client.get(f"/v1/mailbox/filters/{rule_id}",
                                headers=auth(world["mine"]))
        assert mine.json()["name"] == "Receipts"

    async def test_an_org_key_is_not_a_mailbox(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/mailbox/filters", headers=auth(world["org_key"])
        )
        assert response.status_code == 403

    async def test_a_malformed_id_is_just_not_found(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.delete(
            "/v1/mailbox/filters/not-a-uuid", headers=auth(world["mine"])
        )
        assert response.status_code == 404


class RejectingDoveadm:
    """A doveadm that is installed and refuses the compiled script --
    the failure a real server gives, which the file-writing fallback
    never exercises."""

    available = True

    async def install_sieve(self, user: str, script: str) -> None:
        from lightr.dovecot.doveadm import DoveadmError

        raise DoveadmError("sieve put", 75, "error: line 3: unknown extension")


class TestDovecotRejection:
    async def test_a_script_dovecot_refuses_is_rolled_back(
        self, cfg: Config, engine: AsyncEngine, world: dict
    ) -> None:
        app = create_app(cfg, engine=engine)
        app.state.doveadm = RejectingDoveadm()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            response = await c.post(
                "/v1/mailbox/filters", json=RECEIPTS, headers=auth(world["mine"])
            )
            listing = await c.get("/v1/mailbox/filters", headers=auth(world["mine"]))

        assert response.status_code == 400
        assert "unknown extension" in response.json()["error"]
        assert listing.json() == []
