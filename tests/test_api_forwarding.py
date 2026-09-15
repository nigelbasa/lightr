"""/v1/mailbox/forwarding: a mailbox forwarding itself.

Checked by what routing then does with the address, not only by what
the endpoint answers -- a setting that is saved but never consulted is
the failure this engine has had before.
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
from lightr.mail.routing import Disposition, Router
from lightr.models import Account, Alias, AliasType, Domain, Organization
from lightr.repo import AccountRepo, AliasRepo, DomainRepo, OrganizationRepo


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
    return {"domain": domain, "mine": mine, "theirs": theirs}


@pytest_asyncio.fixture
async def client(cfg: Config, engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(cfg, engine=engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def auth(secret: str) -> dict[str, str]:
    return {"X-API-Key": secret}


async def _route(engine: AsyncEngine, address: str):
    async with engine.begin() as conn:
        return await Router(conn).route(address)


class TestForwarding:
    async def test_off_by_default(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.get("/v1/mailbox/forwarding", headers=auth(world["mine"]))
        assert response.json()["enabled"] is False

    async def test_turning_it_on_makes_routing_forward_and_keep_a_copy(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        response = await client.put(
            "/v1/mailbox/forwarding",
            json={"destinations": ["me@gmail.test"]},
            headers=auth(world["mine"]),
        )

        assert response.status_code == 200, response.text
        assert response.json() == {
            "enabled": True, "destinations": ["me@gmail.test"],
            "keeps_copy": True, "replies_routed": True,
        }
        route = await _route(engine, "ops@acme.test")
        assert route.disposition is Disposition.ALIAS_BRIDGE
        assert route.mailbox == "ops@acme.test"
        assert route.forward_to == ["me@gmail.test"]

    async def test_changing_it_replaces_the_destinations(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        headers = auth(world["mine"])
        await client.put("/v1/mailbox/forwarding",
                         json={"destinations": ["one@gmail.test"]}, headers=headers)
        await client.put("/v1/mailbox/forwarding",
                         json={"destinations": ["two@gmail.test"]}, headers=headers)

        assert (await _route(engine, "ops@acme.test")).forward_to == ["two@gmail.test"]

    async def test_turning_it_off_restores_plain_delivery(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        headers = auth(world["mine"])
        await client.put("/v1/mailbox/forwarding",
                         json={"destinations": ["me@gmail.test"]}, headers=headers)

        response = await client.delete("/v1/mailbox/forwarding", headers=headers)

        assert response.status_code == 204
        assert (await _route(engine, "ops@acme.test")).disposition is Disposition.LOCAL

    async def test_an_operators_plain_forward_is_upgraded_not_duplicated(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        async with engine.begin() as conn:
            await AliasRepo(conn).create(
                Alias(domain_id=world["domain"].id, source="ops",
                      destinations=["old@example.test"], type=AliasType.FORWARD)
            )

        await client.put("/v1/mailbox/forwarding",
                         json={"destinations": ["me@gmail.test"]},
                         headers=auth(world["mine"]))

        async with engine.begin() as conn:
            aliases = await AliasRepo(conn).list(domain_id=world["domain"].id)
        assert [(a.source, a.type) for a in aliases] == [("ops", AliasType.BRIDGE)]

    @pytest.mark.parametrize(
        "body",
        [
            {"destinations": []},
            {"destinations": ["ops@acme.test"]},
            {"destinations": [f"a{n}@example.test" for n in range(11)]},
            {"destinations": ["x@example.test"], "type": "forward"},
        ],
    )
    async def test_bad_settings_are_refused(
        self, client: httpx.AsyncClient, world: dict, body: dict
    ) -> None:
        response = await client.put(
            "/v1/mailbox/forwarding", json=body, headers=auth(world["mine"])
        )
        assert response.status_code == 400

    async def test_it_only_ever_touches_the_keys_own_address(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        await client.put("/v1/mailbox/forwarding",
                         json={"destinations": ["me@gmail.test"]},
                         headers=auth(world["theirs"]))

        assert (await _route(engine, "ops@acme.test")).disposition is Disposition.LOCAL
        assert (
            await _route(engine, "other@acme.test")
        ).disposition is Disposition.ALIAS_BRIDGE
