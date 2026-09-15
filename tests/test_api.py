"""The HTTP API: routing, auth, and scoping."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.api.app import create_app
from lightr.apikeys import APIKeyRepo, KeyType
from lightr.config import Config
from lightr.models import Account, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    """Two organizations, so cross-tenant access can be tested."""
    async with engine.begin() as conn:
        orgs, domains, accounts, keys = (
            OrganizationRepo(conn), DomainRepo(conn), AccountRepo(conn), APIKeyRepo(conn)
        )
        acme = await orgs.create(Organization(name="Acme"))
        globex = await orgs.create(Organization(name="Globex"))

        acme_domain = await domains.create(Domain(org_id=acme.id, name="acme.test"))
        globex_domain = await domains.create(Domain(org_id=globex.id, name="globex.test"))

        await accounts.create(Account(domain_id=acme_domain.id, local_part="ops"))

        _, admin_secret = await keys.create("root", key_type=KeyType.ADMIN)
        _, acme_secret = await keys.create("acme-ci", organization_id=acme.id)
        revoked, revoked_secret = await keys.create("old", organization_id=acme.id)
        await keys.revoke(revoked.id)

    return {
        "acme": acme, "globex": globex,
        "acme_domain": acme_domain, "globex_domain": globex_domain,
        "admin_key": admin_secret, "acme_key": acme_secret,
        "revoked_key": revoked_secret,
    }


@pytest_asyncio.fixture
async def client(cfg: Config, engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(cfg, engine=engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def auth(secret: str) -> dict[str, str]:
    return {"X-API-Key": secret}


class TestHealth:
    async def test_is_public(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_reports_the_version(self, client: httpx.AsyncClient) -> None:
        from lightr import __version__

        assert (await client.get("/health")).json()["version"] == __version__


class TestAuthentication:
    async def test_missing_key_is_401(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.get("/v1/domains")
        assert response.status_code == 401
        assert "X-API-Key" in response.json()["error"]

    async def test_invalid_key_is_401(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.get("/v1/domains", headers=auth("lk_nonsense"))
        assert response.status_code == 401

    async def test_revoked_key_is_401(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.get("/v1/domains", headers=auth(world["revoked_key"]))
        assert response.status_code == 401

    async def test_bearer_scheme_is_accepted(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """The Go engine accepted both; existing clients must keep working."""
        response = await client.get(
            "/v1/domains", headers={"Authorization": f"Bearer {world['admin_key']}"}
        )
        assert response.status_code == 200

    async def test_x_api_key_is_accepted(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        assert (
            await client.get("/v1/domains", headers=auth(world["admin_key"]))
        ).status_code == 200

    async def test_key_use_is_recorded(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        await client.get("/v1/domains", headers=auth(world["acme_key"]))

        async with engine.begin() as conn:
            key = await APIKeyRepo(conn).resolve("acme-ci")
        assert key.usage_count >= 1


class TestScoping:
    """An org-scoped key must not see another organization."""

    async def test_admin_sees_every_domain(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        body = (await client.get("/v1/domains", headers=auth(world["admin_key"]))).json()
        assert {d["name"] for d in body} == {"acme.test", "globex.test"}

    async def test_org_key_sees_only_its_own(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        body = (await client.get("/v1/domains", headers=auth(world["acme_key"]))).json()
        assert {d["name"] for d in body} == {"acme.test"}

    async def test_org_key_cannot_read_another_orgs_domain(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            f"/v1/domains/{world['globex_domain'].id}", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_org_key_cannot_read_another_org(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            f"/v1/orgs/{world['globex'].id}", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_org_key_may_read_its_own_org(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            f"/v1/orgs/{world['acme'].id}", headers=auth(world["acme_key"])
        )
        assert response.status_code == 200

    async def test_org_key_cannot_create_an_org(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/orgs", json={"name": "Sneaky"}, headers=auth(world["acme_key"])
        )
        assert response.status_code == 403
        assert "admin" in response.json()["error"]

    async def test_org_key_cannot_mint_api_keys(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/apikeys", json={"name": "escalate"}, headers=auth(world["acme_key"])
        )
        assert response.status_code == 403


class TestResources:
    async def test_create_and_read_a_domain(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        created = await client.post(
            "/v1/domains",
            json={"name": "new.test", "org_id": str(world["acme"].id)},
            headers=auth(world["admin_key"]),
        )
        assert created.status_code == 201

        fetched = await client.get(
            f"/v1/domains/{created.json()['id']}", headers=auth(world["admin_key"])
        )
        assert fetched.json()["name"] == "new.test"

    async def test_duplicate_domain_is_409(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/domains", json={"name": "acme.test"}, headers=auth(world["admin_key"])
        )
        assert response.status_code == 409

    async def test_invalid_domain_name_is_400(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/domains",
            json={"name": "no-dot", "org_id": str(world["acme"].id)},
            headers=auth(world["admin_key"]),
        )
        assert response.status_code == 400

    async def test_ambiguous_org_is_reported(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """With more than one org, an admin key must say which."""
        response = await client.post(
            "/v1/domains", json={"name": "orphan.test"}, headers=auth(world["admin_key"])
        )
        assert response.status_code == 409
        assert "organization" in response.json()["error"]

    async def test_org_key_infers_its_own_org(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """A scoped key never has to state the org -- it has only one."""
        response = await client.post(
            "/v1/domains", json={"name": "inferred.test"}, headers=auth(world["acme_key"])
        )
        assert response.status_code == 201
        assert response.json()["org_id"] == str(world["acme"].id)

    async def test_missing_field_is_400_and_names_it(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/domains", json={}, headers=auth(world["admin_key"])
        )
        assert response.status_code == 400
        assert "name" in response.json()["error"]

    async def test_non_json_body_is_400(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/domains", content=b"not json", headers=auth(world["admin_key"])
        )
        assert response.status_code == 400

    async def test_unknown_domain_is_404(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            "/v1/domains/nope.test", headers=auth(world["admin_key"])
        )
        assert response.status_code == 404

    async def test_domain_with_accounts_is_409(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.delete(
            f"/v1/domains/{world['acme_domain'].id}", headers=auth(world["admin_key"])
        )
        assert response.status_code == 409
        assert "account" in response.json()["error"]

    async def test_create_an_account(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/accounts",
            json={"email": "new@acme.test", "display_name": "New"},
            headers=auth(world["admin_key"]),
        )
        assert response.status_code == 201
        assert response.json()["email"] == "new@acme.test"

    async def test_account_without_a_domain_part_is_400(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/accounts", json={"email": "bare"}, headers=auth(world["admin_key"])
        )
        assert response.status_code == 400

    async def test_account_lookup_by_email(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """The API takes the same references the CLI does."""
        response = await client.get(
            "/v1/accounts/ops@acme.test", headers=auth(world["admin_key"])
        )
        assert response.status_code == 200

    async def test_create_an_alias(self, client: httpx.AsyncClient, world: dict) -> None:
        response = await client.post(
            "/v1/aliases",
            json={"source": "sales@acme.test", "destinations": ["ops@acme.test"]},
            headers=auth(world["admin_key"]),
        )
        assert response.status_code == 201
        assert response.json()["destinations"] == ["ops@acme.test"]


class TestSecretHandling:
    async def test_password_is_never_returned(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/accounts",
            json={"email": "secret@acme.test", "password": "correct-horse-battery"},
            headers=auth(world["admin_key"]),
        )
        body = response.json()
        assert body["password_hash"] == "(set)"
        assert "correct-horse-battery" not in response.text

    async def test_api_key_hash_is_never_listed(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        body = (await client.get("/v1/apikeys", headers=auth(world["admin_key"]))).json()
        assert all(k["key_hash"] == "(set)" for k in body)

    async def test_new_key_is_shown_exactly_once(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        created = await client.post(
            "/v1/apikeys",
            json={"name": "deploy", "org_id": str(world["acme"].id)},
            headers=auth(world["admin_key"]),
        )
        secret = created.json()["key"]
        assert secret.startswith("lk_")

        listed = (await client.get("/v1/apikeys", headers=auth(world["admin_key"]))).json()
        assert all("key" not in k for k in listed)

    async def test_rotation_returns_a_new_secret(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        created = await client.post(
            "/v1/apikeys",
            json={"name": "rotate-me", "org_id": str(world["acme"].id)},
            headers=auth(world["admin_key"]),
        )
        old = created.json()["key"]

        rotated = await client.post(
            f"/v1/apikeys/{created.json()['id']}/rotate",
            headers=auth(world["admin_key"]),
        )
        new = rotated.json()["key"]
        assert new != old

        # The old secret must stop working.
        assert (await client.get("/v1/domains", headers=auth(old))).status_code == 401
        assert (await client.get("/v1/domains", headers=auth(new))).status_code == 200


class TestRouteTable:
    def test_every_route_is_registered_once(self) -> None:
        from lightr.api.app import ROUTES

        # A WebSocketRoute has no `methods`; it is one path, one handler.
        seen = [
            (r.path, tuple(sorted(getattr(r, "methods", None) or ()))) for r in ROUTES
        ]
        assert len(seen) == len(set(seen))

    def test_the_live_updates_socket_is_registered(self) -> None:
        from lightr.api.app import ROUTES
        from lightr.api.events import PATH

        assert PATH in [r.path for r in ROUTES if not getattr(r, "methods", None)]

    async def test_unknown_path_is_404(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get("/v1/nonsense", headers=auth(world["admin_key"]))
        assert response.status_code == 404

    @pytest.mark.parametrize(
        "path", ["/v1/orgs", "/v1/domains", "/v1/accounts", "/v1/aliases", "/v1/apikeys"]
    )
    async def test_every_collection_requires_auth(
        self, client: httpx.AsyncClient, world: dict, path: str
    ) -> None:
        assert (await client.get(path)).status_code == 401


class TestCrossTenant:
    """An org key reaching into another organization's accounts and
    aliases.

    Domains were scoped; the records under them were not.
    `may_reach_account` answered True for any org-scoped key ("narrower
    scopes are checked above"), and nothing above checked. Alias list
    and delete checked nothing at all.
    """

    @pytest_asyncio.fixture
    async def globex(self, engine: AsyncEngine, world: dict) -> dict:
        from lightr.models import Alias
        from lightr.repo import AliasRepo

        async with engine.begin() as conn:
            account = await AccountRepo(conn).create(
                Account(domain_id=world["globex_domain"].id, local_part="ceo")
            )
            alias = await AliasRepo(conn).create(
                Alias(domain_id=world["globex_domain"].id, source="sales",
                      destinations=["ceo@globex.test"])
            )
        return {"account": account, "alias": alias}

    async def test_cannot_read_another_orgs_account(
        self, client: httpx.AsyncClient, world: dict, globex: dict
    ) -> None:
        response = await client.get(
            f"/v1/accounts/{globex['account'].id}", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_cannot_change_another_orgs_account(
        self, client: httpx.AsyncClient, world: dict, globex: dict,
        engine: AsyncEngine,
    ) -> None:
        response = await client.patch(
            f"/v1/accounts/{globex['account'].id}", json={"can_send": False},
            headers=auth(world["acme_key"]),
        )
        assert response.status_code == 403
        async with engine.begin() as conn:
            account = await AccountRepo(conn).resolve(str(globex["account"].id))
        assert account.can_send is True

    async def test_cannot_delete_another_orgs_account(
        self, client: httpx.AsyncClient, world: dict, globex: dict,
        engine: AsyncEngine,
    ) -> None:
        response = await client.delete(
            f"/v1/accounts/{globex['account'].id}", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403
        async with engine.begin() as conn:
            assert await AccountRepo(conn).find("ceo@globex.test") is not None

    async def test_account_list_is_confined_to_the_org(
        self, client: httpx.AsyncClient, world: dict, globex: dict
    ) -> None:
        body = (await client.get("/v1/accounts", headers=auth(world["acme_key"]))).json()
        assert {a["email"] for a in body} == {"ops@acme.test"}

    async def test_alias_list_is_confined_to_the_org(
        self, client: httpx.AsyncClient, world: dict, globex: dict
    ) -> None:
        body = (await client.get("/v1/aliases", headers=auth(world["acme_key"]))).json()
        assert body == []

    async def test_alias_list_by_another_orgs_domain_is_refused(
        self, client: httpx.AsyncClient, world: dict, globex: dict
    ) -> None:
        response = await client.get(
            "/v1/aliases?domain=globex.test", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_cannot_delete_another_orgs_alias(
        self, client: httpx.AsyncClient, world: dict, globex: dict
    ) -> None:
        response = await client.delete(
            f"/v1/aliases/{globex['alias'].id}", headers=auth(world["acme_key"])
        )
        assert response.status_code == 403

    async def test_admin_still_sees_everything(
        self, client: httpx.AsyncClient, world: dict, globex: dict
    ) -> None:
        accounts = (await client.get("/v1/accounts",
                                     headers=auth(world["admin_key"]))).json()
        assert "ceo@globex.test" in {a["email"] for a in accounts}


class TestAliasUpdates:
    """Changing where an alias goes -- including turning a forward into
    a bridge that keeps a copy -- without deleting and recreating it."""

    @pytest_asyncio.fixture
    async def alias_id(self, client: httpx.AsyncClient, world: dict) -> str:
        created = await client.post(
            "/v1/aliases",
            json={"source": "sales@acme.test", "destinations": ["ops@acme.test"]},
            headers=auth(world["acme_key"]),
        )
        return created.json()["id"]

    async def test_destinations_and_type_can_change(
        self, client: httpx.AsyncClient, world: dict, alias_id: str
    ) -> None:
        response = await client.patch(
            f"/v1/aliases/{alias_id}",
            json={"destinations": ["a@example.test", "b@example.test"],
                  "type": "bridge"},
            headers=auth(world["acme_key"]),
        )
        assert response.status_code == 200, response.text
        assert response.json()["destinations"] == ["a@example.test", "b@example.test"]
        assert response.json()["type"] == "bridge"

    async def test_it_can_be_switched_off(
        self, client: httpx.AsyncClient, world: dict, alias_id: str
    ) -> None:
        response = await client.patch(
            f"/v1/aliases/{alias_id}", json={"is_active": False},
            headers=auth(world["acme_key"]),
        )
        assert response.json()["is_active"] is False

    @pytest.mark.parametrize(
        "body",
        [
            {"destinations": []},
            {"destinations": "ops@acme.test"},
            {"destinations": ["not-an-address"]},
            {"type": "teleport"},
            {"is_active": "no"},
            {"source": "other"},
        ],
    )
    async def test_bad_changes_are_refused(
        self, client: httpx.AsyncClient, world: dict, alias_id: str, body: dict
    ) -> None:
        response = await client.patch(
            f"/v1/aliases/{alias_id}", json=body, headers=auth(world["acme_key"])
        )
        assert response.status_code == 400
