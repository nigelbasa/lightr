"""Signing in to the mailbox API, sessions, and password changes.

A token handed to a mail client reaches one mailbox and nothing else;
guessing a password costs the guesser, never the person who mistypes;
and a changed password stops working everywhere at once -- other
devices, IMAP's cached login, all of it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.api.app import create_app
from lightr.api.session import SESSION_PREFIX, purge_expired
from lightr.apikeys import APIKeyRepo, KeyType
from lightr.auth import hash_password
from lightr.config import Config
from lightr.db import schema
from lightr.models import Account, AuthMode, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

PASSWORD = "correct-horse-battery"
NEW_PASSWORD = "a-new-and-longer-passphrase"


class RecordingDoveadm:
    available = True

    def __init__(self) -> None:
        self.flushed: list[str | None] = []

    async def auth_cache_flush(self, user: str | None = None) -> None:
        self.flushed.append(user)


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        orgs, domains, accounts = OrganizationRepo(conn), DomainRepo(conn), AccountRepo(conn)
        acme = await orgs.create(Organization(name="Acme"))
        globex = await orgs.create(Organization(name="Globex"))
        domain = await domains.create(Domain(org_id=acme.id, name="acme.test"))
        await domains.create(Domain(org_id=globex.id, name="globex.test"))
        hashed = hash_password(PASSWORD, rounds=4)
        ops = await accounts.create(
            Account(domain_id=domain.id, local_part="ops", password_hash=hashed)
        )
        await accounts.create(
            Account(domain_id=domain.id, local_part="off", password_hash=hashed,
                    auth_mode=AuthMode.DISABLED)
        )
        ext = await accounts.create(
            Account(domain_id=domain.id, local_part="ext", auth_mode=AuthMode.EXTERNAL)
        )
        keys = APIKeyRepo(conn)
        _, ops_key = await keys.create("ops-cli", key_type=KeyType.ACCOUNT, account_id=ops.id)
        _, ext_key = await keys.create("ext-cli", key_type=KeyType.ACCOUNT, account_id=ext.id)
    return {"ops": ops, "ops_key": ops_key, "ext_key": ext_key}


@pytest.fixture
def doveadm() -> RecordingDoveadm:
    return RecordingDoveadm()


@pytest_asyncio.fixture
async def client(
    cfg: Config, engine: AsyncEngine, doveadm: RecordingDoveadm
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(cfg, engine=engine)
    app.state.doveadm = doveadm
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def sign_in(
    client: httpx.AsyncClient, email: str = "ops@acme.test", password: str = PASSWORD,
    agent: str = "Test Mail/1.0",
) -> httpx.Response:
    return await client.post(
        "/v1/auth/session", json={"email": email, "password": password},
        headers={"User-Agent": agent},
    )


async def token(client: httpx.AsyncClient, **kwargs: str) -> str:
    response = await sign_in(client, **kwargs)
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


class TestSigningIn:
    async def test_the_right_password_returns_a_token_for_that_mailbox(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await sign_in(client)

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["account"]["email"] == "ops@acme.test"
        assert body["expires_at"].endswith("Z")

        sessions = await client.get("/v1/mailbox/sessions", headers=bearer(body["token"]))
        assert sessions.status_code == 200, sessions.text
        (session,) = sessions.json()
        assert session["current"] is True
        assert session["user_agent"] == "Test Mail/1.0"

    async def test_a_wrong_password_and_an_unknown_address_look_alike(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        wrong = await sign_in(client, password="not-the-password")
        unknown = await sign_in(client, email="nobody@acme.test")
        disabled = await sign_in(client, email="off@acme.test")

        assert wrong.status_code == unknown.status_code == disabled.status_code == 401
        assert wrong.json() == unknown.json() == disabled.json()

    async def test_a_directory_that_cannot_answer_is_not_a_wrong_password(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await sign_in(client, email="ext@acme.test")
        assert response.status_code == 503

    async def test_the_token_cannot_reach_the_operator_routes(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        secret = await token(client)
        for path in ("/v1/domains", "/v1/orgs", "/v1/accounts"):
            response = await client.get(path, headers=bearer(secret))
            assert response.status_code == 403, path

    async def test_guessing_one_mailbox_is_refused_before_it_is_tried(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        for _ in range(10):
            assert (await sign_in(client, password="guess")).status_code == 401

        refused = await sign_in(client, password=PASSWORD)
        assert refused.status_code == 429
        assert int(refused.headers["Retry-After"]) > 0

    async def test_a_person_who_mistypes_is_not_locked_out_by_it(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        for _ in range(8):
            await sign_in(client, password="typo")
        assert (await sign_in(client)).status_code == 201
        for _ in range(8):
            assert (await sign_in(client, password="typo")).status_code == 401


class TestSessions:
    async def test_signing_out_ends_the_token(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        secret = await token(client)

        assert (await client.delete("/v1/mailbox/session", headers=bearer(secret))
                ).status_code == 204
        assert (await client.get("/v1/mailbox/sessions", headers=bearer(secret))
                ).status_code == 401

    async def test_an_operator_key_is_not_signed_out_by_mistake(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.delete(
            "/v1/mailbox/session", headers=bearer(world["ops_key"])
        )
        assert response.status_code == 400
        assert "lightr apikey revoke" in response.text

    async def test_another_device_can_be_signed_out(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        phone = await token(client, agent="Phone")
        laptop = await token(client, agent="Laptop")

        listed = (await client.get("/v1/mailbox/sessions", headers=bearer(laptop))).json()
        (phone_session,) = [s for s in listed if s["user_agent"] == "Phone"]

        response = await client.delete(
            f"/v1/mailbox/sessions/{phone_session['id']}", headers=bearer(laptop)
        )
        assert response.status_code == 204
        assert (await client.get("/v1/mailbox/sessions", headers=bearer(phone))
                ).status_code == 401

    async def test_another_mailboxs_session_is_not_found(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        secret = await token(client)
        async with engine.begin() as conn:
            other, _ = await APIKeyRepo(conn).create(
                f"{SESSION_PREFIX}ext@acme.test", key_type=KeyType.ACCOUNT,
                account_id=(await AccountRepo(conn).resolve("ext@acme.test")).id,
            )

        response = await client.delete(
            f"/v1/mailbox/sessions/{other.id}", headers=bearer(secret)
        )
        assert response.status_code == 404


class TestChangingThePassword:
    async def test_it_changes_everywhere_at_once(
        self, client: httpx.AsyncClient, world: dict, doveadm: RecordingDoveadm
    ) -> None:
        other_device = await token(client, agent="Phone")
        this_device = await token(client, agent="Laptop")

        response = await client.post(
            "/v1/mailbox/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            headers=bearer(this_device),
        )

        assert response.status_code == 200, response.text
        assert response.json() == {
            "changed": True, "sessions_revoked": 1, "imap_cache_cleared": True,
        }
        assert doveadm.flushed == ["ops@acme.test"]
        assert (await client.get("/v1/mailbox/sessions", headers=bearer(this_device))
                ).status_code == 200
        assert (await client.get("/v1/mailbox/sessions", headers=bearer(other_device))
                ).status_code == 401
        assert (await sign_in(client)).status_code == 401
        assert (await sign_in(client, password=NEW_PASSWORD)).status_code == 201

    async def test_the_current_password_must_be_right(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        secret = await token(client)
        response = await client.post(
            "/v1/mailbox/password",
            json={"current_password": "wrong", "new_password": NEW_PASSWORD},
            headers=bearer(secret),
        )
        assert response.status_code == 403
        assert (await sign_in(client)).status_code == 201

    @pytest.mark.parametrize(
        ("new", "status", "says"),
        [("short", 400, "at least"), (PASSWORD, 400, "same as the current")],
    )
    async def test_a_new_password_that_will_not_do(
        self, client: httpx.AsyncClient, world: dict, new: str, status: int, says: str
    ) -> None:
        secret = await token(client)
        response = await client.post(
            "/v1/mailbox/password",
            json={"current_password": PASSWORD, "new_password": new},
            headers=bearer(secret),
        )
        assert response.status_code == status
        assert says in response.text

    async def test_an_externally_managed_password_is_not_changed_here(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/v1/mailbox/password",
            json={"current_password": "x", "new_password": NEW_PASSWORD},
            headers=bearer(world["ext_key"]),
        )
        assert response.status_code == 409


class TestNarrowKeysSeeNarrowly:
    async def test_an_account_key_without_an_organization_sees_only_its_own(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """Operator listings filtered by organization alone, so a key
        with none listed every tenant on the server."""
        orgs = await client.get("/v1/orgs", headers=bearer(world["ops_key"]))
        domains = await client.get("/v1/domains", headers=bearer(world["ops_key"]))

        assert orgs.status_code == 200 and orgs.json() == []
        assert [d["name"] for d in domains.json()] == ["acme.test"]


class TestCleanup:
    async def test_dead_sessions_are_purged_and_nothing_else(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.api.session import _now

        async with engine.begin() as conn:
            keys = APIKeyRepo(conn)
            ops_id = world["ops"].id
            live, _ = await keys.create(
                f"{SESSION_PREFIX}ops@acme.test", key_type=KeyType.ACCOUNT,
                account_id=ops_id, expires_at=_now() + timedelta(days=1),
            )
            expired, _ = await keys.create(
                f"{SESSION_PREFIX}ops@acme.test", key_type=KeyType.ACCOUNT,
                account_id=ops_id, expires_at=_now() - timedelta(minutes=1),
            )
            revoked, _ = await keys.create(
                f"{SESSION_PREFIX}ops@acme.test", key_type=KeyType.ACCOUNT, account_id=ops_id,
            )
            await keys.revoke(revoked.id)

            assert await purge_expired(conn) == 2
            remaining = {
                row.name if not row.name.startswith(SESSION_PREFIX) else str(row.id)
                for row in await conn.execute(select(schema.api_keys))
            }

        assert str(live.id) in remaining
        assert str(expired.id) not in remaining and str(revoked.id) not in remaining
        assert {"ops-cli", "ext-cli"} <= remaining
