"""The internal endpoints Dovecot's passdb/userdb Lua script calls.

These see plaintext passwords, so their security properties get tested
as carefully as their behaviour.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.api.app import create_app
from lightr.api.internal import AUTH_HEADER
from lightr.auth import hash_password
from lightr.config import Config
from lightr.models import Account, AuthMode, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

INTERNAL_KEY = "shared-secret-for-dovecot"
FAST_ROUNDS = 4


@pytest.fixture
def dovecot_cfg(cfg: Config) -> Config:
    cfg.dovecot.internal_key = INTERNAL_KEY
    return cfg


@pytest_asyncio.fixture
async def seeded(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        accounts = AccountRepo(conn)
        await accounts.create(
            Account(
                domain_id=domain.id,
                local_part="ops",
                password_hash=hash_password("correct-horse", rounds=FAST_ROUNDS),
                quota_bytes=2_147_483_648,
                maildir_path="/var/mail/lightr/acme.test/ops",
            )
        )
        await accounts.create(
            Account(
                domain_id=domain.id,
                local_part="ldapuser",
                auth_mode=AuthMode.EXTERNAL,
            )
        )
        await accounts.create(
            Account(domain_id=domain.id, local_part="nomaildir")
        )


@pytest_asyncio.fixture
async def client(
    dovecot_cfg: Config, engine: AsyncEngine, seeded: None
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(dovecot_cfg, engine=engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def internal() -> dict[str, str]:
    return {AUTH_HEADER: INTERNAL_KEY}


class TestSharedSecret:
    async def test_missing_secret_is_refused(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/verify",
            json={"username": "ops@acme.test", "password": "correct-horse"},
        )
        assert response.status_code == 403

    async def test_wrong_secret_is_refused(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/verify",
            json={"username": "ops@acme.test", "password": "correct-horse"},
            headers={AUTH_HEADER: "guess"},
        )
        assert response.status_code == 403

    async def test_an_api_key_does_not_open_these_routes(
        self, client: httpx.AsyncClient
    ) -> None:
        """An ordinary operator key must not reach the passdb."""
        response = await client.post(
            "/internal/auth/verify",
            json={"username": "ops@acme.test", "password": "correct-horse"},
            headers={"X-API-Key": "lk_whatever"},
        )
        assert response.status_code == 403

    async def test_unconfigured_secret_refuses_everything(
        self, cfg: Config, engine: AsyncEngine, seeded: None
    ) -> None:
        """An install that never set internal_key must not accept a
        blank one, which would make the passdb wide open."""
        app = create_app(cfg, engine=engine)  # internal_key is ""
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            response = await c.post(
                "/internal/auth/verify",
                json={"username": "ops@acme.test", "password": "correct-horse"},
                headers={AUTH_HEADER: ""},
            )
        assert response.status_code == 503


class TestPassdb:
    async def test_correct_password_succeeds(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/verify",
            json={"username": "ops@acme.test", "password": "correct-horse"},
            headers=internal(),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["user"] == "ops@acme.test"
        assert body["home"] == "/var/mail/lightr/acme.test/ops"

    async def test_wrong_password_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/verify",
            json={"username": "ops@acme.test", "password": "wrong"},
            headers=internal(),
        )
        assert response.status_code == 401

    async def test_unknown_and_wrong_look_identical(
        self, client: httpx.AsyncClient
    ) -> None:
        """Both must be a plain refusal, so the passdb cannot be used
        to enumerate which addresses exist."""
        wrong = await client.post(
            "/internal/auth/verify",
            json={"username": "ops@acme.test", "password": "wrong"},
            headers=internal(),
        )
        unknown = await client.post(
            "/internal/auth/verify",
            json={"username": "ghost@acme.test", "password": "wrong"},
            headers=internal(),
        )
        assert wrong.status_code == unknown.status_code == 401
        assert set(wrong.json()) == set(unknown.json())

    async def test_password_is_never_echoed(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/verify",
            json={"username": "ops@acme.test", "password": "correct-horse"},
            headers=internal(),
        )
        assert "correct-horse" not in response.text

    async def test_external_account_is_a_temporary_failure(
        self, client: httpx.AsyncClient
    ) -> None:
        """503 tells Dovecot to retry rather than cache a rejection."""
        response = await client.post(
            "/internal/auth/verify",
            json={"username": "ldapuser@acme.test", "password": "x"},
            headers=internal(),
        )
        assert response.status_code == 503

    @pytest.mark.parametrize(
        "payload",
        [{}, {"username": "ops@acme.test"}, {"password": "x"}, {"username": "  "}],
    )
    async def test_incomplete_requests_are_400(
        self, client: httpx.AsyncClient, payload: dict
    ) -> None:
        response = await client.post(
            "/internal/auth/verify", json=payload, headers=internal()
        )
        assert response.status_code == 400

    async def test_non_json_body_is_400(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/verify", content=b"garbage", headers=internal()
        )
        assert response.status_code == 400


class TestUserdb:
    async def test_returns_the_maildir_and_quota(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/user", json={"username": "ops@acme.test"}, headers=internal()
        )
        assert response.status_code == 200
        body = response.json()
        assert body["home"] == "/var/mail/lightr/acme.test/ops"
        assert body["mail"] == "maildir:/var/mail/lightr/acme.test/ops"
        assert body["quota_rule"] == "*:bytes=2147483648"

    async def test_needs_no_password(self, client: httpx.AsyncClient) -> None:
        """LMTP delivery looks up a mailbox without any credentials."""
        response = await client.post(
            "/internal/auth/user", json={"username": "ops@acme.test"}, headers=internal()
        )
        assert response.status_code == 200

    async def test_derives_a_maildir_when_none_is_stored(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.post(
            "/internal/auth/user",
            json={"username": "nomaildir@acme.test"},
            headers=internal(),
        )
        assert response.status_code == 200
        assert response.json()["home"].endswith("acme.test/nomaildir")

    async def test_no_quota_rule_when_unlimited(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/user",
            json={"username": "nomaildir@acme.test"},
            headers=internal(),
        )
        assert "quota_rule" not in response.json()

    async def test_unknown_account_is_404(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/user", json={"username": "ghost@acme.test"}, headers=internal()
        )
        assert response.status_code == 404

    async def test_get_with_a_query_parameter(self, client: httpx.AsyncClient) -> None:
        response = await client.get(
            "/internal/auth/user?user=ops@acme.test", headers=internal()
        )
        assert response.status_code == 200

    async def test_missing_username_is_400(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/internal/auth/user", json={}, headers=internal()
        )
        assert response.status_code == 400
