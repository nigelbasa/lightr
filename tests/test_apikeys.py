"""API key creation, verification, and scoping."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.apikeys import (
    KEY_PREFIX,
    APIKey,
    APIKeyError,
    APIKeyRepo,
    KeyType,
    Permission,
    generate_secret,
    hash_secret,
)
from lightr.models import Domain, Organization
from lightr.repo import DomainRepo, NotFoundError, OrganizationRepo


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


@pytest_asyncio.fixture
async def scope(conn: AsyncConnection) -> dict:
    org = await OrganizationRepo(conn).create(Organization(name="Acme"))
    domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
    return {"org": org, "domain": domain}


@pytest.fixture
def repo(conn: AsyncConnection) -> APIKeyRepo:
    return APIKeyRepo(conn)


class TestSecretGeneration:
    def test_secret_is_prefixed_and_long(self) -> None:
        secret, prefix, digest = generate_secret()
        assert secret.startswith(f"{KEY_PREFIX}_")
        assert len(secret) > 32
        assert secret.startswith(prefix)
        assert len(digest) == 64  # sha256 hex

    def test_secrets_are_unique(self) -> None:
        assert len({generate_secret()[0] for _ in range(100)}) == 100

    def test_hash_is_deterministic(self) -> None:
        assert hash_secret("lk_abc") == hash_secret("lk_abc")
        assert hash_secret("lk_abc") != hash_secret("lk_abd")


class TestCreation:
    async def test_secret_is_returned_once(self, repo: APIKeyRepo, scope: dict) -> None:
        key, secret = await repo.create("ci", organization_id=scope["org"].id)
        assert secret.startswith("lk_")
        # The stored record must not carry the secret.
        assert secret not in key.model_dump_json()

    async def test_stored_as_a_hash_only(self, repo: APIKeyRepo, scope: dict) -> None:
        _, secret = await repo.create("ci", organization_id=scope["org"].id)
        listed = await repo.list()
        assert listed[0].key_hash == hash_secret(secret)
        assert listed[0].key_hash != secret

    async def test_default_permissions_by_type(self, repo: APIKeyRepo, scope: dict) -> None:
        key, _ = await repo.create("ops", organization_id=scope["org"].id)
        assert Permission.READ in key.permissions
        assert Permission.ADMIN not in key.permissions

    async def test_admin_key_needs_no_scope(self, repo: APIKeyRepo) -> None:
        key, _ = await repo.create("root", key_type=KeyType.ADMIN)
        assert key.allows(Permission.ADMIN)

    @pytest.mark.parametrize(
        ("key_type", "message"),
        [
            (KeyType.ORG, "organization"),
            (KeyType.DOMAIN, "domain"),
            (KeyType.ACCOUNT, "account"),
        ],
    )
    async def test_scoped_key_requires_its_scope(
        self, repo: APIKeyRepo, key_type: KeyType, message: str
    ) -> None:
        with pytest.raises(APIKeyError, match=message):
            await repo.create("bad", key_type=key_type)

    async def test_negative_expiry_is_rejected(self, repo: APIKeyRepo, scope: dict) -> None:
        with pytest.raises(APIKeyError, match="positive"):
            await repo.create("x", organization_id=scope["org"].id, expires_in_days=0)

    async def test_expiry_is_set(self, repo: APIKeyRepo, scope: dict) -> None:
        key, _ = await repo.create(
            "temp", organization_id=scope["org"].id, expires_in_days=30
        )
        assert key.expires_at is not None
        assert not key.expired


class TestVerification:
    async def test_valid_secret_verifies(self, repo: APIKeyRepo, scope: dict) -> None:
        _, secret = await repo.create("ci", organization_id=scope["org"].id)
        assert (await repo.verify(secret)) is not None

    async def test_wrong_secret_fails(self, repo: APIKeyRepo, scope: dict) -> None:
        await repo.create("ci", organization_id=scope["org"].id)
        assert await repo.verify("lk_totally-wrong") is None

    @pytest.mark.parametrize("junk", ["", "not-a-key", "bearer abc"])
    async def test_malformed_secrets_fail_fast(self, repo: APIKeyRepo, junk: str) -> None:
        assert await repo.verify(junk) is None

    async def test_revoked_key_fails(self, repo: APIKeyRepo, scope: dict) -> None:
        key, secret = await repo.create("ci", organization_id=scope["org"].id)
        await repo.revoke(key.id)
        assert await repo.verify(secret) is None

    async def test_expired_key_fails(self, repo: APIKeyRepo, scope: dict) -> None:
        from sqlalchemy import update

        from lightr.db import schema

        key, secret = await repo.create("ci", organization_id=scope["org"].id)
        await repo._conn.execute(
            update(schema.api_keys)
            .where(schema.api_keys.c.id == str(key.id))
            .values(expires_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1))
        )
        assert await repo.verify(secret) is None

    async def test_rotation_invalidates_the_old_secret(
        self, repo: APIKeyRepo, scope: dict
    ) -> None:
        key, old = await repo.create("ci", organization_id=scope["org"].id)
        new = await repo.rotate(key.id)

        assert await repo.verify(old) is None
        assert await repo.verify(new) is not None

    async def test_rotation_keeps_the_scope(self, repo: APIKeyRepo, scope: dict) -> None:
        key, _ = await repo.create("ci", organization_id=scope["org"].id)
        new = await repo.rotate(key.id)

        rotated = await repo.verify(new)
        assert rotated is not None
        assert rotated.organization_id == scope["org"].id


class TestIPRestrictions:
    def _key(self, **kwargs) -> APIKey:
        return APIKey(name="k", prefix="lk_x", key_hash="x", **kwargs)

    def test_empty_allowlist_permits_everything(self) -> None:
        assert self._key().allows_ip("203.0.113.5") is True
        assert self._key().allows_ip(None) is True

    def test_exact_address_matches(self) -> None:
        key = self._key(allowed_ips=["203.0.113.5"])
        assert key.allows_ip("203.0.113.5") is True
        assert key.allows_ip("203.0.113.6") is False

    def test_cidr_matches(self) -> None:
        key = self._key(allowed_ips=["203.0.113.0/24"])
        assert key.allows_ip("203.0.113.99") is True
        assert key.allows_ip("198.51.100.1") is False

    def test_unknown_address_is_denied_when_restricted(self) -> None:
        """An unverifiable request must not pass an IP restriction."""
        assert self._key(allowed_ips=["203.0.113.0/24"]).allows_ip(None) is False

    def test_malformed_address_is_denied(self) -> None:
        assert self._key(allowed_ips=["203.0.113.0/24"]).allows_ip("not-an-ip") is False

    def test_malformed_allowlist_entry_is_skipped(self) -> None:
        key = self._key(allowed_ips=["garbage", "203.0.113.5"])
        assert key.allows_ip("203.0.113.5") is True

    def test_ipv6(self) -> None:
        key = self._key(allowed_ips=["2001:db8::/32"])
        assert key.allows_ip("2001:db8::1") is True
        assert key.allows_ip("2001:dead::1") is False

    async def test_verify_enforces_the_allowlist(
        self, repo: APIKeyRepo, scope: dict
    ) -> None:
        _, secret = await repo.create(
            "ci", organization_id=scope["org"].id, allowed_ips=["203.0.113.0/24"]
        )
        assert await repo.verify(secret, ip="203.0.113.9") is not None
        assert await repo.verify(secret, ip="198.51.100.1") is None


class TestPermissions:
    def _key(self, permissions: list[Permission]) -> APIKey:
        return APIKey(name="k", prefix="p", key_hash="h", permissions=permissions)

    def test_explicit_permission(self) -> None:
        assert self._key([Permission.READ]).allows(Permission.READ)
        assert not self._key([Permission.READ]).allows(Permission.WRITE)

    def test_admin_implies_everything(self) -> None:
        key = self._key([Permission.ADMIN])
        assert key.allows(Permission.WRITE)
        assert key.allows(Permission.MAILBOX)

    def test_scope_description(self) -> None:
        assert "all organizations" in APIKey(
            name="k", prefix="p", key_hash="h", type=KeyType.ADMIN
        ).scope_description()

        org_id = uuid4()
        assert str(org_id) in APIKey(
            name="k", prefix="p", key_hash="h", organization_id=org_id
        ).scope_description()


class TestLookup:
    async def test_resolve_by_prefix(self, repo: APIKeyRepo, scope: dict) -> None:
        key, _ = await repo.create("ci", organization_id=scope["org"].id)
        assert (await repo.resolve(key.prefix)).id == key.id

    async def test_resolve_by_name(self, repo: APIKeyRepo, scope: dict) -> None:
        key, _ = await repo.create("deploy", organization_id=scope["org"].id)
        assert (await repo.resolve("deploy")).id == key.id

    async def test_resolve_by_id(self, repo: APIKeyRepo, scope: dict) -> None:
        key, _ = await repo.create("ci", organization_id=scope["org"].id)
        assert (await repo.resolve(str(key.id))).id == key.id

    async def test_unknown_reference_suggests_list(self, repo: APIKeyRepo) -> None:
        with pytest.raises(NotFoundError, match="lightr apikey list"):
            await repo.resolve("nope")

    async def test_list_scopes_to_an_org(self, repo: APIKeyRepo, scope: dict) -> None:
        await repo.create("a", organization_id=scope["org"].id)
        await repo.create("root", key_type=KeyType.ADMIN)

        assert len(await repo.list(organization_id=scope["org"].id)) == 1
        assert len(await repo.list()) == 2

    async def test_delete(self, repo: APIKeyRepo, scope: dict) -> None:
        key, secret = await repo.create("ci", organization_id=scope["org"].id)
        await repo.delete(key.id)
        assert await repo.verify(secret) is None

    async def test_use_is_recorded(self, repo: APIKeyRepo, scope: dict) -> None:
        key, _ = await repo.create("ci", organization_id=scope["org"].id)
        await repo.record_use(key.id, "203.0.113.5")

        refreshed = await repo.resolve(str(key.id))
        assert refreshed.usage_count == 1
        assert refreshed.last_used_ip == "203.0.113.5"
