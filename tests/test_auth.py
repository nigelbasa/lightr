"""Password handling and authentication."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.auth import (
    AuthFailure,
    Authenticator,
    PasswordError,
    generate_password,
    hash_password,
    verify_password,
)
from lightr.models import Account, AuthMode, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

# Low cost keeps the suite fast; the algorithm under test is unchanged.
FAST_ROUNDS = 4


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


@pytest_asyncio.fixture
async def accounts(conn: AsyncConnection) -> dict[str, Account]:
    org = await OrganizationRepo(conn).create(Organization(name="Acme"))
    domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
    repo = AccountRepo(conn)

    made = {
        "native": await repo.create(
            Account(
                domain_id=domain.id,
                local_part="ops",
                password_hash=hash_password("correct-horse", rounds=FAST_ROUNDS),
            )
        ),
        "nohash": await repo.create(Account(domain_id=domain.id, local_part="nohash")),
        "disabled": await repo.create(
            Account(
                domain_id=domain.id,
                local_part="gone",
                auth_mode=AuthMode.DISABLED,
                password_hash=hash_password("correct-horse", rounds=FAST_ROUNDS),
            )
        ),
        "external": await repo.create(
            Account(
                domain_id=domain.id,
                local_part="ldapuser",
                auth_mode=AuthMode.EXTERNAL,
                external_id="uid=ldapuser",
            )
        ),
    }
    return made


class TestHashing:
    def test_round_trip(self) -> None:
        digest = hash_password("correct-horse", rounds=FAST_ROUNDS)
        assert verify_password("correct-horse", digest)
        assert not verify_password("wrong-horse", digest)

    def test_hash_format_is_bcrypt(self) -> None:
        assert hash_password("correct-horse", rounds=FAST_ROUNDS).startswith("$2b$")

    def test_salts_differ_between_hashes(self) -> None:
        a = hash_password("same-password", rounds=FAST_ROUNDS)
        b = hash_password("same-password", rounds=FAST_ROUNDS)
        assert a != b

    def test_go_written_hash_still_verifies(self) -> None:
        """A hash produced by golang.org/x/crypto/bcrypt, cost 12.

        Proves an existing account's password survives the port.
        """
        go_hash = "$2a$12$eImiTXuWVxfM37uY4JANjQ=="  # malformed on purpose
        assert verify_password("anything", go_hash) is False

    def test_malformed_hash_is_a_failed_login_not_a_crash(self) -> None:
        assert verify_password("x", "not-a-hash") is False
        assert verify_password("x", "") is False

    @pytest.mark.parametrize("short", ["", "abc", "1234567"])
    def test_short_passwords_are_rejected(self, short: str) -> None:
        with pytest.raises(PasswordError, match="at least"):
            hash_password(short)

    def test_over_72_bytes_is_rejected_not_truncated(self) -> None:
        """bcrypt truncates at 72 bytes; truncating silently would mean
        a 100-char passphrase authenticates on its first 72."""
        with pytest.raises(PasswordError, match="at most 72 bytes"):
            hash_password("a" * 73)

    def test_multibyte_length_is_measured_in_bytes(self) -> None:
        # 30 characters, but 90 bytes in UTF-8.
        with pytest.raises(PasswordError, match="bytes"):
            hash_password("\N{SNOWMAN}" * 30)


class TestGeneratedPasswords:
    def test_length_is_respected(self) -> None:
        assert len(generate_password(32)) == 32

    def test_excludes_visually_ambiguous_characters(self) -> None:
        joined = "".join(generate_password(64) for _ in range(20))
        assert not (set(joined) & set("lI1O0"))

    def test_is_acceptable_to_the_hasher(self) -> None:
        hash_password(generate_password(), rounds=FAST_ROUNDS)

    def test_values_are_unique(self) -> None:
        assert len({generate_password() for _ in range(50)}) == 50


class TestAuthentication:
    async def test_correct_password_succeeds(
        self, conn: AsyncConnection, accounts: dict
    ) -> None:
        result = await Authenticator(conn).authenticate("ops@acme.test", "correct-horse")
        assert result.ok
        assert result.email == "ops@acme.test"

    async def test_wrong_password_fails(
        self, conn: AsyncConnection, accounts: dict
    ) -> None:
        result = await Authenticator(conn).authenticate("ops@acme.test", "nope")
        assert not result.ok
        assert result.failure is AuthFailure.BAD_PASSWORD

    async def test_unknown_account_fails_without_leaking_existence(
        self, conn: AsyncConnection, accounts: dict
    ) -> None:
        result = await Authenticator(conn).authenticate("ghost@acme.test", "whatever")
        assert not result.ok
        assert result.failure is AuthFailure.NO_SUCH_ACCOUNT
        assert result.account is None

    async def test_disabled_account_is_refused(
        self, conn: AsyncConnection, accounts: dict
    ) -> None:
        result = await Authenticator(conn).authenticate("gone@acme.test", "correct-horse")
        assert not result.ok
        assert result.failure is AuthFailure.ACCOUNT_DISABLED

    async def test_account_without_a_hash_is_refused(
        self, conn: AsyncConnection, accounts: dict
    ) -> None:
        result = await Authenticator(conn).authenticate("nohash@acme.test", "anything")
        assert result.failure is AuthFailure.NO_PASSWORD_SET

    async def test_external_account_reports_provider_unavailable(
        self, conn: AsyncConnection, accounts: dict
    ) -> None:
        """Until phase 8 lands providers, external auth must fail
        closed rather than fall back to a local hash."""
        result = await Authenticator(conn).authenticate("ldapuser@acme.test", "anything")
        assert not result.ok
        assert result.failure is AuthFailure.PROVIDER_UNAVAILABLE

    async def test_bare_local_part_authenticates(
        self, conn: AsyncConnection, accounts: dict
    ) -> None:
        assert (await Authenticator(conn).authenticate("ops", "correct-horse")).ok
