"""Repository behaviour, especially reference resolution."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.models import Account, Alias, AliasType, AuthMode, Domain, Organization
from lightr.repo import (
    AccountRepo,
    AliasRepo,
    AmbiguousReferenceError,
    ConflictError,
    DomainRepo,
    NotFoundError,
    OrganizationRepo,
)


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


@pytest_asyncio.fixture
async def seeded(conn: AsyncConnection) -> dict[str, object]:
    """One org, two domains, three accounts, one alias."""
    org = await OrganizationRepo(conn).create(Organization(name="Acme Ltd"))
    domains = DomainRepo(conn)
    acme = await domains.create(Domain(org_id=org.id, name="acme.test"))
    other = await domains.create(Domain(org_id=org.id, name="other.test"))

    accounts = AccountRepo(conn)
    ops = await accounts.create(Account(domain_id=acme.id, local_part="ops"))
    # Same local part on both domains, to exercise ambiguity.
    await accounts.create(Account(domain_id=acme.id, local_part="shared"))
    await accounts.create(Account(domain_id=other.id, local_part="shared"))

    alias = await AliasRepo(conn).create(
        Alias(domain_id=acme.id, source="sales", destinations=["ops@acme.test"])
    )
    return {"org": org, "acme": acme, "other": other, "ops": ops, "alias": alias}


class TestOrganizationResolution:
    async def test_by_exact_name(self, conn: AsyncConnection, seeded: dict) -> None:
        found = await OrganizationRepo(conn).resolve("Acme Ltd")
        assert found.id == seeded["org"].id

    async def test_by_uuid(self, conn: AsyncConnection, seeded: dict) -> None:
        found = await OrganizationRepo(conn).resolve(str(seeded["org"].id))
        assert found.name == "Acme Ltd"

    async def test_by_prefix(self, conn: AsyncConnection, seeded: dict) -> None:
        assert (await OrganizationRepo(conn).resolve("Acme")).id == seeded["org"].id

    async def test_missing_reference_suggests_a_command(self, conn: AsyncConnection) -> None:
        with pytest.raises(NotFoundError, match="lightr org list"):
            await OrganizationRepo(conn).resolve("nope")

    async def test_ambiguous_prefix_lists_candidates(self, conn: AsyncConnection) -> None:
        repo = OrganizationRepo(conn)
        await repo.create(Organization(name="Globex One"))
        await repo.create(Organization(name="Globex Two"))

        with pytest.raises(AmbiguousReferenceError, match="matches 2"):
            await repo.resolve("Globex")

    async def test_default_creates_one_when_empty(self, conn: AsyncConnection) -> None:
        org = await OrganizationRepo(conn).default()
        assert org.name == "default"

    async def test_default_returns_the_only_org(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        assert (await OrganizationRepo(conn).default()).id == seeded["org"].id


class TestDomainResolution:
    async def test_by_name(self, conn: AsyncConnection, seeded: dict) -> None:
        assert (await DomainRepo(conn).resolve("acme.test")).id == seeded["acme"].id

    async def test_by_email_address(self, conn: AsyncConnection, seeded: dict) -> None:
        """An email address resolves to its domain -- a common slip."""
        assert (await DomainRepo(conn).resolve("ops@acme.test")).id == seeded["acme"].id

    async def test_trailing_dot_and_case_are_normalised(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        assert (await DomainRepo(conn).resolve("ACME.test.")).id == seeded["acme"].id

    async def test_duplicate_creation_is_rejected(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        with pytest.raises(ConflictError, match="already exists"):
            await DomainRepo(conn).create(
                Domain(org_id=seeded["org"].id, name="acme.test")
            )

    async def test_is_local(self, conn: AsyncConnection, seeded: dict) -> None:
        repo = DomainRepo(conn)
        assert await repo.is_local("acme.test") is True
        assert await repo.is_local("elsewhere.test") is False

    @pytest.mark.parametrize("bad", ["", "no-dot", "has space.test"])
    async def test_invalid_names_are_rejected(self, bad: str, seeded: dict) -> None:
        with pytest.raises(ValueError):
            Domain(org_id=seeded["org"].id, name=bad)

    async def test_hostname_falls_back_to_the_domain(self, seeded: dict) -> None:
        assert seeded["acme"].hostname == "acme.test"


class TestAccountResolution:
    async def test_by_email(self, conn: AsyncConnection, seeded: dict) -> None:
        found = await AccountRepo(conn).resolve("ops@acme.test")
        assert found.id == seeded["ops"].id
        assert found.email == "ops@acme.test"

    async def test_by_bare_local_part_when_unambiguous(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        assert (await AccountRepo(conn).resolve("ops")).id == seeded["ops"].id

    async def test_bare_local_part_across_domains_is_ambiguous(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        with pytest.raises(AmbiguousReferenceError) as excinfo:
            await AccountRepo(conn).resolve("shared")
        assert "shared@acme.test" in str(excinfo.value)

    async def test_find_returns_none_instead_of_raising(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        assert await AccountRepo(conn).find("ghost@acme.test") is None

    async def test_list_carries_the_domain_name(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        accounts = await AccountRepo(conn).list()
        assert all(a.email is not None for a in accounts)

    async def test_set_password_hash_switches_to_native(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        repo = AccountRepo(conn)
        await repo.set_password_hash(seeded["ops"].id, "$2b$12$replacement")

        refreshed = await repo.resolve("ops@acme.test")
        assert refreshed.password_hash == "$2b$12$replacement"
        assert refreshed.auth_mode is AuthMode.NATIVE

    @pytest.mark.parametrize("bad", ["", "has@at", "has space"])
    async def test_invalid_local_parts_are_rejected(self, bad: str, seeded: dict) -> None:
        with pytest.raises(ValueError):
            Account(domain_id=seeded["acme"].id, local_part=bad)

    async def test_counts_scope_to_a_domain(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        repo = AccountRepo(conn)
        assert await repo.count() == 3
        assert await repo.count(domain_id=seeded["other"].id) == 1


class TestAliases:
    async def test_destinations_round_trip_as_json(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        found = await AliasRepo(conn).resolve("sales")
        assert found.destinations == ["ops@acme.test"]

    async def test_source_strips_a_domain_if_given(self, seeded: dict) -> None:
        alias = Alias(domain_id=seeded["acme"].id, source="Sales@acme.test")
        assert alias.source == "sales"

    async def test_comma_separated_destinations_are_accepted(self, seeded: dict) -> None:
        """The CLI passes --destinations a,b -- accept it directly."""
        alias = Alias(
            domain_id=seeded["acme"].id,
            source="team",
            destinations="a@x.test, b@y.test",
        )
        assert alias.destinations == ["a@x.test", "b@y.test"]

    async def test_lookup_ignores_inactive_aliases(
        self, conn: AsyncConnection, seeded: dict
    ) -> None:
        repo = AliasRepo(conn)
        alias = seeded["alias"]
        alias.is_active = False
        await repo.update(alias)

        assert await repo.lookup(seeded["acme"].id, "sales") is None

    async def test_bridge_type_persists(self, conn: AsyncConnection, seeded: dict) -> None:
        repo = AliasRepo(conn)
        await repo.create(
            Alias(
                domain_id=seeded["acme"].id,
                source="bridged",
                destinations=["you@gmail.test"],
                type=AliasType.BRIDGE,
            )
        )
        assert (await repo.resolve("bridged")).type is AliasType.BRIDGE
