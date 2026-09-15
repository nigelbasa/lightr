"""Recipient routing: accounts, aliases, loops, and rejections."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.db import schema
from lightr.mail.routing import Disposition, RejectReason, Router
from lightr.models import Account, Alias, AliasType, AuthMode, Domain, Organization
from lightr.repo import AccountRepo, AliasRepo, DomainRepo, OrganizationRepo


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


@pytest_asyncio.fixture
async def world(conn: AsyncConnection) -> dict:
    org = await OrganizationRepo(conn).create(Organization(name="Acme"))
    domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))

    accounts = AccountRepo(conn)
    ops = await accounts.create(Account(domain_id=domain.id, local_part="ops"))
    await accounts.create(Account(domain_id=domain.id, local_part="team"))
    await accounts.create(
        Account(domain_id=domain.id, local_part="gone", auth_mode=AuthMode.DISABLED)
    )
    # A mailbox that a bridge alias of the same name mirrors into.
    await accounts.create(Account(domain_id=domain.id, local_part="bridged"))

    aliases = AliasRepo(conn)
    await aliases.create(
        Alias(domain_id=domain.id, source="sales", destinations=["ops@acme.test"])
    )
    await aliases.create(
        Alias(domain_id=domain.id, source="all",
              destinations=["ops@acme.test", "team@acme.test"])
    )
    await aliases.create(
        Alias(domain_id=domain.id, source="out", destinations=["someone@external.test"])
    )
    await aliases.create(
        Alias(domain_id=domain.id, source="chain", destinations=["sales@acme.test"])
    )
    await aliases.create(
        Alias(domain_id=domain.id, source="inactive",
              destinations=["ops@acme.test"], is_active=False)
    )
    await aliases.create(
        Alias(
            domain_id=domain.id,
            source="bridged",
            destinations=["you@gmail.test"],
            type=AliasType.BRIDGE,
        )
    )
    # A pair of aliases that point at each other.
    await aliases.create(
        Alias(domain_id=domain.id, source="ping", destinations=["pong@acme.test"])
    )
    await aliases.create(
        Alias(domain_id=domain.id, source="pong", destinations=["ping@acme.test"])
    )
    # An alias converging on the same mailbox by two paths.
    await aliases.create(
        Alias(domain_id=domain.id, source="both",
              destinations=["sales@acme.test", "ops@acme.test"])
    )

    return {"org": org, "domain": domain, "ops": ops}


@pytest.fixture
def router(conn: AsyncConnection) -> Router:
    return Router(conn)


class TestLocalDelivery:
    async def test_real_mailbox(self, router: Router, world: dict) -> None:
        route = await router.route("ops@acme.test")
        assert route.disposition is Disposition.LOCAL
        assert route.mailbox == "ops@acme.test"
        assert route.delivers_locally

    async def test_address_is_case_insensitive(self, router: Router, world: dict) -> None:
        assert (await router.route("OPS@ACME.TEST")).disposition is Disposition.LOCAL

    async def test_disabled_account_is_rejected(self, router: Router, world: dict) -> None:
        route = await router.route("gone@acme.test")
        assert route.reason is RejectReason.ACCOUNT_DISABLED
        assert route.reason.smtp_code == 550


class TestRejections:
    async def test_foreign_domain_is_relay_denied(
        self, router: Router, world: dict
    ) -> None:
        route = await router.route("someone@elsewhere.test")
        assert route.reason is RejectReason.NOT_LOCAL_DOMAIN
        assert "Relay access denied" in route.reason.smtp_message

    async def test_unknown_local_part(self, router: Router, world: dict) -> None:
        route = await router.route("ghost@acme.test")
        assert route.reason is RejectReason.NO_SUCH_MAILBOX

    async def test_malformed_address(self, router: Router, world: dict) -> None:
        assert (await router.route("not-an-address")).rejected

    async def test_inactive_alias_is_not_used(self, router: Router, world: dict) -> None:
        route = await router.route("inactive@acme.test")
        assert route.reason is RejectReason.NO_SUCH_MAILBOX

    async def test_suppressed_address(
        self, router: Router, world: dict, conn: AsyncConnection
    ) -> None:
        await conn.execute(
            insert(schema.suppression_list).values(
                email="ops@acme.test", reason="hard bounce"
            )
        )
        route = await router.route("ops@acme.test")
        assert route.reason is RejectReason.SUPPRESSED

    async def test_suppression_beats_a_real_mailbox(
        self, router: Router, world: dict, conn: AsyncConnection
    ) -> None:
        """Suppression exists to stop delivery; a live mailbox must not
        override it."""
        await conn.execute(
            insert(schema.suppression_list).values(email="ops@acme.test", reason="x")
        )
        assert (await router.route("ops@acme.test")).rejected


class TestAliases:
    async def test_forward_to_one(self, router: Router, world: dict) -> None:
        route = await router.route("sales@acme.test")
        assert route.disposition is Disposition.ALIAS_FORWARD
        assert route.forward_to == ["ops@acme.test"]
        assert not route.delivers_locally

    async def test_forward_to_several(self, router: Router, world: dict) -> None:
        route = await router.route("all@acme.test")
        assert set(route.forward_to) == {"ops@acme.test", "team@acme.test"}

    async def test_forward_to_external(self, router: Router, world: dict) -> None:
        route = await router.route("out@acme.test")
        assert route.forward_to == ["someone@external.test"]

    async def test_alias_pointing_at_an_alias(self, router: Router, world: dict) -> None:
        route = await router.route("chain@acme.test")
        assert route.forward_to == ["ops@acme.test"]

    async def test_converging_paths_deliver_once(
        self, router: Router, world: dict
    ) -> None:
        """Two routes to one mailbox must not mean two copies."""
        route = await router.route("both@acme.test")
        assert route.forward_to == ["ops@acme.test"]

    async def test_a_bridge_with_an_accounts_name_mirrors_into_it(
        self, router: Router, world: dict
    ) -> None:
        """'bridged' is both an account and a bridge alias; the bridge
        applies, and it mirrors into that account.

        This asserted LOCAL -- the opposite of its own docstring. A
        bridge always shares its name with the mailbox it mirrors into,
        so returning LOCAL whenever an account existed meant no bridge
        could ever fire, and this test pinned that in place. A plain
        forward alias with an account's name is still ignored; see
        tests/test_replies.py."""
        route = await router.route("bridged@acme.test")
        assert route.disposition is Disposition.ALIAS_BRIDGE
        assert route.mailbox == "bridged@acme.test"


class TestAliasLoops:
    async def test_mutual_aliases_are_detected(
        self, router: Router, world: dict
    ) -> None:
        route = await router.route("ping@acme.test")
        assert route.reason is RejectReason.ALIAS_LOOP

    async def test_a_loop_is_transient_not_permanent(
        self, router: Router, world: dict
    ) -> None:
        """A loop is an operator's misconfiguration, not the sender's
        fault -- 4xx so it can be fixed without generating bounces."""
        route = await router.route("ping@acme.test")
        assert route.reason is not None
        assert route.reason.smtp_code == 451

    async def test_self_referential_alias(
        self, router: Router, world: dict, conn: AsyncConnection
    ) -> None:
        await AliasRepo(conn).create(
            Alias(
                domain_id=world["domain"].id,
                source="selfref",
                destinations=["selfref@acme.test"],
            )
        )
        assert (await router.route("selfref@acme.test")).reason is RejectReason.ALIAS_LOOP

    async def test_deep_chain_is_bounded(
        self, router: Router, world: dict, conn: AsyncConnection
    ) -> None:
        """Even without a cycle, expansion must stop."""
        aliases = AliasRepo(conn)
        for index in range(10):
            await aliases.create(
                Alias(
                    domain_id=world["domain"].id,
                    source=f"hop{index}",
                    destinations=[f"hop{index + 1}@acme.test"],
                )
            )
        assert (await router.route("hop0@acme.test")).reason is RejectReason.ALIAS_LOOP


class TestBridgeAliases:
    async def test_bridge_keeps_a_local_copy_and_forwards(
        self, router: Router, world: dict, conn: AsyncConnection
    ) -> None:
        route = await router.route("bridged@acme.test")

        assert route.disposition is Disposition.ALIAS_BRIDGE
        assert route.delivers_locally
        assert route.mailbox == "bridged@acme.test"
        assert route.forward_to == ["you@gmail.test"]
        assert route.alias_id is not None

    async def test_bridge_without_a_mailbox_degrades_to_forward(
        self, router: Router, world: dict, conn: AsyncConnection
    ) -> None:
        """Better to forward than to drop the mail."""
        await AliasRepo(conn).create(
            Alias(
                domain_id=world["domain"].id,
                source="nomailbox",
                destinations=["you@gmail.test"],
                type=AliasType.BRIDGE,
            )
        )
        route = await router.route("nomailbox@acme.test")
        assert route.disposition is Disposition.ALIAS_FORWARD
        assert route.forward_to == ["you@gmail.test"]


class TestBatch:
    async def test_mixed_recipients(self, router: Router, world: dict) -> None:
        routes = await router.route_all(
            ["ops@acme.test", "ghost@acme.test", "sales@acme.test"]
        )
        assert [r.disposition for r in routes] == [
            Disposition.LOCAL,
            Disposition.REJECT,
            Disposition.ALIAS_FORWARD,
        ]

    async def test_one_rejection_does_not_affect_the_others(
        self, router: Router, world: dict
    ) -> None:
        routes = await router.route_all(["ghost@acme.test", "ops@acme.test"])
        assert routes[0].rejected
        assert routes[1].delivers_locally
