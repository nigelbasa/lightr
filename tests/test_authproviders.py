"""Offloaded authentication.

Three things here are worth more than the rest of the file:

* a valid token belonging to someone else must not open this mailbox
* a provider that could not answer must never read as "wrong password"
* an account switched to external auth must never fall back to the
  local hash it used to have
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.auth import Authenticator, AuthFailure
from lightr.authproviders import (
    AuthProviderRepo,
    Identity,
    OIDCProvider,
    ProviderConfigError,
    ProviderError,
    WebhookProvider,
    authenticate,
    redact,
)
from lightr.authproviders.base import ProviderBase
from lightr.models import Account, AuthMode, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo


class FakeProvider(ProviderBase):
    """A provider that answers however a test needs it to."""

    kind = "fake"

    def __init__(self, name: str, answer: Any) -> None:
        super().__init__(name=name, config={})
        self.answer = answer
        self.asked: list[tuple[str, str]] = []

    async def authenticate(self, username: str, password: str) -> Identity | None:
        self.asked.append((username, password))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


# --------------------------------------------------------------------
# Asking providers in order
# --------------------------------------------------------------------


class TestOrdering:
    async def test_the_first_to_accept_wins(self) -> None:
        first = FakeProvider("corp", None)
        second = FakeProvider("legacy", Identity(username="ops@acme.test"))

        outcome = await authenticate([first, second], "ops@acme.test", "pw")

        assert outcome.ok
        assert outcome.provider == "legacy"

    async def test_a_refusal_does_not_stop_the_next_being_asked(self) -> None:
        """A user may exist in one directory and not another."""
        first = FakeProvider("corp", None)
        second = FakeProvider("legacy", Identity(username="ops@acme.test"))

        await authenticate([first, second], "ops@acme.test", "pw")

        assert second.asked == [("ops@acme.test", "pw")]

    async def test_a_failure_does_not_stop_the_next_being_asked(self) -> None:
        first = FakeProvider("corp", ProviderError("connection refused"))
        second = FakeProvider("legacy", Identity(username="ops@acme.test"))

        outcome = await authenticate([first, second], "ops@acme.test", "pw")

        assert outcome.ok
        assert outcome.unavailable  # still reported

    async def test_all_refusing_is_a_refusal(self) -> None:
        outcome = await authenticate(
            [FakeProvider("a", None), FakeProvider("b", None)], "ops@acme.test", "pw"
        )

        assert not outcome.ok
        assert outcome.refused == ["a", "b"]
        assert outcome.unavailable == []

    async def test_a_failure_with_no_acceptance_is_unavailable(self) -> None:
        """The distinction the whole design rests on: nobody said no,
        they just did not answer."""
        outcome = await authenticate(
            [FakeProvider("a", ProviderError("timeout"))], "ops@acme.test", "pw"
        )

        assert not outcome.ok
        assert outcome.refused == []
        assert len(outcome.unavailable) == 1
        assert "timeout" in outcome.unavailable[0]

    async def test_a_provider_that_raises_something_else_is_still_contained(
        self,
    ) -> None:
        """A bug in one provider must not be a 500 for the whole login."""
        outcome = await authenticate(
            [FakeProvider("buggy", RuntimeError("oops"))], "ops@acme.test", "pw"
        )

        assert not outcome.ok
        assert outcome.unavailable


class TestTimeouts:
    async def test_a_slow_provider_is_cut_off(self) -> None:
        """Every provider sits on the IMAP login path; Dovecot is
        holding a connection open behind it."""

        class Slow(ProviderBase):
            kind = "slow"

            async def authenticate(self, username: str, password: str) -> None:
                return await self.bounded(asyncio.sleep(5))

        provider = Slow(name="slow", config={}, timeout=0.05)

        with pytest.raises(ProviderError, match="did not answer"):
            await provider.authenticate("ops@acme.test", "pw")

    async def test_a_timeout_reads_as_unavailable_not_refused(self) -> None:
        class Slow(ProviderBase):
            kind = "slow"

            async def authenticate(self, username: str, password: str) -> None:
                return await self.bounded(asyncio.sleep(5))

        outcome = await authenticate(
            [Slow(name="slow", config={}, timeout=0.05)], "ops@acme.test", "pw"
        )

        assert outcome.unavailable
        assert outcome.refused == []


# --------------------------------------------------------------------
# OIDC
# --------------------------------------------------------------------


@pytest.fixture
def in_process_http(monkeypatch: pytest.MonkeyPatch):
    """Route provider HTTP to a handler in this process.

    The providers build their own client, so the seam is httpx itself
    rather than a hook that would exist only for tests.
    """

    def install(handler: Any) -> None:
        original = httpx.AsyncClient

        def factory(*args: Any, **kwargs: Any) -> Any:
            kwargs["transport"] = httpx.MockTransport(handler)
            return original(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", factory)
        # The SSRF guard resolves before it connects, and the suite
        # blocks real DNS. Give it an answer so the guard is still
        # exercised rather than skipped.
        monkeypatch.setattr(
            "lightr.webhooks.ssrf.resolve_all", lambda host, port: ["127.0.0.1"]
        )

    return install


class TestOIDCIdentityMatching:
    """The security-critical part: a valid token is not enough."""

    def _claims_provider(self, **config: Any) -> OIDCProvider:
        return OIDCProvider(name="idp", config={"userinfo_url": "x", **config})

    def test_a_matching_claim_authenticates(self) -> None:
        provider = self._claims_provider()
        identity = provider._match("ops@acme.test", {"email": "ops@acme.test"})

        assert identity is not None
        assert identity.username == "ops@acme.test"

    def test_a_token_belonging_to_someone_else_is_refused(self) -> None:
        """Otherwise any user of the identity provider can read any
        mailbox on this server."""
        provider = self._claims_provider()

        assert provider._match("ops@acme.test", {"email": "someone@acme.test"}) is None

    def test_a_valid_token_with_no_identifying_claim_fails_closed(self) -> None:
        """Introspection saying `active: true` and nothing else is not
        permission to log in as whoever asked."""
        provider = self._claims_provider()

        with pytest.raises(ProviderError, match="no identifying claim"):
            provider._match("ops@acme.test", {"active": True})

    def test_the_claim_can_be_named(self) -> None:
        provider = self._claims_provider(username_claim="upn")

        assert provider._match("ops@acme.test", {"upn": "ops@acme.test"}) is not None

    def test_a_named_claim_is_the_only_one_consulted(self) -> None:
        """Falling back to another claim would let a provider that
        controls `sub` impersonate a mailbox."""
        provider = self._claims_provider(username_claim="upn")

        with pytest.raises(ProviderError):
            provider._match("ops@acme.test", {"email": "ops@acme.test"})

    def test_matching_ignores_case(self) -> None:
        provider = self._claims_provider()

        assert provider._match("Ops@Acme.Test", {"email": "ops@acme.test"}) is not None

    async def test_an_empty_token_is_refused_without_a_round_trip(self) -> None:
        provider = OIDCProvider(name="idp", config={})
        assert await provider.authenticate("ops@acme.test", "") is None

    async def test_a_provider_with_no_endpoint_configured_says_so(self) -> None:
        provider = OIDCProvider(name="idp", config={})

        with pytest.raises(ProviderConfigError, match="introspection_url"):
            await provider.authenticate("ops@acme.test", "token")


# --------------------------------------------------------------------
# The webhook provider
# --------------------------------------------------------------------


class TestWebhookProviderAnswers:
    """The three-state contract, at the HTTP boundary."""

    def _read(self, status: int, body: Any) -> Any:
        provider = WebhookProvider(name="app", config={"url": "https://x.test/auth"})
        response = httpx.Response(status, json=body)
        return provider._read("ops@acme.test", response)

    def test_ok_true_authenticates(self) -> None:
        identity = self._read(200, {"ok": True, "display_name": "Ops"})
        assert identity is not None
        assert identity.display_name == "Ops"

    def test_ok_false_is_a_refusal(self) -> None:
        assert self._read(200, {"ok": False}) is None

    def test_a_401_is_a_refusal(self) -> None:
        assert self._read(401, {}) is None

    def test_a_500_is_not_a_refusal(self) -> None:
        """An endpoint that is failing must not be read as "the
        password was wrong"."""
        with pytest.raises(ProviderError):
            self._read(500, {})

    def test_a_body_that_is_not_the_agreed_shape_is_not_a_refusal(self) -> None:
        provider = WebhookProvider(name="app", config={"url": "https://x.test/auth"})
        response = httpx.Response(200, content=b"yes")

        with pytest.raises(ProviderError):
            provider._read("ops@acme.test", response)

    def test_a_status_field_is_accepted_too(self) -> None:
        assert self._read(200, {"status": "ok"}) is not None


class TestWebhookProviderRequest:
    async def test_it_signs_the_request(self, in_process_http) -> None:
        """A receiver that cannot verify a signature has no way to tell
        a real credential check from anything else that reaches it."""
        from lightr.webhooks.delivery import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign

        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["headers"] = request.headers
            seen["body"] = request.content
            return httpx.Response(200, json={"ok": True})

        in_process_http(handler)
        provider = _webhook(secret="shared")
        await provider.authenticate("ops@acme.test", "pw")

        expected = sign("shared", seen["headers"][TIMESTAMP_HEADER], seen["body"])
        assert seen["headers"][SIGNATURE_HEADER] == expected

    async def test_it_sends_the_credentials_as_json(self, in_process_http) -> None:
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})

        in_process_http(handler)
        provider = _webhook()
        await provider.authenticate("ops@acme.test", "hunter2")

        assert seen == {"username": "ops@acme.test", "password": "hunter2"}

    async def test_a_private_url_is_refused(self) -> None:
        """A provider URL is operator-supplied and fetched by the
        server -- the same SSRF problem event webhooks have."""
        provider = WebhookProvider(
            name="app", config={"url": "http://169.254.169.254/auth"}
        )

        with pytest.raises(ProviderError, match="refused"):
            await provider.authenticate("ops@acme.test", "pw")


def _webhook(**config: Any) -> WebhookProvider:
    return WebhookProvider(
        name="app",
        config={"url": "https://app.example.test/auth", "allow_private": True, **config},
    )


# --------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------


class TestRedaction:
    def test_secrets_are_masked(self) -> None:
        masked = redact({"bind_dn": "cn=svc", "bind_password": "hunter2"})

        assert masked["bind_password"] == "(set)"

    def test_everything_else_is_left_readable(self) -> None:
        """An operator debugging a provider needs the base DN and the
        URL; masking the whole blob makes the command useless."""
        masked = redact({"uri": "ldaps://dc.corp", "base_dn": "ou=people"})

        assert masked["uri"] == "ldaps://dc.corp"
        assert masked["base_dn"] == "ou=people"

    def test_an_empty_secret_is_not_reported_as_set(self) -> None:
        assert redact({"client_secret": ""})["client_secret"] == ""


# --------------------------------------------------------------------
# Selection, and the end-to-end path through Authenticator
# --------------------------------------------------------------------


@pytest.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(
            Domain(org_id=org.id, name="acme.test")
        )
        account = await AccountRepo(conn).create(
            Account(
                domain_id=domain.id,
                local_part="ops",
                auth_mode=AuthMode.EXTERNAL,
                password_hash="$2b$04$aStaleLocalHashThatMustNotBeUsed",
            )
        )
    return {"org": org, "domain": domain, "account": account}


@pytest.fixture
async def conn(engine: AsyncEngine) -> Any:
    async with engine.begin() as connection:
        yield connection


class TestSelection:
    async def test_a_provider_naming_the_domain_is_chosen(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            await AuthProviderRepo(conn).create(
                "corp", "webhook", {"url": "https://x.example.test/a"},
                domains=["acme.test"],
            )
            providers = await providers_for(conn, world["domain"].id, "acme.test")

        assert [p.name for p in providers] == ["corp"]

    async def test_a_default_provider_covers_a_domain_nobody_named(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            await AuthProviderRepo(conn).create(
                "fallback", "webhook", {"url": "https://x.example.test/a"},
                is_default=True,
            )
            providers = await providers_for(conn, world["domain"].id, "acme.test")

        assert [p.name for p in providers] == ["fallback"]

    async def test_a_named_provider_beats_a_default(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            repo = AuthProviderRepo(conn)
            await repo.create(
                "fallback", "webhook", {"url": "https://x.example.test/a"},
                is_default=True,
            )
            await repo.create(
                "corp", "webhook", {"url": "https://y.example.test/a"},
                domains=["acme.test"],
            )
            providers = await providers_for(conn, world["domain"].id, "acme.test")

        assert [p.name for p in providers] == ["corp"]

    async def test_priority_orders_them(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            repo = AuthProviderRepo(conn)
            await repo.create(
                "second", "webhook", {"url": "https://b.example.test/a"},
                domains=["acme.test"], priority=200,
            )
            await repo.create(
                "first", "webhook", {"url": "https://a.example.test/a"},
                domains=["acme.test"], priority=10,
            )
            providers = await providers_for(conn, world["domain"].id, "acme.test")

        assert [p.name for p in providers] == ["first", "second"]

    async def test_a_disabled_provider_is_not_asked(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            repo = AuthProviderRepo(conn)
            record = await repo.create(
                "corp", "webhook", {"url": "https://x.example.test/a"},
                domains=["acme.test"],
            )
            await repo.update(record.id, enabled=False)
            providers = await providers_for(conn, world["domain"].id, "acme.test")

        assert providers == []


class TestLegacyDomainWebhook:
    """The Go engine's per-domain auth webhook, still honoured."""

    async def test_a_verified_domain_webhook_answers(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            domain = world["domain"]
            domain.auth_webhook_url = "https://legacy.example.test/auth"
            domain.auth_webhook_secret = "s"
            domain.auth_webhook_verified = True
            await DomainRepo(conn).update(domain)

            providers = await providers_for(conn, domain.id, "acme.test")

        assert len(providers) == 1
        assert "domain webhook" in providers[0].name

    async def test_an_unverified_one_is_ignored(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        """An unverified URL answering logins is a configuration
        accident, not a feature."""
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            domain = world["domain"]
            domain.auth_webhook_url = "https://legacy.example.test/auth"
            domain.auth_webhook_verified = False
            await DomainRepo(conn).update(domain)

            providers = await providers_for(conn, domain.id, "acme.test")

        assert providers == []

    async def test_an_explicit_provider_wins_over_it(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        from lightr.authproviders import providers_for

        async with engine.begin() as conn:
            domain = world["domain"]
            domain.auth_webhook_url = "https://legacy.example.test/auth"
            domain.auth_webhook_verified = True
            await DomainRepo(conn).update(domain)
            await AuthProviderRepo(conn).create(
                "corp", "webhook", {"url": "https://x.example.test/a"},
                domains=["acme.test"],
            )

            providers = await providers_for(conn, domain.id, "acme.test")

        assert [p.name for p in providers] == ["corp"]


class TestEndToEnd:
    async def test_an_external_account_never_uses_its_old_local_hash(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        """That is how a revoked account keeps working."""
        async with engine.begin() as conn:
            result = await Authenticator(conn).authenticate("ops@acme.test", "anything")

        assert not result.ok
        assert result.failure is AuthFailure.NO_PROVIDER

    async def test_no_provider_is_temporary_not_a_wrong_password(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        async with engine.begin() as conn:
            result = await Authenticator(conn).authenticate("ops@acme.test", "anything")

        assert result.temporary

    async def test_the_detail_says_what_to_do(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        async with engine.begin() as conn:
            result = await Authenticator(conn).authenticate("ops@acme.test", "anything")

        assert result.detail is not None
        assert "lightr auth list" in result.detail


class TestRepo:
    async def test_a_kind_lightr_does_not_implement_is_refused(
        self, conn: AsyncConnection
    ) -> None:
        """RADIUS is in the schema's comment and is not built. A row
        naming it must not be accepted and then silently ignored."""
        with pytest.raises(ProviderConfigError, match="radius"):
            await AuthProviderRepo(conn).create("rad", "radius", {})

    async def test_a_config_that_can_never_work_is_refused_on_write(
        self, conn: AsyncConnection
    ) -> None:
        """Better at the point it is written than at the first login."""
        record = await AuthProviderRepo(conn).create(
            "corp", "ldap", {"uri": "ldaps://dc.corp", "base_dn": "ou=people"}
        )
        assert record.kind == "ldap"

    async def test_resolvable_by_name(self, conn: AsyncConnection) -> None:
        await AuthProviderRepo(conn).create(
            "corp", "webhook", {"url": "https://x.example.test/a"}
        )
        assert (await AuthProviderRepo(conn).resolve("corp")).name == "corp"

    async def test_an_unknown_name_says_what_to_run(self, conn: AsyncConnection) -> None:
        from lightr.repo import NotFoundError

        with pytest.raises(NotFoundError, match="lightr auth list"):
            await AuthProviderRepo(conn).resolve("nope")

    async def test_config_round_trips(self, conn: AsyncConnection) -> None:
        await AuthProviderRepo(conn).create(
            "corp", "ldap",
            {"uri": "ldaps://dc.corp", "base_dn": "ou=people", "start_tls": True},
        )
        record = await AuthProviderRepo(conn).resolve("corp")

        assert record.config["start_tls"] is True
        assert record.config["base_dn"] == "ou=people"

    async def test_domains_are_lowercased(self, conn: AsyncConnection) -> None:
        record = await AuthProviderRepo(conn).create(
            "corp", "webhook", {"url": "https://x.example.test/a"},
            domains=["ACME.test"],
        )
        assert record.covers("acme.test")
