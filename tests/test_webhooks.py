"""Webhook signing, SSRF protection, and delivery.

The SSRF guard is the security-critical part: a webhook URL is chosen
by a tenant and fetched by the server, which without a guard is a
request-forgery primitive pointed at whatever the server can reach.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.db import schema
from lightr.webhooks.delivery import (
    Attempt,
    Event,
    Webhook,
    WebhookDeliverer,
    WebhookRepo,
    sign,
    verify,
)
from lightr.webhooks.ssrf import SSRFError, is_blocked, vet

SECRET = "a-shared-secret"


class TestSSRFBlocking:
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata
            "http://127.0.0.1:8080/hook",
            "http://localhost/hook",
            "http://10.0.0.5/hook",
            "http://192.168.1.1/hook",
            "http://172.16.0.1/hook",
            "http://[::1]/hook",
            "http://0.0.0.0/hook",
        ],
    )
    def test_private_and_reserved_targets_are_refused(self, url: str) -> None:
        with pytest.raises(SSRFError):
            vet(url)

    def test_cloud_metadata_is_named_explicitly(self) -> None:
        """The single most valuable SSRF target."""
        with pytest.raises(SSRFError, match="private or reserved"):
            vet("http://169.254.169.254/latest/meta-data/iam/")

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://example.test/",
            "ftp://example.test/",
            "//example.test/hook",
        ],
    )
    def test_non_http_schemes_are_refused(self, url: str) -> None:
        with pytest.raises(SSRFError):
            vet(url)

    def test_credentials_in_the_url_are_refused(self) -> None:
        """user:pass@host reads as one host to a person and resolves as
        another."""
        with pytest.raises(SSRFError, match="credentials"):
            vet("http://real.test@evil.test/hook")

    @pytest.mark.parametrize("port", [22, 25, 3306, 5432, 6379, 11211])
    def test_service_ports_are_refused(self, port: int) -> None:
        with pytest.raises(SSRFError, match="not allowed"):
            vet(f"http://example.test:{port}/hook")

    def test_unresolvable_host_is_refused(self) -> None:
        with pytest.raises(SSRFError):
            vet("http://this-name-does-not-resolve.invalid/hook")

    def test_allow_private_is_opt_in(self) -> None:
        """Operators whose target really is on the local network can
        say so; the default stays safe."""
        target = vet("http://127.0.0.1:8080/hook", allow_private=True)
        assert target.address.startswith("127.")


class TestAddressChecks:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.0.1",
            "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "fc00::1",
        ],
    )
    def test_blocked(self, address: str) -> None:
        assert is_blocked(address)

    @pytest.mark.parametrize("address", ["93.184.216.34", "8.8.8.8", "2606:4700::1"])
    def test_allowed(self, address: str) -> None:
        assert not is_blocked(address)

    def test_ipv4_mapped_ipv6_is_unwrapped(self) -> None:
        """::ffff:127.0.0.1 reaches the same host as 127.0.0.1, so it
        must not slip past as 'some IPv6 address'."""
        assert is_blocked("::ffff:127.0.0.1")
        assert is_blocked("::ffff:169.254.169.254")

    def test_unparseable_is_treated_as_unsafe(self) -> None:
        assert is_blocked("not-an-address")


class TestPinning:
    def test_connect_url_uses_the_vetted_address(self) -> None:
        """Connecting by name would allow a second DNS lookup to
        resolve somewhere else."""
        target = vet("http://127.0.0.1:8080/hook", allow_private=True)
        assert "127.0.0.1" in target.connect_url
        assert target.host == "127.0.0.1"

    def test_path_survives_pinning(self) -> None:
        target = vet("http://127.0.0.1:8080/a/b?c=d", allow_private=True)
        assert "/a/b?c=d" in target.connect_url


class TestSignatures:
    def test_round_trip(self) -> None:
        payload = b'{"event":"mail.received"}'
        timestamp = str(int(datetime.now(UTC).timestamp()))

        signature = sign(SECRET, timestamp, payload)

        assert verify(SECRET, signature, timestamp, payload)

    def test_a_tampered_body_fails(self) -> None:
        timestamp = str(int(datetime.now(UTC).timestamp()))
        signature = sign(SECRET, timestamp, b'{"amount":1}')

        assert not verify(SECRET, signature, timestamp, b'{"amount":1000}')

    def test_the_wrong_secret_fails(self) -> None:
        timestamp = str(int(datetime.now(UTC).timestamp()))
        signature = sign(SECRET, timestamp, b"x")

        assert not verify("another-secret", signature, timestamp, b"x")

    def test_an_old_signature_is_refused(self) -> None:
        """The timestamp is signed too, so a captured request cannot be
        replayed forever."""
        old = str(int((datetime.now(UTC) - timedelta(hours=1)).timestamp()))
        signature = sign(SECRET, old, b"x")

        assert not verify(SECRET, signature, old, b"x")

    def test_a_future_timestamp_is_refused(self) -> None:
        future = str(int((datetime.now(UTC) + timedelta(hours=1)).timestamp()))
        assert not verify(SECRET, sign(SECRET, future, b"x"), future, b"x")

    def test_reusing_a_signature_with_a_new_timestamp_fails(self) -> None:
        """The point of signing both together."""
        original = str(int(datetime.now(UTC).timestamp()))
        signature = sign(SECRET, original, b"x")
        replayed = str(int(datetime.now(UTC).timestamp()) + 1)

        assert not verify(SECRET, signature, replayed, b"x")

    @pytest.mark.parametrize("bad", ["", "not-a-number", "99999999999999999999"])
    def test_malformed_timestamps_are_refused(self, bad: str) -> None:
        assert not verify(SECRET, "sha256=x", bad, b"x")

    def test_signature_is_prefixed_with_its_algorithm(self) -> None:
        assert sign(SECRET, "1", b"x").startswith("sha256=")


class TestRetryClassification:
    @pytest.mark.parametrize("code", [500, 502, 503, 504, 429])
    def test_server_errors_are_retryable(self, code: int) -> None:
        assert Attempt(ok=False, status_code=code).retryable

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 410, 422])
    def test_client_errors_are_not(self, code: int) -> None:
        """A 4xx means the receiver understood and refused."""
        assert not Attempt(ok=False, status_code=code).retryable

    def test_a_transport_failure_is_retryable(self) -> None:
        assert Attempt(ok=False, status_code=None, error="timeout").retryable

    def test_success_is_not_retried(self) -> None:
        assert not Attempt(ok=True, status_code=200).retryable


class TestEventSubscription:
    def _hook(self, events: list[str], **kwargs) -> Webhook:
        return Webhook(
            id=uuid4(), name="h", url="http://x.test/h", secret=SECRET,
            events=events, **kwargs,
        )

    def test_a_subscribed_event_matches(self) -> None:
        assert self._hook(["mail.received"]).wants(Event.MAIL_RECEIVED)

    def test_an_unsubscribed_event_does_not(self) -> None:
        assert not self._hook(["mail.sent"]).wants(Event.MAIL_RECEIVED)

    def test_a_wildcard_matches_everything(self) -> None:
        assert self._hook(["*"]).wants(Event.MAIL_BOUNCED)

    def test_no_events_means_all_events(self) -> None:
        assert self._hook([]).wants(Event.MAIL_RECEIVED)

    def test_an_inactive_hook_wants_nothing(self) -> None:
        assert not self._hook(["*"], active=False).wants(Event.MAIL_RECEIVED)


class TestDelivery:
    async def test_a_blocked_url_fails_without_retrying(self) -> None:
        """The URL itself is the problem; retrying cannot fix it."""
        hook = Webhook(
            id=uuid4(), name="evil", url="http://169.254.169.254/", secret=SECRET
        )

        attempt = await WebhookDeliverer().deliver(hook, Event.MAIL_RECEIVED, {})

        assert not attempt.ok
        assert not attempt.retryable
        assert "private or reserved" in attempt.error

    async def test_an_unreachable_endpoint_is_retryable(self) -> None:
        hook = Webhook(
            id=uuid4(), name="down", url="http://127.0.0.1:9000/hook",
            secret=SECRET, timeout=2,
        )

        attempt = await WebhookDeliverer(allow_private=True).deliver(
            hook, Event.MAIL_RECEIVED, {}
        )

        assert not attempt.ok
        assert attempt.retryable


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


async def _store_hook(conn: AsyncConnection, **overrides) -> UUID:
    hook_id = uuid4()
    now = datetime.now(UTC).replace(tzinfo=None)
    values = {
        "id": str(hook_id),
        "name": "ops",
        "url": "http://hooks.example.test/lightr",
        "secret": SECRET,
        "events": json.dumps(["mail.received"]),
        "active": True,
        "created_at": now,
        "updated_at": now,
    }
    values.update(overrides)
    await conn.execute(insert(schema.webhooks).values(**values))
    return hook_id


class TestRepository:
    async def test_only_subscribed_hooks_are_returned(
        self, conn: AsyncConnection
    ) -> None:
        await _store_hook(conn, name="wants", events=json.dumps(["mail.received"]))
        await _store_hook(conn, name="other", events=json.dumps(["mail.sent"]))

        hooks = await WebhookRepo(conn).list_for(Event.MAIL_RECEIVED)
        assert [h.name for h in hooks] == ["wants"]

    async def test_inactive_hooks_are_excluded(self, conn: AsyncConnection) -> None:
        await _store_hook(conn, active=False)
        assert await WebhookRepo(conn).list_for(Event.MAIL_RECEIVED) == []

    async def test_a_successful_attempt_is_logged(
        self, conn: AsyncConnection
    ) -> None:
        hook_id = await _store_hook(conn)
        repo = WebhookRepo(conn)

        await repo.record(
            hook_id, Event.MAIL_RECEIVED, {"to": "ops@acme.test"},
            Attempt(ok=True, status_code=200, duration_ms=42),
        )

        assert (await repo.stats(hook_id))["delivered"] == 1

    async def test_a_retryable_failure_is_deferred(
        self, conn: AsyncConnection
    ) -> None:
        hook_id = await _store_hook(conn)
        repo = WebhookRepo(conn)

        await repo.record(
            hook_id, Event.MAIL_RECEIVED, {},
            Attempt(ok=False, status_code=503),
        )

        assert (await repo.stats(hook_id))["deferred"] == 1

    async def test_a_permanent_failure_is_recorded_as_failed(
        self, conn: AsyncConnection
    ) -> None:
        hook_id = await _store_hook(conn)
        repo = WebhookRepo(conn)

        await repo.record(
            hook_id, Event.MAIL_RECEIVED, {}, Attempt(ok=False, status_code=404)
        )

        assert (await repo.stats(hook_id))["failed"] == 1

    async def test_a_large_payload_is_truncated(
        self, conn: AsyncConnection
    ) -> None:
        from sqlalchemy import select

        hook_id = await _store_hook(conn)
        await WebhookRepo(conn).record(
            hook_id, Event.MAIL_RECEIVED, {"body": "x" * 50_000},
            Attempt(ok=True, status_code=200),
        )

        stored = (
            await conn.execute(select(schema.webhook_events.c.payload))
        ).scalar_one()
        assert len(stored) <= 10_000
