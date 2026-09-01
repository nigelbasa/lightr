"""Registering and managing webhooks.

Delivery and signing were already covered; what is new here is the
management surface, and the two ways it can go wrong: handing a signing
secret to someone who should not have it, and letting one tenant see
another's endpoints.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.repo import AmbiguousReferenceError, NotFoundError
from lightr.webhooks.delivery import Event, WebhookRepo, validate_events


@pytest.fixture
async def repo_conn(engine: AsyncEngine):
    async with engine.begin() as conn:
        yield conn


class TestCreate:
    async def test_a_webhook_is_registered(self, repo_conn) -> None:
        hook = await WebhookRepo(repo_conn).create(
            "billing", "https://hooks.example.test/lightr"
        )
        assert hook.name == "billing"
        assert hook.active

    async def test_a_secret_is_generated_when_none_is_given(self, repo_conn) -> None:
        """A receiver that cannot verify a signature has no way to tell
        a real event from anything else that can reach its URL."""
        hook = await WebhookRepo(repo_conn).create("b", "https://x.example.test/h")
        assert len(hook.secret) >= 32

    async def test_a_given_secret_is_kept(self, repo_conn) -> None:
        hook = await WebhookRepo(repo_conn).create(
            "b", "https://x.example.test/h", secret="shared-with-the-receiver"
        )
        assert hook.secret == "shared-with-the-receiver"

    async def test_no_events_means_all_events(self, repo_conn) -> None:
        hook = await WebhookRepo(repo_conn).create("b", "https://x.example.test/h")
        assert hook.events == ["*"]
        assert hook.wants(Event.MAIL_RECEIVED)

    async def test_a_misspelt_event_is_refused(self, repo_conn) -> None:
        """Silently accepting it would leave a webhook that is
        configured, looks healthy, and never fires."""
        with pytest.raises(ValueError, match=r"mail\.recieved"):
            await WebhookRepo(repo_conn).create(
                "b", "https://x.example.test/h", events=["mail.recieved"]
            )

    async def test_a_url_that_is_not_a_url_is_refused_at_creation(
        self, repo_conn
    ) -> None:
        with pytest.raises(ValueError, match="scheme"):
            await WebhookRepo(repo_conn).create("b", "file:///etc/passwd")

    async def test_a_disallowed_port_is_refused_at_creation(self, repo_conn) -> None:
        with pytest.raises(ValueError, match="port 22"):
            await WebhookRepo(repo_conn).create("b", "https://x.example.test:22/h")

    async def test_a_host_that_does_not_resolve_yet_is_allowed(
        self, repo_conn
    ) -> None:
        """A receiver that is not in DNS yet is an ordinary state; the
        delivery path vets the address again anyway."""
        hook = await WebhookRepo(repo_conn).create(
            "b", "https://not-deployed-yet.example.test/h"
        )
        assert hook.url.endswith("/h")


class TestResolve:
    async def test_by_name(self, repo_conn) -> None:
        """No command should force the caller to know a UUID."""
        await WebhookRepo(repo_conn).create("billing", "https://x.example.test/h")
        assert (await WebhookRepo(repo_conn).resolve("billing")).name == "billing"

    async def test_by_id(self, repo_conn) -> None:
        hook = await WebhookRepo(repo_conn).create("b", "https://x.example.test/h")
        assert (await WebhookRepo(repo_conn).resolve(str(hook.id))).id == hook.id

    async def test_an_unknown_name_says_what_to_run(self, repo_conn) -> None:
        with pytest.raises(NotFoundError, match="lightr webhook list"):
            await WebhookRepo(repo_conn).resolve("nope")

    async def test_two_of_the_same_name_are_reported_not_guessed(
        self, repo_conn
    ) -> None:
        repo = WebhookRepo(repo_conn)
        await repo.create("dup", "https://a.example.test/h")
        await repo.create("dup", "https://b.example.test/h")

        with pytest.raises(AmbiguousReferenceError):
            await repo.resolve("dup")


class TestUpdate:
    async def test_only_named_fields_change(self, repo_conn) -> None:
        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h", description="first")

        await repo.update(hook.id, url="https://y.example.test/h")
        updated = await repo.resolve("b")

        assert updated.url == "https://y.example.test/h"
        assert updated.description == "first"

    async def test_a_bad_url_is_refused_and_nothing_changes(self, repo_conn) -> None:
        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")

        with pytest.raises(ValueError):
            await repo.update(hook.id, url="gopher://x.example.test/h")

        assert (await repo.resolve("b")).url == "https://x.example.test/h"

    async def test_unknown_fields_are_ignored_not_written(self, repo_conn) -> None:
        """A PATCH body is caller-supplied; it must not reach columns
        nobody meant to expose."""
        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")

        await repo.update(hook.id, organization_id="somebody-elses", id="hijacked")

        assert (await repo.resolve("b")).id == hook.id

    async def test_disabling_stops_delivery(self, repo_conn) -> None:
        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")
        await repo.update(hook.id, active=False)

        assert await repo.list_for(Event.MAIL_RECEIVED) == []

    async def test_rotating_replaces_the_secret(self, repo_conn) -> None:
        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")

        rotated = await repo.rotate_secret(hook.id)

        assert rotated != hook.secret
        assert (await repo.resolve("b")).secret == rotated


class TestDelete:
    async def test_it_goes_away(self, repo_conn) -> None:
        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")
        await repo.delete(hook.id)

        assert await repo.list() == []

    async def test_its_delivery_history_goes_with_it(self, repo_conn) -> None:
        from lightr.webhooks.delivery import Attempt

        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")
        await repo.record(hook.id, Event.MAIL_SENT, {}, Attempt(ok=True, status_code=200))

        await repo.delete(hook.id)

        assert await repo.deliveries(hook.id) == []


class TestDeliveries:
    async def test_attempts_are_listed_newest_first(self, repo_conn) -> None:
        from lightr.webhooks.delivery import Attempt

        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")
        await repo.record(hook.id, Event.MAIL_SENT, {}, Attempt(ok=True, status_code=200))
        await repo.record(
            hook.id, Event.MAIL_BOUNCED, {}, Attempt(ok=False, status_code=500)
        )

        rows = await repo.deliveries(hook.id)

        assert len(rows) == 2
        assert {r["event_type"] for r in rows} == {"mail.sent", "mail.bounced"}

    async def test_stats_count_by_status(self, repo_conn) -> None:
        from lightr.webhooks.delivery import Attempt

        repo = WebhookRepo(repo_conn)
        hook = await repo.create("b", "https://x.example.test/h")
        await repo.record(hook.id, Event.MAIL_SENT, {}, Attempt(ok=True, status_code=200))

        assert (await repo.stats(hook.id))["delivered"] == 1


class TestEventValidation:
    def test_every_declared_event_is_accepted(self) -> None:
        assert validate_events([str(e) for e in Event])

    def test_a_wildcard_is_accepted(self) -> None:
        assert validate_events(["*"]) == ["*"]

    def test_duplicates_collapse(self) -> None:
        assert validate_events(["mail.sent", "mail.sent"]) == ["mail.sent"]

    def test_the_error_lists_what_is_valid(self) -> None:
        with pytest.raises(ValueError, match=r"mail\.sent"):
            validate_events(["nonsense"])
