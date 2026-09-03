"""Rate limits.

The honest claim is narrow: these refuse more work than a caller is
entitled to, before that work reaches the database or Dovecot. They do
nothing about a flood large enough to fill the link, and the tests are
written to hold the code to the narrow claim rather than the flattering
one.

The failure mode worth guarding is a limiter that is too eager: an
integration that stops working at 3am because a bucket was accidentally
shared, or because "no limit" was read as "no requests".
"""

from __future__ import annotations

import httpx
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.api.app import create_app
from lightr.config import Config
from lightr.ratelimit import Bucket, KeyLimiter, Limiter


class TestBucket:
    def test_a_burst_up_to_capacity_is_allowed(self) -> None:
        """A limit that spread requests evenly would refuse an ordinary
        page of parallel fetches."""
        bucket = Bucket(capacity=5, period=60.0)

        assert all(bucket.take(now=100.0) for _ in range(5))

    def test_the_next_one_is_refused(self) -> None:
        bucket = Bucket(capacity=5, period=60.0)
        for _ in range(5):
            bucket.take(now=100.0)

        assert not bucket.take(now=100.0)

    def test_it_refills_over_time(self) -> None:
        bucket = Bucket(capacity=60, period=60.0)
        for _ in range(60):
            bucket.take(now=100.0)

        assert bucket.take(now=102.0)

    def test_retry_after_is_never_zero(self) -> None:
        """A Retry-After of 0 tells a client to retry immediately,
        which is the traffic the limit exists to stop."""
        bucket = Bucket(capacity=1, period=60.0)
        bucket.take(now=100.0)

        assert bucket.retry_after(now=100.0) >= 1


class TestLimiter:
    def test_callers_do_not_share_a_bucket(self) -> None:
        """One noisy address must not lock everyone else out."""
        limiter = Limiter(capacity=1, period=60.0)

        assert limiter.allow("10.0.0.1")
        assert not limiter.allow("10.0.0.1")
        assert limiter.allow("10.0.0.2")

    def test_the_table_does_not_grow_without_bound(self) -> None:
        """It is keyed by client address, so without a sweep a caller
        could grow it by rotating source addresses."""
        limiter = Limiter(capacity=1, period=0.001)
        for n in range(Limiter.SWEEP_AT + 10):
            limiter.allow(f"10.0.{n // 256}.{n % 256}")

        assert len(limiter) < Limiter.SWEEP_AT + 10

    def test_forgetting_a_caller_clears_its_budget(self) -> None:
        limiter = Limiter(capacity=1, period=60.0)
        limiter.allow("10.0.0.1")

        limiter.forget("10.0.0.1")

        assert limiter.allow("10.0.0.1")


class TestKeyLimiter:
    def test_a_key_is_limited_by_its_own_setting(self) -> None:
        limiter = KeyLimiter()

        allowed = [
            limiter.check("key-1", rate_limit=2, daily_limit=0) for _ in range(3)
        ]

        assert allowed[:2] == [None, None]
        assert allowed[2] is not None

    def test_keys_do_not_share_a_budget(self) -> None:
        limiter = KeyLimiter()
        limiter.check("key-1", rate_limit=1, daily_limit=0)

        assert limiter.check("key-2", rate_limit=1, daily_limit=0) is None

    def test_zero_means_unlimited_not_forbidden(self) -> None:
        """An operator setting a limit to nothing means "do not limit
        this key". Reading it as "refuse everything" would take an
        integration down at the moment someone tried to relax a limit.
        """
        limiter = KeyLimiter()

        assert all(
            limiter.check("key-1", rate_limit=0, daily_limit=0) is None
            for _ in range(500)
        )

    def test_the_daily_limit_is_separate_from_the_per_minute_one(self) -> None:
        limiter = KeyLimiter()

        results = [
            limiter.check("key-1", rate_limit=1000, daily_limit=2) for _ in range(3)
        ]

        assert results[:2] == [None, None]
        assert results[2] is not None

    def test_changing_a_key_limit_takes_effect(self) -> None:
        """The bucket is rebuilt when the configured capacity changes,
        so raising a limit does not wait out the old one."""
        limiter = KeyLimiter()
        limiter.check("key-1", rate_limit=1, daily_limit=0)

        assert limiter.check("key-1", rate_limit=100, daily_limit=0) is None


class TestWhatItDoesNotClaim:
    def test_state_is_per_process(self) -> None:
        """Two Lightrs behind a load balancer each enforce their own
        copy of the limit. That is a documented property, not a bug --
        but it must not be quietly untrue either way."""
        first, second = Limiter(1, 60.0), Limiter(1, 60.0)

        assert first.allow("10.0.0.1")
        assert second.allow("10.0.0.1")


@pytest_asyncio.fixture
async def limited(cfg: Config, engine: AsyncEngine):
    """An API whose failure budget is small enough to exhaust."""
    cfg.limits.auth_failures_per_minute = 3
    app = create_app(cfg, engine=engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestTheAPIMiddleware:
    async def test_guessing_a_key_is_refused_after_a_few_tries(
        self, limited: httpx.AsyncClient
    ) -> None:
        codes = [
            (await limited.get("/v1/orgs", headers={"X-API-Key": f"lk_wrong{n}"}))
            .status_code
            for n in range(6)
        ]

        assert codes[0] == 401
        assert 429 in codes

    async def test_the_refusal_says_when_to_come_back(
        self, limited: httpx.AsyncClient
    ) -> None:
        """A 429 without Retry-After trains clients to retry at once,
        which is the traffic the limit exists to stop."""
        for n in range(6):
            response = await limited.get(
                "/v1/orgs", headers={"X-API-Key": f"lk_wrong{n}"}
            )
            if response.status_code == 429:
                assert int(response.headers["Retry-After"]) >= 1
                return
        raise AssertionError("never rate limited")

    async def test_health_is_not_limited(self, limited: httpx.AsyncClient) -> None:
        """It is what a load balancer polls. Limiting it takes the
        server out of rotation under exactly the load the limit was
        meant to survive."""
        codes = {(await limited.get("/health")).status_code for _ in range(50)}

        assert 429 not in codes

    async def test_a_valid_key_gets_its_failure_budget_back(
        self, cfg: Config, engine: AsyncEngine
    ) -> None:
        """Otherwise an office behind one NAT locks itself out by
        mistyping a key a few times."""
        from lightr.apikeys import APIKeyRepo, KeyType

        cfg.limits.auth_failures_per_minute = 3
        async with engine.begin() as conn:
            _, secret = await APIKeyRepo(conn).create("root", key_type=KeyType.ADMIN)

        app = create_app(cfg, engine=engine)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            for n in range(2):
                await c.get("/v1/orgs", headers={"X-API-Key": f"lk_wrong{n}"})
            assert (
                await c.get("/v1/orgs", headers={"X-API-Key": secret})
            ).status_code == 200
            for n in range(2):
                assert (
                    await c.get("/v1/orgs", headers={"X-API-Key": f"lk_bad{n}"})
                ).status_code == 401
