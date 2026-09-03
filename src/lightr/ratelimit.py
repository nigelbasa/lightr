"""Rate limits for the API and the SMTP listeners.

What this is, precisely: **rate limiting**, not DDoS protection. It
refuses more work than a caller is entitled to, cheaply, before that
work reaches the database or Dovecot. It does nothing about a flood
large enough to fill the link or exhaust the accept queue -- that is
answered upstream, by the network, and claiming otherwise in a mail
server's own process would be a lie an operator might rely on.

Two things it does buy:

* an API key cannot spend the whole server on itself, and
  ``rate_limit``/``daily_limit`` -- columns that have been stored on
  every key since the Go engine and read by nothing -- finally mean
  something
* guessing an API key, or hammering the SMTP port, costs the caller
  time

**State lives in this process.** One Lightr, one set of buckets. Run
two behind a load balancer and each enforces the limit separately, so
the effective limit is doubled -- correct behaviour for the single
process the .deb installs, and worth knowing before adding a second.
Backing this with the database would make it exact and put a write on
the path of every request, which is the wrong trade for a limit whose
job is to be cheap.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(slots=True)
class Bucket:
    """A token bucket: ``capacity`` tokens, refilled over ``period``.

    Bursts are allowed up to the capacity, which is what makes this
    usable for real clients -- a limit that spread requests evenly
    would refuse an ordinary page of parallel fetches.
    """

    capacity: float
    period: float
    tokens: float = field(default=0.0)
    updated: float = field(default=0.0)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.updated = time.monotonic()

    def take(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        elapsed = max(0.0, now - self.updated)
        self.updated = now
        self.tokens = min(
            self.capacity, self.tokens + elapsed * (self.capacity / self.period)
        )
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True

    def retry_after(self, now: float | None = None) -> int:
        """Whole seconds until one token is available. Never zero."""
        now = time.monotonic() if now is None else now
        missing = max(0.0, 1.0 - self.tokens)
        return max(1, int(missing / (self.capacity / self.period)) + 1)


def limiter(capacity: int, period: float) -> Limiter | None:
    """A limiter, or None when the setting says not to limit.

    Zero means unlimited everywhere in Lightr. Reading it as "capacity
    zero" would make an operator who set a limit to nothing, meaning
    "stop limiting this", refuse every request instead -- and on the
    receive listener that is the whole inbound mail flow.
    """
    return Limiter(capacity, period) if capacity > 0 else None


class Limiter:
    """Token buckets keyed by whatever identifies the caller.

    Idle keys are dropped rather than accumulating: an unauthenticated
    limiter is keyed by client address, so without this a caller could
    grow the table by rotating source addresses.
    """

    #: Sweep when the table gets this big, not on a timer: a timer
    #: needs a running loop, and this has to work in the SMTP handler
    #: and the API middleware alike.
    SWEEP_AT = 4096

    def __init__(self, capacity: float, period: float) -> None:
        self.capacity = capacity
        self.period = period
        self._buckets: dict[str, Bucket] = {}

    def bucket(self, key: str) -> Bucket:
        found = self._buckets.get(key)
        if found is None:
            if len(self._buckets) >= self.SWEEP_AT:
                self._sweep()
            found = self._buckets[key] = Bucket(self.capacity, self.period)
        return found

    def allow(self, key: str) -> bool:
        return self.bucket(key).take()

    def retry_after(self, key: str) -> int:
        return self.bucket(key).retry_after()

    def forget(self, key: str) -> None:
        self._buckets.pop(key, None)

    def _sweep(self) -> None:
        """Drop buckets that have refilled -- they hold no state."""
        now = time.monotonic()
        for key, bucket in list(self._buckets.items()):
            if now - bucket.updated > self.period:
                del self._buckets[key]

    def __len__(self) -> int:
        return len(self._buckets)


class KeyLimiter:
    """Per-API-key limits, taken from the key's own settings.

    A key carries ``rate_limit`` (requests per minute) and
    ``daily_limit``. Both were stored and neither was read; this is
    what reads them.
    """

    def __init__(self) -> None:
        self._minute: dict[str, Bucket] = {}
        self._day: dict[str, Bucket] = {}

    def check(self, key_id: str, rate_limit: int, daily_limit: int) -> int | None:
        """Return seconds to wait, or None if the request may proceed.

        A limit of zero or less means unlimited: an operator who sets
        it to nothing means "do not limit this key", and reading it as
        "refuse everything" would take an integration down.
        """
        for table, limit, period in (
            (self._minute, rate_limit, 60.0),
            (self._day, daily_limit, 86_400.0),
        ):
            if limit <= 0:
                continue
            bucket = table.get(key_id)
            if bucket is None or bucket.capacity != limit:
                bucket = table[key_id] = Bucket(float(limit), period)
            if not bucket.take():
                return bucket.retry_after()
        return None

    def forget(self, key_id: str) -> None:
        self._minute.pop(key_id, None)
        self._day.pop(key_id, None)


__all__ = ["Bucket", "KeyLimiter", "Limiter", "limiter"]
