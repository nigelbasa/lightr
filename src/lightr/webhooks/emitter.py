"""Emitting webhook events from the engine.

Delivery happens in the background. A webhook receiver that is slow or
down must not slow down or fail mail delivery -- the mail is the
product, the notification is not.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.webhooks.delivery import Event, WebhookDeliverer, WebhookRepo

log = logging.getLogger("lightr.webhooks")

#: Cap on concurrent in-flight deliveries. Without one, a burst of mail
#: to a slow endpoint would open an unbounded number of connections.
MAX_CONCURRENT = 10


class Emitter:
    """Fires webhook events without blocking the caller."""

    def __init__(self, engine: AsyncEngine, *, allow_private: bool = False) -> None:
        self._engine = engine
        self._deliverer = WebhookDeliverer(allow_private=allow_private)
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        self._tasks: set[asyncio.Task] = set()

    def emit(self, event: Event | str, payload: dict[str, Any]) -> None:
        """Schedule delivery and return immediately.

        Fire-and-forget on purpose: the caller is on the mail path.
        """
        task = asyncio.create_task(self._emit(event, payload))
        # Hold a reference: a task with no strong reference can be
        # garbage-collected mid-flight, which drops the event silently.
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _emit(self, event: Event | str, payload: dict[str, Any]) -> None:
        try:
            async with self._engine.begin() as conn:
                hooks = await WebhookRepo(conn).list_for(event)
        except Exception:
            log.exception("could not load webhooks for %s", event)
            return

        if not hooks:
            return

        await asyncio.gather(
            *(self._deliver_one(hook, event, payload) for hook in hooks),
            return_exceptions=True,
        )

    async def _deliver_one(
        self, hook: Any, event: Event | str, payload: dict[str, Any]
    ) -> None:
        async with self._semaphore:
            attempt = await self._deliverer.deliver(hook, event, payload)

        try:
            async with self._engine.begin() as conn:
                await WebhookRepo(conn).record(hook.id, event, payload, attempt)
        except Exception:
            log.exception("could not record a webhook delivery for %s", hook.name)

        if not attempt.ok:
            log.warning(
                "webhook %s failed: %s %s",
                hook.name, attempt.status_code, attempt.error or attempt.body[:100],
            )

    async def drain(self, timeout: float = 10.0) -> None:
        """Wait for in-flight deliveries, for a clean shutdown."""
        if not self._tasks:
            return
        await asyncio.wait(set(self._tasks), timeout=timeout)


__all__ = ["MAX_CONCURRENT", "Emitter"]
