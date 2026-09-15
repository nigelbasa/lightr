"""Draining the outbound queue.

Runs as an asyncio task inside the server. If it ever moves to a
separate process, the claim in ``Queue.claim`` is already what makes
that safe.

Delivery is either through a domain's configured relay (a smarthost)
or direct to the recipient's MX. Relay is preferred when configured,
because most operators cannot deliver direct from a small IP without
landing in spam.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from email.message import EmailMessage

from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config
from lightr.mail.dkim import sign_or_warn
from lightr.mail.queue import Queue, QueuedMessage, QueueStatus
from lightr.repo import DomainRepo

log = logging.getLogger("lightr.sender")

#: How long to wait when the queue is empty before looking again.
IDLE_INTERVAL = 10.0

#: How often expired reply tokens are removed.
SWEEP_INTERVAL = 3600.0

#: Sending failures that are not an SMTP status. Treated as transient:
#: a DNS blip or a connection reset is not the recipient's fault.
TRANSIENT_CODE = 451


@dataclass(frozen=True, slots=True)
class SendResult:
    ok: bool
    code: int = 250
    detail: str = ""


class Sender:
    """Delivers queued messages to remote servers."""

    def __init__(self, cfg: Config, engine: AsyncEngine) -> None:
        self.cfg = cfg
        self.engine = engine
        self._stopping = asyncio.Event()

    async def run(self) -> None:
        """Drain the queue until stopped."""
        log.info("outbound sender started")
        last_sweep = 0.0
        while not self._stopping.is_set():
            try:
                sent = await self.drain_once()
            except Exception:
                log.exception("sender iteration failed")
                sent = 0

            # Expired reply tokens. Here rather than on a separate timer
            # because this loop already runs for the life of the server,
            # and the only other thing that cleaned tables was an
            # operator remembering a command.
            now = asyncio.get_running_loop().time()
            if now - last_sweep >= SWEEP_INTERVAL:
                last_sweep = now
                await self.sweep()

            if sent == 0:
                # Nothing to do; wait, but wake immediately on stop.
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._stopping.wait(), timeout=IDLE_INTERVAL
                    )
        log.info("outbound sender stopped")

    def stop(self) -> None:
        self._stopping.set()

    async def sweep(self) -> int:
        """Remove expired reply tokens. Never raises."""
        from lightr.mail.replies import ReplyRouteRepo

        try:
            async with self.engine.begin() as conn:
                removed = await ReplyRouteRepo(conn).sweep()
        except Exception:
            log.exception("could not sweep expired reply tokens")
            return 0
        if removed:
            log.info("removed %d expired reply token(s)", removed)
        return removed

    async def drain_once(self, limit: int = 10) -> int:
        """Claim and attempt a batch. Returns how many were attempted."""
        async with self.engine.begin() as conn:
            claimed = await Queue(conn).claim(limit=limit)

        for message in claimed:
            await self._attempt(message)
        return len(claimed)

    async def _attempt(self, message: QueuedMessage) -> None:
        result = await self.send(message)

        async with self.engine.begin() as conn:
            queue = Queue(conn)
            if result.ok:
                await queue.mark_sent(message.id)
                log.info("delivered %s to %s", message.id, ", ".join(message.to_addrs))
            else:
                outcome = await queue.mark_failed(
                    message.id, code=result.code, error=result.detail
                )
                if outcome is QueueStatus.FAILED:
                    log.warning(
                        "giving up on %s: %s %s",
                        message.id, result.code, result.detail,
                    )

    async def send(self, message: QueuedMessage) -> SendResult:
        """Send one message. Never raises -- failures become a SendResult."""
        try:
            async with self.engine.begin() as conn:
                domain = await DomainRepo(conn).resolve(str(message.domain_id))
        except LookupError as exc:
            # The domain was deleted after queueing. Nothing will fix
            # this, so it is permanent.
            return SendResult(False, 550, f"unknown sending domain: {exc}")

        payload = self._compose(message, domain)
        helo = self.helo_name(domain)

        if domain.relay_enabled and domain.relay_host:
            return await self._send_via_relay(message, domain, payload, helo)
        return await self._send_direct(message, payload, helo)

    def helo_name(self, domain: object) -> str:
        """The name to greet the remote server with, for this sending domain.

        Left unset, aiosmtplib greets with the machine's own name, which
        on the VPS was "localhost" -- a greeting receiving servers count
        against the sender. A host this server holds a certificate for
        under the sending domain (mail.example.com for example.com) is
        the most specific honest answer; otherwise the server's name.
        """
        name = str(getattr(domain, "name", "") or "").lower().rstrip(".")
        if name:
            for host in self.cfg.tls.domain_certs:
                candidate = host.lower().rstrip(".")
                if candidate == name or candidate.endswith("." + name):
                    return candidate
        return self.cfg.server.hostname

    def _compose(self, message: QueuedMessage, domain: object) -> bytes:
        """The wire form, signed if the domain has a DKIM key.

        A message queued whole is sent whole. Rebuilding every message
        from its subject and plain-text body is what stripped the
        attachments, the HTML part and the headers from everything a
        mail client submitted -- the recipient got a text-only copy of
        what was sent.

        An existing DKIM-Signature on a forwarded message is left in
        place; ours is prepended. The original may or may not still
        verify after forwarding, but it is not ours to remove.
        """
        if message.raw:
            raw = message.raw
        else:
            email = EmailMessage()
            email["From"] = message.from_addr
            email["To"] = ", ".join(message.to_addrs)
            email["Subject"] = message.subject
            email.set_content(message.body)
            raw = email.as_bytes()

        private_key = getattr(domain, "dkim_private_key", None)
        if private_key:
            raw = sign_or_warn(
                raw,
                domain=getattr(domain, "name", ""),
                selector=getattr(domain, "dkim_selector", None) or "default",
                private_key_pem=private_key,
            )
        return raw

    async def _send_via_relay(
        self, message: QueuedMessage, domain: object, payload: bytes, helo: str
    ) -> SendResult:
        """Hand off to a configured smarthost."""
        try:
            import aiosmtplib
        except ImportError:  # pragma: no cover - depends on install
            return SendResult(False, TRANSIENT_CODE, "aiosmtplib is not installed")

        from lightr.mail.relay import connection

        settings = connection(domain)  # type: ignore[arg-type]
        host, port = settings["hostname"], settings["port"]

        try:
            await aiosmtplib.send(
                payload,
                sender=message.sender,
                recipients=message.to_addrs,
                local_hostname=helo,
                timeout=30,
                **settings,
            )
        except Exception as exc:
            return SendResult(False, _code_from(exc), f"relay {host}:{port}: {exc}")
        return SendResult(True)

    async def _send_direct(
        self, message: QueuedMessage, payload: bytes, helo: str
    ) -> SendResult:
        """Deliver straight to the recipient's MX."""
        try:
            import aiosmtplib
        except ImportError:  # pragma: no cover - depends on install
            return SendResult(False, TRANSIENT_CODE, "aiosmtplib is not installed")

        # One recipient domain at a time: different domains have
        # different MX hosts, and a failure for one must not be
        # recorded against the others.
        by_domain: dict[str, list[str]] = {}
        for recipient in message.to_addrs:
            if "@" not in recipient:
                continue
            by_domain.setdefault(recipient.split("@", 1)[1].lower(), []).append(recipient)

        if not by_domain:
            return SendResult(False, 550, "no deliverable recipients")

        for domain_name, recipients in by_domain.items():
            hosts = await self._mx_hosts(domain_name)
            if not hosts:
                return SendResult(False, TRANSIENT_CODE, f"no MX for {domain_name}")

            last: Exception | None = None
            for host in hosts:
                try:
                    await aiosmtplib.send(
                        payload,
                        sender=message.sender,
                        recipients=recipients,
                        hostname=host,
                        port=25,
                        start_tls=None,  # opportunistic
                        local_hostname=helo,
                        timeout=30,
                    )
                    last = None
                    break
                except Exception as exc:
                    last = exc
                    continue
            if last is not None:
                return SendResult(False, _code_from(last), f"{domain_name}: {last}")

        return SendResult(True)

    async def _mx_hosts(self, domain: str) -> list[str]:
        """MX hosts for a domain, in preference order."""
        try:
            import dns.asyncresolver
        except ImportError:  # pragma: no cover - depends on install
            return []

        try:
            answers = await dns.asyncresolver.resolve(domain, "MX")
        except Exception:
            return []

        records = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in records]


def _code_from(exc: Exception) -> int:
    """Extract an SMTP status from an exception, defaulting to transient.

    Guessing permanent would bounce mail that a retry would deliver, so
    anything unrecognised is treated as temporary.
    """
    code = getattr(exc, "code", None)
    if isinstance(code, int) and 200 <= code < 600:
        return code
    return TRANSIENT_CODE


__all__ = ["IDLE_INTERVAL", "SendResult", "Sender"]
