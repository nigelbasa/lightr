"""SMTP receive and submission.

Two listeners with deliberately different rules:

**:25 -- receive.** Unauthenticated mail from the internet. Accepts
only recipients we host; anything else is "Relay access denied", which
is what keeps the server off blocklists.

**:587 -- submission.** Authenticated users sending outbound. Requires
credentials, and requires TLS before accepting them unless the
operator has explicitly allowed otherwise.

Both end at the same place: analysis, routing, then LMTP into Dovecot
for local recipients and the outbound queue for the rest.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message
from email.policy import SMTP as SMTP_POLICY

from aiosmtpd.smtp import AuthResult, Envelope, LoginPassword, Session
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.auth import Authenticator
from lightr.config import Config
from lightr.dovecot.lmtp import LMTPClient, LMTPError
from lightr.mail import headers as header_tools
from lightr.mail.routing import RejectReason, Route, Router

log = logging.getLogger("lightr.smtp")


@dataclass(slots=True)
class DeliveryOutcome:
    """What happened to one message."""

    delivered: list[str] = field(default_factory=list)
    forwarded: list[str] = field(default_factory=list)
    rejected: list[tuple[str, RejectReason]] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.rejected

    def smtp_response(self) -> str:
        """The single status an SMTP client gets for the whole message.

        SMTP has one code for the DATA phase however many recipients
        there were, so a partial failure has to resolve to one answer.
        Anything delivered means success -- reporting failure would
        make the sender retry and duplicate the copies that worked.
        """
        if self.error:
            return f"451 4.3.0 {self.error}"
        if self.delivered or self.forwarded:
            return "250 2.0.0 OK"
        if self.rejected:
            _, reason = self.rejected[0]
            return f"{reason.smtp_code} 5.1.1 {reason.smtp_message}"
        return "550 5.1.1 No valid recipients"


class LightrHandler:
    """aiosmtpd handler for both the receive and submission listeners."""

    def __init__(
        self,
        cfg: Config,
        engine: AsyncEngine,
        *,
        require_auth: bool = False,
    ) -> None:
        self.cfg = cfg
        self.engine = engine
        self.require_auth = require_auth
        self.lmtp = LMTPClient(cfg.dovecot)

    # -- envelope phases ------------------------------------------------

    async def handle_MAIL(  # noqa: N802 - aiosmtpd's naming
        self,
        server: object,
        session: Session,
        envelope: Envelope,
        address: str,
        mail_options: list[str],
    ) -> str:
        if self.require_auth and not getattr(session, "authenticated", False):
            return "530 5.7.0 Authentication required"

        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(  # noqa: N802
        self,
        server: object,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        if len(envelope.rcpt_tos) >= self.cfg.smtp.max_recipients:
            return f"452 4.5.3 Too many recipients (max {self.cfg.smtp.max_recipients})"

        # Submission may send anywhere; receive may not. Checking here
        # rather than after DATA is what stops the server being an open
        # relay, and refuses cheaply.
        if not self.require_auth:
            async with self.engine.begin() as conn:
                route = await Router(conn).route(address)
            if route.rejected:
                assert route.reason is not None
                return f"{route.reason.smtp_code} 5.1.1 {route.reason.smtp_message}"

        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(  # noqa: N802
        self, server: object, session: Session, envelope: Envelope
    ) -> str:
        raw = envelope.content
        if not isinstance(raw, bytes):
            raw = str(raw).encode("utf-8")

        if len(raw) > self.cfg.smtp.max_message_bytes:
            return (
                f"552 5.3.4 Message too large "
                f"(max {self.cfg.smtp.max_message_bytes} bytes)"
            )

        outcome = await self.deliver(
            mail_from=envelope.mail_from or "",
            recipients=list(envelope.rcpt_tos),
            raw=raw,
            remote_ip=_peer_ip(session),
            helo=getattr(session, "host_name", "") or "",
        )
        return outcome.smtp_response()

    # -- authentication -------------------------------------------------

    async def handle_AUTH_PLAIN(  # noqa: N802
        self, server: object, session: Session, envelope: Envelope, args: list[str]
    ) -> AuthResult:  # pragma: no cover - exercised via authenticate()
        return await self.authenticate(server, session, envelope, "PLAIN", None)

    async def authenticate(
        self,
        server: object,
        session: Session,
        envelope: Envelope,
        mechanism: str,
        auth_data: object,
    ) -> AuthResult:
        """aiosmtpd's auth callback."""
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)

        if self.cfg.security.require_tls_for_auth and not _is_secure(session):
            log.warning("refused plaintext auth on an insecure connection")
            return AuthResult(success=False, handled=True)

        username = auth_data.login.decode("utf-8", "replace")
        password = auth_data.password.decode("utf-8", "replace")

        async with self.engine.begin() as conn:
            result = await Authenticator(conn).authenticate(username, password)

        if result.ok:
            return AuthResult(success=True, auth_data=result.email)
        log.info("auth failed for %s: %s", username, result.failure)
        return AuthResult(success=False, handled=True)

    # -- delivery -------------------------------------------------------

    async def deliver(
        self,
        *,
        mail_from: str,
        recipients: list[str],
        raw: bytes,
        remote_ip: str = "",
        helo: str = "",
    ) -> DeliveryOutcome:
        """Analyse, route, and hand off. The core of the receive path."""
        outcome = DeliveryOutcome()

        message = message_from_bytes(raw, policy=SMTP_POLICY)
        analysis = await self.analyse(message, mail_from=mail_from, helo=helo)

        async with self.engine.begin() as conn:
            routes = await Router(conn).route_all(recipients)

        local: list[Route] = []
        for route in routes:
            if route.rejected:
                assert route.reason is not None
                outcome.rejected.append((route.recipient, route.reason))
            elif route.delivers_locally:
                local.append(route)
                outcome.forwarded.extend(route.forward_to)
            else:
                outcome.forwarded.extend(route.forward_to)

        if not local:
            return outcome

        header_tools.apply(message, analysis, self.cfg.server.hostname)
        header_tools.ensure_message_id(message, self.cfg.server.hostname)
        header_tools.ensure_date(message)
        header_tools.add_received(
            message,
            hostname=self.cfg.server.hostname,
            remote_ip=remote_ip or "unknown",
            helo=helo,
            recipient=local[0].mailbox or local[0].recipient,
        )

        mailboxes = [r.mailbox for r in local if r.mailbox]
        try:
            result = await self.lmtp.deliver(mail_from, mailboxes, message)
        except LMTPError as exc:
            log.error("LMTP delivery failed: %s", exc)
            outcome.error = "Mail store temporarily unavailable"
            return outcome

        outcome.delivered.extend(result.delivered)
        for status in result.failed:
            log.warning("LMTP refused %s: %s %s", status.recipient,
                        status.code, status.message)
        return outcome

    async def analyse(
        self, message: Message, *, mail_from: str, helo: str
    ) -> header_tools.Analysis:
        """Score a message and evaluate its authentication.

        SPF, DKIM, and DMARC evaluation land in a later phase; the
        structure is here so the header contract with Sieve is fixed
        and the delivery path does not change when they arrive.
        """
        return header_tools.Analysis(
            score=0.0,
            is_spam=False,
            auth=header_tools.AuthResults(mail_from=mail_from, helo=helo),
            has_attachment=header_tools.has_attachment(message),
        )


def _peer_ip(session: Session) -> str:
    peer = getattr(session, "peer", None)
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return ""


def _is_secure(session: Session) -> bool:
    """Whether the connection is protected by TLS."""
    return getattr(session, "ssl", None) is not None


__all__ = ["DeliveryOutcome", "LightrHandler"]
