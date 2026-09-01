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
from base64 import b64decode
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message
from email.policy import SMTP as SMTP_POLICY
from typing import Any

from aiosmtpd.smtp import MISSING, AuthResult, Envelope, LoginPassword, Session
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

        from lightr.webhooks.emitter import Emitter

        # Fire-and-forget: a slow webhook receiver must not slow down
        # or fail mail delivery.
        self.webhooks = Emitter(engine)

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

        try:
            outcome = await self.deliver(
                mail_from=envelope.mail_from or "",
                recipients=list(envelope.rcpt_tos),
                raw=raw,
                remote_ip=_peer_ip(session),
                helo=getattr(session, "host_name", "") or "",
            )
        except Exception:
            # aiosmtpd would otherwise answer 500 with the exception
            # text in it, which tells a stranger about our internals and
            # tells the sender to give up on something retryable.
            log.exception("unhandled error while accepting mail")
            return "451 4.3.0 Temporary failure, please retry"
        return outcome.smtp_response()

    # -- authentication -------------------------------------------------

    # Authentication is implemented as auth_<MECHANISM> methods on this
    # handler, not through aiosmtpd's `authenticator=` callback.
    #
    # That callback is invoked from a *synchronous* method
    # (SMTP._authenticate) which does not await its result. Passing an
    # async function there returns a coroutine object, which aiosmtpd
    # then evaluates as "not False, not MISSING, not an AuthResult" and
    # treats as a successful login -- accepting every password, for
    # every account, including ones that do not exist.
    #
    # Handler auth_<MECH> methods *are* awaited, so checking credentials
    # against the database is only safe here.

    async def auth_PLAIN(  # noqa: N802 - aiosmtpd's naming
        self, server: Any, args: list[str]
    ) -> AuthResult:
        """AUTH PLAIN, per RFC 4616."""
        if len(args) == 1:
            blob = await server.challenge_auth("")
            if blob is MISSING:
                return AuthResult(success=False)
        else:
            try:
                blob = b64decode(args[1].encode(), validate=True)
            except Exception:
                await server.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)

        try:
            # "{authz_id}\0{login}\0{password}"; authz_id is ignored.
            _, login, password = blob.split(b"\x00")
        except ValueError:
            await server.push("501 5.5.2 Can't split auth value")
            return AuthResult(success=False, handled=True)

        return await self.authenticate(
            server, server.session, server.envelope, "PLAIN",
            LoginPassword(login, password),
        )

    async def auth_LOGIN(  # noqa: N802
        self, server: Any, args: list[str]
    ) -> AuthResult:
        """AUTH LOGIN, the older challenge/response form."""
        if len(args) == 1:
            login = await server.challenge_auth(server.AuthLoginUsernameChallenge)
            if login is MISSING:
                return AuthResult(success=False)
        else:
            try:
                login = b64decode(args[1].encode(), validate=True)
            except Exception:
                await server.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)

        password = await server.challenge_auth(server.AuthLoginPasswordChallenge)
        if password is MISSING:
            return AuthResult(success=False)

        return await self.authenticate(
            server, server.session, server.envelope, "LOGIN",
            LoginPassword(login, password),
        )

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
            return AuthResult(success=False, handled=False)

        username = auth_data.login.decode("utf-8", "replace")
        password = auth_data.password.decode("utf-8", "replace")

        async with self.engine.begin() as conn:
            result = await Authenticator(conn).authenticate(username, password)

        if result.ok:
            return AuthResult(success=True, auth_data=result.email)

        log.info("auth failed for %s: %s", username, result.failure)
        # handled=False, emphatically. In aiosmtpd, handled=True means
        # "I have already sent the response myself" -- and since we send
        # nothing, aiosmtpd completed the exchange with 235 and accepted
        # every wrong password.
        return AuthResult(success=False, handled=False)

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

        # A null sender is the RFC 5321 signal for a bounce. Recording
        # it is what keeps the suppression list current; without this
        # the engine keeps mailing dead addresses forever.
        if not mail_from:
            await self.record_bounces(raw)

        analysis = await self.analyse(
            message,
            mail_from=mail_from,
            helo=helo,
            raw=raw,
            remote_ip=remote_ip,
            recipient_count=len(recipients),
        )

        async with self.engine.begin() as conn:
            routes = await Router(conn).route_all(recipients)

        local: list[Route] = []
        outbound: list[str] = []
        for route in routes:
            if route.rejected:
                # On submission the sender has proved who they are, so
                # "not a domain we host" means "send it onward", not
                # "relay denied". That distinction is the entire point
                # of having a separate :587 -- without it an
                # authenticated user cannot mail anyone external.
                if self.require_auth and route.reason is RejectReason.NOT_LOCAL_DOMAIN:
                    outbound.append(route.recipient)
                    continue
                assert route.reason is not None
                outcome.rejected.append((route.recipient, route.reason))
            elif route.delivers_locally:
                local.append(route)
                outcome.forwarded.extend(route.forward_to)
            else:
                outcome.forwarded.extend(route.forward_to)

        if outbound:
            await self._enqueue_outbound(mail_from, outbound, message)
            outcome.forwarded.extend(outbound)

        if not local:
            # Nothing to hand to Dovecot, but the outcome still matters:
            # a message rejected outright is exactly what an operator
            # wants notified, so this path announces too.
            self._notify(outcome, mail_from=mail_from, message=message)
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

        self._notify(outcome, mail_from=mail_from, message=message)
        return outcome

    def _notify(
        self, outcome: DeliveryOutcome, *, mail_from: str, message: Message
    ) -> None:
        """Announce what happened, without blocking on it."""
        from lightr.webhooks.delivery import Event

        subject = str(message.get("Subject", "") or "")
        message_id = str(message.get("Message-ID", "") or "")

        if outcome.delivered:
            self.webhooks.emit(
                Event.MAIL_RECEIVED,
                {
                    "from": mail_from,
                    "to": outcome.delivered,
                    "subject": subject,
                    "message_id": message_id,
                },
            )
        for recipient, reason in outcome.rejected:
            self.webhooks.emit(
                Event.MAIL_REJECTED,
                {
                    "from": mail_from,
                    "to": recipient,
                    "reason": str(reason),
                    "subject": subject,
                },
            )

    async def _enqueue_outbound(
        self, mail_from: str, recipients: list[str], message: Message
    ) -> None:
        """Queue mail for delivery to another server.

        Queued rather than sent inline: a slow or unreachable remote MTA
        must not hold the submitting client's SMTP session open, and a
        failure should be retried rather than bounced immediately.
        """
        from lightr.mail.queue import Queue
        from lightr.repo import DomainRepo

        sender_domain = mail_from.split("@", 1)[1] if "@" in mail_from else ""

        async with self.engine.begin() as conn:
            try:
                domain = await DomainRepo(conn).resolve(sender_domain)
            except LookupError:
                log.warning(
                    "cannot queue mail from %s: %r is not a domain we host",
                    mail_from, sender_domain,
                )
                return

            body = message.get_body(preferencelist=("plain",))
            text = body.get_content() if body is not None else ""

            await Queue(conn).enqueue(
                org_id=domain.org_id,
                domain_id=domain.id,
                from_addr=mail_from,
                to_addrs=recipients,
                subject=str(message.get("Subject", "") or ""),
                body=text,
            )
        log.info("queued outbound mail from %s to %s", mail_from, ", ".join(recipients))

    async def record_bounces(self, raw: bytes) -> int:
        """Parse a bounce and suppress any dead addresses it names.

        Never raises: a malformed bounce must not stop the message it
        arrived in from being delivered to the postmaster mailbox, where
        a human can look at it.
        """
        from lightr.mail.bounce import BounceRepo, parse

        try:
            bounces = parse(raw)
        except Exception:
            log.exception("could not parse a bounce")
            return 0

        if not bounces:
            return 0

        suppressed = 0
        async with self.engine.begin() as conn:
            repo = BounceRepo(conn)
            for bounce in bounces:
                owner = await self._owner_of(conn, bounce.recipient)
                if owner is None:
                    # We do not know which tenant sent it. Still worth
                    # suppressing, just not attributable.
                    if bounce.should_suppress:
                        await repo.suppress(
                            bounce.recipient, reason=str(bounce.bounce_type)
                        )
                        suppressed += 1
                    continue
                org_id, domain_id = owner
                if await repo.record(bounce, org_id=org_id, domain_id=domain_id):
                    suppressed += 1

        if suppressed:
            log.info("suppressed %d address(es) from a bounce", suppressed)
        return suppressed

    async def _owner_of(self, conn: object, recipient: str) -> tuple[Any, Any] | None:
        """Which org and domain a bounced address belongs to, if ours."""
        del recipient
        from lightr.repo import DomainRepo

        # A bounce names the *remote* address that failed, so it rarely
        # belongs to a local domain. Attribute it to the only domain
        # when there is one, and leave it unattributed otherwise.
        domains = await DomainRepo(conn).list(limit=2)  # type: ignore[arg-type]
        if len(domains) == 1:
            return domains[0].org_id, domains[0].id
        return None

    async def analyse(
        self,
        message: Message,
        *,
        mail_from: str,
        helo: str,
        raw: bytes = b"",
        remote_ip: str = "",
        recipient_count: int = 1,
    ) -> header_tools.Analysis:
        """Evaluate authentication and score the message.

        Authenticated submission skips this: a user who proved who they
        are is not spam-checked, and SPF would fail for them anyway
        since they are sending from wherever they happen to be.
        """
        if self.require_auth or not self.cfg.spam.enabled:
            return header_tools.Analysis(
                auth=header_tools.AuthResults(mail_from=mail_from, helo=helo),
                has_attachment=header_tools.has_attachment(message),
            )

        from lightr.mail import authentication as mail_auth
        from lightr.mail.spam import RspamdClient, score_message

        spf = await mail_auth.check_spf(remote_ip, mail_from, helo)
        dkim = await mail_auth.check_dkim(raw)
        dmarc = await mail_auth.check_dmarc(
            mail_auth.from_domain_of(raw), spf, dkim
        )

        score = await RspamdClient(self.cfg.spam).score(raw)
        if score is None:
            score = score_message(
                message,
                spf=spf,
                dkim=dkim,
                dmarc=dmarc,
                recipient_count=recipient_count,
            )

        _, is_junk = score.verdict(self.cfg.spam)

        return header_tools.Analysis(
            score=score.points,
            is_spam=is_junk,
            reasons=score.reasons,
            auth=header_tools.AuthResults(
                spf=str(spf.result),
                dkim=str(dkim.result),
                dmarc=str(dmarc.result),
                mail_from=mail_from,
                helo=helo,
            ),
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
