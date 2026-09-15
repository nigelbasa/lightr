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
from lightr.mail.routing import Disposition, RejectReason, Route, Router
from lightr.ratelimit import limiter

log = logging.getLogger("lightr.smtp")

#: Received headers after which a message is taken to be looping.
#: RFC 5321 suggests at least 100 as the limit a relay should tolerate;
#: real paths are under 15, so 30 is generous for mail and small for a
#: loop that multiplies on every pass.
MAX_HOPS = 30


@dataclass(slots=True)
class DeliveryOutcome:
    """What happened to one message."""

    delivered: list[str] = field(default_factory=list)
    forwarded: list[str] = field(default_factory=list)
    rejected: list[tuple[str, RejectReason]] = field(default_factory=list)
    #: Taken and deliberately not delivered -- a bounce of a plain
    #: forward, which has nobody local to give it to. Still a 250: the
    #: bounce was received, and refusing it would bounce the bounce.
    accepted: list[str] = field(default_factory=list)
    error: str | None = None
    #: Whether ``error`` is final. A retry will not un-loop a loop or
    #: make a domain ours, and a 4xx would have the client retry for days.
    permanent: bool = False

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
            if self.permanent:
                return f"554 5.7.1 {self.error}"
            return f"451 4.3.0 {self.error}"
        if self.delivered or self.forwarded or self.accepted:
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

        # Only the receive listener is limited by address. Submission
        # is authenticated, so its budget belongs to the account, and
        # limiting it by address would punish an office behind one NAT.
        self.sessions = (
            None
            if require_auth
            else limiter(cfg.limits.smtp_sessions_per_minute, 60.0)
        )
        self.messages = (
            None
            if require_auth
            else limiter(cfg.limits.smtp_messages_per_hour, 3600.0)
        )

        from lightr.webhooks.emitter import Emitter

        # Fire-and-forget: a slow webhook receiver must not slow down
        # or fail mail delivery.
        self.webhooks = Emitter(engine, allow_private=cfg.webhook.allow_private)

    # -- envelope phases ------------------------------------------------

    async def handle_EHLO(  # noqa: N802 - aiosmtpd's naming
        self,
        server: object,
        session: Session,
        envelope: Envelope,
        hostname: str,
        responses: list[str],
    ) -> list[str]:
        """Greet, or refuse an address opening sessions too fast.

        421 is the right code: it means "not now, come back", so a real
        sender retries and a flood is turned away before it costs a
        database round trip. Returning it here rather than at DATA is
        the point -- by DATA the message is already in memory.
        """
        session.host_name = hostname
        if self.sessions is not None and not self.sessions.allow(_peer_ip(session)):
            return ["421 4.7.0 Too many connections, please slow down"]
        return responses

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

        if self.messages is not None and not self.messages.allow(_peer_ip(session)):
            return "421 4.7.0 Too many messages, please slow down"

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
                # aiosmtpd stores what `authenticate` returned, which is
                # the account's address. Without this, deliver() had no
                # way to know who had logged in.
                authenticated_as=(
                    str(session.auth_data)
                    if self.require_auth and getattr(session, "authenticated", False)
                    else None
                ),
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
        authenticated_as: str | None = None,
    ) -> DeliveryOutcome:
        """Analyse, route, and hand off. The core of the receive path.

        ``authenticated_as`` is who logged in on submission. When it is
        given, that account must be allowed to send and the envelope
        sender must be an address it owns.
        """
        outcome = DeliveryOutcome()

        if authenticated_as is not None:
            refusal = await self._may_send(authenticated_as, mail_from)
            if refusal is not None:
                log.warning("refused submission by %s as %r: %s",
                            authenticated_as, mail_from, refusal)
                outcome.error = refusal
                outcome.permanent = True
                return outcome

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

        # A message that has already passed through this many servers is
        # going round in circles -- two forwards pointing at each other
        # across two providers, say. Alias expansion catches loops
        # inside Lightr; only a hop count catches the ones that leave
        # and come back.
        if len(message.get_all("Received") or []) >= MAX_HOPS:
            log.warning("refusing a message with %d Received headers: mail loop",
                        MAX_HOPS)
            outcome.error = "Too many hops, possible mail loop"
            outcome.permanent = True
            return outcome

        async with self.engine.begin() as conn:
            routes = await Router(conn).route_all(recipients)

        local: list[Route] = []
        outbound: list[str] = []
        forwards: list[tuple[Route, str]] = []  # (the alias's route, destination)
        replies: list[Route] = []
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
                continue
            if route.disposition is Disposition.REPLY:
                replies.append(route)
                continue
            if route.delivers_locally:
                local.append(route)
            forwards.extend((route, d) for d in route.forward_to)

        # Stamp the message once, before any copy of it leaves: the
        # local delivery and every forward carry the same analysis and
        # the same Received line.
        targets = [
            *(r.mailbox or r.recipient for r in local),
            *(d for _, d in forwards),
            *outbound,
            *(r.recipient for r in replies),
        ]
        if targets:
            header_tools.apply(message, analysis, self.cfg.server.hostname)
            header_tools.ensure_message_id(message, self.cfg.server.hostname)
            header_tools.ensure_date(message)
            header_tools.add_received(
                message,
                hostname=self.cfg.server.hostname,
                remote_ip=remote_ip or "unknown",
                helo=helo,
                recipient=targets[0],
            )

        if outbound:
            if await self._enqueue_outbound(mail_from, outbound, message):
                outcome.forwarded.extend(outbound)
            else:
                outcome.error = "Cannot send as that address from this server"
                outcome.permanent = True

        extra_mailboxes: list[str] = []
        if forwards:
            extra_mailboxes = await self._forward(
                forwards, mail_from=mail_from, message=message,
                analysis=analysis, outcome=outcome,
            )
        if replies:
            extra_mailboxes += await self._relay_replies(
                replies, mail_from=mail_from, message=message,
                analysis=analysis, outcome=outcome,
            )

        if not local and not extra_mailboxes:
            # Nothing to hand to Dovecot, but the outcome still matters:
            # a message rejected outright is exactly what an operator
            # wants notified, so this path announces too.
            self._notify(outcome, mail_from=mail_from, message=message)
            return outcome

        mailboxes = list(
            dict.fromkeys([r.mailbox for r in local if r.mailbox] + extra_mailboxes)
        )
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

    async def _may_send(self, authenticated_as: str, mail_from: str) -> str | None:
        """Why this login may not send as this address, or None.

        Submission used to check that *someone* had logged in and
        nothing else. Any account could send as any address on any
        domain this server hosts -- and Lightr DKIM-signed the result,
        so the forgery arrived looking genuine.

        An account may send as its own address, or as an alias that
        delivers to it: `sales@` forwarding to `ops@` means ops answers
        sales mail, and refusing that would break the ordinary use of
        an alias.

        Only the envelope sender is checked, not the From header. The
        envelope is what SPF and bounces use and what this server signs
        for; policing the header as well would rule out "on behalf of"
        sending, which is a decision for later rather than an accident
        of this one.
        """
        from lightr.repo import AccountRepo, AliasRepo, DomainRepo

        login = authenticated_as.strip().lower()
        sender = mail_from.strip().lower()

        async with self.engine.begin() as conn:
            account = await AccountRepo(conn).find(login)
            if account is None:
                return "Authenticated account no longer exists"
            if not account.can_send:
                return "This account is not allowed to send mail"
            if sender == login:
                return None
            if "@" not in sender:
                return f"Not allowed to send as {mail_from}"

            local_part, domain_name = sender.split("@", 1)
            try:
                domain = await DomainRepo(conn).resolve(domain_name)
            except LookupError:
                return f"Not allowed to send as {mail_from}"
            alias = await AliasRepo(conn).lookup(domain.id, local_part)
            if alias is not None and login in {
                d.strip().lower() for d in alias.destinations
            }:
                return None
        return f"Not allowed to send as {mail_from}"

    async def _enqueue_outbound(
        self, mail_from: str, recipients: list[str], message: Message
    ) -> bool:
        """Queue submitted mail for delivery to another server.

        Queued rather than sent inline: a slow or unreachable remote MTA
        must not hold the submitting client's SMTP session open, and a
        failure should be retried rather than bounced immediately.

        Returns False when it could not be queued. That used to be a log
        line and a 250 -- the client was told the mail was sent.
        """
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
                return False
            await self._queue(
                conn, domain, from_addr=mail_from, recipients=recipients,
                message=message,
            )
        log.info("queued outbound mail from %s to %s", mail_from, ", ".join(recipients))
        return True

    async def _queue(
        self,
        conn: Any,
        domain: Any,
        *,
        from_addr: str,
        recipients: list[str],
        message: Message,
        envelope_from: str | None = None,
    ) -> None:
        """Put one message in the outbound queue, whole."""
        from lightr.mail.queue import Queue

        try:
            body = message.get_body(preferencelist=("plain",))
            text = body.get_content() if body is not None else ""
        except Exception:  # pragma: no cover - malformed MIME
            text = ""

        await Queue(conn).enqueue(
            org_id=domain.org_id,
            domain_id=domain.id,
            from_addr=from_addr,
            to_addrs=recipients,
            subject=str(message.get("Subject", "") or ""),
            body=text,
            raw=message.as_bytes(),
            envelope_from=envelope_from,
        )

    async def _forward(
        self,
        forwards: list[tuple[Route, str]],
        *,
        mail_from: str,
        message: Message,
        analysis: header_tools.Analysis,
        outcome: DeliveryOutcome,
    ) -> list[str]:
        """Send an alias's copies on. Returns local mailboxes to deliver.

        This was never done. Routing worked out where a forward should
        go, the outcome recorded it as forwarded, the sender got a 250
        -- and nothing was queued. Every message to a forwarding alias
        was accepted and dropped.

        A destination on a domain we host goes straight to Dovecot; one
        elsewhere is queued whole, attributed to the alias's domain so
        it is signed as that domain. Each external copy gets a reply
        token as its envelope sender, so it passes SPF at the other end
        and bounces come back here; a bridge copy also gets it as its
        Reply-To, so the reply can be relayed to the original sender.

        Mail already judged to be spam is not forwarded off the server.
        It still lands in the local Junk folder where there is one, but
        relaying it outward spends this server's reputation on someone
        else's junk -- and receivers blocklist forwarders for exactly
        that.
        """
        from lightr.mail import replies as reply_tools
        from lightr.repo import DomainRepo

        local: list[str] = []
        # Grouped per alias route: one token per message per alias.
        external: dict[int, tuple[Route, list[str]]] = {}

        async with self.engine.begin() as conn:
            domains = DomainRepo(conn)
            for route, destination in forwards:
                address = destination.strip().lower()
                target_domain = address.split("@", 1)[1] if "@" in address else ""
                try:
                    await domains.resolve(target_domain)
                except LookupError:
                    external.setdefault(id(route), (route, []))[1].append(address)
                else:
                    local.append(address)

            if external and analysis.is_spam:
                skipped = [a for _, addrs in external.values() for a in addrs]
                log.info("not forwarding spam off-server to %s", ", ".join(skipped))
                external = {}

            for route, recipients in external.values():
                if route.domain_id is None or route.alias_id is None:  # pragma: no cover
                    continue
                domain = await domains.resolve(str(route.domain_id))
                recipients = list(dict.fromkeys(recipients))
                bridged = route.disposition is Disposition.ALIAS_BRIDGE

                token = await reply_tools.ReplyRouteRepo(conn).create(
                    alias_id=route.alias_id,
                    domain_id=domain.id,
                    account_id=route.account_id if bridged else None,
                    local_address=route.mailbox or route.recipient,
                    destinations=recipients,
                    original_from=reply_tools.reply_target(message, mail_from),
                    original_to=str(message.get("To", "") or "") or None,
                    original_cc=str(message.get("Cc", "") or "") or None,
                    kind=(
                        reply_tools.RouteKind.BRIDGE
                        if bridged
                        else reply_tools.RouteKind.FORWARD
                    ),
                )
                token_address = token.address(domain.name)
                copy = (
                    reply_tools.for_bridge(message, token_address) if bridged else message
                )
                await self._queue(
                    conn, domain,
                    from_addr=mail_from or f"postmaster@{domain.name}",
                    recipients=recipients, message=copy,
                    envelope_from=token_address,
                )
                outcome.forwarded.extend(recipients)

        if external:
            log.info("queued forwards for %s",
                     ", ".join(a for _, addrs in external.values() for a in addrs))
        return local

    async def _relay_replies(
        self,
        replies: list[Route],
        *,
        mail_from: str,
        message: Message,
        analysis: header_tools.Analysis,
        outcome: DeliveryOutcome,
    ) -> list[str]:
        """Handle mail addressed to a reply token. Returns local mailboxes.

        Three cases:

        * **A bounce** (null sender) of something we forwarded. For a
          bridge it goes into the alias's own mailbox, where its owner
          can see a destination has stopped working. A plain forward
          has no mailbox, so it is taken and recorded -- the suppression
          list learned from it at the top of deliver() -- and not
          delivered anywhere.
        * **A reply from a bridge destination.** Cleaned of the path
          through the replier's own provider and sent to the original
          sender, from the alias address.
        * **Anything else** -- a stranger who found a token, an
          autoresponder answering a plain forward's envelope. Refused
          exactly like an address that does not exist.

        A reply judged to be spam is not relayed. For a bridge it lands
        in the alias's mailbox instead, where the Junk rules can file it.
        """
        from lightr.mail import replies as reply_tools
        from lightr.repo import DomainRepo

        local: list[str] = []
        sender = mail_from.strip().lower()
        from_header = reply_tools.header_address(message)

        async with self.engine.begin() as conn:
            for route in replies:
                reply: reply_tools.ReplyRoute = route.reply
                bridged = reply.kind is reply_tools.RouteKind.BRIDGE
                has_mailbox = bridged and reply.account_id is not None

                if not sender:
                    if has_mailbox:
                        local.append(reply.local_address)
                    else:
                        outcome.accepted.append(route.recipient)
                    continue

                if not bridged or not reply.accepts_reply_from(sender, from_header):
                    outcome.rejected.append(
                        (route.recipient, RejectReason.NO_SUCH_MAILBOX)
                    )
                    continue

                if analysis.is_spam:
                    log.info("not relaying a spam reply to %s", reply.original_from)
                    if has_mailbox:
                        local.append(reply.local_address)
                    else:
                        outcome.accepted.append(route.recipient)
                    continue

                domains = DomainRepo(conn)
                domain = await domains.resolve(
                    str(reply.domain_id) if reply.domain_id else reply.local_address
                )
                await self._queue(
                    conn, domain,
                    from_addr=reply.local_address,
                    recipients=[reply.original_from],
                    message=reply_tools.clean_reply(message, reply),
                    envelope_from=reply.local_address,
                )
                outcome.forwarded.append(reply.original_from)
                log.info("relayed a bridge reply from %s to %s as %s",
                         sender, reply.original_from, reply.local_address)

        return local

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

        # rspamd, when it answers, has the last word -- including on
        # blocklists, which its own RBL module checks. Consulting them
        # here as well would count every listing twice.
        score = await RspamdClient(self.cfg.spam).score(raw)
        if score is None:
            from lightr.mail.reputation import ReputationChecker

            listings = await ReputationChecker(self.cfg.spam).check(
                remote_ip=remote_ip,
                sender_domains=[
                    mail_from.rsplit("@", 1)[1] if "@" in mail_from else "",
                    mail_auth.from_domain_of(raw) or "",
                ],
                message=message,
            )
            score = score_message(
                message,
                spf=spf,
                dkim=dkim,
                dmarc=dmarc,
                recipient_count=recipient_count,
                listings=listings,
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
