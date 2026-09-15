"""Deciding where a recipient's mail goes.

Four outcomes, in the order they are checked:

``LOCAL``
    A real account on a domain we host. Delivered to Dovecot via LMTP.
``ALIAS_FORWARD``
    Forwarded to other addresses; no local copy is kept.
``ALIAS_BRIDGE``
    Forwarded *and* mirrored into the account's mailbox, with a reply
    route recorded so replies come back through Lightr.
``REJECT``
    Not ours, or suppressed.

Routing is separated from delivery so it can be tested exhaustively
without a Dovecot or a network -- alias loops in particular, which are
the failure mode that turns one message into thousands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema
from lightr.models import AliasType
from lightr.repo import AccountRepo, AliasRepo, DomainRepo

#: How many alias hops to follow before declaring a loop. Postfix uses
#: a comparable bound; the point is to stop, not to be generous.
MAX_ALIAS_DEPTH = 5


class Disposition(StrEnum):
    LOCAL = "local"
    ALIAS_FORWARD = "alias_forward"
    ALIAS_BRIDGE = "alias_bridge"
    #: Addressed to a reply token: a reply to a bridged copy, or a
    #: bounce of something Lightr forwarded. What happens depends on
    #: who sent it, which routing does not know -- deliver decides.
    REPLY = "reply"
    REJECT = "reject"


class RejectReason(StrEnum):
    NOT_LOCAL_DOMAIN = "not_local_domain"
    NO_SUCH_MAILBOX = "no_such_mailbox"
    SUPPRESSED = "suppressed"
    ALIAS_LOOP = "alias_loop"
    ACCOUNT_DISABLED = "account_disabled"
    RECEIVING_BLOCKED = "receiving_blocked"

    @property
    def smtp_code(self) -> int:
        """The SMTP status this reason should produce.

        A loop is our problem, not the sender's, so it is transient --
        a permanent rejection would generate a bounce for something an
        operator can fix.
        """
        return 451 if self is RejectReason.ALIAS_LOOP else 550

    @property
    def smtp_message(self) -> str:
        return {
            RejectReason.NOT_LOCAL_DOMAIN: "Relay access denied",
            RejectReason.NO_SUCH_MAILBOX: "No such user here",
            RejectReason.SUPPRESSED: "Address suppressed",
            RejectReason.ALIAS_LOOP: "Alias loop detected; try again later",
            RejectReason.ACCOUNT_DISABLED: "Mailbox unavailable",
            # The same words as a disabled account, on purpose. Telling a
            # stranger *why* a mailbox refuses mail tells them which
            # accounts an operator has acted on.
            RejectReason.RECEIVING_BLOCKED: "Mailbox unavailable",
        }[self]


@dataclass(slots=True)
class Route:
    """What to do with one recipient."""

    recipient: str
    disposition: Disposition
    account_id: UUID | None = None
    domain_id: UUID | None = None
    mailbox: str | None = None  # the address to hand to LMTP
    forward_to: list[str] = field(default_factory=list)
    reason: RejectReason | None = None
    alias_id: UUID | None = None
    #: The stored reply route, for Disposition.REPLY.
    reply: Any = None

    @property
    def rejected(self) -> bool:
        return self.disposition is Disposition.REJECT

    @property
    def delivers_locally(self) -> bool:
        return self.disposition in (Disposition.LOCAL, Disposition.ALIAS_BRIDGE)


class Router:
    """Resolves recipients against domains, accounts, and aliases."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn
        self._domains = DomainRepo(conn)
        self._accounts = AccountRepo(conn)
        self._aliases = AliasRepo(conn)

    async def route(self, recipient: str) -> Route:
        """Decide what happens to one recipient address."""
        address = recipient.strip().lower()
        if "@" not in address:
            return Route(recipient, Disposition.REJECT,
                         reason=RejectReason.NO_SUCH_MAILBOX)

        if await self.is_suppressed(address):
            return Route(recipient, Disposition.REJECT, reason=RejectReason.SUPPRESSED)

        local_part, domain_name = address.split("@", 1)

        try:
            domain = await self._domains.resolve(domain_name)
        except LookupError:
            return Route(recipient, Disposition.REJECT,
                         reason=RejectReason.NOT_LOCAL_DOMAIN)

        # A reply token is on one of our domains but is neither an
        # account nor an alias. An unknown or expired token falls
        # through and is refused like any address that does not exist.
        from lightr.mail.replies import ReplyRouteRepo, token_from

        if (token := token_from(local_part)) is not None:
            reply = await ReplyRouteRepo(self._conn).get(token)
            if reply is not None:
                return Route(
                    recipient, Disposition.REPLY, domain_id=domain.id, reply=reply
                )

        # A real mailbox wins over an alias of the same name: an
        # operator who creates both almost certainly means the mailbox.
        account = await self._accounts.find(address)
        if account is not None:
            from lightr.models import AuthMode

            if account.auth_mode is AuthMode.DISABLED:
                return Route(recipient, Disposition.REJECT, domain_id=domain.id,
                             reason=RejectReason.ACCOUNT_DISABLED)
            if not account.can_receive:
                return Route(recipient, Disposition.REJECT, domain_id=domain.id,
                             reason=RejectReason.RECEIVING_BLOCKED)

            # Except a bridge. A bridge mirrors *into* the mailbox of the
            # same name, so it always shares its name with an account --
            # and returning LOCAL here first meant no bridge could ever
            # fire. A plain forward alias with an account's name is still
            # ignored: the mailbox wins.
            bridge = await self._aliases.lookup(domain.id, local_part)
            if bridge is not None and bridge.type is AliasType.BRIDGE:
                try:
                    destinations = await self._expand(
                        bridge.destinations, seen=frozenset({address})
                    )
                except _AliasLoopError:
                    return Route(recipient, Disposition.REJECT, domain_id=domain.id,
                                 reason=RejectReason.ALIAS_LOOP)
                if destinations:
                    return Route(
                        recipient,
                        Disposition.ALIAS_BRIDGE,
                        account_id=account.id,
                        domain_id=domain.id,
                        mailbox=address,
                        forward_to=destinations,
                        alias_id=bridge.id,
                    )

            return Route(
                recipient,
                Disposition.LOCAL,
                account_id=account.id,
                domain_id=domain.id,
                mailbox=address,
            )

        alias = await self._aliases.lookup(domain.id, local_part)
        if alias is None:
            return Route(recipient, Disposition.REJECT, domain_id=domain.id,
                         reason=RejectReason.NO_SUCH_MAILBOX)

        try:
            destinations = await self._expand(alias.destinations, seen=frozenset({address}))
        except _AliasLoopError:
            return Route(recipient, Disposition.REJECT, domain_id=domain.id,
                         reason=RejectReason.ALIAS_LOOP)

        if not destinations:
            return Route(recipient, Disposition.REJECT, domain_id=domain.id,
                         reason=RejectReason.NO_SUCH_MAILBOX)

        if alias.type is AliasType.BRIDGE:
            # A bridge keeps a local copy. It needs a mailbox to keep it
            # in; without one it degrades to a plain forward rather than
            # dropping the mail.
            owner = await self._bridge_mailbox(domain.id, local_part)
            if owner is not None:
                return Route(
                    recipient,
                    Disposition.ALIAS_BRIDGE,
                    account_id=owner[0],
                    domain_id=domain.id,
                    mailbox=owner[1],
                    forward_to=destinations,
                    alias_id=alias.id,
                )

        return Route(
            recipient,
            Disposition.ALIAS_FORWARD,
            domain_id=domain.id,
            forward_to=destinations,
            alias_id=alias.id,
        )

    async def route_all(self, recipients: list[str]) -> list[Route]:
        return [await self.route(r) for r in recipients]

    async def is_suppressed(self, address: str) -> bool:
        """Whether the address is on the suppression list."""
        row = (
            await self._conn.execute(
                select(schema.suppression_list.c.email).where(
                    schema.suppression_list.c.email == address.lower()
                )
            )
        ).first()
        return row is not None

    async def _expand(
        self, destinations: list[str], seen: frozenset[str], depth: int = 0
    ) -> list[str]:
        """Follow aliases that point at other aliases.

        ``seen`` is the *path* currently being followed, not every
        address encountered anywhere. That distinction matters: two
        aliases legitimately converging on one mailbox (``both`` ->
        ``sales`` -> ``ops`` and ``both`` -> ``ops``) is not a loop, and
        treating it as one would reject perfectly good mail. Each
        branch therefore gets its own copy of the path.

        Depth is bounded as well, so a long non-cyclic chain still
        terminates.
        """
        if depth >= MAX_ALIAS_DEPTH:
            raise _AliasLoopError

        resolved: list[str] = []
        for destination in destinations:
            address = destination.strip().lower()
            if not address or "@" not in address:
                continue
            if address in seen:
                raise _AliasLoopError

            local_part, domain_name = address.split("@", 1)
            try:
                domain = await self._domains.resolve(domain_name)
            except LookupError:
                resolved.append(address)  # external: deliver as-is
                continue

            if await self._accounts.find(address) is not None:
                resolved.append(address)
                continue

            nested = await self._aliases.lookup(domain.id, local_part)
            if nested is None:
                # A local address that is neither account nor alias.
                continue
            resolved.extend(
                await self._expand(nested.destinations, seen | {address}, depth + 1)
            )

        # Preserve order, drop duplicates -- a message must not be
        # delivered twice because two aliases converge.
        return list(dict.fromkeys(resolved))

    async def _bridge_mailbox(
        self, domain_id: UUID, local_part: str
    ) -> tuple[UUID, str] | None:
        """The account a bridge alias mirrors into, if one exists."""
        row = (
            await self._conn.execute(
                select(schema.accounts.c.id, schema.domains.c.name)
                .select_from(schema.accounts.join(schema.domains))
                .where(
                    schema.accounts.c.domain_id == str(domain_id),
                    schema.accounts.c.local_part == local_part,
                )
            )
        ).first()
        if row is None:
            return None
        return UUID(row._mapping["id"]), f"{local_part}@{row._mapping['name']}"


class _AliasLoopError(Exception):
    """Internal signal: alias expansion cycled or ran too deep."""


__all__ = [
    "MAX_ALIAS_DEPTH",
    "Disposition",
    "RejectReason",
    "Route",
    "Router",
]
