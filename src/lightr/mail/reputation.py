"""Reputation lists: DNS blocklists for addresses and domains.

The shared memory of the mail world. Spamhaus, Barracuda, SpamCop and
others watch traffic across millions of mailboxes and publish what they
see as DNS zones: ask for ``4.3.2.1.zen.spamhaus.org`` and an answer
means 1.2.3.4 is listed, no answer means it is not. Domain lists work
the same way for the sender's domain and for the domains a message
links to.

A listing is evidence, not a verdict. It adds points to the score --
enough that a listed address plus one other signal files mail as Junk,
not so many that one list junks mail on its own. Refusing mail outright
because of a list is a different decision with a different cost, and
this module does not make it.

Three ways this goes wrong in practice, and what is done about each:

* **The list refuses the query.** Spamhaus answers 127.255.255.254 for
  queries arriving through public resolvers (8.8.8.8, 1.1.1.1, most
  cloud defaults), and other lists answer 127.0.0.1. Read naively that
  is "listed", and every message is junked. Those answers are never
  treated as a listing, and the operator is told once.
* **The resolver lies.** Some resolvers answer every name with an ad
  server's address. Anything outside 127.0.0.0/8 is not a listing.
* **The list is slow or gone.** A lookup gets a short timeout and
  failing adds nothing. A slow list is not evidence of spam.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from email.message import Message

from lightr.config import SpamConfig

log = logging.getLogger("lightr.reputation")

#: Resolves a name to its A records. Empty when the name does not exist.
Resolver = Callable[[str], Awaitable[list[str]]]

#: How long one lookup may take. Lists are advisory; delivery does not
#: wait long for one.
LOOKUP_TIMEOUT = 2.0

#: Link domains looked up per message. A message with five hundred links
#: is not five hundred queries to someone else's free service.
MAX_LINK_DOMAINS = 10

#: How much of a body is searched for links.
MAX_BODY_SCAN = 200_000

#: Answers that mean "I will not answer you", not "listed".
#: 127.255.255.0/24 is Spamhaus's (public resolver, too many queries,
#: malformed query); 127.0.0.1 is what URIBL and others use, and RFC
#: 5782 reserves it as never-listed.
_REFUSALS = ipaddress.ip_network("127.255.255.0/24")
_NEVER_LISTED = ipaddress.IPv4Address("127.0.0.1")
_LISTING_RANGE = ipaddress.ip_network("127.0.0.0/8")

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LINK = re.compile(r"""https?://([^/\s"'<>?#\\]+)""", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Listing:
    """One list naming one thing about a message."""

    zone: str
    subject: str
    kind: str  # "address", "sender domain", "link domain"
    codes: tuple[str, ...]

    @property
    def is_address(self) -> bool:
        return self.kind == "address"

    @property
    def reason(self) -> str:
        return f"{self.kind} {self.subject} listed on {self.zone}"


def ip_query(ip: str, zone: str) -> str | None:
    """The name to look up for an address, or None if it has none.

    IPv4 reverses the octets; IPv6 reverses every nibble (RFC 5782). An
    address that is not on the public internet -- loopback, private,
    link-local, documentation -- is never looked up: no list knows it,
    and asking leaks the shape of the local network.
    """
    zone = _zone(zone)
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not zone or not address.is_global:
        return None
    if isinstance(address, ipaddress.IPv4Address):
        labels = reversed(str(address).split("."))
    else:
        labels = reversed(address.exploded.replace(":", ""))
    return ".".join(labels) + "." + zone


def domain_query(domain: str, zone: str) -> str | None:
    """The name to look up for a domain, or None if it is not one."""
    zone = _zone(zone)
    name = domain.strip().strip(".").lower()
    if name.startswith("www."):
        name = name[4:]
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = name.split(".")
    if not zone or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    if labels[-1].isdigit():  # an IP literal, not a domain
        return None
    return f"{name}.{zone}"


def link_domains(message: Message, limit: int = MAX_LINK_DOMAINS) -> list[str]:
    """Distinct domains linked from a message's text and HTML parts."""
    found: dict[str, None] = {}
    for part in message.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            continue
        text = payload[:MAX_BODY_SCAN].decode("utf-8", errors="replace")
        for match in _LINK.finditer(text):
            host = match.group(1).rsplit("@", 1)[-1].split(":", 1)[0].lower()
            if host.startswith("www."):
                host = host[4:]
            if host and host not in found:
                found[host] = None
                if len(found) >= limit:
                    return list(found)
    return list(found)


async def dns_resolver(name: str) -> list[str]:
    """Look a name up in DNS. Tests replace this."""
    import dns.asyncresolver
    import dns.resolver

    try:
        answer = await dns.asyncresolver.resolve(name, "A", lifetime=LOOKUP_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [record.to_text() for record in answer]


#: Zones already reported as refusing, so a busy server logs it once
#: rather than once per message.
_warned: set[tuple[str, str]] = set()


class ReputationChecker:
    """Looks a message's sender up in the configured lists."""

    def __init__(
        self,
        cfg: SpamConfig,
        *,
        resolver: Resolver | None = None,
        timeout: float = LOOKUP_TIMEOUT,
    ) -> None:
        self._address_zones = [z for z in map(_zone, cfg.dnsbl_zones) if z]
        self._domain_zones = [z for z in map(_zone, cfg.domain_blocklist_zones) if z]
        self._resolver = resolver
        self._timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self._address_zones or self._domain_zones)

    async def check(
        self,
        *,
        remote_ip: str,
        sender_domains: Iterable[str] = (),
        message: Message | None = None,
    ) -> list[Listing]:
        """Every listing for this connection and message. Never raises."""
        if not self.configured:
            return []

        lookups: list[tuple[str, str, str, str]] = []  # name, zone, subject, kind
        for zone in self._address_zones:
            if name := ip_query(remote_ip, zone):
                lookups.append((name, zone, remote_ip, "address"))

        if self._domain_zones:
            subjects: dict[str, str] = {}
            for domain in sender_domains:
                if domain:
                    subjects.setdefault(domain.lower().strip("."), "sender domain")
            if message is not None:
                for domain in link_domains(message):
                    subjects.setdefault(domain, "link domain")
            for zone in self._domain_zones:
                for domain, kind in subjects.items():
                    if name := domain_query(domain, zone):
                        lookups.append((name, zone, domain, kind))

        results = await asyncio.gather(*(self._lookup(*lookup) for lookup in lookups))
        return [listing for listing in results if listing is not None]

    async def _lookup(
        self, name: str, zone: str, subject: str, kind: str
    ) -> Listing | None:
        resolver = self._resolver or dns_resolver
        try:
            answers = await asyncio.wait_for(resolver(name), timeout=self._timeout)
        except TimeoutError:
            log.debug("%s did not answer for %s in time", zone, subject)
            return None
        except ImportError:
            _warn_once(zone, "dnspython is not installed; blocklists are not checked")
            return None
        except Exception as exc:
            log.debug("lookup of %s on %s failed: %s", subject, zone, exc)
            return None

        codes = []
        for answer in answers:
            verdict = classify(answer)
            if verdict == "listed":
                codes.append(answer)
            elif verdict == "refused":
                _warn_once(
                    zone,
                    f"{zone} refused a query (answered {answer}). It is not being "
                    "used. Most lists refuse queries sent through public DNS "
                    "resolvers -- run a local resolver such as unbound. "
                    "Check with: lightr spam lists",
                )
            else:
                _warn_once(
                    zone,
                    f"{zone} answered {answer}, which is not a blocklist answer. "
                    "The DNS resolver may be rewriting responses.",
                )
        if not codes:
            return None
        return Listing(zone=zone, subject=subject, kind=kind, codes=tuple(codes))


def classify(answer: str) -> str:
    """"listed", "refused", or "invalid" for one A record from a list."""
    try:
        address = ipaddress.IPv4Address(answer)
    except ValueError:
        return "invalid"
    if address == _NEVER_LISTED or address in _REFUSALS:
        return "refused"
    if address in _LISTING_RANGE:
        return "listed"
    return "invalid"


@dataclass(frozen=True, slots=True)
class ZoneHealth:
    zone: str
    kind: str
    status: str  # "working", "refused", "no answer", "lists everything", "error"
    detail: str = ""


async def probe(
    zone: str,
    kind: str,
    *,
    resolver: Resolver | None = None,
    timeout: float = LOOKUP_TIMEOUT,
) -> ZoneHealth:
    """Check a zone answers as RFC 5782 requires.

    Every list carries fixed test entries: 127.0.0.2 (or the domain
    ``test``) is always listed, 127.0.0.1 (or ``invalid``) never is. A
    list that answers both the same way is refusing, dead, or behind a
    resolver that rewrites answers, and is no use either way.
    """
    zone = _zone(zone)
    resolver = resolver or dns_resolver
    listed_name, clean_name = (
        (f"2.0.0.127.{zone}", f"1.0.0.127.{zone}")
        if kind == "address"
        else (f"test.{zone}", f"invalid.{zone}")
    )
    try:
        listed = await asyncio.wait_for(resolver(listed_name), timeout=timeout)
        clean = await asyncio.wait_for(resolver(clean_name), timeout=timeout)
    except TimeoutError:
        return ZoneHealth(zone, kind, "no answer", f"no reply within {timeout:g}s")
    except Exception as exc:
        return ZoneHealth(zone, kind, "error", str(exc))

    verdicts = {classify(a) for a in listed}
    if "refused" in verdicts:
        return ZoneHealth(
            zone, kind, "refused",
            f"answered {', '.join(listed)}: queries are being refused, usually "
            "because they arrive through a public resolver",
        )
    if "listed" not in verdicts:
        return ZoneHealth(zone, kind, "no answer", "the test entry is not listed")
    if clean:
        return ZoneHealth(
            zone, kind, "lists everything",
            f"the never-listed entry answered {', '.join(clean)}",
        )
    return ZoneHealth(zone, kind, "working")


def _zone(zone: str) -> str:
    return zone.strip().strip(".").lower()


def _warn_once(zone: str, message: str) -> None:
    key = (zone, message[:40])
    if key not in _warned:
        _warned.add(key)
        log.warning(message)


__all__ = [
    "Listing",
    "ReputationChecker",
    "ZoneHealth",
    "classify",
    "dns_resolver",
    "domain_query",
    "ip_query",
    "link_domains",
    "probe",
]
