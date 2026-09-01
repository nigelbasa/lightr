"""Guarding webhook delivery against SSRF.

A webhook URL is chosen by a tenant and fetched by the server. Without
a guard, that is a request forgery primitive: an org admin could point
a webhook at ``http://169.254.169.254/`` and have Lightr fetch cloud
credentials on their behalf, or scan the private network the server
sits on.

The guard resolves the hostname and checks **every** address it maps
to, then pins the connection to a vetted address. Checking the name and
then connecting by name would leave a DNS-rebinding window between the
two; pinning closes it.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

#: Only these schemes. file:// and gopher:// are ways to read local
#: resources; ftp:// is a redirect vector.
ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Ports a webhook may target. The set is small on purpose: a webhook
#: pointed at :22 or :3306 is not a webhook.
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443, 3000, 5000, 8000, 9000})

#: Ranges no webhook may reach. Cloud metadata endpoints live in
#: link-local, which is the single most valuable target here.
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",         # this host
        "10.0.0.0/8",        # private
        "127.0.0.0/8",       # loopback
        "169.254.0.0/16",    # link-local, incl. 169.254.169.254 metadata
        "172.16.0.0/12",     # private
        "192.0.0.0/24",      # IETF protocol assignments
        "192.168.0.0/16",    # private
        "198.18.0.0/15",     # benchmarking
        "224.0.0.0/4",       # multicast
        "240.0.0.0/4",       # reserved
        "255.255.255.255/32",
        "::1/128",           # IPv6 loopback
        "fc00::/7",          # IPv6 unique-local
        "fe80::/10",         # IPv6 link-local
        "ff00::/8",          # IPv6 multicast
        "::/128",            # unspecified
    )
)


class SSRFError(ValueError):
    """A webhook URL was refused."""


@dataclass(frozen=True, slots=True)
class VettedTarget:
    """A URL that passed the guard, pinned to one address."""

    url: str
    host: str
    address: str
    port: int

    @property
    def connect_url(self) -> str:
        """The URL with the hostname replaced by the vetted address.

        Requests must still carry the original Host header, so callers
        pass that separately -- but connecting by address is what stops
        a second DNS lookup from resolving somewhere else.
        """
        parsed = urlparse(self.url)
        literal = (
            f"[{self.address}]" if ":" in self.address else self.address
        )
        return parsed._replace(netloc=f"{literal}:{self.port}").geturl()


def is_blocked(address: str) -> bool:
    """Whether an IP falls in a range webhooks may not reach."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True  # unparseable is not safe

    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) reaches the same
    # host as the IPv4 address it wraps, so unwrap before checking.
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped

    return any(parsed in network for network in BLOCKED_NETWORKS)


def resolve_all(host: str, port: int) -> list[str]:
    """Every address a hostname maps to."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"could not resolve {host}: {exc}") from exc
    return list(dict.fromkeys(info[4][0] for info in infos))


def vet(url: str, *, allow_private: bool = False) -> VettedTarget:
    """Check a webhook URL and pin it to a safe address.

    ``allow_private`` exists for operators whose webhook target really
    is on the local network. It is off by default because the safe
    default matters more than the convenient one.
    """
    parsed = urlparse(url.strip())

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"{parsed.scheme or 'that'} is not an allowed scheme; use http or https"
        )
    if not parsed.hostname:
        raise SSRFError("the URL has no host")
    if "@" in (parsed.netloc or ""):
        # user:pass@host is a classic way to make a URL read as one
        # host to a human and resolve as another.
        raise SSRFError("credentials in the URL are not allowed")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFError(
            f"port {port} is not allowed; permitted ports are "
            f"{', '.join(str(p) for p in sorted(ALLOWED_PORTS))}"
        )

    addresses = resolve_all(parsed.hostname, port)
    if not addresses:
        raise SSRFError(f"{parsed.hostname} did not resolve to any address")

    if not allow_private:
        # Every address must be safe, not just the first. A host that
        # resolves to one public and one private address is a way to
        # win the race on a later lookup.
        blocked = [a for a in addresses if is_blocked(a)]
        if blocked:
            raise SSRFError(
                f"{parsed.hostname} resolves to a private or reserved "
                f"address ({blocked[0]}), which webhooks may not reach"
            )

    return VettedTarget(
        url=url.strip(),
        host=parsed.hostname,
        address=addresses[0],
        port=port,
    )


__all__ = [
    "ALLOWED_PORTS",
    "ALLOWED_SCHEMES",
    "BLOCKED_NETWORKS",
    "SSRFError",
    "VettedTarget",
    "is_blocked",
    "resolve_all",
    "vet",
]
