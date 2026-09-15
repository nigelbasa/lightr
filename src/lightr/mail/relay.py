"""Sending a domain's mail through a smarthost.

Receiving never changes: MX still points here, and Dovecot still holds
the mail. Only delivery to other servers goes through the relay, so a
domain on a small or poorly-reputed IP can borrow a provider's
reputation. The message is DKIM-signed here, as the domain, before it is
handed over -- the recipient sees the domain's own signature, whatever
the provider adds.

The CLI and the API both change settings through ``apply`` so the rules
are the same from either side.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from lightr.models import Domain

#: SMTP submission with TLS from the first byte. Every other port
#: negotiates STARTTLS, if TLS is on.
IMPLICIT_TLS_PORT = 465
DEFAULT_PORT = 587

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")


class RelayError(ValueError):
    """A relay setting that cannot be used."""


@dataclass(frozen=True, slots=True)
class RelayChange:
    """What to change. None leaves a setting as it is."""

    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    use_tls: bool | None = None
    skip_verify: bool | None = None
    clear: bool = False


def apply(domain: Domain, change: RelayChange) -> Domain:
    """Apply a change to a domain's relay settings, in place.

    An empty username or password removes it. Raises RelayError, and
    leaves the caller to not save, when the result could not work or
    would send a password in the clear.
    """
    if change.clear:
        domain.relay_enabled = False
        domain.relay_host = None
        domain.relay_port = None
        domain.relay_username = None
        domain.relay_password = None
        domain.relay_use_tls = False
        domain.relay_tls_skip_verify = False
        return domain

    if change.host is not None:
        domain.relay_host = normalise_host(change.host)
    if change.port is not None:
        domain.relay_port = check_port(change.port)
    if change.username is not None:
        domain.relay_username = change.username.strip() or None
    if change.password is not None:
        domain.relay_password = change.password or None
    if change.use_tls is not None:
        domain.relay_use_tls = change.use_tls
    if change.skip_verify is not None:
        domain.relay_tls_skip_verify = change.skip_verify
    if change.enabled is not None:
        domain.relay_enabled = change.enabled

    if domain.relay_enabled:
        if not domain.relay_host:
            raise RelayError("a relay needs a host before it can be enabled")
        if bool(domain.relay_username) != bool(domain.relay_password):
            raise RelayError("a relay login needs both a username and a password")
        if domain.relay_username and not uses_tls(domain):
            # The provider's credentials would cross the internet in
            # the clear, and they send mail as every domain on the account.
            raise RelayError(
                "refusing to send the relay password without TLS: "
                f"turn TLS on, or use port {IMPLICIT_TLS_PORT}"
            )
    return domain


def normalise_host(value: str) -> str | None:
    host = value.strip().lower().rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise RelayError(f"{value!r} is not a hostname") from None
    return host


def check_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise RelayError(f"{value!r} is not a port number")
    return value


def uses_tls(domain: Domain) -> bool:
    return domain.relay_port == IMPLICIT_TLS_PORT or bool(domain.relay_use_tls)


def connection(domain: Domain) -> dict[str, Any]:
    """aiosmtplib keyword arguments for reaching this domain's relay.

    Port 465 is TLS from the start (``use_tls``); asking it for STARTTLS
    instead fails before the greeting, which is how the sender used to
    treat it.
    """
    port = domain.relay_port or DEFAULT_PORT
    implicit = port == IMPLICIT_TLS_PORT
    return {
        "hostname": domain.relay_host or "",
        "port": port,
        "use_tls": implicit,
        "start_tls": bool(domain.relay_use_tls) and not implicit,
        "validate_certs": not domain.relay_tls_skip_verify,
        "username": domain.relay_username or None,
        "password": domain.relay_password or None,
    }


def view(domain: Domain) -> dict[str, Any]:
    """The settings, for showing. The password is never included."""
    return {
        "domain": domain.name,
        "enabled": domain.relay_enabled,
        "host": domain.relay_host,
        "port": domain.relay_port or (DEFAULT_PORT if domain.relay_host else None),
        "tls": (
            "implicit" if (domain.relay_port == IMPLICIT_TLS_PORT)
            else "starttls" if domain.relay_use_tls
            else "off"
        ),
        "verify_certificate": not domain.relay_tls_skip_verify,
        "username": domain.relay_username,
        "password": "(set)" if domain.relay_password else None,
    }


async def test_login(domain: Domain, *, local_hostname: str, timeout: float = 15.0) -> str:
    """Connect, negotiate TLS, log in, and quit -- sending nothing.

    Returns a one-line description of what worked. Raises RelayError
    with the server's own words when something did not.
    """
    import aiosmtplib

    if not domain.relay_host:
        raise RelayError("no relay host is set")
    settings = connection(domain)
    username = settings.pop("username")
    password = settings.pop("password")
    client = aiosmtplib.SMTP(local_hostname=local_hostname, timeout=timeout, **settings)
    try:
        await client.connect()
        if username:
            await client.login(username, password or "")
        await client.quit()
    except Exception as exc:  # aiosmtplib raises a family; all end the same way
        raise RelayError(f"{settings['hostname']}:{settings['port']}: {exc}") from exc
    finally:
        if client.is_connected:
            client.close()
    how = "TLS" if settings["use_tls"] else "STARTTLS" if settings["start_tls"] else "no TLS"
    login = f"logged in as {username}" if username else "no login"
    return f"{settings['hostname']}:{settings['port']} accepted the connection ({how}, {login})"


__all__ = [
    "DEFAULT_PORT",
    "IMPLICIT_TLS_PORT",
    "RelayChange",
    "RelayError",
    "apply",
    "connection",
    "test_login",
    "uses_tls",
    "view",
]
