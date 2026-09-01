"""What every authentication provider must do, and must not do.

The whole design rests on one three-state answer:

``Identity``
    These credentials are good, and this is who they belong to.
``None``
    The provider was reached, understood the question, and says no.
``ProviderError``
    The provider could not be reached, or could not answer.

Collapsing the last two is the mistake that matters. If an LDAP outage
reads as "wrong password", every user on the server is told their
password is wrong, and a good number of them will change it -- turning
a ten-minute outage into a week of support. It is the same reasoning
that keeps a DMARC ``temperror`` from being a ``fail``: a lookup that
did not happen is not evidence of forgery.

Every provider sits on the IMAP login path, so every provider is
bounded by a timeout it cannot exceed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

#: No provider call may take longer than this. Dovecot is holding an
#: IMAP connection open behind it.
DEFAULT_TIMEOUT = 5.0

#: Config keys whose values must never be printed or returned.
SECRET_KEYS = frozenset(
    {"bind_password", "client_secret", "secret", "password", "api_key", "token"}
)


class ProviderError(RuntimeError):
    """The provider could not answer. Not a failed login."""


class ProviderConfigError(ProviderError):
    """The provider is configured wrongly, so it can never answer."""


@dataclass(frozen=True, slots=True)
class Identity:
    """Who a provider says these credentials belong to."""

    username: str
    external_id: str | None = None
    display_name: str | None = None
    groups: tuple[str, ...] = ()


@runtime_checkable
class Provider(Protocol):
    """One configured credential source."""

    name: str
    kind: str

    async def authenticate(self, username: str, password: str) -> Identity | None:
        """Check credentials.

        Returns an Identity on success and None on a genuine refusal.
        Raises ProviderError when it could not tell which.
        """
        ...


@dataclass(slots=True)
class ProviderBase:
    """Shared plumbing: naming, config access, and the timeout."""

    name: str
    config: dict[str, Any] = field(default_factory=dict)
    timeout: float = DEFAULT_TIMEOUT

    kind = "base"

    def required(self, key: str) -> str:
        value = self.config.get(key)
        if not value:
            raise ProviderConfigError(
                f"{self.kind} provider {self.name!r} needs {key!r} in its config"
            )
        return str(value)

    def optional(self, key: str, default: str | None = None) -> str | None:
        value = self.config.get(key)
        return str(value) if value else default

    async def bounded(self, coro: Any) -> Any:
        """Run a provider call under this provider's timeout.

        A timeout is an unavailable provider, never a refused login --
        the provider never said no, it never said anything.
        """
        try:
            return await asyncio.wait_for(coro, timeout=self.timeout)
        except TimeoutError as exc:
            raise ProviderError(
                f"{self.kind} provider {self.name!r} did not answer within "
                f"{self.timeout:g}s"
            ) from exc


def redact(config: dict[str, Any]) -> dict[str, Any]:
    """A config safe to print: secrets masked, everything else intact.

    Not the whole blob masked -- an operator debugging a provider needs
    to see the base DN and the URL, and hiding those makes the command
    useless for the one job it has.
    """
    return {
        key: ("(set)" if key.lower() in SECRET_KEYS and value else value)
        for key, value in config.items()
    }


__all__ = [
    "DEFAULT_TIMEOUT",
    "SECRET_KEYS",
    "Identity",
    "Provider",
    "ProviderBase",
    "ProviderConfigError",
    "ProviderError",
    "redact",
]
