"""OAuth 2.0 and OpenID Connect, as a mail server can use them.

There is no browser on this path. An IMAP client does not redirect a
user to an identity provider mid-``LOGIN``; it obtains a token
elsewhere and presents it -- as XOAUTH2, or as the password in a plain
login. So what this provider does is **validate a bearer token**, by
one of the two ways a provider will answer:

*introspection* (RFC 7662)
    POST the token to the introspection endpoint with client
    credentials. The authoritative answer, and the one that reflects a
    revoked token immediately.
*userinfo* (OIDC Core)
    GET the userinfo endpoint with the token as a bearer credential.
    Available on every OIDC provider, including ones that do not expose
    introspection.

The check that matters is not "is this token valid" but **"is this
token this account's"**. A valid token belonging to someone else,
presented as the password for this mailbox, must fail -- otherwise any
user of the identity provider can read any mailbox on the server. That
is why an answer with no identifying claim at all is refused rather
than accepted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from lightr.authproviders.base import (
    Identity,
    ProviderBase,
    ProviderConfigError,
    ProviderError,
)
from lightr.webhooks.ssrf import SSRFError, vet

log = logging.getLogger("lightr.auth.oidc")

#: Claims that can carry the account's identity, most specific first.
IDENTITY_CLAIMS = ("email", "preferred_username", "username", "upn", "sub")


@dataclass(slots=True)
class OIDCProvider(ProviderBase):
    """Validates a bearer token against an OAuth2/OIDC provider."""

    kind = "oidc"

    async def authenticate(self, username: str, token: str) -> Identity | None:
        if not token:
            return None
        return await self.bounded(self._validate(username, token))

    async def _validate(self, username: str, token: str) -> Identity | None:
        claims = await self._claims(token)
        if claims is None:
            return None
        return self._match(username, claims)

    async def _claims(self, token: str) -> dict[str, Any] | None:
        if self.config.get("introspection_url"):
            return await self._introspect(token)
        if self.config.get("userinfo_url"):
            return await self._userinfo(token)
        raise ProviderConfigError(
            f"oidc provider {self.name!r} needs an 'introspection_url' or a "
            f"'userinfo_url' in its config"
        )

    # -- the two ways to ask ---------------------------------------------

    async def _introspect(self, token: str) -> dict[str, Any] | None:
        url = self.required("introspection_url")
        client_id = self.required("client_id")
        client_secret = self.required("client_secret")

        payload = await self._request(
            "POST",
            url,
            data={"token": token, "token_type_hint": "access_token"},
            auth=(client_id, client_secret),
        )
        assert payload is not None  # introspection never refuses this way
        # RFC 7662: `active` is the whole answer. False means revoked,
        # expired, or never issued -- a real refusal.
        if not payload.get("active"):
            return None
        return payload

    async def _userinfo(self, token: str) -> dict[str, Any] | None:
        url = self.required("userinfo_url")
        return await self._request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {token}"},
            # Here a 401 is the provider rejecting the *token*, which is
            # a real answer. On introspection it would mean our own
            # client credentials are wrong, which is not.
            unauthorized_is_refusal=True,
        )

    # -- matching ---------------------------------------------------------

    def _match(self, username: str, claims: dict[str, Any]) -> Identity | None:
        """Check the token actually belongs to this account."""
        claim_name = self.optional("username_claim")
        names = (claim_name,) if claim_name else IDENTITY_CLAIMS

        found = [
            str(claims[name]).strip().lower()
            for name in names
            if name and claims.get(name)
        ]
        if not found:
            # The provider said the token is valid but would not say
            # whose it is. Accepting that would let any valid token open
            # any mailbox.
            raise ProviderError(
                f"oidc provider {self.name!r} returned no identifying claim "
                f"(looked for {', '.join(n for n in names if n)}); "
                f"set 'username_claim' to the one it does return"
            )

        wanted = username.strip().lower()
        if wanted not in found:
            log.info("oidc token for %s presented as %s", found[0], wanted)
            return None

        return Identity(
            username=username,
            external_id=_string(claims.get("sub")),
            display_name=_string(claims.get("name") or claims.get("given_name")),
            groups=tuple(str(g) for g in (claims.get("groups") or ())),
        )

    # -- transport --------------------------------------------------------

    async def _request(
        self, method: str, url: str, *, unauthorized_is_refusal: bool = False, **kwargs: Any
    ) -> dict[str, Any] | None:
        try:
            target = vet(url, allow_private=bool(self.config.get("allow_private")))
        except SSRFError as exc:
            raise ProviderError(f"provider URL was refused: {exc}") from exc

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on install
            raise ProviderError("httpx is not installed") from exc

        headers = dict(kwargs.pop("headers", {}))
        headers["Host"] = target.host
        headers.setdefault("Accept", "application/json")

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False
            ) as client:
                response = await client.request(
                    method, target.connect_url, headers=headers, **kwargs
                )
        except Exception as exc:
            raise ProviderError(f"{url} was unreachable: {exc}") from exc

        if response.status_code == 401 and unauthorized_is_refusal:
            return None
        if response.status_code >= 300:
            raise ProviderError(
                f"{url} answered HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderError(f"{url} did not return JSON") from exc
        if not isinstance(payload, dict):
            raise ProviderError(f"{url} did not return a JSON object")
        return payload


def _string(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


__all__ = ["IDENTITY_CLAIMS", "OIDCProvider"]
