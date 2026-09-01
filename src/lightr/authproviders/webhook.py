"""Delegating authentication to an HTTP endpoint.

The simplest offload there is: Lightr POSTs the credentials to a URL an
operator controls, and that endpoint says yes or no. It is what an
application with its own user table wants, and it is the shape the Go
engine's ``domains.auth_webhook_url`` column already described.

Three things make it safe enough to send a plaintext password over:

* the URL goes through the same SSRF guard as event webhooks, so it
  cannot be pointed at the cloud metadata endpoint or a private host
* the request is HMAC-signed with a shared secret, so the endpoint can
  tell a real request from anything else that can reach it
* redirects are not followed -- the destination of a redirect is
  chosen by the receiver, which would undo the first two
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from lightr.authproviders.base import Identity, ProviderBase, ProviderError
from lightr.webhooks.delivery import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign
from lightr.webhooks.ssrf import SSRFError, vet

log = logging.getLogger("lightr.auth.webhook")


@dataclass(slots=True)
class WebhookProvider(ProviderBase):
    """Asks an HTTP endpoint whether these credentials are good."""

    kind = "webhook"

    async def authenticate(self, username: str, password: str) -> Identity | None:
        return await self.bounded(self._ask(username, password))

    async def _ask(self, username: str, password: str) -> Identity | None:
        url = self.required("url")
        try:
            target = vet(url, allow_private=bool(self.config.get("allow_private")))
        except SSRFError as exc:
            raise ProviderError(f"auth webhook URL was refused: {exc}") from exc

        body = json.dumps({"username": username, "password": password}).encode("utf-8")
        timestamp = str(int(datetime.now(UTC).timestamp()))
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "lightr-auth/1",
            TIMESTAMP_HEADER: timestamp,
            "Host": target.host,
        }
        if secret := self.optional("secret"):
            headers[SIGNATURE_HEADER] = sign(secret, timestamp, body)

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on install
            raise ProviderError("httpx is not installed") from exc

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False
            ) as client:
                response = await client.post(
                    target.connect_url, content=body, headers=headers
                )
        except Exception as exc:
            raise ProviderError(f"auth webhook {url} was unreachable: {exc}") from exc

        return self._read(username, response)

    def _read(self, username: str, response: Any) -> Identity | None:
        """Turn the endpoint's answer into yes, no, or "it did not say".

        401 and 403 are the endpoint refusing, which is a real answer.
        A 5xx, a timeout, or a body that is not the agreed shape is the
        endpoint failing -- and an endpoint that is failing must not be
        read as "the password was wrong".
        """
        if response.status_code in (401, 403):
            return None
        if response.status_code >= 300 or response.status_code < 200:
            raise ProviderError(
                f"auth webhook answered HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProviderError("auth webhook did not return JSON") from exc
        if not isinstance(payload, dict):
            raise ProviderError("auth webhook did not return a JSON object")

        accepted = payload.get("ok")
        if accepted is None:
            accepted = str(payload.get("status", "")).lower() in ("ok", "success")
        if not accepted:
            return None

        return Identity(
            username=str(payload.get("username") or username),
            external_id=_string(payload.get("id") or payload.get("external_id")),
            display_name=_string(payload.get("display_name") or payload.get("name")),
            groups=tuple(str(g) for g in (payload.get("groups") or ())),
        )


def _string(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


__all__ = ["WebhookProvider"]
