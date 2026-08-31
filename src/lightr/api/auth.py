"""API authentication and scoping.

Two distinct principals, kept apart deliberately:

* **operator** -- an API key, scoped to an organization, a domain, or
  an account, used for the ``/v1/{orgs,domains,accounts,...}`` routes
* **mailbox** -- one account's own session, used for ``/v1/mailbox/*``

Collapsing them into a single dependency is how a mailbox token ends
up able to list every domain on the server, so they do not share a
code path.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from starlette.requests import Request

from lightr.apikeys import APIKey, APIKeyRepo, KeyType, Permission


class AuthError(Exception):
    """Authentication or authorisation failed."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is making a request, and what they may reach."""

    key: APIKey

    @property
    def is_admin(self) -> bool:
        return self.key.type is KeyType.ADMIN or Permission.ADMIN in self.key.permissions

    def require(self, permission: Permission) -> None:
        if not self.key.allows(permission):
            raise AuthError(403, f"this key does not allow {permission}")

    def require_admin(self) -> None:
        if not self.is_admin:
            raise AuthError(403, "this operation requires an admin key")

    def scoped_org(self) -> UUID | None:
        """The organization this key is confined to, if any."""
        return None if self.is_admin else self.key.organization_id

    def may_reach_org(self, org_id: UUID) -> bool:
        if self.is_admin:
            return True
        return self.key.organization_id == org_id

    def may_reach_domain(self, domain_id: UUID, org_id: UUID) -> bool:
        if self.is_admin:
            return True
        if self.key.domain_id is not None:
            return self.key.domain_id == domain_id
        return self.key.organization_id == org_id

    def may_reach_account(self, account_id: UUID) -> bool:
        if self.is_admin:
            return True
        if self.key.account_id is not None:
            return self.key.account_id == account_id
        return True  # narrower scopes are checked by domain/org above


def extract_secret(request: Request) -> str | None:
    """Pull the API key out of the request.

    Accepts ``X-API-Key: <key>`` and ``Authorization: Bearer <key>``,
    matching what the Go engine accepted so existing clients keep
    working.
    """
    if header := request.headers.get("X-API-Key"):
        return header.strip()

    authorization = request.headers.get("Authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() == "bearer" and value:
        return value.strip()
    return None


def client_ip(request: Request) -> str | None:
    """The caller's address, honouring one layer of reverse proxy.

    Only the *last* entry of X-Forwarded-For is trustworthy, and only
    when a proxy is actually in front; a client can forge earlier ones.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else None


async def authenticate(request: Request) -> Principal:
    """Resolve the operator principal for a request, or raise."""
    secret = extract_secret(request)
    if not secret:
        raise AuthError(401, "missing API key -- send X-API-Key or Authorization: Bearer")

    conn = request.state.conn
    key = await APIKeyRepo(conn).verify(secret, ip=client_ip(request))
    if key is None:
        raise AuthError(401, "invalid, expired, or revoked API key")

    return Principal(key=key)


__all__ = [
    "AuthError",
    "Principal",
    "authenticate",
    "client_ip",
    "extract_secret",
]
