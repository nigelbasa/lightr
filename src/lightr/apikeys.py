"""API keys.

A key is shown once, at creation, and stored only as a SHA-256 hash.
The visible prefix lets an operator identify a key in a list, and lets
lookup narrow to a handful of candidates before doing constant-time
comparison.

bcrypt is deliberately *not* used here. API keys are high-entropy
random values, not user-chosen passwords, so there is nothing for a
slow hash to defend against -- and every API request would pay the
cost.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema

KEY_PREFIX = "lk"
PREFIX_LENGTH = 12
SECRET_BYTES = 32


class KeyType(StrEnum):
    ADMIN = "admin"  # everything, including other organizations
    ORG = "org"  # one organization
    DOMAIN = "domain"  # one domain
    ACCOUNT = "account"  # one mailbox


class Permission(StrEnum):
    READ = "read"
    WRITE = "write"
    SEND = "send"
    MAILBOX = "mailbox"
    ADMIN = "admin"


#: What each key type may do unless narrowed further.
DEFAULT_PERMISSIONS: dict[KeyType, list[Permission]] = {
    KeyType.ADMIN: [Permission.ADMIN, Permission.READ, Permission.WRITE,
                    Permission.SEND, Permission.MAILBOX],
    KeyType.ORG: [Permission.READ, Permission.WRITE, Permission.SEND],
    KeyType.DOMAIN: [Permission.READ, Permission.WRITE, Permission.SEND],
    KeyType.ACCOUNT: [Permission.READ, Permission.MAILBOX, Permission.SEND],
}


class APIKeyError(ValueError):
    """A key could not be created or used."""


class APIKey(BaseModel):
    """A stored key. Never holds the secret itself."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str | None = None
    prefix: str
    key_hash: str
    organization_id: UUID | None = None
    domain_id: UUID | None = None
    account_id: UUID | None = None
    user_id: UUID | None = None
    type: KeyType = KeyType.ORG
    permissions: list[Permission] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    rate_limit: int = 1000
    daily_limit: int = 100_000
    active: bool = True
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    last_used_ip: str | None = None
    usage_count: int = 0
    usage_today: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None))

    @property
    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        return self.expires_at < datetime.now(UTC).replace(tzinfo=None)

    @property
    def usable(self) -> bool:
        return self.active and not self.expired

    def allows(self, permission: Permission) -> bool:
        if Permission.ADMIN in self.permissions:
            return True
        return permission in self.permissions

    def allows_ip(self, ip: str | None) -> bool:
        """Whether a request from ``ip`` is permitted.

        An empty allow-list permits everything. A non-empty one that
        the address does not match denies -- including when the address
        is unknown, since an unverifiable request must not pass a
        restriction that exists precisely to verify it.
        """
        if not self.allowed_ips:
            return True
        if ip is None:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.allowed_ips:
            try:
                if "/" in entry:
                    if address in ipaddress.ip_network(entry, strict=False):
                        return True
                elif address == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def scope_description(self) -> str:
        """A human phrase for what this key covers."""
        if self.type is KeyType.ADMIN:
            return "all organizations"
        for label, value in (
            ("account", self.account_id),
            ("domain", self.domain_id),
            ("organization", self.organization_id),
        ):
            if value is not None:
                return f"{label} {value}"
        return "unscoped"


def generate_secret() -> tuple[str, str, str]:
    """Make a new key. Returns (secret, prefix, hash).

    The secret is the only time the caller sees the full value.
    """
    body = secrets.token_urlsafe(SECRET_BYTES)
    secret = f"{KEY_PREFIX}_{body}"
    return secret, secret[:PREFIX_LENGTH], hash_secret(secret)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _dump_list(values: list[Any]) -> str:
    return json.dumps([str(v) for v in values])


def _load_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(v) for v in raw]
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(v) for v in parsed] if isinstance(parsed, list) else []


class APIKeyRepo:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(
        self,
        name: str,
        *,
        key_type: KeyType = KeyType.ORG,
        organization_id: UUID | None = None,
        domain_id: UUID | None = None,
        account_id: UUID | None = None,
        permissions: list[Permission] | None = None,
        allowed_ips: list[str] | None = None,
        expires_in_days: int | None = None,
        description: str | None = None,
    ) -> tuple[APIKey, str]:
        """Create a key. Returns the record and the one-time secret."""
        if key_type is KeyType.ORG and organization_id is None:
            raise APIKeyError("an org-scoped key needs an organization")
        if key_type is KeyType.DOMAIN and domain_id is None:
            raise APIKeyError("a domain-scoped key needs a domain")
        if key_type is KeyType.ACCOUNT and account_id is None:
            raise APIKeyError("an account-scoped key needs an account")

        secret, prefix, digest = generate_secret()
        expires_at = None
        if expires_in_days is not None:
            if expires_in_days <= 0:
                raise APIKeyError("--expires-in must be a positive number of days")
            expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=expires_in_days)

        key = APIKey(
            name=name,
            description=description,
            prefix=prefix,
            key_hash=digest,
            organization_id=organization_id,
            domain_id=domain_id,
            account_id=account_id,
            type=key_type,
            permissions=permissions or DEFAULT_PERMISSIONS[key_type],
            allowed_ips=allowed_ips or [],
            expires_at=expires_at,
        )

        await self._conn.execute(
            insert(schema.api_keys).values(
                id=str(key.id),
                name=key.name,
                description=key.description,
                prefix=key.prefix,
                key_hash=key.key_hash,
                organization_id=str(organization_id) if organization_id else None,
                domain_id=str(domain_id) if domain_id else None,
                account_id=str(account_id) if account_id else None,
                user_id=None,
                type=str(key.type),
                permissions=_dump_list(key.permissions),
                allowed_ips=_dump_list(key.allowed_ips),
                allowed_domains=_dump_list(key.allowed_domains),
                rate_limit=key.rate_limit,
                daily_limit=key.daily_limit,
                active=key.active,
                expires_at=key.expires_at,
                metadata=None,
                created_at=key.created_at,
                updated_at=key.updated_at,
            )
        )
        return key, secret

    async def verify(self, secret: str, *, ip: str | None = None) -> APIKey | None:
        """Look up a presented secret, or None if it is not usable."""
        if not secret or not secret.startswith(f"{KEY_PREFIX}_"):
            return None

        digest = hash_secret(secret)
        row = (
            await self._conn.execute(
                select(schema.api_keys).where(schema.api_keys.c.key_hash == digest)
            )
        ).first()
        if row is None:
            return None

        key = self._to_model(row._mapping)
        if not key.usable or not key.allows_ip(ip):
            return None
        return key

    async def list(
        self, organization_id: UUID | None = None, limit: int = 100
    ) -> list[APIKey]:
        stmt = (
            select(schema.api_keys)
            .order_by(schema.api_keys.c.created_at.desc())
            .limit(limit)
        )
        if organization_id is not None:
            stmt = stmt.where(schema.api_keys.c.organization_id == str(organization_id))
        rows = await self._conn.execute(stmt)
        return [self._to_model(r._mapping) for r in rows]

    async def resolve(self, ref: str) -> APIKey:
        """Find a key by id, prefix, or name."""
        from lightr.repo import AmbiguousReferenceError, NotFoundError

        table = schema.api_keys
        try:
            as_uuid: UUID | None = UUID(ref)
        except ValueError:
            as_uuid = None

        if as_uuid is not None:
            row = (
                await self._conn.execute(select(table).where(table.c.id == str(as_uuid)))
            ).first()
            if row is None:
                raise NotFoundError("api key", ref)
            return self._to_model(row._mapping)

        rows = (
            await self._conn.execute(
                select(table).where((table.c.name == ref) | (table.c.prefix == ref))
            )
        ).fetchall()
        if not rows:
            raise NotFoundError("api key", ref, "try `lightr apikey list`")
        if len(rows) > 1:
            raise AmbiguousReferenceError(
                "api key", ref, [r._mapping["prefix"] for r in rows]
            )
        return self._to_model(rows[0]._mapping)

    async def revoke(self, key_id: UUID) -> None:
        await self._conn.execute(
            update(schema.api_keys)
            .where(schema.api_keys.c.id == str(key_id))
            .values(active=False, updated_at=datetime.now(UTC).replace(tzinfo=None))
        )

    async def rotate(self, key_id: UUID) -> str:
        """Replace a key's secret in place, keeping its scope. Returns the new secret."""
        secret, prefix, digest = generate_secret()
        await self._conn.execute(
            update(schema.api_keys)
            .where(schema.api_keys.c.id == str(key_id))
            .values(
                prefix=prefix,
                key_hash=digest,
                updated_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
        return secret

    async def delete(self, key_id: UUID) -> None:
        from sqlalchemy import delete as sql_delete

        await self._conn.execute(
            sql_delete(schema.api_keys).where(schema.api_keys.c.id == str(key_id))
        )

    async def record_use(self, key_id: UUID, ip: str | None) -> None:
        await self._conn.execute(
            update(schema.api_keys)
            .where(schema.api_keys.c.id == str(key_id))
            .values(
                last_used_at=datetime.now(UTC).replace(tzinfo=None),
                last_used_ip=ip,
                usage_count=schema.api_keys.c.usage_count + 1,
                usage_today=schema.api_keys.c.usage_today + 1,
            )
        )

    @staticmethod
    def _to_model(mapping: Any) -> APIKey:
        data = dict(mapping)
        data["permissions"] = _load_list(data.get("permissions"))
        data["allowed_ips"] = _load_list(data.get("allowed_ips"))
        data["allowed_domains"] = _load_list(data.get("allowed_domains"))
        data.pop("metadata", None)
        return APIKey.model_validate(data)


__all__ = [
    "DEFAULT_PERMISSIONS",
    "APIKey",
    "APIKeyError",
    "APIKeyRepo",
    "KeyType",
    "Permission",
    "generate_secret",
    "hash_secret",
]
