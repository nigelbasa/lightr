"""Domain model.

Plain Pydantic models over the Core schema. Deliberately not an ORM:
the engine reads and writes explicit column sets, and an identity map
would buy nothing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator


def _now() -> datetime:
    """Naive UTC, matching what the Go engine wrote into SQLite."""
    return datetime.now(UTC).replace(tzinfo=None)


class _Record(BaseModel):
    model_config = ConfigDict(from_attributes=True, validate_assignment=True)


class AuthMode(StrEnum):
    """How an account authenticates."""

    NATIVE = "native"  # bcrypt hash in accounts.password_hash
    EXTERNAL = "external"  # delegated to an auth_providers entry
    DISABLED = "disabled"


class AliasType(StrEnum):
    FORWARD = "forward"  # deliver to destinations, drop the local copy
    BRIDGE = "bridge"  # mirror locally *and* forward, with reply routing


class SpamPolicy(StrEnum):
    JUNK = "junk"  # file into the Junk folder
    REJECT = "reject"  # refuse at SMTP time
    TAG = "tag"  # deliver to INBOX with headers only


class TrustLevel(StrEnum):
    INTERNAL = "internal"
    PARTNER = "partner"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class Organization(_Record):
    id: UUID = Field(default_factory=uuid4)
    name: str
    created_at: datetime = Field(default_factory=_now)


class Domain(_Record):
    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    name: str
    mail_hostname: str | None = None
    dkim_private_key: str | None = None
    dkim_selector: str | None = "default"
    webhook_url: str | None = None
    auth_webhook_url: str | None = None
    auth_webhook_secret: str | None = None
    auth_webhook_verified: bool = False
    auth_webhook_verified_at: datetime | None = None
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    relay_enabled: bool = False
    relay_host: str | None = None
    relay_port: int | None = None
    relay_username: str | None = None
    relay_password: str | None = None
    relay_use_tls: bool = False
    relay_tls_skip_verify: bool = False
    spam_policy: SpamPolicy = SpamPolicy.JUNK
    is_verified: bool = False
    created_at: datetime = Field(default_factory=_now)

    @field_validator("name")
    @classmethod
    def _normalise_name(cls, v: str) -> str:
        name = v.strip().lower().rstrip(".")
        if not name or "." not in name:
            raise ValueError(f"{v!r} is not a valid domain name")
        if " " in name:
            raise ValueError(f"{v!r} contains whitespace")
        return name

    @property
    def hostname(self) -> str:
        """The public mail hostname, falling back to the domain itself."""
        return self.mail_hostname or self.name


class Account(_Record):
    id: UUID = Field(default_factory=uuid4)
    domain_id: UUID
    local_part: str
    display_name: str | None = None
    auth_mode: AuthMode = AuthMode.NATIVE
    password_hash: str | None = None
    external_id: str | None = None
    quota_bytes: int | None = None
    maildir_path: str | None = None
    #: Whether this account may send through submission. Off stops a
    #: compromised account spamming without locking its owner out.
    can_send: bool = True
    #: Whether mail addressed to this account is accepted.
    can_receive: bool = True
    created_at: datetime = Field(default_factory=_now)

    # Populated on read when the domain is known; not a stored column.
    domain_name: str | None = None

    @field_validator("local_part")
    @classmethod
    def _normalise_local_part(cls, v: str) -> str:
        local = v.strip().lower()
        if not local:
            raise ValueError("local part cannot be empty")
        if "@" in local:
            raise ValueError("local part must not contain '@'")
        if any(c.isspace() for c in local):
            raise ValueError("local part must not contain whitespace")
        return local

    @computed_field  # type: ignore[prop-decorator]
    @property
    def email(self) -> str | None:
        """The full address. Computed, so it appears in model_dump()."""
        if self.domain_name is None:
            return None
        return f"{self.local_part}@{self.domain_name}"

    def with_domain(self, domain: Domain) -> Self:
        self.domain_name = domain.name
        return self


class Alias(_Record):
    id: UUID = Field(default_factory=uuid4)
    domain_id: UUID
    source: str
    destinations: list[str] = Field(default_factory=list)
    type: AliasType = AliasType.FORWARD
    is_active: bool = True
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    @field_validator("source")
    @classmethod
    def _normalise_source(cls, v: str) -> str:
        source = v.strip().lower()
        if not source:
            raise ValueError("alias source cannot be empty")
        # An alias source is a local part; strip a domain if one was given.
        return source.split("@", 1)[0]

    @field_validator("destinations", mode="before")
    @classmethod
    def _parse_destinations(cls, v: Any) -> Any:
        """Accept the JSON array the Go engine stored, or a real list."""
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
            except json.JSONDecodeError:
                # Tolerate the comma-separated form the CLI accepts.
                return [d.strip() for d in v.split(",") if d.strip()]
            return parsed if isinstance(parsed, list) else [parsed]
        return v


class Suppression(_Record):
    email: str
    reason: str
    org_id: UUID | None = None
    created_at: datetime = Field(default_factory=_now)


__all__ = [
    "Account",
    "Alias",
    "AliasType",
    "AuthMode",
    "Domain",
    "Organization",
    "SpamPolicy",
    "Suppression",
    "TrustLevel",
]
