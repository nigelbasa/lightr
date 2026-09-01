"""Which provider answers for an account, and in what order.

Selection is deliberately boring, because an operator debugging a
login needs to be able to predict it:

1. an ``auth_providers`` row whose ``domains`` names this account's
   domain, lowest ``priority`` first
2. failing that, any row marked ``is_default``
3. failing that, the domain's own ``auth_webhook_url`` -- the column
   the Go engine used, honoured so an existing install keeps working,
   and only when ``auth_webhook_verified`` is set

Providers are tried in order until one accepts. A provider that
*refuses* is a real answer and the next one still gets asked -- a user
may exist in one directory and not another. A provider that *fails*
is remembered, and if nothing accepts, the whole attempt reports
unavailable rather than "wrong password".
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.authproviders.base import (
    DEFAULT_TIMEOUT,
    Identity,
    Provider,
    ProviderConfigError,
    ProviderError,
)
from lightr.authproviders.ldap import LDAPProvider
from lightr.authproviders.oidc import OIDCProvider
from lightr.authproviders.webhook import WebhookProvider
from lightr.db import schema
from lightr.models import _now

log = logging.getLogger("lightr.auth.providers")

#: Provider kinds Lightr implements. The schema comment also mentions
#: ``radius``; it is not built, and a row naming it is refused rather
#: than accepted and silently ignored.
KINDS = {
    "ldap": LDAPProvider,
    "oidc": OIDCProvider,
    "oauth2": OIDCProvider,  # token validation is the same job
    "webhook": WebhookProvider,
}


@dataclass(slots=True)
class ProviderRecord:
    """A stored provider, before it is built into a live one."""

    id: UUID
    org_id: UUID | None
    name: str
    kind: str
    enabled: bool = True
    priority: int = 100
    config: dict[str, Any] = field(default_factory=dict)
    domains: list[str] = field(default_factory=list)
    is_default: bool = False
    auto_provision: bool = False
    sync_groups: bool = False
    sync_profile: bool = False

    def covers(self, domain: str) -> bool:
        return domain.lower() in {d.lower() for d in self.domains}

    def build(self) -> Provider:
        factory = KINDS.get(self.kind)
        if factory is None:
            raise ProviderConfigError(
                f"{self.kind!r} is not a provider Lightr implements. "
                f"Supported: {', '.join(sorted(KINDS))}"
            )
        config = dict(self.config)
        config.setdefault("sync_groups", self.sync_groups)
        return factory(
            name=self.name,
            config=config,
            timeout=float(config.get("timeout") or DEFAULT_TIMEOUT),
        )


@dataclass(slots=True)
class Outcome:
    """What happened when the providers were asked.

    Carries the per-provider detail because "authentication failed" is
    useless to whoever has to fix it: what they need is which provider
    was asked, and what it said.
    """

    identity: Identity | None = None
    provider: str | None = None
    unavailable: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.identity is not None

    @property
    def asked(self) -> list[str]:
        return self.refused + self.unavailable


class AuthProviderRepo:
    """Stored authentication providers."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(
        self,
        name: str,
        kind: str,
        config: dict[str, Any],
        *,
        org_id: UUID | None = None,
        domains: list[str] | None = None,
        priority: int = 100,
        is_default: bool = False,
        enabled: bool = True,
        auto_provision: bool = False,
        sync_groups: bool = False,
    ) -> ProviderRecord:
        if kind not in KINDS:
            raise ProviderConfigError(
                f"{kind!r} is not a provider Lightr implements. "
                f"Supported: {', '.join(sorted(KINDS))}"
            )

        record = ProviderRecord(
            id=uuid4(),
            org_id=org_id,
            name=name,
            kind=kind,
            enabled=enabled,
            priority=priority,
            config=config,
            domains=[d.lower() for d in (domains or [])],
            is_default=is_default,
            auto_provision=auto_provision,
            sync_groups=sync_groups,
        )
        # Built once here so a config that can never work is rejected
        # at the point it is written, not at the first login attempt.
        record.build()

        now = _now()
        await self._conn.execute(
            insert(schema.auth_providers).values(
                id=str(record.id),
                org_id=str(org_id) if org_id else "",
                name=name,
                provider=kind,
                enabled=enabled,
                priority=priority,
                config=json.dumps(config),
                domains=json.dumps(record.domains),
                is_default=is_default,
                auto_provision=auto_provision,
                sync_groups=sync_groups,
                sync_profile=False,
                created_at=now,
                updated_at=now,
            )
        )
        return record

    async def list(self, *, org_id: UUID | None = None) -> list[ProviderRecord]:
        stmt = select(schema.auth_providers).order_by(
            schema.auth_providers.c.priority, schema.auth_providers.c.name
        )
        if org_id is not None:
            stmt = stmt.where(schema.auth_providers.c.org_id == str(org_id))
        rows = await self._conn.execute(stmt)
        return [_to_record(r._mapping) for r in rows]

    async def resolve(self, ref: str) -> ProviderRecord:
        from lightr.repo import AmbiguousReferenceError, NotFoundError, _as_uuid

        table = schema.auth_providers
        if (as_uuid := _as_uuid(ref)) is not None:
            row = (
                await self._conn.execute(select(table).where(table.c.id == str(as_uuid)))
            ).first()
            if row is None:
                raise NotFoundError("auth provider", ref)
            return _to_record(row._mapping)

        rows = (
            await self._conn.execute(select(table).where(table.c.name == ref))
        ).fetchall()
        if not rows:
            raise NotFoundError("auth provider", ref, "try `lightr auth list`")
        if len(rows) > 1:
            raise AmbiguousReferenceError(
                "auth provider", ref, [str(r._mapping["id"]) for r in rows]
            )
        return _to_record(rows[0]._mapping)

    async def update(self, provider_id: UUID, **values: Any) -> None:
        allowed = {
            "name", "enabled", "priority", "is_default", "auto_provision",
            "sync_groups",
        }
        changes = {k: v for k, v in values.items() if k in allowed}
        if "config" in values:
            changes["config"] = json.dumps(values["config"])
        if "domains" in values:
            changes["domains"] = json.dumps(
                [str(d).lower() for d in (values["domains"] or [])]
            )
        if not changes:
            return

        await self._conn.execute(
            update(schema.auth_providers)
            .where(schema.auth_providers.c.id == str(provider_id))
            .values(**changes, updated_at=_now())
        )

    async def delete(self, provider_id: UUID) -> None:
        await self._conn.execute(
            delete(schema.auth_providers).where(
                schema.auth_providers.c.id == str(provider_id)
            )
        )

    async def for_domain(self, domain: str) -> list[ProviderRecord]:
        """Every enabled provider that could answer for this domain."""
        rows = await self._conn.execute(
            select(schema.auth_providers)
            .where(schema.auth_providers.c.enabled.is_(True))
            .order_by(schema.auth_providers.c.priority)
        )
        records = [_to_record(r._mapping) for r in rows]

        named = [r for r in records if r.covers(domain)]
        if named:
            return named
        return [r for r in records if r.is_default]


def _to_record(mapping: Any) -> ProviderRecord:
    data = dict(mapping)
    return ProviderRecord(
        id=UUID(data["id"]),
        org_id=UUID(data["org_id"]) if data.get("org_id") else None,
        name=data["name"],
        kind=data["provider"],
        enabled=bool(data.get("enabled", True)),
        priority=int(data.get("priority") or 100),
        config=_json_object(data.get("config")),
        domains=_json_list(data.get("domains")),
        is_default=bool(data.get("is_default")),
        auto_provision=bool(data.get("auto_provision")),
        sync_groups=bool(data.get("sync_groups")),
        sync_profile=bool(data.get("sync_profile")),
    )


def _json_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(v) for v in raw]
    try:
        parsed = json.loads(raw or "[]")
    except (json.JSONDecodeError, TypeError):
        return [d.strip() for d in str(raw or "").split(",") if d.strip()]
    return [str(v) for v in parsed] if isinstance(parsed, list) else []


# --------------------------------------------------------------------
# Asking them
# --------------------------------------------------------------------


async def providers_for(conn: AsyncConnection, domain_id: UUID, domain: str) -> list[Provider]:
    """Every provider that may answer for this domain, in order.

    Falls back to the domain's own ``auth_webhook_url`` -- the column
    the Go engine used -- when no ``auth_providers`` row applies. An
    explicit row always wins: it is the one someone configured on
    purpose.
    """
    records = await AuthProviderRepo(conn).for_domain(domain)
    if records:
        return [r.build() for r in records]

    return await _legacy_domain_webhook(conn, domain_id)


async def _legacy_domain_webhook(
    conn: AsyncConnection, domain_id: UUID
) -> list[Provider]:
    row = (
        await conn.execute(
            select(
                schema.domains.c.name,
                schema.domains.c.auth_webhook_url,
                schema.domains.c.auth_webhook_secret,
                schema.domains.c.auth_webhook_verified,
            ).where(schema.domains.c.id == str(domain_id))
        )
    ).first()
    if row is None or not row.auth_webhook_url:
        return []

    if not row.auth_webhook_verified:
        # An unverified URL answering logins is a configuration
        # accident, not a feature.
        log.warning(
            "%s has an auth webhook that has not been verified; it will not be "
            "used. Run: lightr auth verify %s",
            row.name, row.name,
        )
        return []

    return [
        WebhookProvider(
            name=f"{row.name} (domain webhook)",
            config={
                "url": row.auth_webhook_url,
                "secret": row.auth_webhook_secret or "",
            },
        )
    ]


async def authenticate(
    providers: list[Provider], username: str, password: str
) -> Outcome:
    """Ask each provider in turn, and report what each one said."""
    outcome = Outcome()

    for provider in providers:
        try:
            identity = await provider.authenticate(username, password)
        except ProviderError as exc:
            log.warning("auth provider %s could not answer: %s", provider.name, exc)
            outcome.unavailable.append(f"{provider.name}: {exc}")
            continue
        except Exception as exc:  # a provider bug must not be a 500
            log.exception("auth provider %s raised", provider.name)
            outcome.unavailable.append(f"{provider.name}: {exc}")
            continue

        if identity is not None:
            outcome.identity = identity
            outcome.provider = provider.name
            return outcome
        outcome.refused.append(provider.name)

    return outcome


__all__ = [
    "KINDS",
    "AuthProviderRepo",
    "Outcome",
    "ProviderRecord",
    "authenticate",
    "providers_for",
]
