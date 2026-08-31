"""Repositories over the Core schema.

Every lookup accepts a *reference* -- a UUID or the object's human name
-- so no command line or API call ever forces the caller to know a
UUID. This was the single biggest usability gap in the Go CLI and is
built in here rather than bolted on.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import Select, delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema
from lightr.models import Account, Alias, Domain, Organization, _now


class NotFoundError(LookupError):
    """No object matched the given reference."""

    def __init__(self, kind: str, ref: str, hint: str | None = None) -> None:
        message = f"no {kind} matching {ref!r}"
        if hint:
            message = f"{message} -- {hint}"
        super().__init__(message)
        self.kind = kind
        self.ref = ref


class AmbiguousReferenceError(LookupError):
    """A reference matched more than one object."""

    def __init__(self, kind: str, ref: str, matches: Sequence[str]) -> None:
        shown = ", ".join(matches[:5])
        super().__init__(
            f"{ref!r} matches {len(matches)} {kind}s ({shown}); use the id or a fuller name"
        )
        self.matches = list(matches)


class ConflictError(ValueError):
    """The object already exists."""


def _as_uuid(ref: str) -> UUID | None:
    try:
        return UUID(str(ref))
    except (ValueError, AttributeError, TypeError):
        return None


def _json_list(value: Any) -> str:
    return json.dumps(list(value or []))


# --------------------------------------------------------------------
# Organizations
# --------------------------------------------------------------------


class OrganizationRepo:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(self, org: Organization) -> Organization:
        await self._conn.execute(
            insert(schema.organizations).values(
                id=str(org.id), name=org.name, created_at=org.created_at
            )
        )
        return org

    async def list(self, limit: int = 100, offset: int = 0) -> list[Organization]:
        rows = await self._conn.execute(
            select(schema.organizations)
            .order_by(schema.organizations.c.name)
            .limit(limit)
            .offset(offset)
        )
        return [Organization.model_validate(r._mapping) for r in rows]

    async def resolve(self, ref: str) -> Organization:
        """Find an organization by id or name (exact, then prefix)."""
        table = schema.organizations
        if (as_uuid := _as_uuid(ref)) is not None:
            row = (
                await self._conn.execute(select(table).where(table.c.id == str(as_uuid)))
            ).first()
            if row is None:
                raise NotFoundError("organization", ref)
            return Organization.model_validate(row._mapping)

        exact = (await self._conn.execute(select(table).where(table.c.name == ref))).first()
        if exact is not None:
            return Organization.model_validate(exact._mapping)

        partial = (
            await self._conn.execute(
                select(table).where(func.lower(table.c.name).like(f"{ref.lower()}%"))
            )
        ).fetchall()
        if not partial:
            raise NotFoundError("organization", ref, "try `lightr org list`")
        if len(partial) > 1:
            raise AmbiguousReferenceError(
                "organization", ref, [r._mapping["name"] for r in partial]
            )
        return Organization.model_validate(partial[0]._mapping)

    async def rename(self, org_id: UUID, name: str) -> None:
        await self._conn.execute(
            update(schema.organizations)
            .where(schema.organizations.c.id == str(org_id))
            .values(name=name)
        )

    async def delete(self, org_id: UUID) -> None:
        await self._conn.execute(
            delete(schema.organizations).where(schema.organizations.c.id == str(org_id))
        )

    async def count(self) -> int:
        return int(
            (await self._conn.execute(select(func.count()).select_from(schema.organizations)))
            .scalar_one()
        )

    async def default(self) -> Organization:
        """The organization to use when the caller didn't name one.

        Single-tenant installs are the common case; making them state
        an org on every command is pure friction.
        """
        rows = await self.list(limit=2)
        if not rows:
            org = Organization(name="default")
            return await self.create(org)
        if len(rows) > 1:
            raise AmbiguousReferenceError(
                "organization", "(unspecified)", [r.name for r in rows]
            )
        return rows[0]


# --------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------

_DOMAIN_COLUMNS = (
    "id org_id name mail_hostname dkim_private_key dkim_selector webhook_url "
    "auth_webhook_url auth_webhook_secret auth_webhook_verified auth_webhook_verified_at "
    "tls_cert_file tls_key_file relay_enabled relay_host relay_port relay_username "
    "relay_password relay_use_tls relay_tls_skip_verify spam_policy is_verified created_at"
).split()


class DomainRepo:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(self, domain: Domain) -> Domain:
        if await self._exists(domain.name):
            raise ConflictError(f"domain {domain.name!r} already exists")
        values = domain.model_dump(include=set(_DOMAIN_COLUMNS))
        values["id"] = str(domain.id)
        values["org_id"] = str(domain.org_id)
        values["spam_policy"] = str(domain.spam_policy)
        await self._conn.execute(insert(schema.domains).values(**values))
        return domain

    async def _exists(self, name: str) -> bool:
        return (
            await self._conn.execute(
                select(schema.domains.c.id).where(schema.domains.c.name == name.lower())
            )
        ).first() is not None

    async def list(self, org_id: UUID | None = None, limit: int = 100) -> list[Domain]:
        stmt: Select = select(schema.domains).order_by(schema.domains.c.name).limit(limit)
        if org_id is not None:
            stmt = stmt.where(schema.domains.c.org_id == str(org_id))
        rows = await self._conn.execute(stmt)
        return [Domain.model_validate(r._mapping) for r in rows]

    async def resolve(self, ref: str) -> Domain:
        """Find a domain by id or name. An email address resolves to its domain."""
        table = schema.domains
        if (as_uuid := _as_uuid(ref)) is not None:
            row = (
                await self._conn.execute(select(table).where(table.c.id == str(as_uuid)))
            ).first()
            if row is None:
                raise NotFoundError("domain", ref)
            return Domain.model_validate(row._mapping)

        name = ref.strip().lower().rstrip(".")
        if "@" in name:
            name = name.split("@", 1)[1]

        row = (await self._conn.execute(select(table).where(table.c.name == name))).first()
        if row is None:
            raise NotFoundError("domain", ref, "try `lightr domain list`")
        return Domain.model_validate(row._mapping)

    async def update(self, domain: Domain) -> None:
        values = domain.model_dump(include=set(_DOMAIN_COLUMNS))
        values.pop("id", None)
        values["org_id"] = str(domain.org_id)
        values["spam_policy"] = str(domain.spam_policy)
        await self._conn.execute(
            update(schema.domains).where(schema.domains.c.id == str(domain.id)).values(**values)
        )

    async def delete(self, domain_id: UUID) -> None:
        await self._conn.execute(
            delete(schema.domains).where(schema.domains.c.id == str(domain_id))
        )

    async def is_local(self, domain_name: str) -> bool:
        """Whether this server is authoritative for the domain."""
        return await self._exists(domain_name)


# --------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------

_ACCOUNT_COLUMNS = (
    "id domain_id local_part display_name auth_mode password_hash external_id "
    "quota_bytes maildir_path created_at"
).split()


class AccountRepo:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(self, account: Account) -> Account:
        values = account.model_dump(include=set(_ACCOUNT_COLUMNS))
        values["id"] = str(account.id)
        values["domain_id"] = str(account.domain_id)
        values["auth_mode"] = str(account.auth_mode)
        await self._conn.execute(insert(schema.accounts).values(**values))
        return account

    async def list(
        self, domain_id: UUID | None = None, limit: int = 100, offset: int = 0
    ) -> list[Account]:
        stmt = (
            select(schema.accounts, schema.domains.c.name.label("domain_name"))
            .select_from(schema.accounts.join(schema.domains))
            .order_by(schema.domains.c.name, schema.accounts.c.local_part)
            .limit(limit)
            .offset(offset)
        )
        if domain_id is not None:
            stmt = stmt.where(schema.accounts.c.domain_id == str(domain_id))
        rows = await self._conn.execute(stmt)
        return [Account.model_validate(r._mapping) for r in rows]

    async def resolve(self, ref: str) -> Account:
        """Find an account by id or email address.

        A bare local part resolves only when it is unambiguous across
        all domains -- which it usually is on a single-domain install.
        """
        base = select(schema.accounts, schema.domains.c.name.label("domain_name")).select_from(
            schema.accounts.join(schema.domains)
        )

        if (as_uuid := _as_uuid(ref)) is not None:
            row = (
                await self._conn.execute(base.where(schema.accounts.c.id == str(as_uuid)))
            ).first()
            if row is None:
                raise NotFoundError("account", ref)
            return Account.model_validate(row._mapping)

        value = ref.strip().lower()
        if "@" in value:
            local, domain_name = value.split("@", 1)
            row = (
                await self._conn.execute(
                    base.where(
                        schema.accounts.c.local_part == local,
                        schema.domains.c.name == domain_name,
                    )
                )
            ).first()
            if row is None:
                raise NotFoundError("account", ref, "try `lightr account list`")
            return Account.model_validate(row._mapping)

        rows = (
            await self._conn.execute(base.where(schema.accounts.c.local_part == value))
        ).fetchall()
        if not rows:
            raise NotFoundError("account", ref, "try `lightr account list`")
        if len(rows) > 1:
            raise AmbiguousReferenceError(
                "account",
                ref,
                [f"{r._mapping['local_part']}@{r._mapping['domain_name']}" for r in rows],
            )
        return Account.model_validate(rows[0]._mapping)

    async def find(self, email: str) -> Account | None:
        """Like resolve, but returns None instead of raising."""
        try:
            return await self.resolve(email)
        except LookupError:
            return None

    async def update(self, account: Account) -> None:
        values = account.model_dump(include=set(_ACCOUNT_COLUMNS))
        values.pop("id", None)
        values["domain_id"] = str(account.domain_id)
        values["auth_mode"] = str(account.auth_mode)
        await self._conn.execute(
            update(schema.accounts)
            .where(schema.accounts.c.id == str(account.id))
            .values(**values)
        )

    async def set_password_hash(self, account_id: UUID, password_hash: str) -> None:
        await self._conn.execute(
            update(schema.accounts)
            .where(schema.accounts.c.id == str(account_id))
            .values(password_hash=password_hash, auth_mode="native")
        )

    async def delete(self, account_id: UUID) -> None:
        await self._conn.execute(
            delete(schema.accounts).where(schema.accounts.c.id == str(account_id))
        )

    async def count(self, domain_id: UUID | None = None) -> int:
        stmt = select(func.count()).select_from(schema.accounts)
        if domain_id is not None:
            stmt = stmt.where(schema.accounts.c.domain_id == str(domain_id))
        return int((await self._conn.execute(stmt)).scalar_one())


# --------------------------------------------------------------------
# Aliases
# --------------------------------------------------------------------


class AliasRepo:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(self, alias: Alias) -> Alias:
        await self._conn.execute(
            insert(schema.aliases).values(
                id=str(alias.id),
                domain_id=str(alias.domain_id),
                source=alias.source,
                destinations=_json_list(alias.destinations),
                type=str(alias.type),
                is_active=alias.is_active,
                created_at=alias.created_at,
                updated_at=alias.updated_at,
            )
        )
        return alias

    async def list(self, domain_id: UUID | None = None, limit: int = 100) -> list[Alias]:
        stmt = select(schema.aliases).order_by(schema.aliases.c.source).limit(limit)
        if domain_id is not None:
            stmt = stmt.where(schema.aliases.c.domain_id == str(domain_id))
        rows = await self._conn.execute(stmt)
        return [Alias.model_validate(r._mapping) for r in rows]

    async def resolve(self, ref: str, domain_id: UUID | None = None) -> Alias:
        table = schema.aliases
        if (as_uuid := _as_uuid(ref)) is not None:
            row = (
                await self._conn.execute(select(table).where(table.c.id == str(as_uuid)))
            ).first()
            if row is None:
                raise NotFoundError("alias", ref)
            return Alias.model_validate(row._mapping)

        source = ref.strip().lower().split("@", 1)[0]
        stmt = select(table).where(table.c.source == source)
        if domain_id is not None:
            stmt = stmt.where(table.c.domain_id == str(domain_id))
        rows = (await self._conn.execute(stmt)).fetchall()
        if not rows:
            raise NotFoundError("alias", ref, "try `lightr alias list`")
        if len(rows) > 1:
            raise AmbiguousReferenceError(
                "alias", ref, [str(r._mapping["id"]) for r in rows]
            )
        return Alias.model_validate(rows[0]._mapping)

    async def lookup(self, domain_id: UUID, source: str) -> Alias | None:
        """Delivery-path lookup: exact, active aliases only."""
        row = (
            await self._conn.execute(
                select(schema.aliases).where(
                    schema.aliases.c.domain_id == str(domain_id),
                    schema.aliases.c.source == source.lower(),
                    schema.aliases.c.is_active.is_(True),
                )
            )
        ).first()
        return Alias.model_validate(row._mapping) if row else None

    async def update(self, alias: Alias) -> None:
        await self._conn.execute(
            update(schema.aliases)
            .where(schema.aliases.c.id == str(alias.id))
            .values(
                source=alias.source,
                destinations=_json_list(alias.destinations),
                type=str(alias.type),
                is_active=alias.is_active,
                updated_at=_now(),
            )
        )

    async def delete(self, alias_id: UUID) -> None:
        await self._conn.execute(
            delete(schema.aliases).where(schema.aliases.c.id == str(alias_id))
        )


__all__ = [
    "AccountRepo",
    "AliasRepo",
    "AmbiguousReferenceError",
    "ConflictError",
    "DomainRepo",
    "NotFoundError",
    "OrganizationRepo",
]
