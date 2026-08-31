"""Compatibility with databases written by the Go engine.

This is the phase-1 gate. The Go binary can no longer be built, so
compatibility is proven against its verbatim DDL (tests/fixtures/
go_schema.sql) rather than against a running process.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.db import schema
from lightr.db.engine import create_all, ping, table_names

# Tables the Go engine created that Lightr no longer models.
RETIRED_TABLES = {"messages", "encryption_keys", "encrypted_messages"}


async def test_python_schema_creates_cleanly(engine: AsyncEngine) -> None:
    present = await table_names(engine)
    assert schema.metadata.tables.keys() <= present


async def test_retired_tables_are_not_created(engine: AsyncEngine) -> None:
    present = await table_names(engine)
    assert not (present & RETIRED_TABLES)


async def test_engine_answers_ping(engine: AsyncEngine) -> None:
    assert await ping(engine) is True


class TestGoWrittenDatabase:
    """Open a database the Go engine created and use it."""

    async def test_every_modelled_table_exists(self, go_engine: AsyncEngine) -> None:
        present = await table_names(go_engine)
        missing = set(schema.metadata.tables) - present
        assert missing == set(), f"Python models tables the Go schema lacks: {sorted(missing)}"

    async def test_retired_tables_are_tolerated(self, go_engine: AsyncEngine) -> None:
        """Their presence must not break anything -- we just ignore them."""
        present = await table_names(go_engine)
        assert RETIRED_TABLES & present
        assert await ping(go_engine) is True

    async def test_create_all_is_idempotent_over_go_schema(
        self, go_engine: AsyncEngine
    ) -> None:
        """Running create_all on a Go database must not error or clobber."""
        await create_all(go_engine)
        present = await table_names(go_engine)
        assert "organizations" in present
        assert RETIRED_TABLES & present  # still there, untouched

    async def test_tenancy_round_trip(self, go_engine: AsyncEngine) -> None:
        """Write through the Python schema, read it back."""
        org_id, domain_id, account_id = str(uuid4()), str(uuid4()), str(uuid4())
        now = datetime.now(UTC).replace(tzinfo=None)

        async with go_engine.begin() as conn:
            await conn.execute(
                insert(schema.organizations).values(id=org_id, name="Acme Ltd", created_at=now)
            )
            await conn.execute(
                insert(schema.domains).values(
                    id=domain_id,
                    org_id=org_id,
                    name="acme.test",
                    mail_hostname="mail.acme.test",
                    dkim_selector="default",
                    spam_policy="junk",
                    is_verified=True,
                    created_at=now,
                )
            )
            await conn.execute(
                insert(schema.accounts).values(
                    id=account_id,
                    domain_id=domain_id,
                    local_part="ops",
                    display_name="Operations",
                    auth_mode="native",
                    password_hash="$2b$12$notarealhash",
                    quota_bytes=1024 * 1024 * 1024,
                    created_at=now,
                )
            )

        async with go_engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        schema.accounts.c.local_part,
                        schema.domains.c.name,
                        schema.organizations.c.name.label("org_name"),
                        schema.domains.c.is_verified,
                    )
                    .select_from(
                        schema.accounts.join(schema.domains).join(schema.organizations)
                    )
                    .where(schema.accounts.c.id == account_id)
                )
            ).one()

        assert row.local_part == "ops"
        assert row.name == "acme.test"
        assert row.org_name == "Acme Ltd"
        assert row.is_verified is True

    async def test_new_dovecot_columns_are_absent_on_go_databases(
        self, go_engine: AsyncEngine
    ) -> None:
        """maildir_path and sieve_generated_at need an Alembic migration.

        The Go schema predates them, so selecting them must fail until
        the migration runs. This test documents the gap rather than
        pretending it isn't there.
        """
        with pytest.raises(Exception, match="maildir_path"):
            async with go_engine.connect() as conn:
                await conn.execute(select(schema.accounts.c.maildir_path))


class TestSQLitePragmas:
    async def test_foreign_keys_are_enforced(self, engine: AsyncEngine) -> None:
        """SQLite defaults foreign keys to OFF; we turn them on."""
        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    insert(schema.domains).values(
                        id=str(uuid4()), org_id="no-such-org", name="orphan.test"
                    )
                )

    async def test_wal_is_enabled(self, engine: AsyncEngine) -> None:
        from sqlalchemy import text

        async with engine.connect() as conn:
            mode = (await conn.execute(text("PRAGMA journal_mode"))).scalar()
        assert mode == "wal"
