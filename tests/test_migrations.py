"""Migration paths: fresh install, and adopting a Go-written database."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa

from lightr.config import Config
from lightr.db import migrate


def _columns(db_path: Path, table: str) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def _tables(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        conn.close()


@pytest.fixture
def go_db(tmp_path: Path, go_ddl: str) -> Config:
    """A config pointing at a database the Go engine would have written."""
    cfg = Config.model_validate({"data_dir": str(tmp_path)})
    assert cfg.database.path is not None
    conn = sqlite3.connect(cfg.database.path)
    try:
        conn.executescript(go_ddl)
        # Seed a row so we can prove the migration preserves data.
        conn.execute(
            "INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)",
            (str(uuid4()), "Acme Ltd", datetime.now(UTC).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    return cfg


class TestFreshInstall:
    def test_upgrade_creates_the_full_schema(self, cfg: Config) -> None:
        migrate.upgrade(cfg)

        assert cfg.database.path is not None
        tables = _tables(cfg.database.path)
        assert {"organizations", "domains", "accounts", "aliases", "api_keys"} <= tables
        assert "maildir_path" in _columns(cfg.database.path, "accounts")

    def test_upgrade_is_idempotent(self, cfg: Config) -> None:
        migrate.upgrade(cfg)
        migrate.upgrade(cfg)  # must not raise

        assert migrate.is_up_to_date(cfg)

    def test_reports_head_revision(self, cfg: Config) -> None:
        migrate.upgrade(cfg)
        assert migrate.current_revision(cfg) == migrate.head_revision(cfg)


class TestAdoptingAGoDatabase:
    """The upgrade path for an existing v0.1.0 install."""

    def test_dovecot_columns_are_added(self, go_db: Config) -> None:
        assert go_db.database.path is not None
        assert "maildir_path" not in _columns(go_db.database.path, "accounts")

        migrate.upgrade(go_db)

        assert "maildir_path" in _columns(go_db.database.path, "accounts")
        assert "sieve_generated_at" in _columns(go_db.database.path, "filter_rules")

    def test_existing_data_survives(self, go_db: Config) -> None:
        migrate.upgrade(go_db)

        assert go_db.database.path is not None
        conn = sqlite3.connect(go_db.database.path)
        try:
            names = [r[0] for r in conn.execute("SELECT name FROM organizations")]
        finally:
            conn.close()
        assert names == ["Acme Ltd"]

    def test_0002_leaves_the_retired_tables_alone(self, go_db: Config) -> None:
        """Adopting a Go database must not destroy anything.

        0002 preserves messages and encryption_keys because at that
        point they might have been the only copy. 0003 drops them, once
        that question was answered -- so the safety is in the ordering:
        an operator can stop at 0002, take a backup, and go on.
        """
        migrate.upgrade(go_db, "0002")

        assert go_db.database.path is not None
        tables = _tables(go_db.database.path)
        assert {"messages", "encryption_keys"} <= tables

    def test_engine_can_use_the_migrated_database(self, go_db: Config) -> None:
        migrate.upgrade(go_db)

        url = go_db.database_url.replace("+aiosqlite", "")
        engine = sa.create_engine(url)
        try:
            with engine.connect() as conn:
                from lightr.db import schema

                conn.execute(sa.select(schema.accounts.c.maildir_path))
        finally:
            engine.dispose()


class TestAsyncEntryPoint:
    async def test_upgrade_async_works_inside_a_loop(self, cfg: Config) -> None:
        await migrate.upgrade_async(cfg)
        assert migrate.is_up_to_date(cfg)

    async def test_current_revision_works_inside_a_loop(self, cfg: Config) -> None:
        """`lightr status` asks from inside its own event loop, and
        `lightr migrate` asks from outside one. Both have to work."""
        await migrate.upgrade_async(cfg)

        assert migrate.current_revision(cfg) == migrate.head_revision(cfg)

    def test_current_revision_works_outside_a_loop(self, cfg: Config) -> None:
        migrate.upgrade(cfg)

        assert migrate.current_revision(cfg) == migrate.head_revision(cfg)

    def test_it_never_builds_a_synchronous_engine(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It used to strip `+asyncpg` off the URL and build a sync
        engine, which SQLAlchemy resolves to psycopg2 -- a driver
        Lightr neither depends on nor installs. Every Postgres install
        failed with ModuleNotFoundError at the first `lightr migrate`.

        SQLite hid it, because its synchronous driver is in the stdlib
        and is always importable. So the test is not "does it work" but
        "does it reach for the synchronous path at all".
        """
        migrate.upgrade(cfg)

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("built a synchronous engine")

        monkeypatch.setattr(sa, "create_engine", forbidden)

        assert migrate.current_revision(cfg) == migrate.head_revision(cfg)


class TestRetiredTables:
    """0003 drops what Dovecot now owns.

    0002 deliberately left these in place because they could have held
    the only copy of something. That question is answered: the old
    encrypted mail is not wanted.
    """

    def test_a_go_database_loses_them(self, go_db: Config) -> None:
        assert go_db.database.path is not None
        before = _tables(go_db.database.path)
        assert {"messages", "encryption_keys"} <= before

        migrate.upgrade(go_db)

        after = _tables(go_db.database.path)
        assert not ({"messages", "encryption_keys", "encrypted_messages"} & after)

    def test_the_tables_lightr_owns_survive(self, go_db: Config) -> None:
        migrate.upgrade(go_db)

        assert go_db.database.path is not None
        tables = _tables(go_db.database.path)
        assert {"organizations", "domains", "accounts", "aliases", "api_keys"} <= tables

    def test_data_in_the_surviving_tables_is_untouched(self, go_db: Config) -> None:
        migrate.upgrade(go_db)

        assert go_db.database.path is not None
        conn = sqlite3.connect(go_db.database.path)
        try:
            assert [r[0] for r in conn.execute("SELECT name FROM organizations")] == [
                "Acme Ltd"
            ]
        finally:
            conn.close()

    def test_a_fresh_install_never_creates_them(self, cfg: Config) -> None:
        migrate.upgrade(cfg)

        assert cfg.database.path is not None
        assert not ({"messages", "encryption_keys"} & _tables(cfg.database.path))

    def test_head_is_0006(self, cfg: Config) -> None:
        migrate.upgrade(cfg)
        assert migrate.current_revision(cfg) == migrate.head_revision(cfg) == "0006"

    def test_downgrade_recreates_them_empty(self, go_db: Config) -> None:
        """Reversible in structure only -- the contents are gone, and
        the docstring on 0003 says so."""
        migrate.upgrade(go_db)
        migrate.downgrade(go_db, "0002")

        assert go_db.database.path is not None
        assert "messages" in _tables(go_db.database.path)


class TestByteCounts:
    """A 2 GB quota is one past the top of a signed 32-bit column.

    SQLite stores it regardless -- its INTEGER is already 64-bit and its
    typing is dynamic -- so the narrow column only ever failed on
    Postgres, partway through migrating real data.
    """

    def test_a_two_gigabyte_quota_survives(self, cfg: Config) -> None:
        migrate.upgrade(cfg)

        assert cfg.database.path is not None
        conn = sqlite3.connect(cfg.database.path)
        try:
            conn.execute(
                "insert into organizations (id, name) values ('o', 'Acme')"
            )
            conn.execute(
                "insert into domains (id, org_id, name) values ('d', 'o', 'acme.test')"
            )
            conn.execute(
                "insert into accounts (id, domain_id, local_part, auth_mode, "
                "quota_bytes) values ('a', 'd', 'ops', 'native', ?)",
                (2 * 1024**3,),
            )
            conn.commit()
            stored = conn.execute(
                "select quota_bytes from accounts where id='a'"
            ).fetchone()[0]
        finally:
            conn.close()

        assert stored == 2147483648

    def test_the_column_is_declared_wide(self) -> None:
        """The declaration is what Postgres reads; SQLite ignores it."""
        import sqlalchemy as sa

        from lightr.db import schema

        for column in ("quota_bytes", "used_bytes"):
            assert isinstance(schema.accounts.c[column].type, sa.BigInteger), column
