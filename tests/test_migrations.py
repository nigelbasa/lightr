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
        assert migrate.current_revision(cfg) == migrate.head_revision(cfg) == "0002"


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

    def test_retired_tables_are_left_alone(self, go_db: Config) -> None:
        """Their contents may be the only copy -- never drop them here."""
        migrate.upgrade(go_db)

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
