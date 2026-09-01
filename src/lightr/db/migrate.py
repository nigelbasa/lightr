"""Running Alembic migrations from inside the application.

``lightr migrate`` and the test-suite both come through here rather
than shelling out to the ``alembic`` CLI, so migrations always target
the database the running config points at.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from lightr.config import Config

# Inside the package, not beside it: a wheel only ships what is under
# the package directory, and `pip install lightr && lightr migrate`
# has to work.
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def alembic_config(cfg: Config) -> AlembicConfig:
    """Build an Alembic config bound to this install's database."""
    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    alembic_cfg.set_main_option("sqlalchemy.url", cfg.database_url)
    # env.py reads the config back out of here rather than re-loading
    # from disk, so an in-memory config (tests) works too.
    alembic_cfg.attributes["lightr_config"] = cfg
    return alembic_cfg


def upgrade(cfg: Config, revision: str = "head") -> None:
    """Apply migrations up to ``revision``.

    Runs in a worker thread: Alembic's env.py calls ``asyncio.run``,
    which cannot nest inside an already-running event loop.
    """
    command.upgrade(alembic_config(cfg), revision)


def downgrade(cfg: Config, revision: str) -> None:
    command.downgrade(alembic_config(cfg), revision)


async def upgrade_async(cfg: Config, revision: str = "head") -> None:
    """Await an upgrade from inside a running event loop."""
    await asyncio.to_thread(upgrade, cfg, revision)


def head_revision(cfg: Config) -> str | None:
    """The newest revision the code knows about."""
    return ScriptDirectory.from_config(alembic_config(cfg)).get_current_head()


def current_revision(cfg: Config) -> str | None:
    """The revision the database is stamped at, or None if unmanaged."""
    from sqlalchemy import create_engine as create_sync_engine

    url = cfg.database_url.replace("+aiosqlite", "").replace("+asyncpg", "")
    engine = create_sync_engine(url)
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()


def is_up_to_date(cfg: Config) -> bool:
    return current_revision(cfg) == head_revision(cfg)
