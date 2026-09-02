"""Running Alembic migrations from inside the application.

``lightr migrate`` and the test-suite both come through here rather
than shelling out to the ``alembic`` CLI, so migrations always target
the database the running config points at.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

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


def _run_coro(coro: Any) -> Any:
    """Run a coroutine whether or not a loop is already running.

    ``current_revision`` is called from both -- ``lightr migrate`` is
    synchronous, ``lightr status`` asks from inside its own event loop
    -- and ``asyncio.run`` refuses the second case. A worker thread
    gets its own loop, which is the only way to serve both without
    making every caller async.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


async def _current_revision(cfg: Config) -> str | None:
    from lightr.db.engine import create_engine

    engine = create_engine(cfg)
    try:
        async with engine.connect() as conn:
            return await conn.run_sync(
                lambda sync_conn: MigrationContext.configure(
                    sync_conn
                ).get_current_revision()
            )
    finally:
        await engine.dispose()


def current_revision(cfg: Config) -> str | None:
    """The revision the database is stamped at, or None if unmanaged.

    Goes through the async driver rather than stripping ``+asyncpg``
    off the URL and building a synchronous engine. That strip left a
    bare ``postgresql://``, which SQLAlchemy resolves to psycopg2 -- a
    driver Lightr does not depend on and does not install, so every
    Postgres install failed here with ModuleNotFoundError.
    """
    return _run_coro(_current_revision(cfg))


def is_up_to_date(cfg: Config) -> bool:
    return current_revision(cfg) == head_revision(cfg)
