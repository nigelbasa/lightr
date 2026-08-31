"""Database engine construction and lifecycle.

One dialect abstraction for both SQLite and Postgres. The Go engine did
this by hand with a ``bind()`` helper that rewrote ``?`` into ``$n``;
SQLAlchemy Core handles it, so queries are written once.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import event, inspect, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from lightr.config import Config, DatabaseDriver
from lightr.db.schema import metadata


def create_engine(cfg: Config, *, echo: bool = False) -> AsyncEngine:
    """Build an async engine for the configured database.

    SQLite gets WAL and foreign-key enforcement, neither of which is on
    by default. Postgres needs neither.
    """
    kwargs: dict[str, Any] = {"echo": echo, "future": True}

    if cfg.database.driver is DatabaseDriver.SQLITE:
        if cfg.database.path is not None:
            cfg.database.path.parent.mkdir(parents=True, exist_ok=True)
        # SQLite writes serialise anyway; a pool adds contention, not
        # throughput. Keep the default pool but let checkouts wait.
        kwargs["connect_args"] = {"timeout": 30}
    else:
        kwargs["pool_size"] = 10
        kwargs["max_overflow"] = 20
        kwargs["pool_pre_ping"] = True

    engine = create_async_engine(cfg.database_url, **kwargs)

    if cfg.database.driver is DatabaseDriver.SQLITE:
        _apply_sqlite_pragmas(engine)

    return engine


def _apply_sqlite_pragmas(engine: AsyncEngine) -> None:
    """Enable WAL and foreign keys on every SQLite connection.

    SQLite defaults to foreign keys *off*, which would silently accept
    the orphaned rows the schema's constraints exist to prevent.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()


async def create_all(engine: AsyncEngine) -> None:
    """Create any missing tables.

    Alembic owns migrations; this exists for tests and for ``lightr
    init`` on a fresh database.
    """
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)


@asynccontextmanager
async def connection(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """A transactional connection that commits on clean exit."""
    async with engine.begin() as conn:
        yield conn


async def ping(engine: AsyncEngine) -> bool:
    """Return True if the database answers. Used by health checks."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        return False
    return True


async def table_names(engine: AsyncEngine) -> set[str]:
    """Tables actually present in the database, whatever wrote them."""
    async with engine.connect() as conn:
        return set(
            await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names())
        )


def sqlite_path_from_url(url: str) -> Path | None:
    """Extract the file path from a SQLite URL, if it is one."""
    prefix = "sqlite+aiosqlite:///"
    if url.startswith(prefix):
        return Path(url[len(prefix) :])
    return None
