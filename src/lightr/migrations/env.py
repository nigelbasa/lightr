"""Alembic environment.

The database URL comes from Lightr's own config rather than
alembic.ini, so migrations always target the same database the engine
uses. Pass -x config=<path> to migrate a different install.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config
from lightr.db.engine import create_engine
from lightr.db.schema import metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = metadata


def _lightr_config() -> Config:
    """The config to migrate against.

    Prefers one handed in programmatically (lightr.db.migrate), so tests
    and `lightr migrate` target the running install rather than
    whatever /etc/lightr/config.yaml happens to say.
    """
    injected = config.attributes.get("lightr_config")
    if isinstance(injected, Config):
        return injected
    return Config.load(context.get_x_argument(as_dictionary=True).get("config"))


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it."""
    cfg = _lightr_config()
    context.configure(
        url=cfg.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: object) -> None:
    context.configure(
        connection=connection,  # type: ignore[arg-type]
        target_metadata=target_metadata,
        # SQLite cannot ALTER most things in place; batch mode rewrites
        # the table instead. Harmless on Postgres.
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    cfg = _lightr_config()
    engine: AsyncEngine = create_engine(cfg)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_do_run_migrations)
            await connection.commit()
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
