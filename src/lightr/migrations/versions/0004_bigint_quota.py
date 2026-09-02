"""Widen the byte-count columns to 64 bits

A 2 GB quota is 2147483648 -- one past the top of a signed 32-bit
column. SQLite accepted it because its typing is dynamic, so this only
ever surfaced on Postgres, and then as a hard refusal partway through
a data migration.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = ("quota_bytes", "used_bytes")


def _has(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return False
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    # SQLite has no real ALTER COLUMN TYPE and does not need one -- its
    # INTEGER is already 64-bit. Only Postgres has anything to widen.
    if op.get_bind().dialect.name == "sqlite":
        return
    for column in COLUMNS:
        if _has("accounts", column):
            op.alter_column(
                "accounts", column, type_=sa.BigInteger(), existing_nullable=True
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        return
    for column in COLUMNS:
        if _has("accounts", column):
            op.alter_column(
                "accounts", column, type_=sa.Integer(), existing_nullable=True
            )
