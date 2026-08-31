"""Dovecot migration

Adds the columns the Dovecot handover needs, and retires the tables
Dovecot now owns.

On a fresh install 0001 already created these columns, so each change
checks first. On a database written by the Go engine the tables existed
before 0001 ran, so ``checkfirst`` skipped them and the columns really
are missing -- this is where they get added.

The retired tables are *not* dropped. ``messages``, ``encryption_keys``,
and ``encrypted_messages`` may hold data an operator still needs to
migrate into Dovecot (see docs/PYTHON-REWRITE.md section 2). Dropping
them here would destroy the only copy. ``lightr data migrate-store``
removes them once their contents are safely in Maildir.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_COLUMNS: list[tuple[str, sa.Column]] = [
    ("accounts", sa.Column("maildir_path", sa.Text(), nullable=True)),
    ("filter_rules", sa.Column("sieve_generated_at", sa.DateTime(), nullable=True)),
]


def _existing_columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    for table, column in NEW_COLUMNS:
        if column.name not in _existing_columns(table):
            op.add_column(table, column)


def downgrade() -> None:
    for table, column in NEW_COLUMNS:
        if column.name in _existing_columns(table):
            with op.batch_alter_table(table) as batch:
                batch.drop_column(column.name)
