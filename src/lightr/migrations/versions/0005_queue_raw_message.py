"""Queue messages whole

The queue held a subject and a plain-text body, and the sender rebuilt
every message from those two fields. Anything a mail client submitted
lost its attachments, its HTML part and its headers on the way out, and
forwarding -- which has to pass the message on intact -- could not be
built on it at all.

``raw`` carries the message as it should leave. ``envelope_from`` is
the SMTP sender when it differs from the From header, which is what a
forward rewritten with SRS needs. Both are nullable: rows queued before
this migration still compose from subject and body.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_COLUMNS: list[tuple[str, sa.Column]] = [
    ("email_queue", sa.Column("raw", sa.LargeBinary(), nullable=True)),
    ("email_queue", sa.Column("envelope_from", sa.Text(), nullable=True)),
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
