"""Block sending and receiving separately

`auth_mode = disabled` stops an account logging in, sending and
receiving all at once. That is the wrong tool for the two situations
that actually come up: a compromised account that has to stop sending
while its owner logs in to change the password, and a mailbox that
should stop accepting new mail while someone reads what is already
there.

Both default to true, so every existing account behaves exactly as it
did.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_COLUMNS: list[tuple[str, sa.Column]] = [
    (
        "accounts",
        sa.Column("can_send", sa.Boolean(), nullable=False, server_default=sa.true()),
    ),
    (
        "accounts",
        sa.Column(
            "can_receive", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    ),
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
