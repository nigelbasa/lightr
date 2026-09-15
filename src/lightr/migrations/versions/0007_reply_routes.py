"""Reply routes for every forward, not only bridges

``alias_reply_routes`` existed since the Go engine and nothing in this
engine read or wrote it. It now backs two things: the Reply-To token on
a bridged copy, and the envelope sender of every forward -- which has
to be an address on our own domain or the forward fails SPF at its
destination.

A plain forward has no mailbox, so ``account_id`` becomes nullable.
``domain_id`` says which domain the token address is on, ``kind`` says
whether replies are relayed or only bounces are expected, and the index
on ``created_at`` is what the expiry sweep uses.

On a fresh database 0001 already built the table this way, so each
change checks first.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "alias_reply_routes"
INDEX = "idx_alias_reply_routes_created"


def _inspect() -> sa.engine.reflection.Inspector:
    return sa.inspect(op.get_bind())


def upgrade() -> None:
    inspector = _inspect()
    if TABLE not in inspector.get_table_names():
        return
    columns = {c["name"]: c for c in inspector.get_columns(TABLE)}

    if "domain_id" not in columns:
        op.add_column(TABLE, sa.Column("domain_id", sa.String(36), nullable=True))
    if "kind" not in columns:
        op.add_column(
            TABLE,
            sa.Column("kind", sa.Text(), nullable=False, server_default="bridge"),
        )
    if "account_id" in columns and not columns["account_id"].get("nullable", True):
        # SQLite cannot relax NOT NULL in place; batch mode rebuilds the
        # table, which is fine for a table this small.
        with op.batch_alter_table(TABLE) as batch:
            batch.alter_column(
                "account_id",
                existing_type=columns["account_id"]["type"],
                nullable=True,
            )

    indexes = {i["name"] for i in _inspect().get_indexes(TABLE)}
    if INDEX not in indexes:
        op.create_index(INDEX, TABLE, ["created_at"])


def downgrade() -> None:
    inspector = _inspect()
    if TABLE not in inspector.get_table_names():
        return
    indexes = {i["name"] for i in inspector.get_indexes(TABLE)}
    if INDEX in indexes:
        op.drop_index(INDEX, table_name=TABLE)
    columns = {c["name"] for c in inspector.get_columns(TABLE)}
    with op.batch_alter_table(TABLE) as batch:
        for name in ("kind", "domain_id"):
            if name in columns:
                batch.drop_column(name)
