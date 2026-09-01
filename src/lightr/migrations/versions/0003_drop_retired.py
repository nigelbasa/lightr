"""Drop the tables Dovecot now owns

0002 deliberately left these in place because they could have held the
only copy of data an operator still needed. That question is now
answered: the encrypted mail from the Go engine is not wanted, so the
tables go.

* ``messages`` -- Dovecot owns the message store. The mailbox API and
  CLI read through IMAP, so nothing queries this any more.
* ``encryption_keys`` / ``encrypted_messages`` -- replaced by Dovecot's
  ``mail_crypt`` plugin.

This is destructive and deliberately not reversible in any useful
sense: ``downgrade`` recreates the tables, but not their contents.
Anyone who needs the old data should take it from a backup, or from
the ``archive/go-engine`` branch's engine.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RETIRED = ("encrypted_messages", "encryption_keys", "messages")


def _existing() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    present = _existing()
    for table in RETIRED:
        if table in present:
            op.drop_table(table)


def downgrade() -> None:
    """Recreate the tables, empty.

    The Go engine's schema is preserved in
    tests/fixtures/go_schema.sql if the full column set is ever needed;
    this restores only enough for the tables to exist again.
    """
    present = _existing()

    if "messages" not in present:
        op.create_table(
            "messages",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("account_id", sa.String(36), nullable=False),
            sa.Column("folder", sa.Text()),
            sa.Column("size_bytes", sa.Integer()),
            sa.Column("storage_path", sa.Text()),
            sa.Column("subject", sa.Text()),
            sa.Column("from", sa.Text()),
            sa.Column("to", sa.Text()),
            sa.Column("received_at", sa.DateTime()),
            sa.Column("read_at", sa.DateTime()),
            sa.Column("deleted_at", sa.DateTime()),
        )

    if "encryption_keys" not in present:
        op.create_table(
            "encryption_keys",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("account_id", sa.String(36), nullable=False),
            sa.Column("org_id", sa.String(36), nullable=False),
            sa.Column("type", sa.Text(), nullable=False),
            sa.Column("fingerprint", sa.Text(), nullable=False, unique=True),
            sa.Column("public_key", sa.Text(), nullable=False),
            sa.Column("private_key", sa.Text()),
            sa.Column("created_date", sa.DateTime(), nullable=False),
        )

    if "encrypted_messages" not in present:
        op.create_table(
            "encrypted_messages",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("message_id", sa.String(36), nullable=False, unique=True),
            sa.Column("encryption_type", sa.Text(), nullable=False),
            sa.Column("encrypted_body", sa.Text(), nullable=False),
            sa.Column("recipients", sa.Text(), nullable=False),
        )
