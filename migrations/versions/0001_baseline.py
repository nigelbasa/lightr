"""Baseline schema

Creates every table Lightr owns. Uses ``checkfirst`` so it is safe to
run against a database the Go engine already populated -- adopting an
existing install and provisioning a fresh one follow the same linear
history, with no ``alembic stamp`` step for operators to get wrong.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from lightr.db.schema import metadata

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    metadata.drop_all(bind=bind, checkfirst=True)
