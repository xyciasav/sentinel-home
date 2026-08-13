"""source device custom names

Revision ID: 20260813_0038
Revises: 20260812_0037
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260813_0038"
down_revision: str | None = "20260812_0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("source_devices", sa.Column("custom_name", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("source_devices", "custom_name")
