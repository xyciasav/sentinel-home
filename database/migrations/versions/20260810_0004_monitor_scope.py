"""Distinguish internal and external service checks."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0004"
down_revision: str | None = "20260810_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "service_monitors",
        sa.Column("target_scope", sa.String(20), nullable=False, server_default="internal"),
    )


def downgrade() -> None:
    op.drop_column("service_monitors", "target_scope")
