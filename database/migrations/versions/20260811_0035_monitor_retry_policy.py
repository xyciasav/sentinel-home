"""Add configurable service failure confirmation."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0035"
down_revision: str | None = "20260811_0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "service_monitors",
        sa.Column("failure_threshold", sa.Integer(), nullable=False, server_default="3"),
    )
    op.add_column(
        "service_monitors",
        sa.Column("retry_interval_seconds", sa.Integer(), nullable=False, server_default="60"),
    )
    op.add_column(
        "service_monitors",
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("service_monitors", sa.Column("next_retry_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("service_monitors", "next_retry_at")
    op.drop_column("service_monitors", "consecutive_failures")
    op.drop_column("service_monitors", "retry_interval_seconds")
    op.drop_column("service_monitors", "failure_threshold")
