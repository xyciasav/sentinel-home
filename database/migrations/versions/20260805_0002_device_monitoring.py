"""Add lightweight TCP reachability state to devices."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260805_0002"
down_revision: str | None = "20260805_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("monitor_port", sa.Integer()))
    op.add_column(
        "devices", sa.Column("status", sa.String(20), nullable=False, server_default="unknown")
    )
    op.add_column("devices", sa.Column("last_checked_at", sa.DateTime(timezone=True)))
    op.add_column("devices", sa.Column("last_latency_ms", sa.Integer()))
    op.add_column("devices", sa.Column("last_failure_reason", sa.String(100)))


def downgrade() -> None:
    op.drop_column("devices", "last_failure_reason")
    op.drop_column("devices", "last_latency_ms")
    op.drop_column("devices", "last_checked_at")
    op.drop_column("devices", "status")
    op.drop_column("devices", "monitor_port")
