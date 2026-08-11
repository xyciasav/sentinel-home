"""Add recurring maintenance windows and expected incidents."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0029"
down_revision: str | None = "20260811_0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "incidents", sa.Column("expected", sa.Boolean(), nullable=False, server_default="false")
    )
    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="CASCADE")),
        sa.Column(
            "monitor_id", sa.Uuid(), sa.ForeignKey("service_monitors.id", ondelete="CASCADE")
        ),
        sa.Column("day_of_week", sa.Integer()),
        sa.Column("time_of_day", sa.String(5), nullable=False),
        sa.Column("duration_minutes", sa.Integer(), nullable=False),
        sa.Column("timezone", sa.String(100), nullable=False),
        sa.Column("suppress_notifications", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_maintenance_windows_device_id", "maintenance_windows", ["device_id"])
    op.create_index("ix_maintenance_windows_monitor_id", "maintenance_windows", ["monitor_id"])


def downgrade() -> None:
    op.drop_index("ix_maintenance_windows_monitor_id", table_name="maintenance_windows")
    op.drop_index("ix_maintenance_windows_device_id", table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
    op.drop_column("incidents", "expected")
