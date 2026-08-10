"""Add HTTP service monitors and result history."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0003"
down_revision: str | None = "20260805_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_monitors",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("expected_status", sa.Integer(), nullable=False, server_default="200"),
        sa.Column("expected_text", sa.String(500)),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("severity", sa.String(20), nullable=False, server_default="normal"),
        sa.Column("status", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("outage_started_at", sa.DateTime(timezone=True)),
        sa.Column("last_response_ms", sa.Integer()),
        sa.Column("last_status_code", sa.Integer()),
        sa.Column("last_failure_reason", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_service_monitors_device_id", "service_monitors", ["device_id"])
    op.create_table(
        "monitor_results",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "monitor_id",
            sa.Uuid(),
            sa.ForeignKey("service_monitors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("response_ms", sa.Integer()),
        sa.Column("status_code", sa.Integer()),
        sa.Column("failure_reason", sa.String(500)),
    )
    op.create_index(
        "ix_monitor_results_monitor_checked", "monitor_results", ["monitor_id", "checked_at"]
    )


def downgrade() -> None:
    op.drop_table("monitor_results")
    op.drop_index("ix_service_monitors_device_id", table_name="service_monitors")
    op.drop_table("service_monitors")
