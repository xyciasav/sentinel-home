"""Add Linux agent enrollment, metrics, and package inventory."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0014"
down_revision: str | None = "20260810_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_enrollments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_enrollments_device_id", "agent_enrollments", ["device_id"])
    op.create_table(
        "agent_metrics",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "agent_id", sa.Uuid(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("cpu_percent", sa.Integer(), nullable=False),
        sa.Column("memory_percent", sa.Integer(), nullable=False),
        sa.Column("memory_used_bytes", sa.BigInteger(), nullable=False),
        sa.Column("memory_total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("disk_percent", sa.Integer(), nullable=False),
        sa.Column("disk_free_bytes", sa.BigInteger(), nullable=False),
        sa.Column("disk_total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("uptime_seconds", sa.BigInteger(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_agent_metrics_agent_collected", "agent_metrics", ["agent_id", "collected_at"]
    )
    op.create_table(
        "installed_packages",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "agent_id", sa.Uuid(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("architecture", sa.String(50)),
        sa.Column("manager", sa.String(30), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_installed_packages_agent_name", "installed_packages", ["agent_id", "name"], unique=True
    )


def downgrade() -> None:
    op.drop_table("installed_packages")
    op.drop_table("agent_metrics")
    op.drop_table("agent_enrollments")
