"""Add safe manual network discovery results."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0008"
down_revision: str | None = "20260810_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "discovery_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("subnet", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("hosts_checked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "discovered_hosts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "run_id",
            sa.Uuid(),
            sa.ForeignKey("discovery_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("address", sa.String(45), nullable=False),
        sa.Column("open_ports", sa.String(200), nullable=False),
        sa.Column("state", sa.String(20), nullable=False, server_default="new"),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_discovered_hosts_run_id", "discovered_hosts", ["run_id"])
    op.create_index(
        "ix_discovered_hosts_run_address", "discovered_hosts", ["run_id", "address"], unique=True
    )


def downgrade() -> None:
    op.drop_table("discovered_hosts")
    op.drop_table("discovery_runs")
