"""Add native application integrations and snapshots."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0032"
down_revision: str | None = "20260811_0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "application_integrations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("base_url", sa.String(500), nullable=False),
        sa.Column("credential_encrypted", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_sync_status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("last_sync_error", sa.String(500)),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "application_snapshots",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "integration_id",
            sa.Uuid(),
            sa.ForeignKey("application_integrations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.String(100)),
        sa.Column("queue_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("item_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("disk_free_bytes", sa.BigInteger()),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_application_snapshots_integration_time",
        "application_snapshots",
        ["integration_id", "collected_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_application_snapshots_integration_time", table_name="application_snapshots")
    op.drop_table("application_snapshots")
    op.drop_table("application_integrations")
