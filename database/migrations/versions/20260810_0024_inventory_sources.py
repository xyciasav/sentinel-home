"""Add external inventory sources and staged devices."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0024"
down_revision: str | None = "20260810_0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "inventory_sources",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("base_url", sa.String(500), nullable=False),
        sa.Column("credential_encrypted", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_sync_status", sa.String(30), nullable=False, server_default="never"),
        sa.Column("last_sync_error", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "source_devices",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "source_id",
            sa.Uuid(),
            sa.ForeignKey("inventory_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("address", sa.String(45)),
        sa.Column("mac_address", sa.String(30)),
        sa.Column("manufacturer", sa.String(100)),
        sa.Column("model", sa.String(100)),
        sa.Column("area_name", sa.String(100)),
        sa.Column(
            "imported_device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="SET NULL")
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_source_devices_source_external",
        "source_devices",
        ["source_id", "external_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_source_devices_source_external", table_name="source_devices")
    op.drop_table("source_devices")
    op.drop_table("inventory_sources")
