"""Add persistent network identity activity."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0028"
down_revision: str | None = "20260811_0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "network_identity_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "source_id", sa.Uuid(), sa.ForeignKey("inventory_sources.id", ondelete="SET NULL")
        ),
        sa.Column(
            "source_device_id", sa.Uuid(), sa.ForeignKey("source_devices.id", ondelete="SET NULL")
        ),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("old_value", sa.String(255)),
        sa.Column("new_value", sa.String(255)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_network_identity_events_occurred", "network_identity_events", ["occurred_at"]
    )
    op.create_index(
        "ix_network_identity_events_source_id", "network_identity_events", ["source_id"]
    )
    op.create_index(
        "ix_network_identity_events_source_device_id",
        "network_identity_events",
        ["source_device_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_network_identity_events_source_device_id", table_name="network_identity_events"
    )
    op.drop_index("ix_network_identity_events_source_id", table_name="network_identity_events")
    op.drop_index("ix_network_identity_events_occurred", table_name="network_identity_events")
    op.drop_table("network_identity_events")
