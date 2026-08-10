"""Track observed port changes."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0009"
down_revision: str | None = "20260810_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "network_changes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("address", sa.String(45), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("service", sa.String(100)),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_network_changes_device_id", "network_changes", ["device_id"])
    op.create_index("ix_network_changes_detected_at", "network_changes", ["detected_at"])


def downgrade() -> None:
    op.drop_table("network_changes")
