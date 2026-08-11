"""Add network alert acknowledgment state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0030"
down_revision: str | None = "20260811_0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "network_identity_events", sa.Column("acknowledged_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "network_identity_events",
        sa.Column("acknowledged_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
    )


def downgrade() -> None:
    op.drop_column("network_identity_events", "acknowledged_by")
    op.drop_column("network_identity_events", "acknowledged_at")
