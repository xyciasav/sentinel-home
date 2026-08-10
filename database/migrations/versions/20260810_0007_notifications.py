"""Add notification delivery history."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0007"
down_revision: str | None = "20260810_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id", ondelete="SET NULL")),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("recipient", sa.String(320)),
        sa.Column("subject", sa.String(300), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("provider_id", sa.String(100)),
        sa.Column("error", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_notification_deliveries_incident_id", "notification_deliveries", ["incident_id"]
    )
    op.create_index(
        "ix_notification_deliveries_created_at", "notification_deliveries", ["created_at"]
    )


def downgrade() -> None:
    op.drop_table("notification_deliveries")
