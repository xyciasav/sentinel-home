"""Add persistent application anomalies and alert acknowledgment."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0034"
down_revision: str | None = "20260811_0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "application_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "integration_id",
            sa.Uuid(),
            sa.ForeignKey("application_integrations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_application_events_integration_id", "application_events", ["integration_id"]
    )
    op.create_index("ix_application_events_occurred_at", "application_events", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_application_events_occurred_at", table_name="application_events")
    op.drop_index("ix_application_events_integration_id", table_name="application_events")
    op.drop_table("application_events")
