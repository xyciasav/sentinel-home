"""Track container lifecycle and health events."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0031"
down_revision: str | None = "20260811_0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "container_instances",
        sa.Column("present", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.create_table(
        "container_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "agent_id", sa.Uuid(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("container_id", sa.String(64), nullable=False),
        sa.Column("container_name", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_container_events_agent_id", "container_events", ["agent_id"])
    op.create_index("ix_container_events_occurred_at", "container_events", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_container_events_occurred_at", table_name="container_events")
    op.drop_index("ix_container_events_agent_id", table_name="container_events")
    op.drop_table("container_events")
    op.drop_column("container_instances", "present")
