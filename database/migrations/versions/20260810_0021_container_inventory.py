"""Add read-only container inventory."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0021"
down_revision: str | None = "20260810_0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "container_instances",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "agent_id",
            sa.Uuid(),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("container_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("image", sa.String(500), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("health", sa.String(30)),
        sa.Column("status", sa.String(500), nullable=False),
        sa.Column("ports", sa.String(1000), nullable=False, server_default=""),
        sa.Column("restart_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_container_instances_agent_container",
        "container_instances",
        ["agent_id", "container_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_container_instances_agent_container", table_name="container_instances")
    op.drop_table("container_instances")
