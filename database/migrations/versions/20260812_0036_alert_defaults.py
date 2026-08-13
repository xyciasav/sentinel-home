"""Add global service alert defaults."""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "20260812_0036"
down_revision: str | None = "20260811_0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    table = op.create_table(
        "alert_defaults",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("failure_threshold", sa.Integer(), nullable=False, server_default="3"),
        sa.Column(
            "retry_interval_seconds", sa.Integer(), nullable=False, server_default="60"
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.bulk_insert(
        table,
        [
            {
                "id": 1,
                "failure_threshold": 3,
                "retry_interval_seconds": 60,
                "updated_at": datetime.now(UTC),
            }
        ],
    )


def downgrade() -> None:
    op.drop_table("alert_defaults")
