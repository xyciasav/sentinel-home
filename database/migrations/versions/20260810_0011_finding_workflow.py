"""Add KEV enrichment and vulnerability workflow fields."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0011"
down_revision: str | None = "20260810_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "vulnerability_findings",
        sa.Column("known_exploited", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("vulnerability_findings", sa.Column("required_action", sa.Text()))
    op.add_column("vulnerability_findings", sa.Column("action_due", sa.String(20)))
    op.add_column("vulnerability_findings", sa.Column("user_notes", sa.Text()))


def downgrade() -> None:
    op.drop_column("vulnerability_findings", "user_notes")
    op.drop_column("vulnerability_findings", "action_due")
    op.drop_column("vulnerability_findings", "required_action")
    op.drop_column("vulnerability_findings", "known_exploited")
