"""Add remediation dispatch and execution result fields."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0018"
down_revision: str | None = "20260810_0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("remediation_plans", sa.Column("dispatched_at", sa.DateTime(timezone=True)))
    op.add_column("remediation_plans", sa.Column("completed_at", sa.DateTime(timezone=True)))
    op.add_column("remediation_plans", sa.Column("result_output", sa.Text()))
    op.add_column("remediation_plans", sa.Column("result_error", sa.String(500)))


def downgrade() -> None:
    op.drop_column("remediation_plans", "result_error")
    op.drop_column("remediation_plans", "result_output")
    op.drop_column("remediation_plans", "completed_at")
    op.drop_column("remediation_plans", "dispatched_at")
