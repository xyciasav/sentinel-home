"""Add approval-gated package remediation plans."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0017"
down_revision: str | None = "20260810_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remediation_plans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Uuid(),
            sa.ForeignKey("vulnerability_findings.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "agent_id",
            sa.Uuid(),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("installed_version", sa.String(255), nullable=False),
        sa.Column("target_version", sa.String(255), nullable=False),
        sa.Column("operation", sa.String(30), nullable=False, server_default="package_upgrade"),
        sa.Column("status", sa.String(30), nullable=False, server_default="draft"),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("approved_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_remediation_plans_agent_status", "remediation_plans", ["agent_id", "status"]
    )


def downgrade() -> None:
    op.drop_index("ix_remediation_plans_agent_status", table_name="remediation_plans")
    op.drop_table("remediation_plans")
