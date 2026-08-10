"""Add persistent storage scan jobs."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0013"
down_revision: str | None = "20260810_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "storage_scan_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Uuid(),
            sa.ForeignKey("storage_targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("files_scanned", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_storage_scan_jobs_target_id", "storage_scan_jobs", ["target_id"])
    op.create_index("ix_storage_scan_jobs_created", "storage_scan_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_table("storage_scan_jobs")
