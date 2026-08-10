"""Add read-only storage targets and findings."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0012"
down_revision: str | None = "20260810_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "storage_targets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("relative_path", sa.String(500), nullable=False, unique=True),
        sa.Column("large_file_bytes", sa.BigInteger(), nullable=False),
        sa.Column("old_file_days", sa.Integer(), nullable=False),
        sa.Column("protected_paths", sa.Text(), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True)),
        sa.Column("last_total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("last_file_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "storage_findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Uuid(),
            sa.ForeignKey("storage_targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relative_path", sa.String(1000), nullable=False),
        sa.Column("item_type", sa.String(30), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(300), nullable=False),
        sa.Column("protected", sa.Boolean(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_storage_findings_target_id", "storage_findings", ["target_id"])
    op.create_index(
        "ix_storage_findings_target_path", "storage_findings", ["target_id", "relative_path"]
    )


def downgrade() -> None:
    op.drop_table("storage_findings")
    op.drop_table("storage_targets")
