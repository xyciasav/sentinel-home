"""Add Linux host identity to agents."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0015"
down_revision: str | None = "20260810_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("hostname", sa.String(255)))
    op.add_column("agents", sa.Column("os_name", sa.String(100)))
    op.add_column("agents", sa.Column("os_version", sa.String(100)))
    op.add_column("agents", sa.Column("kernel_version", sa.String(100)))


def downgrade() -> None:
    op.drop_column("agents", "kernel_version")
    op.drop_column("agents", "os_version")
    op.drop_column("agents", "os_name")
    op.drop_column("agents", "hostname")
