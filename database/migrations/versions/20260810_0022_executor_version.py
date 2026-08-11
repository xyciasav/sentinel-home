"""Track the installed remediation helper version."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0022"
down_revision: str | None = "20260810_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("executor_version", sa.String(40)))


def downgrade() -> None:
    op.drop_column("agents", "executor_version")
