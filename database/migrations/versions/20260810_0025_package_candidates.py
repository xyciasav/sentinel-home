"""Track repository upgrade candidates for installed packages."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0025"
down_revision: str | None = "20260810_0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("installed_packages", sa.Column("candidate_version", sa.String(255)))


def downgrade() -> None:
    op.drop_column("installed_packages", "candidate_version")
