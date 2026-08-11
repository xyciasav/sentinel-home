"""Store inventory source health summaries."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0026"
down_revision: str | None = "20260810_0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("inventory_sources", sa.Column("summary_json", sa.Text()))


def downgrade() -> None:
    op.drop_column("inventory_sources", "summary_json")
