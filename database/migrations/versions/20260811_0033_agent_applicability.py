"""Mark devices where endpoint agents are not applicable."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0033"
down_revision: str | None = "20260811_0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("agent_applicable", sa.Boolean(), nullable=False, server_default="true"),
    )


def downgrade() -> None:
    op.drop_column("devices", "agent_applicable")
