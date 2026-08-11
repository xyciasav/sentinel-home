"""Add persistent notification mute toggles for devices and services."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0023"
down_revision: str | None = "20260810_0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("notifications_muted", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "service_monitors",
        sa.Column("notifications_muted", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("service_monitors", "notifications_muted")
    op.drop_column("devices", "notifications_muted")
