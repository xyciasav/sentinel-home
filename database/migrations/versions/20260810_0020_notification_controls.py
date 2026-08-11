"""Add per-device alert muting and notification dismissal."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0020"
down_revision: str | None = "20260810_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("alerts_muted_until", sa.DateTime(timezone=True)))
    op.add_column("devices", sa.Column("alert_mute_reason", sa.String(300)))
    op.add_column("notification_deliveries", sa.Column("dismissed_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("notification_deliveries", "dismissed_at")
    op.drop_column("devices", "alert_mute_reason")
    op.drop_column("devices", "alerts_muted_until")
