"""Group checks into logical services."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0005"
down_revision: str | None = "20260810_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("service_monitors", sa.Column("group_name", sa.String(100)))
    op.create_index("ix_service_monitors_group_name", "service_monitors", ["group_name"])


def downgrade() -> None:
    op.drop_index("ix_service_monitors_group_name", table_name="service_monitors")
    op.drop_column("service_monitors", "group_name")
