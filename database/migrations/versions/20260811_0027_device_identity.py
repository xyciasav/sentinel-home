"""Add canonical MAC identity to devices."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0027"
down_revision: str | None = "20260811_0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("mac_address", sa.String(30)))
    op.create_unique_constraint("uq_devices_mac_address", "devices", ["mac_address"])


def downgrade() -> None:
    op.drop_constraint("uq_devices_mac_address", "devices", type_="unique")
    op.drop_column("devices", "mac_address")
