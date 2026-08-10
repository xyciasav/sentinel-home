"""Add service outage incidents and timelines."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0006"
down_revision: str | None = "20260810_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "monitor_id",
            sa.Uuid(),
            sa.ForeignKey("service_monitors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recovered_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
    )
    op.create_index("ix_incidents_monitor_id", "incidents", ["monitor_id"])
    op.create_index("ix_incidents_status_started", "incidents", ["status", "started_at"])
    op.create_table(
        "incident_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_incident_events_incident_time", "incident_events", ["incident_id", "occurred_at"]
    )


def downgrade() -> None:
    op.drop_table("incident_events")
    op.drop_index("ix_incidents_status_started", table_name="incidents")
    op.drop_index("ix_incidents_monitor_id", table_name="incidents")
    op.drop_table("incidents")
