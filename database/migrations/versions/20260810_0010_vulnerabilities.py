"""Persist service evidence and exact-CPE vulnerability findings."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0010"
down_revision: str | None = "20260810_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "discovered_hosts",
        sa.Column("service_evidence", sa.Text(), nullable=False, server_default="[]"),
    )
    op.create_table(
        "vulnerability_findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("address", sa.String(45), nullable=False),
        sa.Column("cve_id", sa.String(30), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_score", sa.String(10)),
        sa.Column("cpe", sa.String(500), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vulnerability_findings_device_id", "vulnerability_findings", ["device_id"])
    op.create_index(
        "ix_vulnerability_address_cve", "vulnerability_findings", ["address", "cve_id"], unique=True
    )


def downgrade() -> None:
    op.drop_table("vulnerability_findings")
    op.drop_column("discovered_hosts", "service_evidence")
