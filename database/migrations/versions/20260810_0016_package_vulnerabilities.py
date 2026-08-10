"""Add source packages and normalized package vulnerability evidence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260810_0016"
down_revision: str | None = "20260810_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("installed_packages", sa.Column("source_name", sa.String(255)))
    op.add_column("installed_packages", sa.Column("source_version", sa.String(255)))
    op.add_column("vulnerability_findings", sa.Column("affected_package", sa.String(255)))
    op.add_column("vulnerability_findings", sa.Column("installed_version", sa.String(255)))
    op.add_column("vulnerability_findings", sa.Column("fixed_version", sa.String(255)))
    op.add_column("vulnerability_findings", sa.Column("detection_method", sa.String(50)))
    op.execute(
        "UPDATE vulnerability_findings SET detection_method = 'nvd-cpe' "
        "WHERE detection_method IS NULL"
    )
    op.alter_column("vulnerability_findings", "detection_method", nullable=False)
    op.drop_index("ix_vulnerability_address_cve", table_name="vulnerability_findings")
    op.create_index(
        "ix_vulnerability_address_cve_method",
        "vulnerability_findings",
        ["address", "cve_id", "detection_method"],
        unique=True,
    )


def downgrade() -> None:
    op.execute("DELETE FROM vulnerability_findings WHERE detection_method = 'osv-agent-package'")
    op.drop_index("ix_vulnerability_address_cve_method", table_name="vulnerability_findings")
    op.create_index(
        "ix_vulnerability_address_cve",
        "vulnerability_findings",
        ["address", "cve_id"],
        unique=True,
    )
    op.drop_column("vulnerability_findings", "detection_method")
    op.drop_column("vulnerability_findings", "fixed_version")
    op.drop_column("vulnerability_findings", "installed_version")
    op.drop_column("vulnerability_findings", "affected_package")
    op.drop_column("installed_packages", "source_version")
    op.drop_column("installed_packages", "source_name")
