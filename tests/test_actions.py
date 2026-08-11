from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from sentinel.actions import RemediationPlanView, priority


def test_known_exploited_finding_is_prioritized() -> None:
    finding = SimpleNamespace(severity="critical", known_exploited=True)

    assert priority(finding, "critical") == 100


def test_medium_finding_has_explainable_priority() -> None:
    finding = SimpleNamespace(severity="medium", known_exploited=False)

    assert priority(finding, "normal") == 20


def test_remediation_plan_view_accepts_database_model_attributes() -> None:
    plan = SimpleNamespace(
        id=uuid4(),
        finding_id=uuid4(),
        agent_id=uuid4(),
        package_name="openssl",
        installed_version="1.0",
        target_version="1.1",
        operation="package_upgrade",
        status="draft",
        created_at=datetime.now(UTC),
        approved_at=None,
        dispatched_at=None,
        completed_at=None,
        result_output=None,
        result_error=None,
    )

    assert RemediationPlanView.model_validate(plan).package_name == "openssl"
