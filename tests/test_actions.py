from types import SimpleNamespace

from sentinel.actions import priority


def test_known_exploited_finding_is_prioritized() -> None:
    finding = SimpleNamespace(severity="critical", known_exploited=True)

    assert priority(finding, "critical") == 100


def test_medium_finding_has_explainable_priority() -> None:
    finding = SimpleNamespace(severity="medium", known_exploited=False)

    assert priority(finding, "normal") == 20
