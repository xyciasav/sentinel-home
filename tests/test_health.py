from fastapi.testclient import TestClient
from sentinel.main import app


def test_liveness_is_public_and_minimal() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_disabled_test_dependencies() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    assert response.json()["dependencies"]["database"]["status"] == "disabled"
