import pytest
from pydantic import ValidationError
from sentinel.config import Settings


def test_production_rejects_missing_secrets() -> None:
    with pytest.raises(ValidationError, match="invalid production configuration"):
        Settings(sentinel_environment="production")


def test_production_accepts_explicit_strong_configuration() -> None:
    settings = Settings(
        sentinel_environment="production",
        database_url="postgresql://sentinel:strong-password@postgres/sentinel",
        redis_url="redis://redis:6379/0",
        session_secret="x" * 32,
        data_encryption_key="valid-base64-key-material-for-bootstrap",
    )
    assert settings.detailed_retention_days == 30


def test_email_alerts_require_all_resend_settings() -> None:
    assert (
        Settings(resend_api_key="", alert_from_email="", alert_to_email="").email_alerts_configured
        is False
    )
    assert (
        Settings(
            resend_api_key="re_test_key",
            alert_from_email="Sentinel <alerts@example.com>",
            alert_to_email="owner@example.com",
        ).email_alerts_configured
        is True
    )
