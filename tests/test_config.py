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
