from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    sentinel_environment: Literal["development", "test", "production"] = "development"
    sentinel_version: str = "0.31.0"
    database_url: str | None = None
    redis_url: str | None = None
    session_secret: SecretStr | None = None
    data_encryption_key: SecretStr | None = None
    detailed_retention_days: int = Field(default=30, ge=1, le=365)
    session_hours: int = Field(default=12, ge=1, le=168)
    cookie_secure: bool = False
    resend_api_key: SecretStr | None = None
    alert_from_email: str | None = None
    alert_to_email: str | None = None
    nvd_api_key: SecretStr | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    @property
    def email_alerts_configured(self) -> bool:
        return bool(
            self.resend_api_key
            and self.resend_api_key.get_secret_value().strip()
            and self.alert_from_email
            and self.alert_to_email
        )

    @model_validator(mode="after")
    def production_requires_secrets_and_dependencies(self) -> "Settings":
        if self.sentinel_environment != "production":
            return self
        required = {
            "DATABASE_URL": self.database_url,
            "REDIS_URL": self.redis_url,
            "SESSION_SECRET": self.session_secret,
            "DATA_ENCRYPTION_KEY": self.data_encryption_key,
        }
        missing = [name for name, value in required.items() if value is None]
        weak = [
            name
            for name, value in required.items()
            if value is not None
            and "change-me"
            in str(value.get_secret_value() if isinstance(value, SecretStr) else value)
        ]
        if missing or weak:
            problems = [
                *(f"{name} is missing" for name in missing),
                *(f"{name} is unsafe" for name in weak),
            ]
            raise ValueError("invalid production configuration: " + ", ".join(problems))
        if len(self.session_secret.get_secret_value()) < 32:
            raise ValueError("SESSION_SECRET must contain at least 32 characters")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
