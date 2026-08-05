from pathlib import Path

import yaml


def test_portainer_compose_file_exists_and_matches_compose_alias() -> None:
    root = Path(__file__).parents[1]
    portainer_stack = yaml.safe_load((root / "docker-compose.yml").read_text())
    compose_alias = yaml.safe_load((root / "compose.yml").read_text())
    assert portainer_stack == compose_alias
    assert set(portainer_stack["services"]) == {"api", "postgres", "redis"}


def test_compose_requires_secrets_and_derives_internal_urls() -> None:
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text()
    assert "${POSTGRES_PASSWORD:?" in compose
    assert "${SESSION_SECRET:?" in compose
    assert "${DATA_ENCRYPTION_KEY:?" in compose
    assert "REDIS_URL: redis://redis:6379/0" in compose
    assert "DATABASE_URL: postgresql://" in compose
