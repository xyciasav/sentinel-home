from pathlib import Path

import yaml


def test_portainer_compose_file_exists_and_matches_compose_alias() -> None:
    root = Path(__file__).parents[1]
    portainer_stack = yaml.safe_load((root / "docker-compose.yml").read_text())
    compose_alias = yaml.safe_load((root / "compose.yml").read_text())
    assert portainer_stack == compose_alias
    assert set(portainer_stack["services"]) == {"api", "postgres", "redis"}
