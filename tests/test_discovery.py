import pytest
from fastapi import HTTPException
from sentinel.discovery import validated_subnet


def test_discovery_accepts_private_slash_24() -> None:
    network = validated_subnet("10.0.0.25/24")
    assert str(network) == "10.0.0.0/24"


@pytest.mark.parametrize("subnet", ["8.8.8.0/24", "10.0.0.0/16", "not-a-subnet", "::1/128"])
def test_discovery_rejects_unsafe_subnets(subnet: str) -> None:
    with pytest.raises(HTTPException):
        validated_subnet(subnet)
