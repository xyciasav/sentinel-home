from sentinel.setup import setup_status


class ScalarSession:
    def __init__(self, value: int) -> None:
        self.value = value

    async def scalar(self, _statement: object) -> int:
        return self.value


async def test_setup_status_is_uninitialized_without_admins() -> None:
    result = await setup_status(ScalarSession(0))  # type: ignore[arg-type]
    assert result.initialized is False
    assert result.administrator_count == 0


async def test_setup_status_is_initialized_with_admin() -> None:
    result = await setup_status(ScalarSession(1))  # type: ignore[arg-type]
    assert result.initialized is True
    assert result.administrator_count == 1
