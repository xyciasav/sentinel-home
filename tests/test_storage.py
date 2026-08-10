import pytest
from pydantic import ValidationError
from sentinel.storage import TargetInput


@pytest.mark.parametrize("path", ["../private", "/etc", "folder/../../private"])
def test_storage_target_rejects_paths_outside_mount(path: str) -> None:
    with pytest.raises(ValidationError):
        TargetInput(name="unsafe", relative_path=path)


def test_storage_target_normalizes_windows_separators() -> None:
    target = TargetInput(name="media", relative_path="media\\photos")

    assert target.relative_path == "media/photos"
    assert target.large_file_mb == 1024
    assert target.old_file_days == 365
