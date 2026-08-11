from datetime import UTC, datetime
from types import SimpleNamespace

from sentinel.maintenance import window_active


def window(**overrides):
    values = {
        "timezone": "UTC",
        "time_of_day": "03:00",
        "day_of_week": None,
        "duration_minutes": 60,
        "enabled": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_daily_window_is_active_only_during_duration():
    assert window_active(window(), datetime(2026, 8, 11, 3, 30, tzinfo=UTC))
    assert not window_active(window(), datetime(2026, 8, 11, 4, 1, tzinfo=UTC))


def test_weekly_window_handles_crossing_midnight():
    scheduled = window(day_of_week=0, time_of_day="23:30", duration_minutes=120)
    assert window_active(scheduled, datetime(2026, 8, 11, 0, 15, tzinfo=UTC))
    assert not window_active(scheduled, datetime(2026, 8, 11, 2, 0, tzinfo=UTC))


def test_disabled_window_is_never_active():
    assert not window_active(window(enabled=False), datetime(2026, 8, 11, 3, 30, tzinfo=UTC))
