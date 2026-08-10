from sentinel.reports import percentage


def test_percentage_reports_real_uptime() -> None:
    assert percentage(99, 100) == 99.0
    assert percentage(2, 3) == 66.67


def test_percentage_has_no_data_state() -> None:
    assert percentage(0, 0) is None
