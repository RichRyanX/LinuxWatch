# tests/test_off_hours.py
# Unit tests for the off-hours login detection rule. Tests that logins outside
# working hours are flagged and logins during working hours are ignored.

from datetime import datetime
from rules.off_hours import OffHoursRule

def make_entry(timestamp, user="ryan", ip="192.168.1.1"):
    return {
        "timestamp": timestamp,
        "host":      "fedora",
        "process":   "sshd",
        "pid":       "100",
        "message":   f"Accepted password for {user} from {ip} port 22 ssh2",
        "raw":       f"Mar 28 00:00:00 fedora sshd[100]: Accepted password for {user} from {ip} port 22 ssh2",
    }


def test_off_hours_late_night_fires():
    """A login at 3am should trigger a WARNING."""
    entries = [make_entry(datetime(2026, 3, 28, 3, 15, 0))]
    alerts = OffHoursRule().detect(entries)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "WARNING"


def test_off_hours_early_morning_fires():
    """A login at 6am (before 8am) should trigger a WARNING."""
    entries = [make_entry(datetime(2026, 3, 28, 6, 0, 0))]
    alerts = OffHoursRule().detect(entries)
    assert len(alerts) == 1


def test_off_hours_business_hours_silent():
    """A login at 10am should not trigger any alert."""
    entries = [make_entry(datetime(2026, 3, 28, 10, 0, 0))]
    alerts = OffHoursRule().detect(entries)
    assert len(alerts) == 0


def test_off_hours_exactly_at_start_silent():
    """A login exactly at 8am should not trigger any alert."""
    entries = [make_entry(datetime(2026, 3, 28, 8, 0, 0))]
    alerts = OffHoursRule().detect(entries)
    assert len(alerts) == 0