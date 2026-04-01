# tests/test_new_user.py
# Unit tests for the new user creation detection rule. Tests that useradd
# events are correctly detected and non-matching lines are ignored.

from datetime import datetime
from rules.new_user import NewUserRule

def make_entry(timestamp, message):
    return {
        "timestamp": timestamp,
        "host":      "fedora",
        "process":   "useradd",
        "pid":       "300",
        "message":   message,
        "raw":       f"Mar 28 12:00:00 fedora useradd[300]: {message}",
    }


def test_new_user_fires():
    """A useradd event should trigger a WARNING alert."""
    entries = [make_entry(
        datetime(2026, 3, 28, 12, 0, 0),
        "new user: name=hacker, UID=1001, GID=1001"
    )]
    alerts = NewUserRule().detect(entries)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "WARNING"
    assert "hacker" in alerts[0]["message"]


def test_new_user_silent_on_unrelated():
    """Non-useradd log lines should not trigger any alert."""
    entries = [make_entry(
        datetime(2026, 3, 28, 12, 0, 0),
        "Failed password for root from 10.0.0.1 port 22"
    )]
    alerts = NewUserRule().detect(entries)
    assert len(alerts) == 0


def test_new_user_multiple():
    """Two useradd events should generate two alerts."""
    entries = [
        make_entry(datetime(2026, 3, 28, 12, 0, 0), "new user: name=hacker1, UID=1001, GID=1001"),
        make_entry(datetime(2026, 3, 28, 12, 1, 0), "new user: name=hacker2, UID=1002, GID=1002"),
    ]
    alerts = NewUserRule().detect(entries)
    assert len(alerts) == 2