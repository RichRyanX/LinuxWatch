# tests/test_sudo.py
# Unit tests for the sudo anomaly detection rule. Tests first-time sudo usage
# detection and ensures repeat sudo users are not flagged.

from datetime import datetime
from rules.sudo_anomaly import SudoAnomalyRule

def make_entry(timestamp, user, command="/bin/bash"):
    return {
        "timestamp": timestamp,
        "host":      "fedora",
        "process":   "sudo",
        "pid":       "200",
        "message":   f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}",
        "raw":       f"Mar 28 12:00:00 fedora sudo[200]: {user} : TTY=pts/0 ; USER=root ; COMMAND={command}",
    }


def test_sudo_first_time_fires():
    """A user appearing only once in sudo logs should trigger a WARNING."""
    entries = [make_entry(datetime(2026, 3, 28, 12, 0, 0), "hacker")]
    alerts = SudoAnomalyRule().detect(entries)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "WARNING"
    assert "hacker" in alerts[0]["message"]


def test_sudo_repeat_user_silent():
    """A user with multiple sudo entries should not be flagged."""
    entries = [
        make_entry(datetime(2026, 3, 28, 12, 0, 0), "ryan"),
        make_entry(datetime(2026, 3, 28, 12, 5, 0), "ryan"),
    ]
    alerts = SudoAnomalyRule().detect(entries)
    assert len(alerts) == 0


def test_sudo_multiple_first_timers():
    """Two different first-time sudo users should each generate one alert."""
    entries = [
        make_entry(datetime(2026, 3, 28, 12, 0, 0), "hacker1"),
        make_entry(datetime(2026, 3, 28, 12, 1, 0), "hacker2"),
    ]
    alerts = SudoAnomalyRule().detect(entries)
    assert len(alerts) == 2