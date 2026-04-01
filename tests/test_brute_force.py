# tests/test_brute_force.py
# Unit tests for the SSH brute force detection rule. Tests that the rule fires
# correctly when the threshold is exceeded and stays silent when it isn't.

from datetime import datetime
from rules.brute_force import BruteForceRule

def make_entry(timestamp, ip, user="root"):
    """Helper to build a fake log entry dict."""
    return {
        "timestamp": timestamp,
        "host":      "fedora",
        "process":   "sshd",
        "pid":       "100",
        "message":   f"Failed password for {user} from {ip} port 22 ssh2",
        "raw":       f"Mar 28 12:00:00 fedora sshd[100]: Failed password for {user} from {ip} port 22 ssh2",
    }


def test_brute_force_fires_above_threshold():
    """6 failures from same IP within 60s should trigger a CRITICAL alert."""
    entries = [
        make_entry(datetime(2026, 3, 28, 12, 0, i*5), "10.0.0.1")
        for i in range(6)
    ]
    alerts = BruteForceRule().detect(entries)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert "10.0.0.1" in alerts[0]["message"]


def test_brute_force_silent_below_threshold():
    """4 failures from same IP should not trigger any alert."""
    entries = [
        make_entry(datetime(2026, 3, 28, 12, 0, i*5), "10.0.0.1")
        for i in range(4)
    ]
    alerts = BruteForceRule().detect(entries)
    assert len(alerts) == 0


def test_brute_force_different_ips():
    """6 failures spread across different IPs should not trigger any alert."""
    entries = [
        make_entry(datetime(2026, 3, 28, 12, 0, 0), f"10.0.0.{i}")
        for i in range(6)
    ]
    alerts = BruteForceRule().detect(entries)
    assert len(alerts) == 0


def test_brute_force_outside_window():
    """6 failures from same IP but spread over 10 minutes should not trigger."""
    entries = [
        make_entry(datetime(2026, 3, 28, 12, i, 0), "10.0.0.1")
        for i in range(6)
    ]
    alerts = BruteForceRule().detect(entries)
    assert len(alerts) == 0