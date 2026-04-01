# rules/brute_force.py
# Detects SSH brute force attacks by counting failed login attempts from the
# same IP within a 60-second sliding window. Fires a CRITICAL alert if an IP
# exceeds 5 failures in that window.

import re
from datetime import timedelta
from rules.base_rule import BaseRule

# Matches lines like:
# Failed password for root from 192.168.1.1 port 22 ssh2
# Failed password for invalid user admin from 10.0.0.5 port 41022 ssh2
FAILED_LOGIN_PATTERN = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+'
)

WINDOW_SECONDS = 60
THRESHOLD = 5


class BruteForceRule(BaseRule):

    name     = "ssh_brute_force"
    severity = "CRITICAL"

    def detect(self, entries: list[dict]) -> list[dict]:
        """
        Slide a 60-second window over failed SSH login entries.
        If any single IP accumulates more than 5 failures in that window,
        emit one alert per offending IP.
        """
        # Collect all failed login events, keyed by source IP
        failures: dict[str, list[dict]] = {}

        for entry in entries:
            match = FAILED_LOGIN_PATTERN.search(entry["message"])
            if not match:
                continue
            ip = match.group(2)
            failures.setdefault(ip, []).append(entry)

        alerts = []

        for ip, events in failures.items():
            # Events are already in file order; sort by timestamp to be safe
            events.sort(key=lambda e: e["timestamp"])

            # Slide window: for each event, count how many follow within 60s
            for i, anchor in enumerate(events):
                window = [
                    e for e in events[i:]
                    if e["timestamp"] - anchor["timestamp"] <= timedelta(seconds=WINDOW_SECONDS)
                ]
                if len(window) >= THRESHOLD:
                    alerts.append(self.make_alert(
                        message  = f"{len(window)} failed SSH logins from {ip} within {WINDOW_SECONDS}s",
                        timestamp= anchor["timestamp"],
                        evidence = [e["raw"] for e in window],
                    ))
                    break  # one alert per IP is enough

        return alerts