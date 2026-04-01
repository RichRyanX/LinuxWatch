# rules/sudo_anomaly.py
# Detects sudo usage by accounts that have no prior sudo history in the log.
# Flags any user running sudo for the first time as a WARNING — could indicate
# privilege escalation by a compromised or unexpected account.

import re
from rules.base_rule import BaseRule

# Matches lines like:
# sudo: ryan : TTY=pts/0 ; PWD=/home/ryan ; USER=root ; COMMAND=/bin/bash
SUDO_PATTERN = re.compile(r'(\w+)\s+:.*COMMAND=')


class SudoAnomalyRule(BaseRule):

    name     = "sudo_anomaly"
    severity = "WARNING"

    def detect(self, entries: list[dict]) -> list[dict]:
        """
        Collect all users who appear in sudo log lines.
        Any user whose first sudo event is their ONLY sudo event gets flagged —
        meaning they have no established sudo history in this log window.
        """
        # Map each user to all their sudo entries
        sudo_usage: dict[str, list[dict]] = {}

        for entry in entries:
            match = SUDO_PATTERN.search(entry["message"])
            if not match:
                continue
            user = match.group(1)
            sudo_usage.setdefault(user, []).append(entry)

        alerts = []

        for user, events in sudo_usage.items():
            # Flag users with only one sudo event — no history, first-time use
            if len(events) == 1:
                e = events[0]
                alerts.append(self.make_alert(
                    message   = f"First-time sudo usage detected for user '{user}'",
                    timestamp = e["timestamp"],
                    evidence  = [e["raw"]],
                ))

        return alerts