# rules/new_user.py
# Detects new user account creation events in the log. Any useradd or adduser
# event is flagged as WARNING — unauthorized account creation is a common
# persistence technique used by attackers after gaining initial access.

import re
from rules.base_rule import BaseRule

# Matches lines like:
# new user: name=hacker, UID=1001, GID=1001, home=/home/hacker, shell=/bin/bash
# useradd[1234]: new user: name=hacker ...
NEW_USER_PATTERN = re.compile(r'new user:\s+name=(\S+)')


class NewUserRule(BaseRule):

    name     = "new_user_creation"
    severity = "WARNING"

    def detect(self, entries: list[dict]) -> list[dict]:
        """
        Scan all log entries for new user creation events.
        Each unique useradd event generates one alert.
        """
        alerts = []

        for entry in entries:
            match = NEW_USER_PATTERN.search(entry["message"])
            if not match:
                continue
            username = match.group(1).rstrip(',')
            alerts.append(self.make_alert(
                message   = f"New user account created: '{username}'",
                timestamp = entry["timestamp"],
                evidence  = [entry["raw"]],
            ))

        return alerts