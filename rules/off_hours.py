# rules/off_hours.py
# Detects successful logins that occur outside configured working hours.
# Off-hours access (default: before 08:00 or after 20:00) is flagged as
# WARNING — legitimate users rarely log in at 3am.

import re
from rules.base_rule import BaseRule

# Matches lines like:
# Accepted password for ryan from 192.168.1.5 port 52134 ssh2
# Accepted publickey for deploy from 10.0.0.2 port 44231 ssh2
ACCEPTED_LOGIN_PATTERN = re.compile(
    r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)'
)

WORK_HOUR_START = 8   # 08:00
WORK_HOUR_END   = 20  # 20:00


class OffHoursRule(BaseRule):

    name     = "off_hours_login"
    severity = "WARNING"

    def detect(self, entries: list[dict]) -> list[dict]:
        """
        Flag any successful SSH login that falls outside working hours.
        Working hours are configurable via WORK_HOUR_START / WORK_HOUR_END.
        """
        alerts = []

        for entry in entries:
            match = ACCEPTED_LOGIN_PATTERN.search(entry["message"])
            if not match:
                continue

            hour = entry["timestamp"].hour
            if hour < WORK_HOUR_START or hour >= WORK_HOUR_END:
                user = match.group(1)
                ip   = match.group(2)
                alerts.append(self.make_alert(
                    message   = f"Off-hours login by '{user}' from {ip} at {entry['timestamp'].strftime('%H:%M')}",
                    timestamp = entry["timestamp"],
                    evidence  = [entry["raw"]],
                ))

        return alerts