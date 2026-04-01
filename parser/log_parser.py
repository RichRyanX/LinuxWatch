# parser/log_parser.py
# This is the foundation — it reads raw log lines and normalizes them into structured dicts that every rule will consume.

import re
from datetime import datetime
from typing import Optional

# Matches standard syslog format:
# Mar 22 11:04:33 hostname process[pid]: message
SYSLOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)$'
)

CURRENT_YEAR = datetime.now().year


def parse_line(line: str) -> Optional[dict]:
    """
    Parse a single syslog-format log line into a structured dict.
    Returns None if the line doesn't match the expected format.
    """
    line = line.strip()
    if not line:
        return None

    match = SYSLOG_PATTERN.match(line)
    if not match:
        return None

    parts = match.groupdict()

    # Build a full timestamp — syslog has no year, so we assume current year
    raw_ts = f"{parts['month']} {parts['day'].zfill(2)} {parts['time']} {CURRENT_YEAR}"
    try:
        timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "host":      parts["host"],
        "process":   parts["process"],
        "pid":       parts["pid"],       # may be None
        "message":   parts["message"],
        "raw":       line,
    }


def parse_file(filepath: str) -> list[dict]:
    """
    Read a log file and return a list of parsed log entry dicts.
    Lines that don't match syslog format are silently skipped.
    """
    entries = []
    try:
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                entry = parse_line(line)
                if entry:
                    entries.append(entry)
    except FileNotFoundError:
        print(f"[error] log file not found: {filepath}")
    except PermissionError:
        print(f"[error] permission denied: {filepath} — try running with sudo")
    return entries