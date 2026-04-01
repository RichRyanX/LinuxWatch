# LinuxWatch

A Python CLI tool that ingests Linux system logs, applies rule-based detection logic to surface suspicious activity, and generates a structured incident report.

Built as a portfolio project demonstrating practical SOC-analyst thinking — parsing real logs, detecting real attack patterns, producing real output.

---

## Features

- Detects SSH brute force attacks (sliding 60-second window)
- Detects first-time sudo usage by unknown accounts
- Detects new user account creation events
- Detects successful logins outside working hours
- Outputs a color-coded terminal summary via `rich`
- Exports machine-readable JSON alerts
- Generates a self-contained static HTML incident report

---

## Usage
```bash
# Terminal summary only
python3 linuxwatch.py --log /var/log/auth.log

# With JSON alert export
python3 linuxwatch.py --log /var/log/auth.log --json alerts.json

# With HTML report
python3 linuxwatch.py --log /var/log/auth.log --html report.html

# All outputs at once
python3 linuxwatch.py --log /var/log/auth.log --json alerts.json --html report.html
```

---

## Detection Rules

| Rule | Severity | Logic |
|---|---|---|
| `ssh_brute_force` | CRITICAL | 5+ failed logins from same IP within 60s |
| `sudo_anomaly` | WARNING | sudo usage by account with no prior sudo history |
| `new_user_creation` | WARNING | `useradd` / `adduser` event detected |
| `off_hours_login` | WARNING | Successful login outside 08:00–20:00 |

---

## Project Structure
```
linuxwatch/
├── linuxwatch.py          # CLI entry point
├── parser/
│   └── log_parser.py      # Syslog parser
├── rules/
│   ├── base_rule.py       # Abstract base class
│   ├── brute_force.py     # SSH brute force detector
│   ├── sudo_anomaly.py    # Sudo anomaly detector
│   ├── new_user.py        # New user creation detector
│   └── off_hours.py       # Off-hours login detector
├── output/
│   ├── html_report.py     # Jinja2 HTML report renderer
│   └── templates/
│       └── report.html.j2 # HTML report template
└── tests/                 # pytest unit tests (14 tests)
```

---

## Running Tests
```bash
python3 -m pytest tests/ -v
```

---

## Stack

Python 3 · re · datetime · argparse · rich · Jinja2 · pytest

---

## Why I built this

Log analysis is the daily work of a SOC analyst. This tool simulates that workflow — ingest raw logs, apply detection logic, surface anomalies, produce a report. Every component maps to a real skill used in a security operations center.