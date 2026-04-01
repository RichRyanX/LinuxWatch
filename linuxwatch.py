# linuxwatch.py
# Main CLI entry point for LinuxWatch. Accepts a log file path and output format
# via argparse, runs all 4 detection rules against the parsed log, and prints a
# rich-formatted summary to the terminal with optional JSON alert output.

import argparse
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box

from parser.log_parser import parse_file
from rules.brute_force import BruteForceRule
from rules.sudo_anomaly import SudoAnomalyRule
from rules.new_user import NewUserRule
from rules.off_hours import OffHoursRule

console = Console()

RULES = [
    BruteForceRule(),
    SudoAnomalyRule(),
    NewUserRule(),
    OffHoursRule(),
]

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "WARNING":  "bold yellow",
    "INFO":     "bold cyan",
}


def run_analysis(log_path: str) -> list[dict]:
    """Parse the log file and run all rules. Returns combined alert list."""
    console.print(f"\n[bold cyan]LinuxWatch[/bold cyan] — scanning [green]{log_path}[/green]\n")

    entries = parse_file(log_path)
    if not entries:
        console.print("[yellow]No log entries parsed. Check the file path and format.[/yellow]")
        return []

    console.print(f"[dim]Parsed {len(entries)} log entries. Running {len(RULES)} rules...[/dim]\n")

    all_alerts = []
    for rule in RULES:
        alerts = rule.detect(entries)
        all_alerts.extend(alerts)

    return all_alerts


def print_summary(alerts: list[dict]) -> None:
    """Print a rich-formatted alert summary table to the terminal."""
    if not alerts:
        console.print("[bold green]No suspicious activity detected.[/bold green]")
        return

    table = Table(
        title=f"Detection Results — {len(alerts)} alert(s) found",
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column("Severity",  style="bold",  width=10)
    table.add_column("Rule",      style="cyan",  width=22)
    table.add_column("Message",   style="white", width=52)
    table.add_column("Timestamp", style="dim",   width=20)

    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        severity = alert["severity"]
        color    = SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            alert["rule"],
            alert["message"],
            alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print(table)


def save_json(alerts: list[dict], output_path: str) -> None:
    """Serialize alerts to a JSON file."""
    serializable = []
    for a in alerts:
        serializable.append({
            "rule":      a["rule"],
            "severity":  a["severity"],
            "message":   a["message"],
            "timestamp": a["timestamp"].isoformat(),
            "evidence":  a["evidence"],
        })

    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2)

    console.print(f"\n[bold green]JSON alerts saved to:[/bold green] {output_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="linuxwatch",
        description="Linux log analyser — detects suspicious activity in syslog-format logs.",
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to the log file to analyse (e.g. /var/log/auth.log)",
    )
    parser.add_argument(
        "--json",
        metavar="OUTPUT",
        help="Save alerts to a JSON file at the given path",
    )

    args = parser.parse_args()

    alerts = run_analysis(args.log)
    print_summary(alerts)

    if args.json:
        save_json(alerts, args.json)


if __name__ == "__main__":
    main()