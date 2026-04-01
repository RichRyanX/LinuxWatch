# output/html_report.py
# Renders the Jinja2 HTML report template with alert data and writes the result
# to a single self-contained HTML file that can be opened in any browser.

from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from pathlib import Path


def save_html(alerts: list[dict], log_path: str, output_path: str) -> None:
    """
    Render the HTML report template with the given alerts and save to output_path.
    """
    # Load template from output/templates/
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.html.j2")

    # Count by severity for the summary bar
    critical_count = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    warning_count  = sum(1 for a in alerts if a["severity"] == "WARNING")
    info_count     = sum(1 for a in alerts if a["severity"] == "INFO")

    # Format alerts for the template — convert timestamps to strings
    formatted = []
    for a in sorted(alerts, key=lambda x: x["timestamp"]):
        formatted.append({
            "rule":      a["rule"],
            "severity":  a["severity"],
            "message":   a["message"],
            "timestamp": a["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "evidence":  a["evidence"],
        })

    html = template.render(
        log_path       = log_path,
        generated_at   = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alerts         = formatted,
        critical_count = critical_count,
        warning_count  = warning_count,
        info_count     = info_count,
    )

    with open(output_path, "w") as f:
        f.write(html)