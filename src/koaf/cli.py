from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from koaf import __version__
from koaf.engine import AuditEngine
from koaf.logger import setup_logger
from koaf.models import Finding, Severity


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="koaf",
        description="KOAF: Kali OPSEC anonymity surface audit tool.",
    )
    parser.add_argument("--audit", action="store_true", help="Run read-only audit mode.")
    parser.add_argument(
        "--external",
        action="store_true",
        help="Enable external IP, IPv6, and provider lookup checks.",
    )
    parser.add_argument(
        "--no-external",
        action="store_true",
        help="Keep external lookup checks disabled. This is the default behavior.",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Show beginner-friendly explanations for each finding.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of Rich tables.",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Redact sensitive values such as public IPs, routes, hostnames, and profile names.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def _display_finding(finding: Finding, redact: bool) -> Finding:
    return finding.redacted() if redact else finding


def render_table(console: Console, title: str, findings: list[Finding], redact: bool) -> None:
    table = Table(title=title)
    table.add_column("Category", style="cyan")
    table.add_column("Finding")
    table.add_column("Status")
    table.add_column("Severity", style="bold")

    for original in findings:
        finding = _display_finding(original, redact)
        color = {
            Severity.INFO: "white",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
        }[finding.severity]

        table.add_row(
            finding.category,
            finding.title,
            finding.status,
            f"[{color}]{finding.severity.value}[/{color}]",
        )

    console.print(table)


def render_explanations(
    console: Console,
    title: str,
    findings: list[Finding],
    redact: bool,
) -> None:
    console.print(f"\n[bold]{title}[/bold]")

    for original in findings:
        finding = _display_finding(original, redact)
        body = (
            f"[bold]Category:[/bold] {finding.category}\n"
            f"[bold]Status:[/bold] {finding.status}\n"
            f"[bold]Severity:[/bold] {finding.severity.value}\n\n"
            f"{finding.details}"
        )

        if finding.evidence:
            body += f"\n\n[bold]Evidence:[/bold]\n{finding.evidence}"

        console.print(Panel(body, title=finding.title, expand=False))


def render_json(findings: list[Finding], alerts: list[Finding], redact: bool) -> None:
    payload = {
        "tool": "KOAF",
        "version": __version__,
        "mode": "audit",
        "redacted": redact,
        "findings": [finding.to_dict(redact=redact) for finding in findings],
        "correlation_alerts": [alert.to_dict(redact=redact) for alert in alerts],
    }
    print(json.dumps(payload, indent=2))


def main() -> int:
    args = parse_args()
    console = Console(stderr=args.json)
    logger = setup_logger(verbose=args.verbose, enable_console=not args.json)

    if not args.audit:
        console.print("[red]No mode selected.[/red] Use: koaf --audit")
        return 2

    if not args.json:
        console.print(f"[bold cyan]KOAF[/bold cyan] v{__version__}")
        console.print("[italic]Kali OPSEC Automation Framework - read-only audit mode[/italic]\n")

    external_enabled = args.external and not args.no_external

    logger.info("Mode selected: AUDIT")
    engine = AuditEngine(logger, external_enabled=external_enabled)
    findings, alerts = engine.run()

    if args.json:
        render_json(findings, alerts, redact=args.redact)
        return 0

    render_table(console, "KOAF Audit Findings", findings, redact=args.redact)

    if alerts:
        render_table(console, "Correlation Alerts", alerts, redact=args.redact)

    if args.explain:
        render_explanations(console, "Finding explanations", findings, redact=args.redact)
        if alerts:
            render_explanations(console, "Correlation explanations", alerts, redact=args.redact)

    return 0


if __name__ == "__main__":
    sys.exit(main())
