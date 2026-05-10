from __future__ import annotations

import argparse

from rich.console import Console
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
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def render_table(console: Console, title: str, findings: list[Finding]) -> None:
    table = Table(title=title)
    table.add_column("Category", style="cyan")
    table.add_column("Finding")
    table.add_column("Status")
    table.add_column("Severity", style="bold")

    for finding in findings:
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


def main() -> int:
    args = parse_args()
    console = Console()
    logger = setup_logger(verbose=args.verbose)

    console.print(f"[bold cyan]KOAF[/bold cyan] v{__version__}")
    console.print("[italic]Kali OPSEC Automation Framework - read-only audit mode[/italic]\n")

    if not args.audit:
        console.print("[red]No mode selected.[/red] Use: koaf --audit")
        return 2

    logger.info("Mode selected: AUDIT")
    engine = AuditEngine(logger)
    findings, alerts = engine.run()

    render_table(console, "KOAF Audit Findings", findings)

    if alerts:
        render_table(console, "Correlation Alerts", alerts)

    return 0
