"""Transparent audit coverage derived only from primary checks, never correlations."""

from __future__ import annotations

from collections import Counter

from koaf.models import CheckOutcome, Finding

_OUTCOMES = tuple(CheckOutcome)


def summarize_coverage(findings: list[Finding]) -> dict:
    """Describe coverage of reported checks, without an invented anonymity score."""
    controls = [f for f in findings if f.category not in {"Summary", "Correlation"}]
    counts = Counter(f.outcome for f in controls)
    category_totals: dict[str, Counter] = {}
    for finding in controls:
        category_totals.setdefault(finding.category, Counter())[finding.outcome] += 1

    unknown = counts[CheckOutcome.UNKNOWN]
    assessed = len(controls) - unknown
    if not controls:
        status = "NO_DATA"
    elif not assessed:
        status = "NOT_ASSESSED"
    elif unknown:
        status = "PARTIAL"
    else:
        status = "ASSESSED"

    return {
        "status": status,
        "total_controls": len(controls),
        "assessed_controls": assessed,
        "unknown_controls": unknown,
        "outcomes": {outcome.value: counts[outcome] for outcome in _OUTCOMES},
        "categories": {
            category: {
                "total": sum(totals.values()),
                "unknown": totals[CheckOutcome.UNKNOWN],
                "outcomes": {outcome.value: totals[outcome] for outcome in _OUTCOMES},
            }
            for category, totals in sorted(category_totals.items())
        },
    }
