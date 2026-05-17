from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class Finding:
    category: str
    title: str
    status: str
    severity: Severity
    details: str
    evidence: str = ""
    sensitive: bool = False

    def redacted(self) -> Finding:
        if not self.sensitive:
            return self

        return replace(
            self,
            status="REDACTED",
            evidence="REDACTED" if self.evidence else "",
        )

    def to_dict(self, redact: bool = False) -> dict[str, Any]:
        finding = self.redacted() if redact else self

        return {
            "category": finding.category,
            "title": finding.title,
            "status": finding.status,
            "severity": finding.severity.value,
            "details": finding.details,
            "evidence": finding.evidence,
        }
