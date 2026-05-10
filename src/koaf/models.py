from __future__ import annotations

from dataclasses import dataclass
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "status": self.status,
            "severity": self.severity.value,
            "details": self.details,
            "evidence": self.evidence,
        }
