from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    detector: str
    category: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line: int
    message: str
    evidence: str
    remediation: str
    fingerprint: str = ""
    blocking: bool = False

    def __post_init__(self) -> None:
        if not self.fingerprint:
            key = "|".join(
                [
                    self.detector,
                    self.category,
                    self.file_path,
                    str(self.line),
                    self.message,
                    self.evidence,
                ]
            )
            self.fingerprint = sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file_path": self.file_path,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
            "blocking": self.blocking,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def blocking_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.blocking]
