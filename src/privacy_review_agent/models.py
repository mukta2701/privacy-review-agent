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


class EvidenceTier(str, Enum):
    CONFIRMED = "confirmed"
    KEYWORD = "keyword"


def normalize_evidence(evidence: str) -> str:
    return " ".join(evidence.strip().split())


def compute_fingerprint(
    detector: str,
    category: str,
    file_path: str,
    evidence: str,
    occurrence: int = 1,
) -> str:
    key = "|".join([detector, category, file_path, normalize_evidence(evidence), str(occurrence)])
    return sha256(key.encode("utf-8")).hexdigest()[:16]


def compute_legacy_fingerprint(
    detector: str,
    category: str,
    file_path: str,
    line: int,
    message: str,
    evidence: str,
) -> str:
    key = "|".join([detector, category, file_path, str(line), message, evidence])
    return sha256(key.encode("utf-8")).hexdigest()[:16]


def assign_occurrences(findings: list[Finding]) -> None:
    groups: dict[tuple[str, str, str, str], list[Finding]] = {}
    for finding in findings:
        key = (
            finding.file_path,
            finding.detector,
            finding.category,
            normalize_evidence(finding.evidence),
        )
        groups.setdefault(key, []).append(finding)
    for group in groups.values():
        group.sort(key=lambda item: item.line)
        for index, finding in enumerate(group, start=1):
            finding.set_occurrence(index)


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
    tier: EvidenceTier = EvidenceTier.KEYWORD
    occurrence: int = 1
    legacy_fingerprint: str = ""
    suppressed: bool = False
    suppression_reason: str = ""

    def __post_init__(self) -> None:
        if not self.legacy_fingerprint:
            self.legacy_fingerprint = compute_legacy_fingerprint(
                self.detector,
                self.category,
                self.file_path,
                self.line,
                self.message,
                self.evidence,
            )
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                self.detector,
                self.category,
                self.file_path,
                self.evidence,
                self.occurrence,
            )

    def set_occurrence(self, occurrence: int) -> None:
        self.occurrence = occurrence
        self.fingerprint = compute_fingerprint(
            self.detector,
            self.category,
            self.file_path,
            self.evidence,
            self.occurrence,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
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
            "tier": self.tier.value,
        }
        if self.suppressed:
            payload["suppressed"] = True
            payload["suppression_reason"] = self.suppression_reason
        return payload


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def blocking_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.blocking]
