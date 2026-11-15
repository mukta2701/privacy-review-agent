from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, EvidenceTier, Finding, Severity
from privacy_review_agent.semgrep_runner import _target_arg
from privacy_review_agent.utils import iter_text_files

SECRET_PATTERNS = [
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
]


def _merge_secret_findings(
    gitleaks_findings: list[Finding], regex_findings: list[Finding]
) -> list[Finding]:
    seen = {
        (os.path.realpath(finding.file_path), finding.line)
        for finding in gitleaks_findings
    }
    merged = list(gitleaks_findings)
    merged.extend(
        finding
        for finding in regex_findings
        if (os.path.realpath(finding.file_path), finding.line) not in seen
    )
    return sorted(merged, key=lambda finding: (finding.file_path, finding.line, finding.category))


class SecretsDetector(Detector):
    name = "secrets"

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        gitleaks_findings = self._scan_with_gitleaks(files)
        regex_findings = self._scan_with_patterns(files, context)
        return _merge_secret_findings(gitleaks_findings, regex_findings)

    def _scan_with_patterns(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        out: list[Finding] = []
        for path, lines in iter_text_files(files):
            for idx, line in enumerate(lines, start=1):
                for pattern in SECRET_PATTERNS:
                    if not pattern.search(line):
                        continue
                    confidence = Confidence.HIGH
                    if context.settings.allow_verifier_egress and not context.settings.offline_mode:
                        confidence = self._verify_when_supported(line)
                    out.append(
                        Finding(
                            detector=self.name,
                            category="SECRET_EXPOSURE",
                            severity=Severity.CRITICAL,
                            confidence=confidence,
                            file_path=str(path),
                            line=idx,
                            message="Potential hardcoded secret detected",
                            evidence=line.strip()[:200],
                            remediation=(
                                "Remove secret from code, rotate credential, "
                                "and move to approved secret manager."
                            ),
                            tier=EvidenceTier.CONFIRMED,
                        )
                    )
                    break
        return out

    def _verify_when_supported(self, line: str) -> Confidence:
        # Hook for optional live verification integrations. For MVP we keep this conservative.
        if "sk_live_" in line or "AKIA" in line:
            return Confidence.HIGH
        return Confidence.MEDIUM

    def _scan_with_gitleaks(self, files: list[Path]) -> list[Finding]:
        if not shutil.which("gitleaks"):
            return []

        file_args = [_target_arg(path) for path in files if path.exists()]
        if not file_args:
            return []

        cmd = [
            "gitleaks",
            "detect",
            "--no-git",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--",
            *file_args,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except OSError:
            return []

        if result.returncode not in (0, 1):
            return []

        try:
            entries = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for entry in entries:
            findings.append(
                Finding(
                    detector=self.name,
                    category="SECRET_EXPOSURE",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    file_path=str(entry.get("File", "")),
                    line=int(entry.get("StartLine", 1)),
                    message=str(entry.get("Description", "Potential secret detected")),
                    evidence=str(entry.get("Match", ""))[:200],
                    remediation="Remove secret from code and rotate credential.",
                    tier=EvidenceTier.CONFIRMED,
                )
            )
        return findings
