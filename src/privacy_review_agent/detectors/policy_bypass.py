from __future__ import annotations

from pathlib import Path

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, Finding, Severity
from privacy_review_agent.utils import has_any_token, iter_text_files

STATIC_BYPASS_PATTERNS = {
    "if (true)",
    "if true:",
    "consent = true",
    "privacy_check = false",
}


class PolicyBypassDetector(Detector):
    name = "policy_bypass"

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, lines in iter_text_files(files):
            for idx, line in enumerate(lines, start=1):
                low = line.lower()
                if has_any_token(low, STATIC_BYPASS_PATTERNS) or has_any_token(
                    low, context.settings.bypass_markers
                ):
                    findings.append(
                        Finding(
                            detector=self.name,
                            category="POLICY_BYPASS",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file_path=str(path),
                            line=idx,
                            message="Potential privacy or consent policy bypass",
                            evidence=line.strip()[:200],
                            remediation=(
                                "Remove bypass and enforce "
                                "consent/privacy/redaction checks."
                            ),
                        )
                    )
        return findings
