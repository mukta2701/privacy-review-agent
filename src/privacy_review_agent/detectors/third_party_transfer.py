from __future__ import annotations

from pathlib import Path

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, EvidenceTier, Finding, Severity
from privacy_review_agent.utils import (
    extract_domain,
    has_any_token,
    is_full_line_comment,
    iter_text_files,
)

TRANSFER_SINKS = {
    "requests.post",
    "requests.get",
    "fetch(",
    "axios.post",
    "axios.get",
    "webhook",
}


class ThirdPartyTransferDetector(Detector):
    name = "third_party_transfer"

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, lines in iter_text_files(files):
            for idx, line in enumerate(lines, start=1):
                if is_full_line_comment(line):
                    continue
                if not has_any_token(line, TRANSFER_SINKS):
                    continue
                if not has_any_token(line, context.settings.sensitive_fields):
                    continue
                domain = extract_domain(line)
                if domain and domain in context.settings.vendor_allowlist:
                    continue
                findings.append(
                    Finding(
                        detector=self.name,
                        category="THIRD_PARTY_PII_TRANSFER",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        file_path=str(path),
                        line=idx,
                        message=(
                            "Sensitive data appears to be sent "
                            "to unapproved external destination"
                        ),
                        evidence=line.strip()[:200],
                        remediation=(
                            "Use approved vendor allowlist and "
                            "minimize or redact PII before transfer."
                        ),
                        tier=EvidenceTier.KEYWORD,
                    )
                )
        return findings
