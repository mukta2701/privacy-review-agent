from __future__ import annotations

from pathlib import Path

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, EvidenceTier, Finding, Severity
from privacy_review_agent.utils import has_any_token, is_full_line_comment, iter_text_files

LOG_SINK_MARKERS = {
    "console.log",
    "logger.info",
    "logger.debug",
    "logger.error",
    "print(",
}

SENSITIVE_LOG_MARKERS = {
    "req.body",
    "request.body",
    "req.headers",
    "authorization",
    "cookie",
    "token",
    "chat",
    "upload",
}


class PiiLoggingDetector(Detector):
    name = "pii_logging"

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, lines in iter_text_files(files):
            for idx, line in enumerate(lines, start=1):
                if is_full_line_comment(line):
                    continue
                if not has_any_token(line, LOG_SINK_MARKERS):
                    continue
                if has_any_token(line, SENSITIVE_LOG_MARKERS) or has_any_token(
                    line, context.settings.sensitive_fields
                ):
                    findings.append(
                        Finding(
                            detector=self.name,
                            category="RAW_PII_LOGGING",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=str(path),
                            line=idx,
                            message="Potential raw sensitive data logging",
                            evidence=line.strip()[:200],
                            remediation=(
                                "Log only allowlisted fields and "
                                "apply redaction before logging."
                            ),
                            tier=EvidenceTier.KEYWORD,
                        )
                    )
        return findings
