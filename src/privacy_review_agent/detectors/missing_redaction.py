from __future__ import annotations

from pathlib import Path

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, Finding, Severity
from privacy_review_agent.utils import (
    has_any_substring,
    has_any_token,
    is_full_line_comment,
    iter_text_files,
)

EVENT_SINK_MARKERS = {
    "logger.info",
    "logger.error",
    "telemetry.track",
    "audit.event",
    "support.log",
}


class MissingRedactionDetector(Detector):
    name = "missing_redaction"

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, lines in iter_text_files(files):
            for idx, line in enumerate(lines, start=1):
                if is_full_line_comment(line):
                    continue
                if not has_any_token(line, EVENT_SINK_MARKERS):
                    continue
                if not has_any_token(line, context.settings.sensitive_fields):
                    continue
                if has_any_substring(line, context.settings.redaction_helpers):
                    continue
                findings.append(
                    Finding(
                        detector=self.name,
                        category="INSUFFICIENT_REDACTION",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=str(path),
                        line=idx,
                        message="Sensitive fields logged or emitted without redaction",
                        evidence=line.strip()[:200],
                        remediation=(
                            "Wrap sensitive fields with approved "
                            "redact/mask/hash/tokenize helpers."
                        ),
                    )
                )
        return findings
