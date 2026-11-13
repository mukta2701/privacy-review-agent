from __future__ import annotations

from pathlib import Path

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, EvidenceTier, Finding, Severity
from privacy_review_agent.utils import has_any_token, is_full_line_comment, iter_text_files

PROMPT_SINK_MARKERS = {
    "prompt",
    "messages=",
    "input=",
    "chat.completions",
    "responses.create",
}


class PiiInPromptsDetector(Detector):
    name = "pii_in_prompts"

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        all_markers = context.settings.sensitive_fields | context.settings.quasi_identifiers

        for path, lines in iter_text_files(files):
            for idx, line in enumerate(lines, start=1):
                if is_full_line_comment(line):
                    continue
                if not has_any_token(line, PROMPT_SINK_MARKERS):
                    continue
                if not has_any_token(line, all_markers):
                    continue

                severity = Severity.HIGH
                confidence = Confidence.HIGH
                if any(helper in line.lower() for helper in context.settings.redaction_helpers):
                    severity = Severity.MEDIUM
                    confidence = Confidence.MEDIUM

                findings.append(
                    Finding(
                        detector=self.name,
                        category="PII_IN_MODEL_PROMPT",
                        severity=severity,
                        confidence=confidence,
                        file_path=str(path),
                        line=idx,
                        message="Potential raw personal/quasi-identifier data in LLM prompt",
                        evidence=line.strip()[:200],
                        remediation="Redact/tokenize personal data before prompt construction.",
                        tier=EvidenceTier.KEYWORD,
                    )
                )
        return findings
