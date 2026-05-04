from __future__ import annotations

from privacy_review_agent.models import ScanResult


def _patch_hint(finding_line: str) -> str:
    note = "# TODO: redact/minimize sensitive fields before this operation"
    return f"```diff\n- {finding_line}\n+ {note}\n```"


def render(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("# Privacy Review Report")
    lines.append("")
    lines.append(f"- Findings: **{len(result.findings)}**")
    lines.append(f"- Blocking: **{len(result.blocking_findings())}**")
    lines.append("")

    if not result.findings:
        lines.append("No findings detected.")
        return "\n".join(lines)

    for finding in result.findings:
        status = "BLOCK" if finding.blocking else "WARN"
        lines.append(
            f"## [{status}] {finding.category} — {finding.file_path}:{finding.line}"
        )
        lines.append(f"- Severity: `{finding.severity.value}`")
        lines.append(f"- Confidence: `{finding.confidence.value}`")
        lines.append(f"- Message: {finding.message}")
        lines.append(f"- Evidence: `{finding.evidence}`")
        lines.append(f"- Remediation: {finding.remediation}")
        lines.append(f"- Fingerprint: `{finding.fingerprint}`")
        lines.append("")
        lines.append("Suggested patch:")
        lines.append(_patch_hint(finding.evidence))
        lines.append("")

    return "\n".join(lines)
