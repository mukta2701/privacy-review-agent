from __future__ import annotations

import os
import shutil
from pathlib import Path

import click

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, EvidenceTier, Finding, Severity
from privacy_review_agent.semgrep_runner import (
    SemgrepFailed,
    SemgrepNotInstalled,
    load_rules,
    metadata_problem,
    run_semgrep,
    taxonomy_categories,
)

MISSING_NOTICE = (
    "Semgrep structural rules were skipped: the `semgrep` binary is not on PATH. "
    "Install it with `pip install 'privacy-review-agent[semgrep]'` to enable them."
)


class SemgrepDetector(Detector):
    name = "semgrep"

    def __init__(self) -> None:
        self._notices: set[str] = set()

    def _notify(self, message: str) -> None:
        if message in self._notices:
            return
        self._notices.add(message)
        click.echo(message, err=True)

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        if shutil.which("semgrep") is None:
            self._notify(MISSING_NOTICE)
            return []
        try:
            rules = load_rules(context.settings.semgrep_rules_dir)
        except ValueError as exc:
            self._notify(f"Semgrep rules could not be loaded ({exc}); skipping.")
            return []
        if not rules:
            return []
        existing = [path for path in files if path.exists() and path.is_file()]
        if not existing:
            return []
        try:
            assert context.settings.semgrep_rules_dir is not None
            matches = run_semgrep(existing, context.settings.semgrep_rules_dir)
        except SemgrepNotInstalled:
            self._notify(MISSING_NOTICE)
            return []
        except SemgrepFailed as exc:
            self._notify(f"Semgrep scan failed ({exc}); continuing without findings.")
            return []
        categories = taxonomy_categories()
        by_realpath = {os.path.realpath(str(path)): str(path) for path in existing}
        findings: list[Finding] = []
        for match in matches:
            real = os.path.realpath(match.path)
            if real not in by_realpath:
                continue
            problem = metadata_problem(match.metadata, categories)
            if problem is not None:
                self._notify(f"Semgrep rule {match.rule_id} skipped: {problem}.")
                continue
            lines = _read_lines(by_realpath[real])
            if lines is None or match.line > len(lines):
                continue
            findings.append(
                Finding(
                    detector=self.name,
                    category=str(match.metadata["category"]),
                    severity=Severity(str(match.metadata["severity"])),
                    confidence=Confidence(str(match.metadata["confidence"])),
                    file_path=by_realpath[real],
                    line=match.line,
                    message=f"{match.rule_id}: {match.message}",
                    evidence=lines[match.line - 1].strip()[:200],
                    remediation=str(match.metadata["remediation"]),
                    tier=EvidenceTier.CONFIRMED,
                )
            )
        return sorted(
            findings, key=lambda finding: (finding.file_path, finding.line)
        )


def _read_lines(file_path: str) -> list[str] | None:
    try:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
