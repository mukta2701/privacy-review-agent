from __future__ import annotations

import ast
import os
import shutil
from collections.abc import Collection
from pathlib import Path

import click

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, EvidenceTier, Finding, Severity
from privacy_review_agent.semgrep_runner import (
    SemgrepFailed,
    SemgrepMatch,
    SemgrepNotInstalled,
    load_rules,
    metadata_problem,
    run_semgrep,
    taxonomy_categories,
)
from privacy_review_agent.utils import extract_domain

MISSING_NOTICE = (
    "Semgrep structural rules were skipped: the `semgrep` binary is not on PATH. "
    "Install it with `pip install 'privacy-review-agent[semgrep]'` to enable them."
)

TRANSFER_RULE_ID = "python-pii-to-third-party"


def _transfer_url_argument(call: ast.Call) -> ast.expr | None:
    """Return the URL argument of a transfer call, if one is present.

    The `url=` keyword wins when present; otherwise the first positional
    argument, or the second one for `.request(...)` (whose first argument
    is the HTTP method).
    """
    for keyword in call.keywords:
        if keyword.arg == "url":
            return keyword.value
    func = call.func
    name = func.attr if isinstance(func, ast.Attribute) else ""
    index = 1 if name == "request" else 0
    if len(call.args) > index:
        return call.args[index]
    return None


def is_allowlisted_transfer(
    match: SemgrepMatch, file_data: bytes, allowlist: Collection[str]
) -> bool:
    """Whether a third-party-transfer match hits an allowlisted vendor.

    Reads the call text from the file bytes using the match span (Semgrep
    offsets are byte offsets) and drops the finding only when the URL
    argument is a plain string literal whose host is in the allowlist.
    Anything else (non-literal URL, unlisted host, literal without a
    scheme, unparseable span, another rule) is reported.
    """
    if match.rule_id != TRANSFER_RULE_ID:
        return False
    try:
        tree = ast.parse(
            file_data[match.offset : match.end_offset].decode("utf-8", errors="replace")
        )
    except (SyntaxError, ValueError):
        return False
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    if not calls:
        return False
    url = _transfer_url_argument(calls[0])
    if not isinstance(url, ast.Constant) or not isinstance(url.value, str):
        return False
    domain = extract_domain(url.value)
    return bool(domain) and domain in allowlist


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
        rules_dir = context.settings.semgrep_rules_dir
        if rules_dir is None:
            return []
        try:
            rules = load_rules(rules_dir)
        except ValueError as exc:
            self._notify(f"Semgrep rules could not be loaded ({exc}); skipping.")
            return []
        if not rules:
            return []
        existing = [path for path in files if path.exists() and path.is_file()]
        if not existing:
            return []
        try:
            matches = run_semgrep(existing, rules_dir)
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
            data = _read_bytes(by_realpath[real])
            if data is None:
                continue
            lines = data.decode("utf-8", errors="ignore").splitlines()
            if match.line > len(lines):
                continue
            if is_allowlisted_transfer(match, data, context.settings.vendor_allowlist):
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
        return sorted(findings, key=lambda finding: (finding.file_path, finding.line))


def _read_bytes(file_path: str) -> bytes | None:
    try:
        return Path(file_path).read_bytes()
    except OSError:
        return None
