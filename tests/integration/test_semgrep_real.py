"""Real-Semgrep tests: skipped when semgrep is absent, run in CI."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from privacy_review_agent.cli import main

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)


def _policies_with_fixture_pack(tmp_path: Path) -> Path:
    dest = tmp_path / "policies"
    shutil.copytree(Path("src/privacy_review_agent/policies"), dest)
    pack = dest / "semgrep_rules"
    pack.mkdir(exist_ok=True)
    for name in ("sample.yaml", "sample.py"):
        shutil.copy(Path("tests/fixtures/semgrep_rules") / name, pack / name)
    return dest


@needs_semgrep
def test_harness_passes_on_fixture_pack():
    from privacy_review_agent.semgrep_harness import run_rule_tests

    result = run_rule_tests(Path("tests/fixtures/semgrep_rules"))

    assert result.failures == []
    assert (result.rules, result.cases) == (1, 2)


def _write_nosem_pack(pack: Path) -> Path:
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "tmp.yaml").write_text(
        """\
rules:
  - id: tmp-nosem-rule
    languages: [python]
    severity: WARNING
    message: Raw PII written to logs without redaction
    metadata:
      category: RAW_PII_LOGGING
      severity: high
      confidence: high
      remediation: Redact or mask PII before logging.
    patterns:
      - pattern: print($X, ...)
      - metavariable-regex:
          metavariable: $X
          regex: (?i).*\\b(email|ssn|phone)\\b.*
""",
        encoding="utf-8",
    )
    (pack / "tmp.py").write_text(
        "# ruleid: tmp-nosem-rule\n"
        "print(user.email)  # nosemgrep\n"
        "# ok: tmp-nosem-rule\n"
        'print("hello")\n',
        encoding="utf-8",
    )
    return pack


@needs_semgrep
def test_nosemgrep_comment_does_not_suppress_finding(tmp_path):
    from privacy_review_agent.semgrep_harness import run_rule_tests

    result = run_rule_tests(_write_nosem_pack(tmp_path / "pack"))

    assert result.failures == []
    assert (result.rules, result.cases) == (1, 2)


@needs_semgrep
def test_semgrepignore_does_not_hide_explicit_targets(tmp_path, monkeypatch):
    from privacy_review_agent.semgrep_harness import run_rule_tests

    pack = _write_nosem_pack(tmp_path / "pack")
    (tmp_path / ".semgrepignore").write_text("tmp.py\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = run_rule_tests(pack)

    assert result.failures == []
    assert (result.rules, result.cases) == (1, 2)


@needs_semgrep
def test_cli_scan_blocks_on_confirmed_semgrep_finding(tmp_path):
    policies = _policies_with_fixture_pack(tmp_path)
    target = Path("tests/fixtures/semgrep_rules/sample.py")
    args = [
        "scan",
        "--policies-dir",
        str(policies),
        "--path",
        str(target),
        "--format",
        "json",
    ]

    first = CliRunner().invoke(main, args)
    assert first.exit_code == 2, first.output
    doc = json.loads(first.stdout)
    blocking = [f for f in doc["findings"] if f["blocking"]]
    assert blocking
    assert all(
        f["detector"] == "semgrep" and f["tier"] == "confirmed" for f in blocking
    )

    second = CliRunner().invoke(main, args)
    assert second.stdout == first.stdout
