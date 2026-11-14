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
