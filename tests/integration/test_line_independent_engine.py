"""Engine-level line-stability checks (Phase 1)."""

from __future__ import annotations

from pathlib import Path

from privacy_review_agent.engine import ReviewEngine

SECRET_LINE = 'API_KEY = "sk_test_12345678901234567890"'


def _scan(target: Path):
    return ReviewEngine().scan_files([target])


def test_fingerprint_stable_when_lines_shift(tmp_path):
    target = tmp_path / "hardcoded.py"
    target.write_text(f"{SECRET_LINE}\n")
    before = _scan(target)
    assert len(before.findings) == 1
    first = before.findings[0]

    target.write_text(f"# comment\n\n\n{SECRET_LINE}\n")
    after = _scan(target)
    assert len(after.findings) == 1
    second = after.findings[0]

    assert second.line != first.line
    assert second.fingerprint == first.fingerprint


def test_identical_lines_get_distinct_fingerprints(tmp_path):
    target = tmp_path / "twice.py"
    target.write_text(f"{SECRET_LINE}\n{SECRET_LINE}\n")
    result = _scan(target)
    assert len(result.findings) == 2
    fingerprints = {finding.fingerprint for finding in result.findings}
    assert len(fingerprints) == 2
    assert sorted(finding.occurrence for finding in result.findings) == [1, 2]


def test_single_secret_line_dedups_with_occurrence_one(tmp_path):
    target = tmp_path / "once.py"
    target.write_text(f"{SECRET_LINE}\n")
    result = _scan(target)
    assert len(result.findings) == 1
    assert result.findings[0].occurrence == 1
