"""Unit tests for personal-mode inline suppressions (`privacy-ok` markers)."""

import json
from pathlib import Path

from privacy_review_agent.config import load_settings
from privacy_review_agent.engine import ReviewEngine
from privacy_review_agent.models import Confidence, Finding, ScanResult, Severity
from privacy_review_agent.reporters.json_reporter import render as render_json
from privacy_review_agent.reporters.markdown_reporter import render as render_md
from privacy_review_agent.reporters.sarif_reporter import render as render_sarif
from privacy_review_agent.suppressions import parse_inline_suppression_reason

_TEST_KEY = "sk_" + "test_12345678901234567890"
SECRET_LINE = 'API_KEY = "' + _TEST_KEY + '"'


def _write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_hash_marker_with_reason_parses():
    line = f"{SECRET_LINE}  # privacy-ok: test fixture"
    assert parse_inline_suppression_reason(line) == "test fixture"


def test_slash_marker_with_reason_parses():
    line = 'const k = "' + _TEST_KEY + '"; // privacy-ok: test fixture'
    assert parse_inline_suppression_reason(line) == "test fixture"


def test_marker_without_colon_parses_nothing():
    assert parse_inline_suppression_reason(f"{SECRET_LINE}  # privacy-ok") is None


def test_marker_with_empty_reason_parses_nothing():
    assert parse_inline_suppression_reason(f"{SECRET_LINE}  # privacy-ok:") is None
    assert parse_inline_suppression_reason(f"{SECRET_LINE}  # privacy-ok:   ") is None


def test_line_without_marker_parses_nothing():
    assert parse_inline_suppression_reason(SECRET_LINE) is None


def test_personal_mode_suppresses_same_line_hash_marker(tmp_path):
    target = _write(tmp_path / "marked.py", f"{SECRET_LINE}  # privacy-ok: test fixture\n")
    settings = load_settings()
    settings.mode = "personal"
    result = ReviewEngine(settings=settings).scan_files([Path(target)])
    assert result.blocking_findings() == []
    assert len(result.findings) == 1
    assert result.findings[0].suppressed is True
    assert result.findings[0].suppression_reason == "test fixture"


def test_personal_mode_suppresses_same_line_slash_marker(tmp_path):
    target = _write(
        tmp_path / "marked.js",
        'const key = "' + _TEST_KEY + '"; // privacy-ok: test fixture\n',
    )
    settings = load_settings()
    settings.mode = "personal"
    result = ReviewEngine(settings=settings).scan_files([Path(target)])
    assert result.blocking_findings() == []
    assert result.findings[0].suppressed is True


def test_org_mode_ignores_marker(tmp_path):
    target = _write(tmp_path / "marked.py", f'{SECRET_LINE}  # privacy-ok: test fixture\n')
    settings = load_settings()
    settings.mode = "org"
    result = ReviewEngine(settings=settings).scan_files([Path(target)])
    assert len(result.blocking_findings()) == 1
    assert all(finding.suppressed is False for finding in result.findings)


def test_json_reporter_marks_suppressed_finding(sample_finding):
    sample_finding.suppressed = True
    sample_finding.suppression_reason = "test fixture"
    doc = json.loads(render_json(ScanResult(findings=[sample_finding])))
    assert doc["findings"][0]["suppressed"] is True
    assert doc["findings"][0]["suppression_reason"] == "test fixture"


def test_json_reporter_omits_suppression_keys_when_not_suppressed(sample_finding):
    doc = json.loads(render_json(ScanResult(findings=[sample_finding])))
    assert "suppressed" not in doc["findings"][0]
    assert "suppression_reason" not in doc["findings"][0]


def test_markdown_reporter_shows_suppressed_finding(sample_finding):
    sample_finding.suppressed = True
    sample_finding.suppression_reason = "test fixture"
    sample_finding.blocking = False
    md = render_md(ScanResult(findings=[sample_finding]))
    assert "SUPPRESSED" in md
    assert "test fixture" in md
    assert "Suppressed: **1**" in md


def test_markdown_reporter_without_suppressed_matches_today(sample_finding):
    md = render_md(ScanResult(findings=[sample_finding]))
    assert "Suppressed:" not in md


def test_sarif_reporter_shows_in_source_suppression(sample_finding):
    sample_finding.suppressed = True
    sample_finding.suppression_reason = "test fixture"
    sample_finding.blocking = False
    doc = json.loads(render_sarif(ScanResult(findings=[sample_finding])))
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "warning"
    assert result["suppressions"][0]["kind"] == "inSource"
    assert result["suppressions"][0]["justification"] == "test fixture"


def test_sarif_reporter_omits_suppressions_key_when_not_suppressed(sample_finding):
    doc = json.loads(render_sarif(ScanResult(findings=[sample_finding])))
    assert "suppressions" not in doc["runs"][0]["results"][0]


def test_suppressed_does_not_change_fingerprint():
    kwargs = {
        "detector": "secrets",
        "category": "SECRET_EXPOSURE",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "file_path": "app.py",
        "line": 5,
        "message": "Hardcoded API key",
        "evidence": 'API_KEY = "' + _TEST_KEY + '"',
        "remediation": "Move to secret manager",
    }
    plain = Finding(**kwargs)
    marked = Finding(**kwargs, suppressed=True, suppression_reason="test fixture")
    assert marked.fingerprint == plain.fingerprint
    assert marked.legacy_fingerprint == plain.legacy_fingerprint
