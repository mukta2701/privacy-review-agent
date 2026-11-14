"""Line-independent fingerprints (Phase 1)."""

from __future__ import annotations

from privacy_review_agent.models import Confidence, Finding, Severity


def _finding(**overrides):
    base = {
        "detector": "secrets",
        "category": "SECRET_EXPOSURE",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "file_path": "a.py",
        "line": 1,
        "message": "Potential hardcoded secret detected",
        "evidence": 'API_KEY = "sk_test_12345678901234567890"',
        "remediation": "Remove secret",
    }
    base.update(overrides)
    return Finding(**base)


def test_fingerprint_stable_under_line_and_message_shifts():
    first = _finding(line=1, message="Potential hardcoded secret detected")
    second = _finding(line=42, message="Something completely different")
    assert first.fingerprint == second.fingerprint


def test_identical_evidence_different_files_differ():
    assert _finding(file_path="a.py").fingerprint != _finding(file_path="b.py").fingerprint


def test_whitespace_normalisation():
    base = _finding(evidence='API_KEY = "sk_test_12345678901234567890"')
    padded = _finding(evidence='   API_KEY   =   "sk_test_12345678901234567890"   ')
    assert base.fingerprint == padded.fingerprint
    other = _finding(evidence='API_KEY = "sk_live_AAAAAAAAAAAAAAAAAAAAAA"')
    assert base.fingerprint != other.fingerprint


def test_legacy_fingerprint_uses_old_formula():
    finding = _finding()
    assert finding.legacy_fingerprint != finding.fingerprint
    moved = _finding(line=99)
    assert moved.legacy_fingerprint != finding.legacy_fingerprint
    assert moved.fingerprint == finding.fingerprint


def test_to_dict_has_no_legacy_fingerprint():
    assert "legacy_fingerprint" not in _finding().to_dict()
