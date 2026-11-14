"""Legacy suppression ids still suppress (Phase 1)."""

from __future__ import annotations

from privacy_review_agent.models import Confidence, Finding, Severity
from privacy_review_agent.suppressions import SuppressionPolicy, is_suppressed


def _finding(**overrides):
    base = {
        "detector": "secrets",
        "category": "SECRET_EXPOSURE",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "file_path": "a.py",
        "line": 7,
        "message": "Potential hardcoded secret detected",
        "evidence": 'API_KEY = "sk_test_12345678901234567890"',
        "remediation": "Remove secret",
    }
    base.update(overrides)
    return Finding(**base)


def _policy(entry_id: str, **overrides) -> SuppressionPolicy:
    entry = {
        "id": entry_id,
        "reason": "temporary false positive",
        "privacy_approver": "privacy.lead",
        "security_approver": "security.lead",
        "created_on": "2099-01-01",
        "expires_on": "2099-01-10",
        "ticket": "https://github.com/org/repo/issues/123",
    }
    entry.update(overrides)
    return SuppressionPolicy(max_ttl_days=14, require_github_issue=True, entries=[entry])


def test_legacy_id_suppresses_when_valid():
    finding = _finding()
    assert finding.legacy_fingerprint != finding.fingerprint
    assert is_suppressed(finding, _policy(finding.legacy_fingerprint)) is True


def test_legacy_id_does_not_bypass_validity_rules():
    finding = _finding()
    expired = _policy(finding.legacy_fingerprint, expires_on="2000-01-01")
    assert is_suppressed(finding, expired) is False
    no_ticket = _policy(finding.legacy_fingerprint)
    del no_ticket.entries[0]["ticket"]
    assert is_suppressed(finding, no_ticket) is False
