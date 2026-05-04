from privacy_review_agent.models import Confidence, Finding, Severity
from privacy_review_agent.suppressions import is_suppressed, load_suppressions


def test_finding_suppressed_with_expiry(tmp_path):
    policy_file = tmp_path / ".privacy-review-ignore.yaml"
    finding = Finding(
        detector="secrets",
        category="SECRET_EXPOSURE",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="a.py",
        line=1,
        message="x",
        evidence="y",
        remediation="z",
    )
    policy_file.write_text(
        f"""
max_ttl_days: 14
require_github_issue: true
entries:
  - id: {finding.fingerprint}
    reason: temporary false positive
    privacy_approver: privacy.lead
    security_approver: security.lead
    created_on: 2099-01-01
    expires_on: 2099-01-10
    ticket: https://github.com/org/repo/issues/123
"""
    )
    policy = load_suppressions(policy_file)
    assert is_suppressed(finding, policy)
