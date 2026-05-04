from privacy_review_agent.models import Confidence, Finding, Severity


def test_finding_serializes():
    finding = Finding(
        detector="secrets",
        category="SECRET_EXPOSURE",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line=10,
        message="Hardcoded API key",
        evidence="sk_live_...",
        remediation="Rotate key",
    )
    payload = finding.to_dict()
    assert payload["category"] == "SECRET_EXPOSURE"
    assert payload["severity"] == Severity.CRITICAL.value
    assert payload["fingerprint"]
