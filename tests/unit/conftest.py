from __future__ import annotations

import pytest

from privacy_review_agent.models import Confidence, Finding, Severity


def pytest_assertrepr_compare(op, left, right):
    return None

@pytest.fixture()
def sample_finding() -> Finding:
    return Finding(
        detector="secrets",
        category="SECRET_EXPOSURE",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line=5,
        message="Hardcoded API key",
        evidence='API_KEY = "sk_test_1234567890123"',
        remediation="Move to secret manager",
    )
