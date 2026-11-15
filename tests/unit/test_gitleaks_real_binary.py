"""Optional real-binary gitleaks test.

Runs the real ``gitleaks`` binary when it is on PATH, and skips otherwise.
It never installs or downloads gitleaks.
"""

import shutil

import pytest

from privacy_review_agent.detectors.secrets import SecretsDetector

# Split so the literal test key never appears in source.
_TEST_KEY = "sk_" + "test_12345678901234567890"


@pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks binary not on PATH"
)
def test_real_gitleaks_scans_only_source_file(tmp_path):
    scanned = tmp_path / "scanned.py"
    unscanned = tmp_path / "other.py"
    scanned.write_text('API_KEY = "' + _TEST_KEY + '"\n')
    unscanned.write_text('API_KEY = "' + _TEST_KEY + '"\n')
    findings = SecretsDetector()._scan_with_gitleaks([scanned])
    assert findings
    assert any("scanned" in finding.file_path for finding in findings)
    assert all("other" not in finding.file_path for finding in findings)
