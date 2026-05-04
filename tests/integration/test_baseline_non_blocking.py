import json

from click.testing import CliRunner

from privacy_review_agent.cli import main
from privacy_review_agent.models import Confidence, Finding, Severity


def test_baseline_fingerprint_non_blocking(tmp_path):
    target = tmp_path / "hardcoded.py"
    target.write_text('API_KEY = "sk_test_12345678901234567890"')

    probe = Finding(
        detector="secrets",
        category="SECRET_EXPOSURE",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path=str(target),
        line=1,
        message="Potential hardcoded secret detected",
        evidence=target.read_text().strip(),
        remediation="Remove secret",
    )

    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps({"fingerprints": [probe.fingerprint]}))

    result = CliRunner().invoke(
        main,
        ["scan", "--path", str(target), "--baseline-file", str(baseline_file)],
    )
    assert result.exit_code == 0
