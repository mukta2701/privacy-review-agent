from __future__ import annotations

import json
import shutil

from click.testing import CliRunner

from privacy_review_agent.cli import main
from privacy_review_agent.models import Confidence, Finding, Severity


def _hide_semgrep(monkeypatch):
    """Isolate keyword-tier assertions from the shipped Semgrep rule pack."""
    real_which = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda *args, **kwargs: None
        if args and args[0] == "semgrep"
        else real_which(*args, **kwargs),
    )


def _secret_probe(target) -> Finding:
    return Finding(
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


def test_unsafe_fixtures_block_only_on_confirmed_secrets(monkeypatch):
    _hide_semgrep(monkeypatch)
    result = CliRunner().invoke(
        main, ["scan", "--path", "tests/fixtures/unsafe", "--format", "json"]
    )
    assert result.exit_code == 2
    doc = json.loads(result.stdout)
    blocking = [f for f in doc["findings"] if f["blocking"]]
    assert blocking, "expected the hardcoded-key fixture to block"
    for finding in blocking:
        assert finding["detector"] == "secrets"
        assert finding["tier"] == "confirmed"
    keyword_detectors = {
        "pii_logging",
        "third_party_transfer",
        "pii_in_prompts",
        "missing_redaction",
        "policy_bypass",
    }
    for finding in doc["findings"]:
        if finding["detector"] in keyword_detectors:
            assert finding["tier"] == "keyword"
            assert finding["blocking"] is False


def test_keyword_only_logging_warns_and_exits_zero(tmp_path, monkeypatch):
    _hide_semgrep(monkeypatch)
    target = tmp_path / "only_keyword.js"
    target.write_text("console.log(req.body)\n")
    result = CliRunner().invoke(
        main, ["scan", "--path", str(target), "--format", "json"]
    )
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert len(doc["findings"]) == 1
    finding = doc["findings"][0]
    assert finding["category"] == "RAW_PII_LOGGING"
    assert finding["confidence"] == "high"
    assert finding["severity"] == "high"
    assert finding["blocking"] is False
    assert finding["tier"] == "keyword"

    md = CliRunner().invoke(main, ["scan", "--path", str(target), "--format", "md"])
    assert md.exit_code == 0
    assert "[WARN] RAW_PII_LOGGING" in md.output
    assert "- Tier: `keyword`" in md.output

    sarif = CliRunner().invoke(
        main, ["scan", "--path", str(target), "--format", "sarif"]
    )
    assert sarif.exit_code == 0
    payload = json.loads(sarif.stdout)
    entry = payload["runs"][0]["results"][0]
    assert entry["level"] == "warning"
    assert entry["properties"]["tier"] == "keyword"


def test_confirmed_secret_blocked_then_cleared_by_baseline_and_suppression(
    tmp_path, monkeypatch
):
    target = tmp_path / "hardcoded.py"
    target.write_text("API_" + 'KEY = "sk_' + 'test_12345678901234567890"\n')

    blocked = CliRunner().invoke(
        main, ["scan", "--path", str(target), "--format", "md"]
    )
    assert blocked.exit_code == 2
    assert "[BLOCK]" in blocked.output
    assert "- Tier: `confirmed`" in blocked.output

    probe = _secret_probe(target)
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps({"fingerprints": [probe.fingerprint]}))
    with_baseline = CliRunner().invoke(
        main,
        ["scan", "--path", str(target), "--baseline-file", str(baseline_file)],
    )
    assert with_baseline.exit_code == 0

    (tmp_path / ".privacy-review-ignore.yaml").write_text(
        f"""entries:
  - id: {probe.fingerprint}
    reason: temporary false positive
    privacy_approver: privacy.lead
    security_approver: security.lead
    created_on: 2099-01-01
    expires_on: 2099-01-10
    ticket: https://github.com/org/repo/issues/123
"""
    )
    monkeypatch.chdir(tmp_path)
    with_suppression = CliRunner().invoke(
        main, ["scan", "--path", str(target)]
    )
    assert with_suppression.exit_code == 0
