from __future__ import annotations

import json

from privacy_review_agent.engine import ReviewEngine
from privacy_review_agent.models import (
    Confidence,
    EvidenceTier,
    Finding,
    ScanResult,
    Severity,
)
from privacy_review_agent.reporters.json_reporter import render as render_json
from privacy_review_agent.reporters.markdown_reporter import render as render_md
from privacy_review_agent.reporters.sarif_reporter import render as render_sarif


def _finding(**overrides):
    base = {
        "detector": "pii_logging",
        "category": "RAW_PII_LOGGING",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "file_path": "app.js",
        "line": 3,
        "message": "Potential raw sensitive data logging",
        "evidence": "console.log(req.body)",
        "remediation": "Redact before logging.",
    }
    base.update(overrides)
    return Finding(**base)


def test_tier_enum_values():
    assert [t.value for t in EvidenceTier] == ["confirmed", "keyword"]


def test_default_tier_is_keyword():
    finding = _finding()
    assert finding.tier is EvidenceTier.KEYWORD


def test_to_dict_includes_tier():
    finding = _finding(tier=EvidenceTier.CONFIRMED)
    assert finding.to_dict()["tier"] == "confirmed"
    assert _finding().to_dict()["tier"] == "keyword"


def test_tier_not_in_fingerprint():
    assert _finding(tier=EvidenceTier.KEYWORD).fingerprint == _finding(
        tier=EvidenceTier.CONFIRMED
    ).fingerprint


def test_reporters_show_tier():
    finding = _finding(tier=EvidenceTier.KEYWORD)
    result = ScanResult(findings=[finding])
    assert json.loads(render_json(result))["findings"][0]["tier"] == "keyword"
    sarif = json.loads(render_sarif(result))
    assert sarif["runs"][0]["results"][0]["properties"]["tier"] == "keyword"
    assert "- Tier: `keyword`" in render_md(result)


def test_engine_blocks_confirmed_not_keyword():
    engine = ReviewEngine()
    keyword = _finding(tier=EvidenceTier.KEYWORD)
    confirmed = _finding(tier=EvidenceTier.CONFIRMED)
    assert engine._is_blocking(keyword, True) is False
    assert engine._is_blocking(confirmed, True) is True
