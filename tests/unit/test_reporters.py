import json

from privacy_review_agent.models import ScanResult
from privacy_review_agent.reporters.json_reporter import render as render_json
from privacy_review_agent.reporters.markdown_reporter import render as render_md
from privacy_review_agent.reporters.sarif_reporter import render as render_sarif


def test_sarif_contains_rule_id(sample_finding):
    sarif = render_sarif(ScanResult(findings=[sample_finding]))
    assert "SECRET_EXPOSURE" in sarif


def test_json_reporter_valid_json(sample_finding):
    payload = render_json(ScanResult(findings=[sample_finding]))
    doc = json.loads(payload)
    assert doc["findings"][0]["category"] == "SECRET_EXPOSURE"


def test_markdown_reporter_has_patch_hint(sample_finding):
    md = render_md(ScanResult(findings=[sample_finding]))
    assert "Suggested patch" in md
