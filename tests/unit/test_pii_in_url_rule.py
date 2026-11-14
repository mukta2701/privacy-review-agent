"""Pure-Python checks for the PII-in-URL Semgrep rule.

Runs without semgrep: loads the rule YAML via ``load_rules``, validates the
metadata, and locks the YAML-data conventions (framework redirect and
``url_for`` sinks, the per-origin import gates, and copied sources and
sanitisers) so the new rule cannot drift from
``python-pii-in-tool-result``. Also locks the appended calibration cases
and their positive/near-miss balance.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from privacy_review_agent.semgrep_harness import check_rule_metadata
from privacy_review_agent.semgrep_runner import load_rules

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")
RULE_ID = "python-pii-in-url"
RULE_FILE = "python-pii-in-url.yaml"
TOOL_RESULT_FILE = "python-pii-in-tool-result.yaml"
MANIFEST = Path("tests/fixtures/labelled/cases.jsonl")

MATCH_CONTROLS = (
    "user.phone_number",
    "user.email_address",
    "user.ssn_last4",
    "user.emailVerified",
)
NOMATCH_CONTROLS = (
    "email_count",
    "settings.EMAIL_HOST",
    "ssn_pattern",
    "phone_type",
    "emails",
    "useremail",
    "user.email_domain",
)


def _rule_doc() -> dict:
    for doc in yaml.safe_load((PACK / RULE_FILE).read_text(encoding="utf-8"))["rules"]:
        if doc["id"] == RULE_ID:
            return doc
    raise AssertionError(f"rule {RULE_ID} not found in {RULE_FILE}")


def _metavariable_regexes(doc: dict) -> list[str]:
    values: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for key, item in node.items():
                if key == "metavariable-regex" and isinstance(item, dict):
                    values.append(item["regex"])
                else:
                    walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for source in doc.get("pattern-sources", []):
        walk(source)
    return values


def test_rule_loads_with_url_metadata():
    rules = load_rules(PACK)
    by_id = {rule.id: rule for rule in rules}

    assert RULE_ID in by_id
    assert check_rule_metadata(PACK) == []
    assert by_id[RULE_ID].metadata["category"] == "PII_IN_URL"
    assert by_id[RULE_ID].metadata["severity"] == "high"
    assert by_id[RULE_ID].metadata["confidence"] == "high"
    remediation = by_id[RULE_ID].metadata["remediation"]
    assert remediation.strip()
    assert "opaque id" in remediation or "token" in remediation

    taxonomy = yaml.safe_load(
        Path("src/privacy_review_agent/policies/taxonomy.yaml").read_text(
            encoding="utf-8"
        )
    )
    defaults = {
        entry["id"]: entry.get("severity_default")
        for entry in taxonomy.get("categories", [])
    }
    assert defaults.get("PII_IN_URL") == "high"


def test_sources_and_sanitisers_match_tool_result_rule():
    new_doc = _rule_doc()
    other_docs = yaml.safe_load((PACK / TOOL_RESULT_FILE).read_text(encoding="utf-8"))[
        "rules"
    ]
    other_doc = next(doc for doc in other_docs if doc["id"] == "python-pii-in-tool-result")

    assert new_doc["pattern-sources"] == other_doc["pattern-sources"]
    assert new_doc["pattern-sanitizers"] == other_doc["pattern-sanitizers"]


def test_sink_covers_each_framework_form_with_resolution():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    assert "flask.redirect" in text
    assert "flask.url_for" in text
    assert "django.shortcuts.redirect" in text
    assert "django.http.HttpResponseRedirect" in text
    assert "django.http.HttpResponsePermanentRedirect" in text
    assert "starlette.responses.RedirectResponse" in text
    assert "fastapi.responses.RedirectResponse" in text
    assert "$CALLEE" in text


def test_bare_sinks_exclude_local_and_module_level_rebinding():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    assert "def $G(...):" in text
    assert "async def $G(...):" in text
    assert "from $M import $F" in text
    assert "def $F(...):" in text
    assert "async def $F(...):" in text
    assert "class $F(...):" in text
    assert "$F = $V" in text
    assert "str($F) == str($I)" in text


def _rule_code() -> str:
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_no_arbitrary_receiver_sink():
    lines = _rule_code().splitlines()
    text = "\n".join(lines)

    assert "$OBJ.redirect" not in text
    assert "$OBJ.url_for" not in text
    assert "$RESPONSE" not in text
    assert "$X.redirect" not in text


def test_name_boundaries_match_derived_and_reject_near_miss():
    regexes = _metavariable_regexes(_rule_doc())
    assert regexes

    import re

    for control in MATCH_CONTROLS:
        assert any(re.fullmatch(pattern, control) for pattern in regexes), control
    for control in NOMATCH_CONTROLS:
        assert not any(re.fullmatch(pattern, control) for pattern in regexes), control


def test_appended_corpus_cases_are_valid_and_balanced():
    cases = [
        json.loads(row)
        for row in MANIFEST.read_text(encoding="utf-8").splitlines()
        if row.strip()
    ]
    new = [case for case in cases if "-url-" in case["id"]]
    assert new, "no python-pii-in-url corpus cases found"

    old_total = len(cases) - len(new)
    assert old_total == 330
    assert len(cases) <= 500

    old_ids = [case["id"] for case in cases if "-url-" not in case["id"]]
    assert len(set(old_ids)) == len(old_ids) == old_total
    assert len({case["id"] for case in new}) == len(new)

    positives = [case for case in new if case["kind"] == "true"]
    near_misses = [case for case in new if case["kind"] == "near_miss"]
    assert len(positives) >= len(near_misses) >= 1
    assert all(case["expect"] == ["semgrep"] for case in positives)
    assert all(case["expect"] == [] for case in near_misses)
    assert all(case["ext"] == "py" for case in new)

    for case in new:
        raw = base64.b64decode(case["text_b64"]).decode("utf-8")
        assert raw and "\r" not in raw
        if "\n" in raw:
            assert "multiline" in case["tags"], case["id"]

    share = (177 + len(near_misses)) / len(cases)
    assert 0.45 <= share <= 0.55
