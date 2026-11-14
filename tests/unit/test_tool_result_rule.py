"""Pure-Python checks for the PII-in-tool-result Semgrep rule.

Runs without semgrep: loads the rule YAML via ``load_rules``, validates the
metadata, and locks the YAML-data conventions (decorator sinks, the import
gate for ``@tool``, and copied sources and sanitisers) so the new rule
cannot drift from ``python-pii-to-telemetry``.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from privacy_review_agent.semgrep_harness import check_rule_metadata
from privacy_review_agent.semgrep_runner import load_rules

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")
RULE_ID = "python-pii-in-tool-result"
RULE_FILE = "python-pii-in-tool-result.yaml"
TELEMETRY_FILE = "python-pii-to-telemetry.yaml"
THIRD_PARTY_FILE = "python-pii-to-third-party.yaml"

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

    walk(doc)
    return values


def test_rule_loads_with_model_prompt_metadata():
    rules = load_rules(PACK)
    by_id = {rule.id: rule for rule in rules}

    assert RULE_ID in by_id
    assert check_rule_metadata(PACK) == []
    assert by_id[RULE_ID].metadata["category"] == "PII_IN_MODEL_PROMPT"
    assert by_id[RULE_ID].metadata["severity"] == "high"
    assert by_id[RULE_ID].metadata["confidence"] == "high"
    remediation = by_id[RULE_ID].metadata["remediation"]
    assert remediation.strip()
    assert "opaque id" in remediation or "redacted" in remediation


def test_sources_and_sanitisers_match_telemetry_and_third_party_rules():
    new_doc = _rule_doc()
    for other_file, other_id in (
        (TELEMETRY_FILE, "python-pii-to-telemetry"),
        (THIRD_PARTY_FILE, "python-pii-to-third-party"),
    ):
        other_docs = yaml.safe_load((PACK / other_file).read_text(encoding="utf-8"))[
            "rules"
        ]
        other_doc = next(doc for doc in other_docs if doc["id"] == other_id)

        assert new_doc["pattern-sources"] == other_doc["pattern-sources"]
        assert new_doc["pattern-sanitizers"] == other_doc["pattern-sanitizers"]


def test_sink_covers_each_decorator_form_with_import_gate():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    assert "mcp\\.tool" in text
    assert "function_tool" in text
    assert "async def" in text
    assert "from langchain_core.tools import tool" in text
    assert "from langchain.tools import tool" in text


def _rule_code() -> str:
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_no_unqualified_tool_or_receiver_sink():
    lines = _rule_code().splitlines()
    text = "\n".join(lines)

    assert "$X.tool" not in text
    assert "@$D2" not in text
    # Literal decorator forms are allowed only as `pattern-not` lines that
    # keep a nested tool function a sink; a sink itself is always `@$D`.
    for line in lines:
        if "@tool" in line or "@mcp.tool" in line or "@function_tool" in line:
            assert "pattern-not:" in line, line
    # The bare-`tool` decorator alternative is only meaningful together
    # with the LangChain import gate in the same file.
    assert "\\Atool\\Z" in text
    assert "from langchain_core.tools import tool" in text
    assert "from langchain.tools import tool" in text


def test_name_boundaries_match_derived_and_reject_near_miss():
    regexes = _metavariable_regexes(_rule_doc())
    assert regexes

    for control in MATCH_CONTROLS:
        assert any(re.fullmatch(pattern, control) for pattern in regexes), control
    for control in NOMATCH_CONTROLS:
        assert not any(re.fullmatch(pattern, control) for pattern in regexes), control
