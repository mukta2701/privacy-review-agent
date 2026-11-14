"""Pure-Python checks for the PII-in-model-prompt Semgrep rule.

Runs without semgrep: loads the rule YAML via ``load_rules``, validates the
metadata, and locks the YAML-data conventions (sinks, copied sources and
sanitisers) so the new rule cannot drift from ``python-raw-pii-logging``.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from privacy_review_agent.semgrep_harness import check_rule_metadata
from privacy_review_agent.semgrep_runner import load_rules

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")
RULE_ID = "python-pii-in-model-prompt"
RULE_FILE = "python-pii-in-model-prompt.yaml"
LOGGING_FILE = "python-raw-pii-logging.yaml"

REQUIRED_SINKS = (
    "$C.chat.completions.create(...)",
    "$C.chat.completions.parse(...)",
    "$C.chat.completions.stream(...)",
    "$C.beta.chat.completions.parse(...)",
    "$C.beta.chat.completions.stream(...)",
    "$C.responses.create(...)",
    "$C.responses.parse(...)",
    "$C.responses.stream(...)",
    "$C.completions.create(...)",
    "$C.messages.create(..., model=$M, ...)",
    "$C.messages.stream(..., model=$M, ...)",
    "$C.generate_content(...)",
    "$C.models.generate_content(...)",
    "$CHAT.send_message(...)",
)

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
    "user.email_count",
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
    assert by_id[RULE_ID].metadata["remediation"].strip()


def test_required_sink_patterns_appear_in_yaml():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    for sink in REQUIRED_SINKS:
        assert sink in text, sink


def test_deprecated_chat_completion_is_not_a_sink():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    assert "ChatCompletion" not in text


def test_sources_and_sanitisers_match_logging_rule():
    new_doc = _rule_doc()
    logging_docs = yaml.safe_load((PACK / LOGGING_FILE).read_text(encoding="utf-8"))["rules"]
    logging_doc = next(doc for doc in logging_docs if doc["id"] == "python-raw-pii-logging")

    assert new_doc["pattern-sources"] == logging_doc["pattern-sources"]
    assert new_doc["pattern-sanitizers"] == logging_doc["pattern-sanitizers"]


def test_name_boundaries_match_derived_and_reject_near_miss():
    regexes = _metavariable_regexes(_rule_doc())
    assert regexes

    for control in MATCH_CONTROLS:
        assert any(re.fullmatch(pattern, control) for pattern in regexes), control
    for control in NOMATCH_CONTROLS:
        assert not any(re.fullmatch(pattern, control) for pattern in regexes), control
