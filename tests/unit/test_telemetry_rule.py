"""Pure-Python checks for the PII-to-telemetry Semgrep rule.

Runs without semgrep: loads the rule YAML via ``load_rules``, validates the
metadata, and locks the YAML-data conventions (sinks, copied sources and
sanitisers) so the new rule cannot drift from ``python-pii-to-third-party``.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from privacy_review_agent.semgrep_harness import check_rule_metadata
from privacy_review_agent.semgrep_runner import load_rules

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")
RULE_ID = "python-pii-to-telemetry"
RULE_FILE = "python-pii-to-telemetry.yaml"
THIRD_PARTY_FILE = "python-pii-to-third-party.yaml"

REQUIRED_SINKS = (
    "sentry_sdk.set_user(...)",
    "sentry_sdk.set_context(...)",
    "sentry_sdk.set_tag(...)",
    "sentry_sdk.set_tags(...)",
    "sentry_sdk.set_extra(...)",
    "sentry_sdk.add_breadcrumb(...)",
    "sentry_sdk.capture_message(...)",
    "sentry_sdk.capture_event(...)",
    "analytics.identify(...)",
    "analytics.track(...)",
    "analytics.page(...)",
    "analytics.screen(...)",
    "analytics.group(...)",
    "analytics.alias(...)",
    "posthog.capture(...)",
    "posthog.identify(...)",
    "posthog.set(...)",
    "posthog.set_once(...)",
    "posthog.alias(...)",
    "posthog.group_identify(...)",
    "$S.capture(...)",
    "$S.identify(...)",
    "$S.set(...)",
    "$S.set_once(...)",
    "$S.alias(...)",
    "$S.group_identify(...)",
    "$S = Posthog(...)",
    "tracer.current_span().set_tag(...)",
    "tracer.current_span().set_tags(...)",
    "ddtrace.tracer.current_span().set_tag(...)",
    "ddtrace.tracer.current_span().set_tags(...)",
    "$S.set_tag(...)",
    "$S.set_tags(...)",
    "$S = tracer.current_span()",
    "$S = tracer.trace(...)",
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


def test_rule_loads_with_telemetry_metadata():
    rules = load_rules(PACK)
    by_id = {rule.id: rule for rule in rules}

    assert RULE_ID in by_id
    assert check_rule_metadata(PACK) == []
    assert by_id[RULE_ID].metadata["category"] == "THIRD_PARTY_PII_TRANSFER"
    assert by_id[RULE_ID].metadata["severity"] == "high"
    assert by_id[RULE_ID].metadata["confidence"] == "high"
    assert by_id[RULE_ID].metadata["remediation"].strip()


def test_required_sink_patterns_appear_in_yaml():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    for sink in REQUIRED_SINKS:
        assert sink in text, sink


def test_unrelated_receivers_are_not_sinks():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    assert "$X.capture(" not in text
    assert "$X.identify(" not in text
    assert "$X.set_tag(" not in text


def test_sources_and_sanitisers_match_third_party_rule():
    new_doc = _rule_doc()
    third_party_docs = yaml.safe_load((PACK / THIRD_PARTY_FILE).read_text(encoding="utf-8"))[
        "rules"
    ]
    third_party_doc = next(
        doc for doc in third_party_docs if doc["id"] == "python-pii-to-third-party"
    )

    assert new_doc["pattern-sources"] == third_party_doc["pattern-sources"]
    assert new_doc["pattern-sanitizers"] == third_party_doc["pattern-sanitizers"]


def test_name_boundaries_match_derived_and_reject_near_miss():
    regexes = _metavariable_regexes(_rule_doc())
    assert regexes

    for control in MATCH_CONTROLS:
        assert any(re.fullmatch(pattern, control) for pattern in regexes), control
    for control in NOMATCH_CONTROLS:
        assert not any(re.fullmatch(pattern, control) for pattern in regexes), control
