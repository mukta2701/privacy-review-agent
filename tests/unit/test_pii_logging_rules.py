"""Pure-Python checks for the shipped PII-logging Semgrep rule pack.

Runs without semgrep: loads the rule YAML via ``load_rules``, validates the
metadata, and checks the YAML-data conventions (sinks, sensitive names and
sanitisers all live in the rule files).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from privacy_review_agent.config import load_settings
from privacy_review_agent.semgrep_harness import check_rule_metadata
from privacy_review_agent.semgrep_runner import load_rules

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")

GENERIC_NAMES = ("name", "message", "body")
SENSITIVE_CONTROLS = ("user_email", "userEmail", "user.email")
DROPPED_NAMES = ("upload", "upload_dir", "chat", "location", "lat", "lon",
                 "headers", "response.headers", "token", "authToken",
                 "user.token", "access_token", "address", "server.address",
                 "cookie", "cookie.max_age", "transcript", "transcript.id",
                 "passport", "passport.id", "authorization",
                 "authorization.status_code", "email_count", "email_template",
                 "email_service", "EMAIL_HOST", "settings.EMAIL_HOST",
                 "phone_type", "phone_count", "ssn_pattern", "ssn_validator",
                 "PHONE_RE", "first_name_field", "first_name_column",
                 "last_name_index", "email_regex.pattern", "user.email_count",
                 "user.email_domain", "user.has_phone")
SUFFIXED_NAMES = ("tokens", "emails", "useremail", "accesstoken")
KEBAB_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def _yaml_texts() -> list[str]:
    return [
        path.read_text(encoding="utf-8")
        for path in sorted(PACK.glob("*.yaml")) + sorted(PACK.glob("*.yml"))
    ]


def _rule_docs() -> list[dict]:
    docs = []
    for path in sorted(PACK.glob("*.yaml")) + sorted(PACK.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        docs.extend(data["rules"])
    return docs


def _metavariable_regexes() -> list[str]:
    values = []

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

    for doc in _rule_docs():
        walk(doc)
    return values


def test_pack_loads_at_least_two_rules():
    rules = load_rules(PACK)

    assert len(rules) >= 2


def test_rule_ids_unique_and_kebab_case():
    rules = load_rules(PACK)
    ids = [rule.id for rule in rules]

    assert len(set(ids)) == len(ids)
    assert all(KEBAB_RE.fullmatch(rid) for rid in ids)


def test_rule_languages_cover_python_and_js_ts():
    languages = {lang for doc in _rule_docs() for lang in doc["languages"]}

    assert "python" in languages
    assert {"javascript", "typescript"} <= languages


def test_rule_metadata_is_valid_and_confirmed_blocking():
    rules = load_rules(PACK)
    expected_categories = {
        "python-pii-in-model-prompt": "PII_IN_MODEL_PROMPT",
        "python-pii-to-third-party": "THIRD_PARTY_PII_TRANSFER",
    }

    assert check_rule_metadata(PACK) == []
    for rule in rules:
        assert rule.metadata["category"] == expected_categories.get(
            rule.id, "RAW_PII_LOGGING"
        )
        assert rule.metadata["severity"] == "high"
        assert rule.metadata["confidence"] == "high"
        assert rule.metadata["remediation"].strip()


def test_each_rule_mentions_every_redaction_helper():
    settings = load_settings()
    assert settings.redaction_helpers == {"redact", "mask", "hash", "tokenize"}
    texts = _yaml_texts()
    assert len(texts) >= 2

    for text in texts:
        for helper in sorted(settings.redaction_helpers):
            assert re.search(
                r"(?<![A-Za-z0-9_])" + re.escape(helper) + r"(?![A-Za-z0-9_])",
                text,
            ), helper


def test_generic_names_are_not_standalone_sensitive_names():
    regexes = _metavariable_regexes()
    assert regexes

    for generic in GENERIC_NAMES:
        assert not any(
            re.fullmatch(pattern, generic) for pattern in regexes
        ), generic
    for control in SENSITIVE_CONTROLS:
        assert any(
            re.fullmatch(pattern, control) for pattern in regexes
        ), control


def test_dropped_and_suffixed_names_do_not_match():
    regexes = _metavariable_regexes()
    assert regexes

    for dropped in DROPPED_NAMES + SUFFIXED_NAMES:
        assert not any(
            re.fullmatch(pattern, dropped) for pattern in regexes
        ), dropped
    for control in ("user.email", "user_email", "userEmail", 'data["email"]',
                    "user.phone_number", "phoneNumber", "user.ssn_last4",
                    "emailVerified", "user.emailVerified", "email_address",
                    "user.email_address", "user.lastName", "user.firstName"):
        assert any(
            re.fullmatch(pattern, control) for pattern in regexes
        ), control


def test_wrapper_sanitisers_appear_in_the_rule_yaml():
    texts = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(PACK.glob("*.yaml")) + sorted(PACK.glob("*.yml"))
    }

    assert re.search(r"(?<![A-Za-z0-9_])len(?![A-Za-z0-9_])", texts["python-raw-pii-logging.yaml"])
    assert re.search(r"(?<![A-Za-z0-9_])bool(?![A-Za-z0-9_])", texts["python-raw-pii-logging.yaml"])
    assert re.search(
        r"(?<![A-Za-z0-9_])Boolean(?![A-Za-z0-9_])", texts["js-ts-raw-pii-logging.yaml"]
    )
