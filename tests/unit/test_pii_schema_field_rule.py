"""Pure-Python checks for the PII schema-field Semgrep rule.

Runs without semgrep: loads the rule YAML via ``load_rules``, validates the
metadata, locks the verbatim reuse of the bare-name regex from
``python-pii-in-url``, and checks the appended calibration cases and their
positive/near-miss balance.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import yaml

from privacy_review_agent.semgrep_harness import check_rule_metadata
from privacy_review_agent.semgrep_runner import load_rules

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")
RULE_ID = "python-pii-schema-field"
RULE_FILE = "python-pii-schema-field.yaml"
URL_RULE_FILE = "python-pii-in-url.yaml"
MANIFEST = Path("tests/fixtures/labelled/cases.jsonl")

MATCH_CONTROLS = (
    "email",
    "user_email",
    "userEmail",
    "phone_number",
    "ssn_last4",
    "first_name",
    "last_name",
    "email_address",
)
NOMATCH_CONTROLS = (
    "email_count",
    "email_verified_at",
    "ssn_pattern",
    "phone_type",
    "EMAIL_HOST",
    "title",
    "slug",
    "user_id",
    "emails",
    "useremail",
)

REQUIRED_POSITIVE_KINDS = (
    "model email",
    "model phone_number",
    "model first_name",
    "model last_name",
    "model ssn_last4",
    "model user_email",
    "model EmailField non-PII name",
    "AddField sensitive name",
    "AddField EmailField",
    "CreateModel tuple",
)

REQUIRED_NEAR_MISS_MARKERS = (
    "email_count",
    "email_verified_at",
    "ssn_pattern",
    "class Profile",
    "title",
    "settings.EMAIL_HOST",
    "RemoveField",
    "AlterField",
    "ForeignKey",
    "mylib",
    "verbose_name",
)


def _rule_doc(rule_id: str, rule_file: str) -> dict:
    for doc in yaml.safe_load((PACK / rule_file).read_text(encoding="utf-8"))["rules"]:
        if doc["id"] == rule_id:
            return doc
    raise AssertionError(f"rule {rule_id} not found in {rule_file}")


def _name_regex(doc: dict) -> str:
    values: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for key, item in node.items():
                if key == "metavariable-regex" and isinstance(item, dict):
                    if item.get("metavariable") == "$N":
                        values.append(item["regex"])
                else:
                    walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for branch in doc.get("patterns", []):
        walk(branch)
    assert len(values) == 1, f"expected one $N regex, found {len(values)}"
    return values[0]


def _bare_source_regex() -> str:
    doc = _rule_doc("python-pii-in-url", URL_RULE_FILE)
    for source in doc.get("pattern-sources", []):
        patterns = source.get("patterns", [])
        if any(isinstance(p, dict) and p.get("pattern") == "$X" for p in patterns):
            for item in patterns:
                if (
                    isinstance(item, dict)
                    and item.get("metavariable-regex", {}).get("metavariable") == "$X"
                ):
                    return item["metavariable-regex"]["regex"]
    raise AssertionError("bare-name $X source not found in python-pii-in-url")


def test_rule_loads_with_schema_field_metadata():
    rules = load_rules(PACK)
    by_id = {rule.id: rule for rule in rules}

    assert RULE_ID in by_id
    assert check_rule_metadata(PACK) == []
    assert by_id[RULE_ID].metadata["category"] == "PII_SCHEMA_FIELD"
    assert by_id[RULE_ID].metadata["severity"] == "medium"
    assert by_id[RULE_ID].metadata["confidence"] == "high"
    remediation = by_id[RULE_ID].metadata["remediation"]
    assert remediation.strip()
    assert "encrypt" in remediation or "hash" in remediation or "retention" in remediation

    taxonomy = yaml.safe_load(
        Path("src/privacy_review_agent/policies/taxonomy.yaml").read_text(encoding="utf-8")
    )
    defaults = {
        entry["id"]: entry.get("severity_default") for entry in taxonomy.get("categories", [])
    }
    assert defaults.get("PII_SCHEMA_FIELD") == "medium"


def test_name_regex_equals_url_rule_bare_name_regex():
    assert _name_regex(_rule_doc(RULE_ID, RULE_FILE)) == _bare_source_regex()


def test_name_regex_matches_sensitive_and_rejects_near_miss():
    regex = _name_regex(_rule_doc(RULE_ID, RULE_FILE))

    for control in MATCH_CONTROLS:
        assert re.fullmatch(regex, control), control
    for control in NOMATCH_CONTROLS:
        assert not re.fullmatch(regex, control), control


def test_rule_uses_django_resolution_without_rebinding_blocks():
    text = (PACK / RULE_FILE).read_text(encoding="utf-8")

    assert "django.db.models.$F" in text
    assert "django.db.models.Model" in text
    assert "django.db.migrations.AddField" in text
    assert "django.db.migrations.CreateModel" in text
    assert "django.db.models.EmailField" in text
    assert "ForeignKey" in text
    assert "OneToOneField" in text
    assert "ManyToManyField" in text

    assert "def $G" not in text
    assert "$F = $V" not in text
    assert "from $M import" not in text


def _schema_cases() -> list[dict]:
    rows = MANIFEST.read_text(encoding="utf-8").splitlines()
    cases = [json.loads(row) for row in rows if row.strip()]
    new = [case for case in cases if "-schema-" in case["id"]]
    assert new, "no python-pii-schema-field corpus cases found"
    return cases, new


def test_appended_corpus_cases_are_valid_and_balanced():
    cases, new = _schema_cases()

    assert len(cases) <= 500
    assert len({case["id"] for case in cases}) == len(cases)

    positives = [case for case in new if case["kind"] == "true"]
    near_misses = [case for case in new if case["kind"] == "near_miss"]
    assert len(positives) >= 10
    assert len(near_misses) >= 12
    assert all(case["expect"] == ["semgrep"] for case in positives)
    assert all(case["expect"] == [] for case in near_misses)
    assert all(case["ext"] == "py" for case in new)

    for case in new:
        raw = base64.b64decode(case["text_b64"]).decode("utf-8")
        assert raw and "\r" not in raw
        if "\n" in raw:
            assert "multiline" in case["tags"], case["id"]

    share = sum(1 for case in cases if case["kind"] == "near_miss") / len(cases)
    assert 0.45 <= share <= 0.55


def test_corpus_covers_required_positive_and_near_miss_kinds():
    _, new = _schema_cases()
    decoded = {case["id"]: base64.b64decode(case["text_b64"]).decode("utf-8") for case in new}
    positives = {cid: text for cid, text in decoded.items() if cid.startswith("tp-schema-")}
    near_miss = {cid: text for cid, text in decoded.items() if cid.startswith("nm-schema-")}

    assert len(positives) >= 10
    assert len(near_miss) >= 12

    joined_pos = "\n".join(positives.values())
    for marker in ("email", "phone_number", "first_name", "last_name", "ssn_last4", "user_email"):
        assert marker in joined_pos, marker
    assert "EmailField" in joined_pos
    assert "AddField" in joined_pos
    assert "CreateModel" in joined_pos

    joined_nm = "\n".join(near_miss.values())
    for marker in REQUIRED_NEAR_MISS_MARKERS:
        assert marker in joined_nm, marker
