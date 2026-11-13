"""Validity tests for the committed labelled corpus manifest."""

import base64
import json
import re
from pathlib import Path

MANIFEST = Path("tests/fixtures/labelled/cases.jsonl")

DETECTOR_NAMES = {
    "secrets",
    "pii_logging",
    "third_party_transfer",
    "pii_in_prompts",
    "missing_redaction",
    "policy_bypass",
}

RESPONSE_BODY = "response" + "." + "body"
PLURAL = "user" + "." + "emails"
RUN_ONE = "user" + "email"
RUN_TWO = "access" + "token"

HOOK_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"password\s*=\s*[\"']",
    r"secret\s*=\s*[\"']",
    r"api_key\s*=\s*[\"']",
    r"BEGIN (RSA |DSA |EC )?PRIVATE KEY",
    r"sk-[a-zA-Z0-9]{20,}",
    r"ghp_[a-zA-Z0-9]{36}",
    r"ghs_[a-zA-Z0-9]{36}",
]


def _load():
    rows = MANIFEST.read_text(encoding="utf-8").splitlines()
    return [json.loads(row) for row in rows if row.strip()]


def _decoded():
    return [base64.b64decode(case["text_b64"]).decode("utf-8") for case in _load()]


def test_manifest_parses_with_expected_size_and_keys():
    cases = _load()
    assert 150 <= len(cases) <= 300
    for case in cases:
        assert set(case) == {"id", "ext", "text_b64", "expect", "kind", "tags"}


def test_near_miss_share_and_empty_expect():
    cases = _load()
    near = [case for case in cases if case["kind"] == "near_miss"]
    assert 0.45 <= len(near) / len(cases) <= 0.55
    for case in near:
        assert case["expect"] == []


def test_ids_unique_detectors_and_ext_valid():
    cases = _load()
    ids = [case["id"] for case in cases]
    assert len(set(ids)) == len(ids)
    for case in cases:
        assert set(case["expect"]) <= DETECTOR_NAMES
        assert case["ext"] in {"py", "js", "ts"}
        assert case["kind"] in {"near_miss", "true"}
        assert isinstance(case["tags"], list)


def test_gated_true_coverage_and_known_gaps():
    cases = _load()
    gated = [case for case in cases if case["kind"] == "true" and "known_gap" not in case["tags"]]
    for name in DETECTOR_NAMES:
        assert sum(1 for case in gated if name in case["expect"]) >= 8, name
    gaps = [case for case in cases if "known_gap" in case["tags"]]
    assert len(gaps) >= 6
    assert all(case["kind"] == "true" for case in gaps)


def test_required_decoded_markers_present_and_single_line():
    texts = _decoded()
    assert all("\n" not in text for text in texts)
    joined = "\n".join(texts)
    assert RESPONSE_BODY in joined
    assert PLURAL in joined
    assert RUN_ONE in joined
    assert RUN_TWO in joined


def test_committed_text_matches_no_hook_pattern():
    raw = MANIFEST.read_text(encoding="utf-8")
    for pattern in HOOK_PATTERNS:
        assert re.search(pattern, raw) is None, pattern
