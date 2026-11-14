"""Tests for score_corpus on small manifests in tmp_path.

Case lines are built from parts so no single source line holds a sink
and a sensitive field together. Semgrep is hidden so these keyword-scoring
tests are isolated from the shipped rule pack.
"""

import base64
import json
import shutil

import pytest

from privacy_review_agent.calibration import score_corpus
from privacy_review_agent.engine import ReviewEngine


@pytest.fixture(autouse=True)
def _without_semgrep(monkeypatch):
    real_which = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda *args, **kwargs: None
        if args and args[0] == "semgrep"
        else real_which(*args, **kwargs),
    )

DETECTOR_NAMES = {
    "secrets",
    "pii_logging",
    "third_party_transfer",
    "pii_in_prompts",
    "missing_redaction",
    "policy_bypass",
    "semgrep",
}

LOG_SINK = "print" + "("
EVENT_SINK = "logger" + "." + "info"
FIELD = "user" + "." + "email"
GAP_FIELD = "user" + "email"


def _encode(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _dump(path, cases):
    rows = []
    for cid, ext, text, expect, kind, tags in cases:
        rows.append(
            json.dumps(
                {
                    "id": cid,
                    "ext": ext,
                    "text_b64": _encode(text),
                    "expect": expect,
                    "kind": kind,
                    "tags": tags,
                }
            )
        )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def _engine():
    return ReviewEngine()


def _log_line():
    return LOG_SINK + FIELD + ")"


def _dual_line():
    return EVENT_SINK + "(" + FIELD + ")"


def _gap_line():
    sink = "console" + "." + "log"
    return sink + "(" + GAP_FIELD + ")"


def test_counts_tp_fp_and_fn(tmp_path):
    manifest = _dump(
        tmp_path / "cases.jsonl",
        [
            ("tp-one", "py", _log_line(), ["pii_logging"], "true", []),
            ("fn-one", "py", _log_line(), ["third_party_transfer"], "true", []),
        ],
    )
    first = score_corpus(_engine(), manifest)
    assert first.overall_precision == 0.5
    assert first.overall_recall == 0.5
    assert first.true_case_count == 2
    assert first.detectors["pii_logging"]["tp"] == 1
    assert first.detectors["pii_logging"]["fp"] == 1
    assert first.detectors["third_party_transfer"]["fn"] == 1


def test_multi_detector_line_counts_each_detector(tmp_path):
    manifest = _dump(
        tmp_path / "cases.jsonl",
        [("tp-dual", "js", _dual_line(), ["pii_logging"], "true", [])],
    )
    scored = score_corpus(_engine(), manifest)
    assert scored.detectors["pii_logging"]["tp"] == 1
    assert scored.detectors["missing_redaction"]["fp"] == 1
    assert scored.detectors["missing_redaction"]["tp"] == 0
    assert scored.overall_precision == 0.5
    assert scored.overall_recall == 1.0


def test_known_gap_excluded_but_listed(tmp_path):
    manifest = _dump(
        tmp_path / "cases.jsonl",
        [
            ("kg-one", "py", _gap_line(), ["pii_logging"], "true", ["known_gap"]),
            ("tp-one", "py", _log_line(), ["pii_logging"], "true", []),
        ],
    )
    scored = score_corpus(_engine(), manifest)
    assert scored.known_gap_count == 1
    assert scored.known_gap_misses == ["kg-one"]
    assert scored.overall_recall == 1.0
    assert scored.overall_precision == 1.0
    assert scored.detectors["pii_logging"]["fn"] == 0


def test_per_detector_keys_cover_all_detectors(tmp_path):
    manifest = _dump(
        tmp_path / "cases.jsonl",
        [("tp-one", "py", _log_line(), ["pii_logging"], "true", [])],
    )
    scored = score_corpus(_engine(), manifest)
    assert set(scored.detectors) == DETECTOR_NAMES
    for entry in scored.detectors.values():
        assert set(entry) == {"precision", "recall", "tp", "fp", "fn"}


def test_duplicate_id_is_a_validation_error(tmp_path):
    manifest = _dump(
        tmp_path / "cases.jsonl",
        [
            ("dup", "py", _log_line(), ["pii_logging"], "true", []),
            ("dup", "py", _log_line(), ["pii_logging"], "true", []),
        ],
    )
    with pytest.raises(ValueError, match="duplicate"):
        score_corpus(_engine(), manifest)


def test_scoring_is_stable_across_runs(tmp_path):
    manifest = _dump(
        tmp_path / "cases.jsonl",
        [
            ("tp-one", "py", _log_line(), ["pii_logging"], "true", []),
            ("tp-dual", "js", _dual_line(), ["pii_logging", "missing_redaction"], "true", []),
            ("kg-one", "py", _gap_line(), ["pii_logging"], "true", ["known_gap"]),
            ("nm-one", "ts", "print" + "(filename)", [], "near_miss", []),
        ],
    )
    first = score_corpus(_engine(), manifest)
    second = score_corpus(_engine(), manifest)
    assert first.to_dict() == second.to_dict()
    assert first.deterministic is True
