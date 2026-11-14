"""Gate tests for calibrate on the default set and on tmp fixture sets.

Case text is built from parts so no single source line holds a sink
and a sensitive field together.
"""

import base64
import json

from click.testing import CliRunner

from privacy_review_agent.cli import main
from privacy_review_agent.engine import CalibrationMetrics

LOG_HEAD = "print" + "("
USER_FIELD = "user" + "." + "email"
QUIET_LINE = "print" + "(filename)"
HOT_LINE_PARTS = ("console" + "." + "log", USER_FIELD)

NEW_KEYS = (
    "overall_precision",
    "overall_recall",
    "near_miss_precision",
    "near_miss_count",
    "true_case_count",
    "known_gap_count",
    "detectors",
    "known_gap_misses",
)

DETECTOR_NAMES = (
    "secrets",
    "pii_logging",
    "third_party_transfer",
    "pii_in_prompts",
    "missing_redaction",
    "policy_bypass",
)


def _encode(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _row(cid, ext, text, expect, kind, tags):
    return json.dumps(
        {
            "id": cid,
            "ext": ext,
            "text_b64": _encode(text),
            "expect": expect,
            "kind": kind,
            "tags": tags,
        }
    )


def _write_set(root, labelled_rows):
    safe = root / "safe"
    risky = root / "unsafe"
    marked = root / "labelled"
    safe.mkdir(parents=True)
    risky.mkdir(parents=True)
    marked.mkdir(parents=True)
    (safe / "clean.py").write_text("def compute(x):\n    return x + 1\n", encoding="utf-8")
    hot = LOG_HEAD + USER_FIELD + ")"
    (risky / "risky.py").write_text(hot + "\n", encoding="utf-8")
    (marked / "cases.jsonl").write_text("\n".join(labelled_rows) + "\n", encoding="utf-8")
    return root


def _quiet_rows(count, hot_index=-1):
    rows = []
    for num in range(count):
        if num == hot_index:
            head, field = HOT_LINE_PARTS
            text = head + "(" + field + ")"
        else:
            text = QUIET_LINE
        rows.append(_row(f"nm-{num:02d}", "py", text, [], "near_miss", []))
    return rows


def test_calibrate_passes_on_default_set():
    runner = CliRunner()
    result = runner.invoke(main, ["calibrate"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    for key in (
        "precision",
        "recall",
        "deterministic",
        "tp",
        "fp",
        "unsafe_file_count",
    ):
        assert key in payload
    for key in NEW_KEYS:
        assert key in payload
    assert set(payload["detectors"]) == set(DETECTOR_NAMES)
    for entry in payload["detectors"].values():
        assert set(entry) == {"precision", "recall", "tp", "fp", "fn"}
    assert payload["near_miss_precision"] > 0.90
    assert payload["overall_recall"] >= 0.80
    assert payload["recall"] == 1.0
    assert payload["deterministic"] is True


def test_calibrate_fails_on_hot_near_miss(tmp_path):
    root = _write_set(tmp_path / "set", _quiet_rows(9, hot_index=0))
    runner = CliRunner()
    result = runner.invoke(main, ["calibrate", "--fixture-set", str(root)])
    assert result.exit_code == 2, result.output


def test_calibrate_missing_manifest_exits_one(tmp_path):
    root = tmp_path / "empty"
    (root / "safe").mkdir(parents=True)
    (root / "unsafe").mkdir(parents=True)
    runner = CliRunner()
    result = runner.invoke(main, ["calibrate", "--fixture-set", str(root)])
    assert result.exit_code == 1, result.output
    assert "cases.jsonl" in result.output


def test_gate_failures_lists_failed_conditions():
    passing = CalibrationMetrics(
        precision=1.0,
        recall=1.0,
        deterministic=True,
        tp=2,
        fp=0,
        unsafe_file_count=2,
        overall_precision=1.0,
        overall_recall=1.0,
        near_miss_precision=1.0,
    )
    assert passing.gate_failures() == []

    low_precision = CalibrationMetrics(
        precision=1.0,
        recall=1.0,
        deterministic=True,
        tp=0,
        fp=1,
        unsafe_file_count=1,
        overall_precision=0.0,
        overall_recall=1.0,
        near_miss_precision=0.5,
    )
    assert len(low_precision.gate_failures()) == 1

    low_recall = CalibrationMetrics(
        precision=1.0,
        recall=1.0,
        deterministic=True,
        tp=1,
        fp=0,
        unsafe_file_count=1,
        overall_precision=1.0,
        overall_recall=0.5,
        near_miss_precision=1.0,
    )
    assert len(low_recall.gate_failures()) == 1

    flaky = CalibrationMetrics(
        precision=1.0,
        recall=1.0,
        deterministic=False,
        tp=1,
        fp=0,
        unsafe_file_count=1,
        overall_precision=1.0,
        overall_recall=1.0,
        near_miss_precision=1.0,
    )
    assert len(flaky.gate_failures()) == 1

    regressed = CalibrationMetrics(
        precision=0.5,
        recall=0.5,
        deterministic=True,
        tp=1,
        fp=1,
        unsafe_file_count=2,
        overall_precision=1.0,
        overall_recall=1.0,
        near_miss_precision=1.0,
    )
    assert len(regressed.gate_failures()) == 1
