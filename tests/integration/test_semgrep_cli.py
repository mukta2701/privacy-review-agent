"""CLI tests for the optional Semgrep engine (stub-driven, plus notice tests)."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from click.testing import CliRunner

from privacy_review_agent.cli import main

STUB_SCRIPT = """\
#!/usr/bin/env python3
import json
import os
import sys
import time

log = os.environ.get("SEMGREP_STUB_ARGV_LOG")
if log:
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(sys.argv) + "\\n")
sleep = float(os.environ.get("SEMGREP_STUB_SLEEP", "0"))
if sleep:
    time.sleep(sleep)
results = os.environ.get("SEMGREP_STUB_RESULTS")
if results:
    with open(results, encoding="utf-8") as fh:
        sys.stdout.write(fh.read())
sys.exit(int(os.environ.get("SEMGREP_STUB_EXIT", "0")))
"""

RULE_ID = "sample-raw-pii-logging"

RULE_YAML = """\
rules:
  - id: sample-raw-pii-logging
    languages: [python]
    severity: WARNING
    message: Raw PII written to logs without redaction
    metadata:
      category: RAW_PII_LOGGING
      severity: high
      confidence: high
      remediation: Redact or mask PII before logging.
    patterns:
      - pattern: print($X)
"""

INSTALL_HINT = "pip install 'privacy-review-agent[semgrep]'"


def _install_stub(bin_dir: Path, monkeypatch) -> dict[str, Path]:
    bin_dir.mkdir(parents=True, exist_ok=True)
    exe = bin_dir / "semgrep"
    exe.write_text(STUB_SCRIPT, encoding="utf-8")
    exe.chmod(0o755)
    argv_log = bin_dir / "argv.log"
    results_file = bin_dir / "results.json"
    results_file.write_text(json.dumps({"results": [], "errors": []}))
    monkeypatch.setenv("SEMGREP_STUB_ARGV_LOG", str(argv_log))
    monkeypatch.setenv("SEMGREP_STUB_RESULTS", str(results_file))
    monkeypatch.setenv("SEMGREP_STUB_EXIT", "0")
    monkeypatch.delenv("SEMGREP_STUB_SLEEP", raising=False)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return {"argv_log": argv_log, "results": results_file}


def _stub_match(target: Path, line: int, rule_id: str = RULE_ID) -> dict:
    return {
        "check_id": rule_id,
        "path": str(target),
        "start": {"line": line, "col": 1},
        "extra": {
            "message": "Raw PII written to logs without redaction",
            "severity": "WARNING",
            "metadata": {
                "category": "RAW_PII_LOGGING",
                "severity": "high",
                "confidence": "high",
                "remediation": "Redact or mask PII before logging.",
            },
            "lines": "<placeholder, do not use>",
        },
    }


def _policies_with_pack(tmp_path: Path, files: dict[str, str]) -> Path:
    dest = tmp_path / "policies"
    shutil.copytree(Path("src/privacy_review_agent/policies"), dest)
    pack = dest / "semgrep_rules"
    pack.mkdir(exist_ok=True)
    for name, content in files.items():
        (pack / name).write_text(content, encoding="utf-8")
    return dest


def _hide_semgrep(monkeypatch, tmp_path: Path) -> None:
    empty = tmp_path / "emptybin"
    empty.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(empty))


def _write_results(results_file: Path, matches: list[dict]) -> None:
    results_file.write_text(json.dumps({"results": matches, "errors": []}))


def test_scan_without_semgrep_warns_once_on_stderr(monkeypatch, tmp_path):
    _hide_semgrep(monkeypatch, tmp_path)
    missing = tmp_path / "no-baseline.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--path",
            "tests/fixtures/unsafe",
            "--format",
            "json",
            "--baseline-file",
            str(missing),
        ],
    )

    assert result.exit_code == 2
    doc = json.loads(result.stdout)
    assert any(f["blocking"] for f in doc["findings"])
    assert INSTALL_HINT not in result.stdout
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    assert "Semgrep" in lines[0]
    assert INSTALL_HINT in lines[0]


def test_scan_safe_md_and_sarif_stdout_have_no_notice(monkeypatch, tmp_path):
    _hide_semgrep(monkeypatch, tmp_path)
    missing = tmp_path / "no-baseline.json"

    md = CliRunner().invoke(
        main,
        ["scan", "--path", "tests/fixtures/safe", "--format", "md",
         "--baseline-file", str(missing)],
    )
    assert md.exit_code == 0
    assert "Semgrep" not in md.stdout

    sarif = CliRunner().invoke(
        main,
        ["scan", "--path", "tests/fixtures/safe", "--format", "sarif",
         "--baseline-file", str(missing)],
    )
    assert sarif.exit_code == 0
    assert "Semgrep" not in sarif.stdout
    assert sarif.stdout.strip().startswith("{")


def test_stubbed_scan_reports_blocking_confirmed_finding(monkeypatch, tmp_path):
    _install_stub(tmp_path / "bin", monkeypatch)
    policies = _policies_with_pack(tmp_path, {"sample.yaml": RULE_YAML})
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")
    _write_results(
        Path(os.environ["SEMGREP_STUB_RESULTS"]), [_stub_match(target, 1)]
    )

    result = CliRunner().invoke(
        main,
        ["scan", "--policies-dir", str(policies), "--path", str(target),
         "--format", "json"],
    )

    assert result.exit_code == 2, result.stderr
    assert result.stderr == ""
    doc = json.loads(result.stdout)
    semgrep_hits = [f for f in doc["findings"] if f["detector"] == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit["tier"] == "confirmed"
    assert hit["blocking"] is True
    assert hit["category"] == "RAW_PII_LOGGING"
    assert hit["severity"] == "high"
    assert hit["confidence"] == "high"
    assert hit["line"] == 1
    assert hit["evidence"] == "print(user.email)"
    assert RULE_ID in hit["message"]


def test_stub_failure_matches_absent_exit_code_and_stdout(monkeypatch, tmp_path):
    policies = _policies_with_pack(tmp_path, {"sample.yaml": RULE_YAML})
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")
    args = [
        "scan", "--policies-dir", str(policies), "--path", str(target),
        "--format", "json",
    ]

    paths = _install_stub(tmp_path / "bin", monkeypatch)
    _write_results(paths["results"], [_stub_match(target, 1)])
    working = CliRunner().invoke(main, args)
    assert working.exit_code == 2

    monkeypatch.setenv("SEMGREP_STUB_EXIT", "3")
    _write_results(paths["results"], [])
    failing = CliRunner().invoke(main, args)
    assert "Semgrep" in failing.stderr
    assert not any(
        f["detector"] == "semgrep" for f in json.loads(failing.stdout)["findings"]
    )

    _hide_semgrep(monkeypatch, tmp_path)
    absent = CliRunner().invoke(main, args)

    assert failing.exit_code == absent.exit_code
    assert failing.stdout == absent.stdout


def test_stubbed_scans_are_byte_identical(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    policies = _policies_with_pack(tmp_path, {"sample.yaml": RULE_YAML})
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")
    _write_results(paths["results"], [_stub_match(target, 1)])
    args = [
        "scan", "--policies-dir", str(policies), "--path", str(target),
        "--format", "json",
    ]

    first = CliRunner().invoke(main, args)
    second = CliRunner().invoke(main, args)

    assert first.exit_code == 2
    assert first.stdout == second.stdout


def test_semgrep_finding_honours_baseline(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    policies = _policies_with_pack(tmp_path, {"sample.yaml": RULE_YAML})
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")
    _write_results(paths["results"], [_stub_match(target, 1)])
    args = [
        "scan", "--policies-dir", str(policies), "--path", str(target),
        "--format", "json",
    ]

    blocked = CliRunner().invoke(main, [*args, "--baseline-file", str(tmp_path / "missing.json")])
    assert blocked.exit_code == 2
    fingerprints = [
        f["fingerprint"]
        for f in json.loads(blocked.stdout)["findings"]
        if f["detector"] == "semgrep"
    ]
    assert len(fingerprints) == 1

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"fingerprints": fingerprints, "fingerprint_version": 2})
    )
    cleared = CliRunner().invoke(main, [*args, "--baseline-file", str(baseline)])

    assert cleared.exit_code == 0
    doc = json.loads(cleared.stdout)
    assert any(f["detector"] == "semgrep" for f in doc["findings"])
    assert not any(f["blocking"] for f in doc["findings"])


def test_semgrep_finding_honours_personal_inline_suppression(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    policies = _policies_with_pack(tmp_path, {"sample.yaml": RULE_YAML})
    target = tmp_path / "app.py"
    target.write_text("print(user.email)  # privacy-ok: test fixture\n")
    _write_results(paths["results"], [_stub_match(target, 1)])

    personal = CliRunner().invoke(
        main,
        ["scan", "--mode", "personal", "--policies-dir", str(policies),
         "--path", str(target), "--format", "json"],
    )
    assert personal.exit_code == 0
    doc = json.loads(personal.stdout)
    hits = [f for f in doc["findings"] if f["detector"] == "semgrep"]
    assert len(hits) == 1
    assert hits[0]["blocking"] is False
    assert hits[0].get("suppressed") is True

    org = CliRunner().invoke(
        main,
        ["scan", "--mode", "org", "--policies-dir", str(policies),
         "--path", str(target), "--format", "json"],
    )
    assert org.exit_code == 2


def test_harness_on_fixture_pack_with_stub(monkeypatch, tmp_path):
    from privacy_review_agent.semgrep_harness import run_rule_tests

    paths = _install_stub(tmp_path / "bin", monkeypatch)
    pack = Path("tests/fixtures/semgrep_rules")
    case = pack / "sample.py"
    _write_results(paths["results"], [_stub_match(case, 7)])

    result = run_rule_tests(pack)

    assert result.failures == []
    assert result.rules == 1
    assert result.cases == 2


def _fixture_set_with_labels(root: Path) -> Path:
    import base64

    def row(cid, ext, text, expect, kind):
        return json.dumps(
            {
                "id": cid,
                "ext": ext,
                "text_b64": base64.b64encode(text.encode()).decode(),
                "expect": expect,
                "kind": kind,
                "tags": [],
            }
        )

    safe = root / "safe"
    unsafe = root / "unsafe"
    labelled = root / "labelled"
    safe.mkdir(parents=True)
    unsafe.mkdir(parents=True)
    labelled.mkdir(parents=True)
    (safe / "clean.py").write_text("def compute(x):\n    return x + 1\n")
    (unsafe / "risky.py").write_text("print(user.email)\n")
    (labelled / "cases.jsonl").write_text(
        row("nm-01", "py", "print(filename)", [], "near_miss") + "\n"
    )
    return root


def _settings_with_pack(monkeypatch, pack_dir: Path):
    import privacy_review_agent.engine as engine_module
    from privacy_review_agent.config import load_settings

    settings = load_settings()
    settings.semgrep_rules_dir = pack_dir
    monkeypatch.setattr(
        engine_module, "load_settings", lambda policies_dir=None: settings
    )


def test_calibrate_failing_pack_exits_2(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    _write_results(paths["results"], [])
    policies = _policies_with_pack(tmp_path, {"sample.yaml": RULE_YAML})
    pack_dir = policies / "semgrep_rules"
    (pack_dir / "sample.py").write_text(
        "# ok: sample-raw-pii-logging\nprint(\"hello\")\n", encoding="utf-8"
    )
    _settings_with_pack(monkeypatch, pack_dir)
    fixture_set = _fixture_set_with_labels(tmp_path / "fixtures")

    result = CliRunner().invoke(
        main, ["calibrate", "--fixture-set", str(fixture_set)]
    )

    assert result.exit_code == 2, result.stdout
    payload = json.loads(result.stdout)
    assert payload["semgrep_rule_tests"]["failures"]


def test_calibrate_passing_pack_exits_0(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    policies = _policies_with_pack(tmp_path, {"sample.yaml": RULE_YAML})
    pack_dir = policies / "semgrep_rules"
    (pack_dir / "sample.py").write_text(
        "# ruleid: sample-raw-pii-logging\nprint(user.email)\n"
        "# ok: sample-raw-pii-logging\nprint(\"hello\")\n",
        encoding="utf-8",
    )
    _write_results(
        paths["results"], [_stub_match(pack_dir / "sample.py", 2)]
    )
    _settings_with_pack(monkeypatch, pack_dir)
    fixture_set = _fixture_set_with_labels(tmp_path / "fixtures")

    result = CliRunner().invoke(
        main, ["calibrate", "--fixture-set", str(fixture_set)]
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["semgrep_rule_tests"]["rules"] == 1
    assert payload["semgrep_rule_tests"]["cases"] == 2
    assert payload["semgrep_rule_tests"]["failures"] == []
    assert set(payload["detectors"]) == {
        "secrets",
        "pii_logging",
        "third_party_transfer",
        "pii_in_prompts",
        "missing_redaction",
        "policy_bypass",
    }


def test_calibrate_without_semgrep_has_no_harness_key(monkeypatch, tmp_path):
    _hide_semgrep(monkeypatch, tmp_path)

    result = CliRunner().invoke(main, ["calibrate"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert "semgrep_rule_tests" not in payload
