"""Unit tests for the offline Semgrep runner seam (spec item 1-4)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from privacy_review_agent.semgrep_runner import (
    SemgrepFailed,
    SemgrepNotInstalled,
    load_rules,
    run_semgrep,
)

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

RULE_METADATA = {
    "category": "RAW_PII_LOGGING",
    "severity": "high",
    "confidence": "high",
    "remediation": "Redact or mask PII before logging.",
}


def _install_stub(bin_dir: Path, monkeypatch) -> dict[str, Path]:
    bin_dir.mkdir(parents=True, exist_ok=True)
    exe = bin_dir / "semgrep"
    exe.write_text(STUB_SCRIPT, encoding="utf-8")
    exe.chmod(0o755)
    argv_log = bin_dir / "argv.log"
    results_file = bin_dir / "results.json"
    monkeypatch.setenv("SEMGREP_STUB_ARGV_LOG", str(argv_log))
    monkeypatch.setenv("SEMGREP_STUB_RESULTS", str(results_file))
    monkeypatch.setenv("SEMGREP_STUB_EXIT", "0")
    monkeypatch.delenv("SEMGREP_STUB_SLEEP", raising=False)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return {"argv_log": argv_log, "results": results_file}


def _write_rule_pack(pack: Path, rule_id: str = "sample-raw-pii-logging") -> Path:
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "sample.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": rule_id,
                        "languages": ["python"],
                        "severity": "WARNING",
                        "message": "Raw PII written to logs without redaction",
                        "metadata": dict(RULE_METADATA),
                        "patterns": [{"pattern": "print($X)"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return pack


def _write_stub_results(
    results_file: Path,
    matches: list[dict],
    *,
    raw: str | None = None,
) -> None:
    if raw is not None:
        results_file.write_text(raw, encoding="utf-8")
        return
    results_file.write_text(
        json.dumps({"results": matches, "errors": []}), encoding="utf-8"
    )


def _stub_match(
    target: Path, line: int, rule_id: str = "sample-raw-pii-logging"
) -> dict:
    return {
        "check_id": rule_id,
        "path": str(target),
        "start": {"line": line, "col": 1},
        "extra": {
            "message": "Raw PII written to logs without redaction",
            "severity": "WARNING",
            "metadata": dict(RULE_METADATA),
            "lines": "<placeholder, do not use>",
        },
    }


def _engine_with_pack(pack: Path):
    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    settings = load_settings()
    settings.semgrep_rules_dir = pack
    return ReviewEngine(settings=settings)



def _write_rule(path: Path, rule_id: str, metadata: dict | None = None) -> None:
    payload: dict = {
        "rules": [
            {
                "id": rule_id,
                "languages": ["python"],
                "severity": "WARNING",
                "message": f"{rule_id} message",
                "patterns": [{"pattern": "print($X)"}],
            }
        ]
    }
    if metadata is not None:
        payload["rules"][0]["metadata"] = metadata
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")


def test_load_rules_missing_dir_returns_empty(tmp_path):
    assert load_rules(tmp_path / "nope") == []


def test_load_rules_none_returns_empty():
    assert load_rules(None) == []


def test_load_rules_empty_dir_returns_empty(tmp_path):
    assert load_rules(tmp_path) == []


def test_load_rules_reads_id_and_metadata_sorted(tmp_path):
    _write_rule(
        tmp_path / "b.yaml",
        "b-rule",
        {"category": "RAW_PII_LOGGING", "severity": "high"},
    )
    sub = tmp_path / "sub"
    sub.mkdir()
    _write_rule(tmp_path / "a.yml", "a-rule", {"category": "SECRET_EXPOSURE"})
    _write_rule(sub / "c.yaml", "c-rule", {"category": "SECRET_EXPOSURE"})
    rules = load_rules(tmp_path)
    assert [rule.id for rule in rules] == ["a-rule", "b-rule", "c-rule"]
    assert rules[1].metadata["severity"] == "high"


def test_load_rules_invalid_yaml_raises(tmp_path):
    (tmp_path / "bad.yaml").write_text("rules: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_load_rules_without_rules_list_raises(tmp_path):
    (tmp_path / "empty.yaml").write_text("foo: 1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_run_semgrep_missing_binary_raises_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda *args, **kwargs: None)
    with pytest.raises(SemgrepNotInstalled):
        run_semgrep([tmp_path / "a.py"], tmp_path)


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["semgrep"], returncode=returncode, stdout=stdout)


def _result_payload(*, check_id="r1", path="/tmp/a.py", line=2):
    return {
        "results": [
            {
                "check_id": check_id,
                "path": path,
                "start": {"line": line, "col": 1},
                "extra": {
                    "message": "msg",
                    "severity": "WARNING",
                    "metadata": {"category": "RAW_PII_LOGGING"},
                    "lines": "placeholder",
                },
            }
        ],
        "errors": [],
    }


def test_run_semgrep_builds_offline_command_and_sorts(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        payload = {
            "results": [
                {
                    "check_id": "b-rule",
                    "path": "b.py",
                    "start": {"line": 3},
                    "extra": {"message": "m", "metadata": {}},
                },
                {
                    "check_id": "a-rule",
                    "path": "a.py",
                    "start": {"line": 1},
                    "extra": {"message": "m", "metadata": {}},
                },
            ],
            "errors": [],
        }
        return _completed(stdout=json.dumps(payload))

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda *args, **kwargs: "/usr/bin/semgrep")
    matches = run_semgrep([Path("b.py"), Path("a.py")], tmp_path / "rules")

    cmd = seen["cmd"]
    assert isinstance(cmd, list)
    assert "shell" not in seen["kwargs"]
    assert cmd[0] == "/usr/bin/semgrep"
    assert "--json" in cmd
    assert "--metrics" in cmd and "off" in cmd
    assert "--disable-version-check" in cmd
    assert "--no-rewrite-rule-ids" in cmd
    assert "--quiet" in cmd
    config_values = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--config"]
    assert config_values == [str(tmp_path / "rules")]
    assert not any(
        str(arg) == "auto"
        or str(arg).startswith("p/")
        or str(arg).startswith("http")
        for arg in cmd
    )
    assert [(m.path, m.rule_id, m.line) for m in matches] == [
        ("a.py", "a-rule", 1),
        ("b.py", "b-rule", 3),
    ]


def test_run_semgrep_nonzero_exit_raises_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _completed(returncode=2, stdout="{}")
    )
    monkeypatch.setattr("shutil.which", lambda *a, **k: "/usr/bin/semgrep")
    with pytest.raises(SemgrepFailed):
        run_semgrep([Path("a.py")], tmp_path)


def test_run_semgrep_invalid_json_raises_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _completed(stdout="not json")
    )
    monkeypatch.setattr("shutil.which", lambda *a, **k: "/usr/bin/semgrep")
    with pytest.raises(SemgrepFailed):
        run_semgrep([Path("a.py")], tmp_path)


def test_run_semgrep_non_object_json_raises_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(stdout="[1, 2]"))
    monkeypatch.setattr("shutil.which", lambda *a, **k: "/usr/bin/semgrep")
    with pytest.raises(SemgrepFailed):
        run_semgrep([Path("a.py")], tmp_path)


def test_run_semgrep_oserror_raises_failed(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr("shutil.which", lambda *a, **k: "/usr/bin/semgrep")
    with pytest.raises(SemgrepFailed):
        run_semgrep([Path("a.py")], tmp_path)


def test_run_semgrep_timeout_raises_failed(monkeypatch, tmp_path):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=1)

    monkeypatch.setattr(subprocess, "run", slow)
    monkeypatch.setattr("shutil.which", lambda *a, **k: "/usr/bin/semgrep")
    with pytest.raises(SemgrepFailed):
        run_semgrep([Path("a.py")], tmp_path)


def test_detector_maps_stub_match_to_confirmed_finding(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    pack = _write_rule_pack(tmp_path / "pack")
    target = tmp_path / "app.py"
    target.write_text('import os\nprint(user.email)\nprint("hello")\n', encoding="utf-8")
    _write_stub_results(paths["results"], [_stub_match(target, 2)])

    result = _engine_with_pack(pack).scan_files([target])

    semgrep_hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit.tier.value == "confirmed"
    assert hit.category == "RAW_PII_LOGGING"
    assert hit.severity.value == "high"
    assert hit.confidence.value == "high"
    assert hit.line == 2
    assert hit.evidence == "print(user.email)"
    assert "sample-raw-pii-logging" in hit.message
    assert hit.remediation == RULE_METADATA["remediation"]
    assert hit.file_path == str(target)
    assert hit.blocking is True


def test_detector_stub_argv_is_offline_only(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    pack = _write_rule_pack(tmp_path / "pack")
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")
    _write_stub_results(paths["results"], [_stub_match(target, 1)])

    _engine_with_pack(pack).scan_files([target])

    argv = json.loads(paths["argv_log"].read_text(encoding="utf-8").strip())
    assert isinstance(argv, list)
    assert "--json" in argv
    assert "--metrics" in argv and "off" in argv
    assert "--disable-version-check" in argv
    assert "--no-rewrite-rule-ids" in argv
    assert "--quiet" in argv
    configs = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--config"]
    assert configs == [str(pack)]
    assert not any(
        arg == "auto" or str(arg).startswith("p/") or str(arg).startswith("http")
        for arg in argv
    )


def test_detector_drops_shadowed_keyword_keeps_others(monkeypatch, tmp_path):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    pack = _write_rule_pack(tmp_path / "pack")
    target = tmp_path / "app.py"
    target.write_text(
        'requests.post("https://x.example", data=user.email); print(user.email)\n'
        "print(user.name)\n",
        encoding="utf-8",
    )
    _write_stub_results(paths["results"], [_stub_match(target, 1)])

    result = _engine_with_pack(pack).scan_files([target])

    assert any(
        f.detector == "semgrep" and f.line == 1 for f in result.findings
    )
    assert not any(
        f.detector == "pii_logging" and f.line == 1 and f.category == "RAW_PII_LOGGING"
        for f in result.findings
    )
    assert any(
        f.detector == "pii_logging"
        and f.line == 2
        and f.category == "RAW_PII_LOGGING"
        for f in result.findings
    )
    assert any(
        f.detector == "third_party_transfer"
        and f.line == 1
        and f.category == "THIRD_PARTY_PII_TRANSFER"
        for f in result.findings
    )


def test_detector_failure_modes_add_no_findings_and_warn(
    monkeypatch, tmp_path, capsys
):
    pack = _write_rule_pack(tmp_path / "pack")
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")

    paths = _install_stub(tmp_path / "bin", monkeypatch)
    original_path = os.environ.get("PATH", "")
    _write_stub_results(paths["results"], [_stub_match(target, 1)])
    plain = _engine_with_pack(pack).scan_files([target])
    assert any(f.detector == "semgrep" for f in plain.findings)
    capsys.readouterr()

    absent_bin = tmp_path / "absentbin"
    absent_bin.mkdir()
    monkeypatch.setenv("PATH", str(absent_bin))
    without_semgrep = _engine_with_pack(pack).scan_files([target])
    without_keys = [(f.detector, f.line, f.category) for f in without_semgrep.findings]
    assert not any(f.detector == "semgrep" for f in without_semgrep.findings)
    assert ("pii_logging", 1, "RAW_PII_LOGGING") in without_keys
    monkeypatch.setenv("PATH", original_path)
    monkeypatch.setenv("SEMGREP_STUB_ARGV_LOG", str(paths["argv_log"]))
    monkeypatch.setenv("SEMGREP_STUB_RESULTS", str(paths["results"]))
    capsys.readouterr()

    failing_setups = [
        {"SEMGREP_STUB_EXIT": "3"},
        {"SEMGREP_STUB_RESULTS_RAW": "{not json"},
    ]
    for setup in failing_setups:
        monkeypatch.setenv("SEMGREP_STUB_EXIT", "0")
        monkeypatch.delenv("SEMGREP_STUB_SLEEP", raising=False)
        if "SEMGREP_STUB_EXIT" in setup:
            monkeypatch.setenv("SEMGREP_STUB_EXIT", setup["SEMGREP_STUB_EXIT"])
            _write_stub_results(paths["results"], [])
        else:
            _write_stub_results(
                paths["results"], [], raw=setup["SEMGREP_STUB_RESULTS_RAW"]
            )
        result = _engine_with_pack(pack).scan_files([target])
        assert not any(f.detector == "semgrep" for f in result.findings)
        assert [
            (f.detector, f.line, f.category) for f in result.findings
        ] == without_keys
        assert "Semgrep" in capsys.readouterr().err


def test_detector_timeout_warns_and_adds_no_findings(monkeypatch, tmp_path, capsys):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    pack = _write_rule_pack(tmp_path / "pack")
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")
    _write_stub_results(paths["results"], [_stub_match(target, 1)])
    monkeypatch.setenv("SEMGREP_STUB_SLEEP", "30")
    monkeypatch.setattr("privacy_review_agent.semgrep_runner.SEMGREP_TIMEOUT", 1)

    result = _engine_with_pack(pack).scan_files([target])

    assert not any(f.detector == "semgrep" for f in result.findings)
    assert "Semgrep" in capsys.readouterr().err


def test_detector_invalid_metadata_skipped_with_notice(
    monkeypatch, tmp_path, capsys
):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    pack = _write_rule_pack(tmp_path / "pack")
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")
    bad = _stub_match(target, 1)
    bad["extra"]["metadata"] = {"category": "NOPE", "severity": "high"}
    _write_stub_results(paths["results"], [bad, _stub_match(target, 1)])

    result = _engine_with_pack(pack).scan_files([target])

    kept = [f for f in result.findings if f.detector == "semgrep"]
    assert len(kept) == 1
    assert kept[0].category == "RAW_PII_LOGGING"
    err = capsys.readouterr().err
    assert "sample-raw-pii-logging" in err


def test_detector_missing_binary_warns_once(monkeypatch, tmp_path, capsys):
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    pack = _write_rule_pack(tmp_path / "pack")
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")

    engine = _engine_with_pack(pack)
    first = engine.scan_files([target])
    second = engine.scan_files([target])

    assert not any(f.detector == "semgrep" for f in first.findings)
    assert not any(f.detector == "semgrep" for f in second.findings)
    err = capsys.readouterr().err
    assert err.count("pip install 'privacy-review-agent[semgrep]'") == 1
    assert "Semgrep" in err


def test_detector_empty_pack_does_not_run(monkeypatch, tmp_path, capsys):
    paths = _install_stub(tmp_path / "bin", monkeypatch)
    pack = tmp_path / "pack"
    pack.mkdir()
    target = tmp_path / "app.py"
    target.write_text("print(user.email)\n", encoding="utf-8")

    result = _engine_with_pack(pack).scan_files([target])

    assert not paths["argv_log"].exists()
    assert capsys.readouterr().err == ""
    assert not any(f.detector == "semgrep" for f in result.findings)

