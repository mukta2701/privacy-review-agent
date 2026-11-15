"""Gitleaks invocation tests for SecretsDetector.

The gitleaks binary is stubbed by patching ``shutil.which`` and
``subprocess.run`` in the secrets detector module, capturing every ``cmd``
passed to ``subprocess.run``.
"""

import json
from pathlib import Path
from unittest import mock

import pytest

from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors import secrets as secrets_module
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.secrets import SecretsDetector

# Split so the literal test key never appears in source.
_TEST_KEY = "sk_" + "test_12345678901234567890"
API_LINE = "API" + '_KEY = "' + _TEST_KEY + '"'


def _make_run(entries=None, returncode=1):
    return mock.Mock(returncode=returncode, stdout=json.dumps(entries or []))


def _run_and_capture_cmds(files, responses=None):
    """Run the scan and return (cmds, findings, fake_run)."""
    if responses is None:
        responses = [_make_run()]
    with (
        mock.patch.object(
            secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"
        ),
        mock.patch.object(
            secrets_module.subprocess, "run", side_effect=responses
        ) as fake_run,
    ):
        findings = SecretsDetector()._scan_with_gitleaks(files)
    cmds = [call[0][0] for call in fake_run.call_args_list]
    return cmds, findings, fake_run


def _expected_cmd(target):
    return [
        "gitleaks",
        "detect",
        "--no-git",
        "--source",
        target,
        "--report-format",
        "json",
        "--report-path",
        "-",
    ]


def test_two_files_make_one_source_call_each(tmp_path, monkeypatch):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("nothing secret here\n")
    b.write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    cmds, _, fake_run = _run_and_capture_cmds(
        [Path("a.py"), Path("b.py")], responses=[_make_run(), _make_run()]
    )
    assert fake_run.call_count == 2
    assert cmds == [_expected_cmd("./a.py"), _expected_cmd("./b.py")]


def test_cmds_have_no_positional_paths_or_dot(tmp_path, monkeypatch):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("nothing secret here\n")
    b.write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    cmds, _, _ = _run_and_capture_cmds(
        [Path("a.py"), Path("b.py")], responses=[_make_run(), _make_run()]
    )
    for cmd in cmds:
        assert "--" not in cmd
        assert "." not in cmd
        values = set()
        for idx, arg in enumerate(cmd):
            if arg in ("--source", "--report-format", "--report-path"):
                values.add(cmd[idx + 1])
        non_options = [arg for arg in cmd[2:] if not arg.startswith("--")]
        assert non_options
        assert set(non_options) <= values


def test_flag_like_filename_gets_dot_slash_prefix(tmp_path, monkeypatch):
    name = "--exclude=*.py"
    (tmp_path / name).write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    cmds, _, _ = _run_and_capture_cmds([Path(name)])
    assert cmds == [_expected_cmd("./--exclude=*.py")]
    assert all("--exclude=*.py" not in cmd for cmd in cmds)


def test_absolute_path_passed_unchanged(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("nothing secret here\n")
    cmds, _, _ = _run_and_capture_cmds([p])
    assert cmds == [_expected_cmd(str(p))]


def test_normal_relative_name_pinned_cmd(tmp_path, monkeypatch):
    p = tmp_path / "app.py"
    p.write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    cmds, _, _ = _run_and_capture_cmds([Path("app.py")])
    assert cmds == [_expected_cmd("./app.py")]


def test_no_existing_files_makes_no_calls(tmp_path):
    cmds, findings, fake_run = _run_and_capture_cmds([tmp_path / "missing.py"])
    assert findings == []
    fake_run.assert_not_called()


def test_missing_binary_makes_no_calls(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("nothing secret here\n")
    with (
        mock.patch.object(secrets_module.shutil, "which", return_value=None),
        mock.patch.object(secrets_module.subprocess, "run") as fake_run,
    ):
        findings = SecretsDetector()._scan_with_gitleaks([p])
    assert findings == []
    fake_run.assert_not_called()


@pytest.mark.parametrize("failure", ["exit-code", "oserror", "bad-json"])
def test_failing_first_run_still_returns_second_findings(
    tmp_path, monkeypatch, failure
):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("nothing secret here\n")
    b.write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    entries = [
        {
            "File": "./b.py",
            "StartLine": 3,
            "Description": "stubbed gitleaks finding",
            "Match": _TEST_KEY,
        }
    ]
    if failure == "exit-code":
        first = _make_run(entries=[], returncode=2)
    elif failure == "oserror":
        first = OSError("boom")
    else:
        first = mock.Mock(returncode=1, stdout="not json{")
    cmds, findings, fake_run = _run_and_capture_cmds(
        [Path("a.py"), Path("b.py")], responses=[first, _make_run(entries)]
    )
    assert fake_run.call_count == 2
    assert len(cmds) == 2
    assert len(findings) == 1
    assert findings[0].line == 3


def test_failed_gitleaks_run_keeps_regex_finding(tmp_path, monkeypatch):
    p = tmp_path / "app.py"
    p.write_text(f"{API_LINE}\n")
    monkeypatch.chdir(tmp_path)
    bad = mock.Mock(returncode=2, stdout=json.dumps([]))
    with (
        mock.patch.object(
            secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"
        ),
        mock.patch.object(secrets_module.subprocess, "run", return_value=bad),
    ):
        findings = SecretsDetector().scan(
            [Path("app.py")], DetectorContext(settings=load_settings())
        )
    assert len(findings) == 1
    assert findings[0].message == "Potential hardcoded secret detected"


def test_dot_slash_prefixed_report_still_dedups(tmp_path, monkeypatch):
    p = tmp_path / "app.py"
    p.write_text(f"{API_LINE}\n")
    monkeypatch.chdir(tmp_path)
    entries = [
        {
            "File": "./app.py",
            "StartLine": 1,
            "Description": "stubbed gitleaks finding",
            "Match": _TEST_KEY,
        }
    ]
    run = mock.Mock(returncode=1, stdout=json.dumps(entries))
    with (
        mock.patch.object(
            secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"
        ),
        mock.patch.object(secrets_module.subprocess, "run", return_value=run),
    ):
        findings = SecretsDetector().scan(
            [Path("app.py")], DetectorContext(settings=load_settings())
        )
    line_one = [f for f in findings if f.line == 1]
    assert len(line_one) == 1
    assert line_one[0].message == "stubbed gitleaks finding"
