"""Gitleaks invocation hardening tests for SecretsDetector.

The gitleaks binary is stubbed by patching ``shutil.which`` and
``subprocess.run`` in the secrets detector module, capturing the ``cmd``
passed to ``subprocess.run``.
"""

import json
from pathlib import Path
from unittest import mock

from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors import secrets as secrets_module
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.secrets import SecretsDetector

# Split so the literal test key never appears in source.
_TEST_KEY = "sk_" + "test_12345678901234567890"
API_LINE = "API" + '_KEY = "' + _TEST_KEY + '"'


def _run_and_capture_cmd(files: list[Path], entries=None, returncode=1):
    run = mock.Mock(returncode=returncode, stdout=json.dumps(entries or []))
    with (
        mock.patch.object(
            secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"
        ),
        mock.patch.object(secrets_module.subprocess, "run", return_value=run) as fake_run,
    ):
        SecretsDetector()._scan_with_gitleaks(files)
    return fake_run.call_args[0][0]


def test_flag_like_filename_gets_dot_slash_prefix(tmp_path, monkeypatch):
    name = "--exclude=*.py"
    (tmp_path / name).write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    cmd = _run_and_capture_cmd([Path(name)])
    assert "./--exclude=*.py" in cmd
    assert "--exclude=*.py" not in cmd


def test_double_dash_separates_options_from_files(tmp_path, monkeypatch):
    (tmp_path / "--exclude=*.py").write_text("nothing secret here\n")
    (tmp_path / "app.py").write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    cmd = _run_and_capture_cmd([Path("--exclude=*.py"), Path("app.py")])
    sep = cmd.index("--")
    assert sep > 0
    for arg in cmd[sep + 1 :]:
        assert not arg.startswith("--") or arg.startswith("./--")


def test_absolute_path_passed_unchanged(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("nothing secret here\n")
    cmd = _run_and_capture_cmd([p])
    sep = cmd.index("--")
    assert str(p) in cmd[sep + 1 :]
    assert f"./{p}" not in cmd


def test_normal_relative_name_options_and_prefix(tmp_path, monkeypatch):
    p = tmp_path / "app.py"
    p.write_text("nothing secret here\n")
    monkeypatch.chdir(tmp_path)
    cmd = _run_and_capture_cmd([Path("app.py")])
    sep = cmd.index("--")
    assert cmd[:sep] == [
        "gitleaks",
        "detect",
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        "-",
    ]
    assert cmd[sep + 1 :] == ["./app.py"]


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
