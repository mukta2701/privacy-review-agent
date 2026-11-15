"""Gitleaks resilience tests for SecretsDetector.

The gitleaks binary is stubbed by patching ``shutil.which`` and
``subprocess.run`` in the secrets detector module. Every test exercises the
public ``SecretsDetector.scan`` so regex production and merging are covered
alongside the subprocess boundary.
"""

import json
import subprocess
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


def _gitleaks_entry(file_path, line):
    return {
        "File": str(file_path),
        "StartLine": line,
        "Description": "stubbed gitleaks finding",
        "Match": _TEST_KEY,
    }


def _ok_run(entries):
    return mock.Mock(returncode=1, stdout=json.dumps(entries))


def _scan(files):
    return SecretsDetector().scan(files, DetectorContext(settings=load_settings()))


def _scan_with_stubs(files, responses, recwarn):
    with (
        mock.patch.object(
            secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"
        ),
        mock.patch.object(
            secrets_module.subprocess, "run", side_effect=responses
        ) as fake_run,
    ):
        findings = _scan(files)
    assert len(recwarn.list) == 0
    return findings, fake_run


def test_timeout_on_every_call(tmp_path):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("nothing secret here\n")
    b.write_text("nothing secret here\n")
    with (
        mock.patch.object(
            secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"
        ),
        mock.patch.object(
            secrets_module.subprocess,
            "run",
            side_effect=[_ok_run([]), _ok_run([])],
        ) as fake_run,
    ):
        _scan([a, b])
    assert secrets_module.GITLEAKS_TIMEOUT == 120
    assert fake_run.call_count == 2
    for call in fake_run.call_args_list:
        assert call.kwargs["timeout"] == secrets_module.GITLEAKS_TIMEOUT


def test_timeout_preserves_findings(tmp_path, recwarn):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    c = tmp_path / "c.py"
    a.write_text("nothing secret here\n")
    b.write_text(API_LINE + "\n")
    c.write_text("nothing secret here\n")
    entry_a = _gitleaks_entry(a, 5)
    entry_c = _gitleaks_entry(c, 7)
    responses = [
        _ok_run([entry_a]),
        subprocess.TimeoutExpired(cmd=["gitleaks"], timeout=120),
        _ok_run([entry_c]),
    ]
    findings, fake_run = _scan_with_stubs([a, b, c], responses, recwarn)
    assert fake_run.call_count == 3
    by_file_line = {(f.file_path, f.line) for f in findings}
    assert by_file_line == {(str(a), 5), (str(b), 1), (str(c), 7)}
    regex_hits = [f for f in findings if (f.file_path, f.line) == (str(b), 1)]
    assert len(regex_hits) == 1
    assert regex_hits[0].message == "Potential hardcoded secret detected"


def _mixed_list_report(b_file):
    return json.dumps([_gitleaks_entry(b_file, 9), "not-an-object"])


@pytest.mark.parametrize(
    "bad_stdout",
    ["null", "{}", '"leaked"', "42", "true", "mixed"],
    ids=["null", "object", "string", "number", "boolean", "mixed-list"],
)
def test_invalid_report_shape(tmp_path, recwarn, bad_stdout):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    c = tmp_path / "c.py"
    a.write_text("nothing secret here\n")
    b.write_text(API_LINE + "\n")
    c.write_text("nothing secret here\n")
    entry_a = _gitleaks_entry(a, 5)
    entry_c = _gitleaks_entry(c, 7)
    if bad_stdout == "mixed":
        bad = mock.Mock(returncode=1, stdout=_mixed_list_report(b))
    else:
        bad = mock.Mock(returncode=1, stdout=bad_stdout)
    responses = [_ok_run([entry_a]), bad, _ok_run([entry_c])]
    findings, fake_run = _scan_with_stubs(
        [Path(str(a)), Path(str(b)), Path(str(c))], responses, recwarn
    )
    assert fake_run.call_count == 3
    by_file_line = {(f.file_path, f.line) for f in findings}
    assert by_file_line == {(str(a), 5), (str(b), 1), (str(c), 7)}
    assert (str(b), 9) not in by_file_line


@pytest.mark.parametrize("stdout", ["", "[]"], ids=["empty-stdout", "empty-list"])
def test_empty_report(tmp_path, recwarn, stdout):
    p = tmp_path / "app.py"
    p.write_text(API_LINE + "\n")
    responses = [mock.Mock(returncode=1, stdout=stdout)]
    findings, fake_run = _scan_with_stubs([p], responses, recwarn)
    assert fake_run.call_count == 1
    assert len(findings) == 1
    assert (findings[0].file_path, findings[0].line) == (str(p), 1)
    assert findings[0].message == "Potential hardcoded secret detected"
