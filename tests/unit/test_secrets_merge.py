"""Gitleaks/regex merge tests for SecretsDetector.

The gitleaks binary is stubbed by patching ``shutil.which`` and
``subprocess.run`` in the secrets detector module.
"""

import json
from unittest import mock

from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors import secrets as secrets_module
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.secrets import SecretsDetector

REGEX_SECRET = 'API_KEY = "sk_test_12345678901234567890"'


def _gitleaks_result(entries, returncode=1):
    run = mock.Mock(
        returncode=returncode,
        stdout=json.dumps(entries),
    )
    return run


def _scan_with_stub(path, entries, returncode=1):
    run = _gitleaks_result(entries, returncode)
    with (
        mock.patch.object(secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"),
        mock.patch.object(secrets_module.subprocess, "run", return_value=run),
    ):
        context = DetectorContext(settings=load_settings())
        return SecretsDetector().scan([path], context)


def test_merges_gitleaks_and_regex_findings(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(f"password = 'hunter2x'\n{REGEX_SECRET}\n")
    entries = [
        {
            "File": str(p),
            "StartLine": 1,
            "Description": "stubbed gitleaks finding",
            "Match": "password = 'hunter2x'",
        }
    ]
    findings = _scan_with_stub(p, entries)
    assert len(findings) == 2
    assert {f.line for f in findings} == {1, 2}


def test_same_line_dedup_prefers_gitleaks(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(f"{REGEX_SECRET}\n{REGEX_SECRET}\n")
    entries = [
        {
            "File": f"{p.parent}/./{p.name}",
            "StartLine": 1,
            "Description": "stubbed gitleaks finding",
            "Match": "sk_test_12345678901234567890",
        }
    ]
    findings = _scan_with_stub(p, entries)
    assert len(findings) == 2
    line_one = [f for f in findings if f.line == 1]
    assert len(line_one) == 1
    assert line_one[0].message == "stubbed gitleaks finding"


def test_secret_inside_comment_is_still_reported(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(f"# {REGEX_SECRET}\n")
    findings = SecretsDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "SECRET_EXPOSURE" for f in findings)


def test_merged_output_is_deterministic(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(f"password = 'hunter2x'\n{REGEX_SECRET}\n")
    entries = [
        {
            "File": str(p),
            "StartLine": 1,
            "Description": "stubbed gitleaks finding",
            "Match": "password = 'hunter2x'",
        }
    ]
    first = _scan_with_stub(p, entries)
    second = _scan_with_stub(p, entries)
    assert [(f.file_path, f.line, f.category, f.message) for f in first] == [
        (f.file_path, f.line, f.category, f.message) for f in second
    ]


def test_gitleaks_failure_still_reports_regex_findings(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(f"{REGEX_SECRET}\n")
    findings = _scan_with_stub(p, [], returncode=2)
    assert any(f.category == "SECRET_EXPOSURE" for f in findings)


def test_gitleaks_invalid_json_still_reports_regex_findings(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(f"{REGEX_SECRET}\n")
    with (
        mock.patch.object(secrets_module.shutil, "which", return_value="/usr/bin/gitleaks"),
        mock.patch.object(
            secrets_module.subprocess,
            "run",
            return_value=mock.Mock(returncode=1, stdout="not json{{"),
        ),
    ):
        findings = SecretsDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "SECRET_EXPOSURE" for f in findings)
