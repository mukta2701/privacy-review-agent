"""CLI tests for personal/org mode and inline `privacy-ok` suppressions."""

import json
from pathlib import Path

from click.testing import CliRunner

from privacy_review_agent.cli import main

_TEST_KEY = "sk_" + "test_12345678901234567890"
SECRET_LINE = 'API_KEY = "' + _TEST_KEY + '"'
MARKED_LINE = SECRET_LINE + "  # privacy-ok: test fixture"


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def _clear_mode(monkeypatch):
    monkeypatch.delenv("PRIVACY_REVIEW_MODE", raising=False)
    monkeypatch.delenv("SECURITY_TEAM_SLUG", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)


def test_scan_personal_mode_suppresses_marked_line(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--mode", "personal", "--path", target])
    assert result.exit_code == 0, result.output


def test_scan_without_marker_still_blocks(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(tmp_path / "plain.py", SECRET_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--mode", "personal", "--path", target])
    assert result.exit_code == 2


def test_scan_personal_mode_suppresses_slash_marker(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(
        tmp_path / "marked.js",
        'const key = "' + _TEST_KEY + '"; // privacy-ok: test fixture\n',
    )
    result = CliRunner().invoke(main, ["scan", "--mode", "personal", "--path", target])
    assert result.exit_code == 0, result.output


def test_scan_marker_on_previous_line_does_not_suppress(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(tmp_path / "above.py", "# privacy-ok: test fixture\n" + SECRET_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--mode", "personal", "--path", target])
    assert result.exit_code == 2


def test_scan_marker_on_next_line_does_not_suppress(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(tmp_path / "below.py", SECRET_LINE + "\n# privacy-ok: test fixture\n")
    result = CliRunner().invoke(main, ["scan", "--mode", "personal", "--path", target])
    assert result.exit_code == 2


def test_scan_empty_reason_does_not_suppress(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    for suffix, marker in (("a", "# privacy-ok:"), ("b", "# privacy-ok")):
        target = _write(tmp_path / f"empty_{suffix}.py", f"{SECRET_LINE}  {marker}\n")
        result = CliRunner().invoke(main, ["scan", "--mode", "personal", "--path", target])
        assert result.exit_code == 2, marker


def test_scan_org_mode_ignores_marker(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(
        main, ["scan", "--mode", "org", "--path", target, "--format", "json"]
    )
    assert result.exit_code == 2
    doc = json.loads(result.output)
    assert all("suppressed" not in finding for finding in doc["findings"])


def test_scan_default_mode_ignores_marker(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--path", target, "--format", "json"])
    assert result.exit_code == 2
    doc = json.loads(result.output)
    assert all("suppressed" not in finding for finding in doc["findings"])


def test_scan_mode_from_env_var(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    monkeypatch.setenv("PRIVACY_REVIEW_MODE", "personal")
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--path", target])
    assert result.exit_code == 0, result.output


def test_scan_option_overrides_env_var(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    monkeypatch.setenv("PRIVACY_REVIEW_MODE", "personal")
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--mode", "org", "--path", target])
    assert result.exit_code == 2


def test_scan_empty_env_var_behaves_as_org(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    monkeypatch.setenv("PRIVACY_REVIEW_MODE", "")
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--path", target])
    assert result.exit_code == 2


def test_scan_invalid_mode_is_usage_error(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--mode", "bogus", "--path", target])
    assert result.exit_code != 0
    assert "Privacy Review Report" not in result.output


def test_scan_invalid_mode_env_var_is_usage_error(tmp_path, monkeypatch):
    _clear_mode(monkeypatch)
    monkeypatch.setenv("PRIVACY_REVIEW_MODE", "bogus")
    target = _write(tmp_path / "marked.py", MARKED_LINE + "\n")
    result = CliRunner().invoke(main, ["scan", "--path", target])
    assert result.exit_code != 0
    assert "Privacy Review Report" not in result.output


def test_rerun_approval_invalid_mode_is_usage_error(monkeypatch):
    _clear_mode(monkeypatch)
    result = CliRunner().invoke(
        main, ["enforce-rerun-approval", "--mode", "bogus"]
    )
    assert result.exit_code != 0


def test_rerun_approval_invalid_mode_env_var_is_usage_error(monkeypatch):
    _clear_mode(monkeypatch)
    monkeypatch.setenv("PRIVACY_REVIEW_MODE", "bogus")
    result = CliRunner().invoke(main, ["enforce-rerun-approval"])
    assert result.exit_code != 0


def test_rerun_approval_personal_with_slug_still_enforces(monkeypatch, tmp_path):
    _clear_mode(monkeypatch)
    monkeypatch.setenv("SECURITY_TEAM_SLUG", "org/team")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    result = CliRunner().invoke(main, ["enforce-rerun-approval", "--mode", "personal"])
    assert result.exit_code == 2
    assert "Fail-closed: GITHUB_EVENT_PATH" in result.output


def test_workflow_wires_privacy_review_mode():
    text = Path(".github/workflows/privacy-review.yml").read_text(encoding="utf-8")
    expected = "PRIVACY_REVIEW_MODE: ${{ vars.PRIVACY_REVIEW_MODE || 'org' }}"
    assert text.count(expected) == 2
