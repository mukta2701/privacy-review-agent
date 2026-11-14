from click.testing import CliRunner

from privacy_review_agent.cli import main


def test_rerun_approval_fail_closed_without_team_slug(monkeypatch):
    monkeypatch.delenv("SECURITY_TEAM_SLUG", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    result = CliRunner().invoke(main, ["enforce-rerun-approval"])
    assert result.exit_code == 2
    assert "Fail-closed" in result.output


def test_rerun_approval_personal_skips_without_team_slug(monkeypatch):
    monkeypatch.delenv("SECURITY_TEAM_SLUG", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("PRIVACY_REVIEW_MODE", raising=False)
    result = CliRunner().invoke(main, ["enforce-rerun-approval", "--mode", "personal"])
    assert result.exit_code == 0
    assert "Skipping rerun approval" in result.output


def test_rerun_approval_org_fails_closed_without_team_slug(monkeypatch):
    monkeypatch.delenv("SECURITY_TEAM_SLUG", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("PRIVACY_REVIEW_MODE", raising=False)
    result = CliRunner().invoke(main, ["enforce-rerun-approval", "--mode", "org"])
    assert result.exit_code == 2
    assert "Fail-closed" in result.output


def test_rerun_approval_default_fails_closed_without_team_slug(monkeypatch):
    monkeypatch.delenv("SECURITY_TEAM_SLUG", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("PRIVACY_REVIEW_MODE", raising=False)
    result = CliRunner().invoke(main, ["enforce-rerun-approval"])
    assert result.exit_code == 2
    assert "Fail-closed" in result.output
