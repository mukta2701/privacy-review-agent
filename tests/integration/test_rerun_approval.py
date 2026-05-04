from click.testing import CliRunner

from privacy_review_agent.cli import main


def test_rerun_approval_fail_closed_without_team_slug(monkeypatch):
    monkeypatch.delenv("SECURITY_TEAM_SLUG", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    result = CliRunner().invoke(main, ["enforce-rerun-approval"])
    assert result.exit_code == 2
    assert "Fail-closed" in result.output
