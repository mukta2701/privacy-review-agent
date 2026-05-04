from click.testing import CliRunner

from privacy_review_agent.cli import main


def test_cli_blocks_on_critical_high_confidence():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--path", "tests/fixtures/unsafe"])
    assert result.exit_code == 2
