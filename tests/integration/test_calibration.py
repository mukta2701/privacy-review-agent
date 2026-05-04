from pathlib import Path

from privacy_review_agent.engine import ReviewEngine


def test_precision_and_recall_targets():
    metrics = ReviewEngine().run_calibration(Path("tests/fixtures"))
    assert metrics.precision >= 0.85
    assert metrics.recall >= 0.80
    assert metrics.deterministic is True
