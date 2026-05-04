from pathlib import Path

from privacy_review_agent.engine import ReviewEngine


def test_engine_scans_only_changed_files(tmp_path):
    p = tmp_path / "x.py"
    p.write_text('API_KEY = "sk_test_12345678901234567890"')

    engine = ReviewEngine()
    result = engine.scan_files([Path(p)], changed_map={str(p): {1}})
    assert result.meta["scanned_file_count"] == 1
    assert len(result.findings) >= 1
