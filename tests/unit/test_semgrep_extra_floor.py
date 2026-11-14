"""The ``semgrep`` extra floor is what CI tests (see spec item 13)."""

from __future__ import annotations

from pathlib import Path


def test_semgrep_extra_floor_in_both_packaging_files():
    for filename in ("pyproject.toml", "setup.py"):
        text = Path(filename).read_text(encoding="utf-8")

        assert "semgrep>=1.185.0" in text, filename
        assert "semgrep>=1.0," not in text, filename
        assert "semgrep>=1.0\"" not in text, filename
        assert "semgrep>=1.0'" not in text, filename
