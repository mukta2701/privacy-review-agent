from __future__ import annotations

import re
from pathlib import Path


def iter_text_files(files: list[Path]) -> list[tuple[Path, list[str]]]:
    out: list[tuple[Path, list[str]]] = []
    for path in files:
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        out.append((path, text.splitlines()))
    return out


def has_any_token(value: str, tokens: set[str]) -> bool:
    low = value.lower()
    return any(token in low for token in tokens)


def extract_domain(value: str) -> str:
    m = re.search(r"https?://([^/\"'\s]+)", value)
    if not m:
        return ""
    return m.group(1).lower()
