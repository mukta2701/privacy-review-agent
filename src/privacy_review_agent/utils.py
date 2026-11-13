from __future__ import annotations

import functools
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


_ACRONYM_BOUNDARY = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ALNUM_BOUNDARY = re.compile(r"(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")


def _normalize_identifier_text(text: str) -> str:
    text = _ACRONYM_BOUNDARY.sub(" ", text)
    text = _CAMEL_BOUNDARY.sub(" ", text)
    return _ALNUM_BOUNDARY.sub(" ", text).lower()


def split_identifier_parts(text: str) -> list[str]:
    """Split text into lowercase word parts on identifier boundaries."""
    return [part for part in re.split(r"[^0-9a-z]+", _normalize_identifier_text(text)) if part]


_SEPARATOR_CHARS = frozenset("_-. \t")


def _is_word(chunk: str) -> bool:
    return re.fullmatch(r"[0-9a-z]+", chunk) is not None


@functools.lru_cache(maxsize=512)
def _compile_marker_pattern(marker: str) -> re.Pattern[str]:
    normalized = _normalize_identifier_text(marker)
    chunks = re.findall(r"[0-9a-z]+|[^0-9a-z]+", normalized)
    pieces = ["(?<![0-9a-z])"]
    for index, chunk in enumerate(chunks):
        if _is_word(chunk):
            pieces.append(re.escape(chunk))
            continue
        prev_is_word = index > 0 and _is_word(chunks[index - 1])
        next_is_word = index + 1 < len(chunks) and _is_word(chunks[index + 1])
        stripped = chunk.replace(" ", "").replace("\t", "")
        if not stripped:
            gap = r"[^0-9a-z]+" if prev_is_word and next_is_word else r"\s*"
            pieces.append(gap)
        elif set(stripped) <= _SEPARATOR_CHARS and prev_is_word and next_is_word:
            pieces.append(r"[^0-9a-z]+")
        else:
            literal = r"\s*".join(re.escape(char) for char in stripped)
            pieces.append(r"\s*" + literal + r"\s*")
    if not chunks:
        pieces.append(r"(?![0-9a-z])")
    elif re.fullmatch(r"[0-9a-z]+", chunks[-1]) is not None:
        pieces.append(r"(?![0-9a-z])")
    return re.compile("".join(pieces))


def has_any_token(value: str, tokens: set[str]) -> bool:
    """Match markers against whole identifier word parts, not substrings."""
    normalized = _normalize_identifier_text(value)
    return any(_compile_marker_pattern(token).search(normalized) for token in tokens)


def has_any_substring(value: str, tokens: set[str]) -> bool:
    low = value.lower()
    return any(token in low for token in tokens)


def is_full_line_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#") or stripped.startswith("//")


def extract_domain(value: str) -> str:
    m = re.search(r"https?://([^/\"'\s]+)", value)
    if not m:
        return ""
    return m.group(1).lower()
