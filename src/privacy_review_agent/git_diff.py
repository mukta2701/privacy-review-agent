from __future__ import annotations

import pathlib
import re
import subprocess

HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _run_git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout


def changed_files(base_ref: str, head_ref: str) -> list[pathlib.Path]:
    out = _run_git(["diff", "--name-only", f"{base_ref}..{head_ref}"])
    files = [pathlib.Path(line.strip()) for line in out.splitlines() if line.strip()]
    return [path for path in files if path.exists() and path.is_file()]


def changed_lines(base_ref: str, head_ref: str) -> dict[str, set[int]]:
    out = _run_git(["diff", "--unified=0", f"{base_ref}..{head_ref}"])
    changed: dict[str, set[int]] = {}
    current = ""

    for line in out.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            changed.setdefault(current, set())
            continue
        match = HUNK_RE.search(line)
        if not match or not current:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count <= 0:
            continue
        for line_number in range(start, start + count):
            changed[current].add(line_number)

    return changed
