"""Offline Semgrep runner seam.

Single entry point for invoking the `semgrep` binary over scanned files with
only a local rules directory. No network access: metrics, version checks and
registry configs are disabled. Shared by the detector and the rule-test
harness so both drive Semgrep the same way.
"""

from __future__ import annotations

import functools
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SEMGREP_TIMEOUT = 120


class SemgrepNotInstalled(Exception):
    """Raised when the `semgrep` binary is not on PATH."""


class SemgrepFailed(Exception):
    """Raised when the `semgrep` run fails (exit code, timeout, bad JSON)."""


@dataclass
class SemgrepRule:
    id: str
    metadata: dict[str, Any]
    path: str


@dataclass
class SemgrepMatch:
    path: str
    rule_id: str
    line: int
    message: str
    metadata: dict[str, Any]


def load_rules(rules_dir: Path | None) -> list[SemgrepRule]:
    """List the rules in a directory (`*.yaml`/`*.yml`, recursive, sorted).

    A missing or empty directory means zero rules. Invalid YAML or a file
    without a top-level `rules` list raises `ValueError`.
    """
    if rules_dir is None or not Path(rules_dir).is_dir():
        return []
    rule_files = sorted(
        [
            *Path(rules_dir).rglob("*.yaml"),
            *Path(rules_dir).rglob("*.yml"),
        ],
        key=str,
    )
    rules: list[SemgrepRule] = []
    for rule_file in rule_files:
        try:
            data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid YAML in {rule_file}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise ValueError(f"no `rules` list in {rule_file}")
        for entry in data["rules"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                raise ValueError(f"rule without string `id` in {rule_file}")
            metadata = entry.get("metadata") or {}
            rules.append(
                SemgrepRule(id=entry["id"], metadata=metadata, path=str(rule_file))
            )
    return rules


@functools.lru_cache(maxsize=1)
def taxonomy_categories() -> set[str]:
    """Ids from the package's `policies/taxonomy.yaml`."""
    data = yaml.safe_load(
        (Path(__file__).parent / "policies" / "taxonomy.yaml").read_text(
            encoding="utf-8"
        )
    )
    return {str(item["id"]) for item in data.get("categories", [])}


VALID_SEVERITIES = ("critical", "high", "medium", "low")
VALID_CONFIDENCES = ("high", "medium", "low")


def metadata_problem(metadata: Any, categories: set[str]) -> str | None:
    """Name what's wrong with a rule's metadata, or `None` when it's valid."""
    if not isinstance(metadata, dict):
        return "metadata is not a mapping"
    if metadata.get("category") not in categories:
        return f"invalid category {metadata.get('category')!r}"
    if metadata.get("severity") not in VALID_SEVERITIES:
        return f"invalid severity {metadata.get('severity')!r}"
    if metadata.get("confidence") not in VALID_CONFIDENCES:
        return f"invalid confidence {metadata.get('confidence')!r}"
    remediation = metadata.get("remediation")
    if not isinstance(remediation, str) or not remediation.strip():
        return "missing remediation"
    return None


def run_semgrep(files: list[Path], rules_dir: Path) -> list[SemgrepMatch]:
    """Run `semgrep` once over the files with only the local rules directory."""
    exe = shutil.which("semgrep")
    if exe is None:
        raise SemgrepNotInstalled("semgrep executable not found on PATH")
    cmd = [
        exe,
        "--config",
        str(rules_dir),
        "--json",
        "--metrics",
        "off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--quiet",
        *(str(path) for path in files),
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT, check=False
        )
    except OSError as exc:
        raise SemgrepFailed(f"could not start semgrep: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SemgrepFailed(f"semgrep timed out: {exc}") from exc
    if result.returncode != 0:
        raise SemgrepFailed(f"semgrep exited with code {result.returncode}")
    try:
        data = json.loads(result.stdout or "")
    except json.JSONDecodeError as exc:
        raise SemgrepFailed(f"semgrep returned invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SemgrepFailed("semgrep returned non-object JSON")
    entries = data.get("results", [])
    if not isinstance(entries, list):
        raise SemgrepFailed("semgrep returned non-list results")
    matches: list[SemgrepMatch] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        start = entry.get("start", {})
        line = start.get("line", 0) if isinstance(start, dict) else 0
        if not isinstance(line, int) or line < 1:
            continue
        extra = entry.get("extra", {})
        extra = extra if isinstance(extra, dict) else {}
        metadata = extra.get("metadata") or {}
        matches.append(
            SemgrepMatch(
                path=str(entry.get("path", "")),
                rule_id=str(entry.get("check_id", "")),
                line=line,
                message=str(extra.get("message", "")),
                metadata=metadata if isinstance(metadata, dict) else {},
            )
        )
    matches.sort(key=lambda match: (match.path, match.rule_id, match.line))
    return matches


__all__ = [
    "SEMGREP_TIMEOUT",
    "VALID_CONFIDENCES",
    "VALID_SEVERITIES",
    "SemgrepFailed",
    "SemgrepMatch",
    "SemgrepNotInstalled",
    "SemgrepRule",
    "load_rules",
    "metadata_problem",
    "run_semgrep",
    "taxonomy_categories",
]
