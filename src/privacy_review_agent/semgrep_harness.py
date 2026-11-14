"""Rule-test harness for the Semgrep rule pack.

Every rule file `<name>.yaml` is tested against its sibling case files
(`<name>.py`, `<name>.js`, `<name>.ts`). A case is the line after a
`# ruleid: <id>` (or `// ruleid: <id>`) comment, which the rule must match,
or after a `# ok: <id>` comment, which the rule must not match. The harness
drives the same runner seam as the detector.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from privacy_review_agent.semgrep_runner import (
    SemgrepFailed,
    SemgrepNotInstalled,
    load_rules,
    metadata_problem,
    run_semgrep,
    taxonomy_categories,
)

ANNOTATION_RE = re.compile(r"^\s*(?:#|//)\s*(ruleid|ok)\s*:\s*(\S+)\s*$")
CASE_EXTS = ("py", "js", "ts")


@dataclass
class HarnessResult:
    rules: int
    cases: int
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": self.rules,
            "cases": self.cases,
            "failures": list(self.failures),
        }


def check_rule_metadata(rules_dir: Path | None) -> list[str]:
    """Flag every rule whose metadata is missing or invalid (pure Python)."""
    categories = taxonomy_categories()
    failures = []
    for rule in load_rules(rules_dir):
        problem = metadata_problem(rule.metadata, categories)
        if problem is not None:
            failures.append(f"{rule.id}: {problem}")
    return sorted(failures)


def _collect_annotations(case_file: Path) -> dict[int, list[tuple[str, str]]]:
    try:
        lines = case_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {}
    found: dict[int, list[tuple[str, str]]] = {}
    for lineno, line in enumerate(lines, start=1):
        match = ANNOTATION_RE.match(line)
        if match:
            found.setdefault(lineno + 1, []).append((match.group(1), match.group(2)))
    return found


def run_rule_tests(rules_dir: Path | None) -> HarnessResult:
    """Run the rule tests over the pack and return counts plus failures."""
    try:
        rules = load_rules(rules_dir)
        failures = check_rule_metadata(rules_dir)
    except ValueError as exc:
        return HarnessResult(rules=0, cases=0, failures=[f"invalid rule pack: {exc}"])

    by_file: dict[str, list[str]] = {}
    for rule in rules:
        by_file.setdefault(rule.path, []).append(rule.id)
    rule_ids = {rule.id for rule in rules}

    case_files: list[Path] = []
    annotated: list[tuple[str, int, str, str]] = []
    for rule_file, ids in by_file.items():
        parent = Path(rule_file).parent
        stem = Path(rule_file).stem
        siblings = [
            parent / f"{stem}.{ext}"
            for ext in CASE_EXTS
            if (parent / f"{stem}.{ext}").is_file()
        ]
        if not siblings:
            failures.extend(f"{rule_id}: no test file for {rule_file}" for rule_id in ids)
            continue
        case_files.extend(sibling for sibling in siblings if sibling not in case_files)
        file_annotations: dict[int, list[tuple[str, str]]] = {}
        for sibling in siblings:
            for line, kinds in _collect_annotations(sibling).items():
                file_annotations.setdefault(line, []).extend(kinds)
                annotated.extend((str(sibling), line, kind, rid) for kind, rid in kinds)
        by_kind: dict[str, dict[str, list[int]]] = {}
        for line, kinds in file_annotations.items():
            for kind, rid in kinds:
                by_kind.setdefault(rid, {}).setdefault(kind, []).append(line)
                if rid not in rule_ids:
                    failures.append(f"{rid}: unknown rule id annotated in {rule_file}")
        for rule_id in ids:
            kinds = by_kind.get(rule_id, {})
            if not kinds.get("ruleid"):
                failures.append(f"{rule_id}: no positive case in {rule_file}")
            if not kinds.get("ok"):
                failures.append(f"{rule_id}: no near-miss case in {rule_file}")

    if failures:
        return HarnessResult(
            rules=len(rules), cases=len(annotated), failures=sorted(set(failures))
        )

    try:
        matches = (
            run_semgrep(case_files, Path(rules_dir)) if case_files and rules_dir else []
        )
    except SemgrepNotInstalled:
        return HarnessResult(
            rules=len(rules),
            cases=len(annotated),
            failures=["semgrep is not installed; cannot run rule tests"],
        )
    except SemgrepFailed as exc:
        return HarnessResult(
            rules=len(rules),
            cases=len(annotated),
            failures=[f"semgrep run failed: {exc}"],
        )

    realpaths = {os.path.realpath(str(path)): str(path) for path in case_files}
    matched = {
        (
            realpaths.get(os.path.realpath(match.path), match.path),
            match.line,
            match.rule_id,
        )
        for match in matches
    }
    for file_str, line, kind, rid in annotated:
        key = (
            realpaths.get(os.path.realpath(file_str), file_str),
            line,
            rid,
        )
        if kind == "ruleid" and key not in matched:
            failures.append(f"{rid}: positive case at {file_str}:{line} did not match")
        elif kind == "ok" and key in matched:
            failures.append(f"{rid}: near-miss case at {file_str}:{line} matched")
    annotated_positive = {
        (
            realpaths.get(os.path.realpath(file_str), file_str),
            line,
            rid,
        )
        for file_str, line, kind, rid in annotated
        if kind == "ruleid"
    }
    for file_str, line, rid in matched:
        if rid not in rule_ids:
            failures.append(f"{rid}: matched but is not a known rule id")
        elif (file_str, line, rid) not in annotated_positive:
            failures.append(
                f"{rid}: match at {file_str}:{line} has no ruleid annotation"
            )
    return HarnessResult(
        rules=len(rules), cases=len(annotated), failures=sorted(set(failures))
    )


__all__ = ["HarnessResult", "check_rule_metadata", "run_rule_tests"]
