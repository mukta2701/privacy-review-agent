"""Score the labelled calibration corpus.

The manifest holds one JSON object per line. Case text is base64 so the
committed file stays inert to scans. Scoring maps each finding back to
(file, line, detector) and counts matches against the labels.
"""

from __future__ import annotations

import base64
import binascii
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from privacy_review_agent.engine import ReviewEngine

DETECTOR_NAMES = (
    "secrets",
    "pii_logging",
    "third_party_transfer",
    "pii_in_prompts",
    "missing_redaction",
    "policy_bypass",
)

CASE_EXTS = ("py", "js", "ts")
NEAR_MISS = "near_miss"
TRUE = "true"
KNOWN_GAP = "known_gap"


@dataclass
class CorpusMetrics:
    overall_precision: float
    overall_recall: float
    near_miss_precision: float
    near_miss_count: int
    true_case_count: int
    known_gap_count: int
    detectors: dict[str, dict[str, float | int]]
    known_gap_misses: list[str]
    deterministic: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_precision": self.overall_precision,
            "overall_recall": self.overall_recall,
            "near_miss_precision": self.near_miss_precision,
            "near_miss_count": self.near_miss_count,
            "true_case_count": self.true_case_count,
            "known_gap_count": self.known_gap_count,
            "detectors": self.detectors,
            "known_gap_misses": self.known_gap_misses,
            "deterministic": self.deterministic,
        }


def _decode_text(raw: str, where: str) -> str:
    try:
        text = base64.b64decode(raw, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ValueError(f"{where}: invalid text_b64: {exc}") from exc
    if "\n" in text or "\r" in text or not text:
        raise ValueError(f"{where}: decoded case must be exactly one non-empty line")
    return text


def _validate_case(case: Any, lineno: int, manifest: Path, seen: set[str]) -> str:
    where = f"{manifest}:{lineno}"
    if not isinstance(case, dict):
        raise ValueError(f"{where}: each line must be a JSON object")
    for key in ("id", "ext", "text_b64", "expect", "kind", "tags"):
        if key not in case:
            raise ValueError(f"{where}: missing key {key!r}")
    cid = case["id"]
    if not isinstance(cid, str) or not cid:
        raise ValueError(f"{where}: id must be a non-empty string")
    if cid in seen:
        raise ValueError(f"{where}: duplicate case id {cid!r}")
    seen.add(cid)
    if case["ext"] not in CASE_EXTS:
        raise ValueError(f"{where}: invalid ext {case['ext']!r}")
    text = _decode_text(case["text_b64"], where)
    if not isinstance(case["expect"], list) or any(
        item not in DETECTOR_NAMES for item in case["expect"]
    ):
        raise ValueError(f"{where}: expect must list known detectors")
    if case["kind"] not in (NEAR_MISS, TRUE):
        raise ValueError(f"{where}: invalid kind {case['kind']!r}")
    if not isinstance(case["tags"], list):
        raise ValueError(f"{where}: tags must be a list")
    if case["kind"] == NEAR_MISS and case["expect"]:
        raise ValueError(f"{where}: near_miss case must have empty expect")
    return text


def _load_cases(manifest: Path) -> list[dict[str, Any]]:
    try:
        raw = manifest.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"calibration corpus manifest not found: {manifest}") from exc
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{manifest}:{lineno}: invalid JSON: {exc}") from exc
        text = _validate_case(case, lineno, manifest, seen)
        case["text"] = text
        cases.append(case)
    return cases


def _scan_keys(engine: ReviewEngine, cases: list[dict[str, Any]]) -> list[tuple[str, str]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        grouped.setdefault(case["ext"], []).append(case)
    found: set[tuple[str, str]] = set()
    with tempfile.TemporaryDirectory(prefix="corpus-") as tmp:
        paths: list[Path] = []
        owners: dict[str, list[dict[str, Any]]] = {}
        for ext, group in grouped.items():
            target = Path(tmp) / f"corpus_case.{ext}"
            target.write_text("".join(item["text"] + "\n" for item in group), encoding="utf-8")
            paths.append(target)
            owners[str(target)] = group
        result = engine.scan_files(paths)
        for finding in result.findings:
            group = owners.get(finding.file_path, [])
            if 1 <= finding.line <= len(group):
                found.add((group[finding.line - 1]["id"], finding.detector))
    return sorted(found)


def _ratio(made: int, total: int) -> float:
    if not total:
        return 1.0
    return round(made / total, 4)


def score_corpus(engine: ReviewEngine, manifest_path: Path) -> CorpusMetrics:
    manifest = Path(manifest_path)
    cases = _load_cases(manifest)

    first = _scan_keys(engine, cases)
    second = _scan_keys(engine, cases)

    by_id = {case["id"]: case for case in cases}
    per: dict[str, dict[str, float | int]] = {
        name: {"precision": 1.0, "recall": 1.0, "tp": 0, "fp": 0, "fn": 0}
        for name in DETECTOR_NAMES
    }
    tp = 0
    fp = 0
    fn = 0
    gap_misses: set[str] = set()
    hit_ids = {cid for cid, _ in first}

    for cid, detector in first:
        case = by_id[cid]
        if KNOWN_GAP in case["tags"]:
            if detector not in case["expect"]:
                fp += 1
                per[detector]["fp"] += 1
        elif detector in case["expect"]:
            tp += 1
            per[detector]["tp"] += 1
        else:
            fp += 1
            per[detector]["fp"] += 1

    for case in cases:
        if KNOWN_GAP in case["tags"]:
            if any(key not in first for key in [(case["id"], item) for item in case["expect"]]):
                gap_misses.add(case["id"])
        else:
            for item in case["expect"]:
                if (case["id"], item) not in first:
                    fn += 1
                    per[item]["fn"] += 1

    for name in DETECTOR_NAMES:
        entry = per[name]
        made_tp = entry["tp"]
        made_fp = entry["fp"]
        made_fn = entry["fn"]
        entry["precision"] = _ratio(made_tp, made_tp + made_fp)
        entry["recall"] = _ratio(made_tp, made_tp + made_fn)

    near = [case for case in cases if case["kind"] == NEAR_MISS]
    clean = sum(1 for case in near if case["id"] not in hit_ids)
    gap_count = sum(1 for case in cases if KNOWN_GAP in case["tags"])
    return CorpusMetrics(
        overall_precision=_ratio(tp, tp + fp),
        overall_recall=_ratio(tp, tp + fn),
        near_miss_precision=_ratio(clean, len(near)),
        near_miss_count=len(near),
        true_case_count=sum(1 for case in cases if case["kind"] == TRUE),
        known_gap_count=gap_count,
        detectors=per,
        known_gap_misses=sorted(gap_misses),
        deterministic=first == second,
    )


__all__ = ["CorpusMetrics", "DETECTOR_NAMES", "score_corpus"]
