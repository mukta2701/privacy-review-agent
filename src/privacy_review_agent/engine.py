from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from privacy_review_agent.calibration import CorpusMetrics, score_corpus
from privacy_review_agent.config import Settings, load_settings
from privacy_review_agent.detectors import (
    MissingRedactionDetector,
    PiiInPromptsDetector,
    PiiLoggingDetector,
    PolicyBypassDetector,
    SecretsDetector,
    ThirdPartyTransferDetector,
)
from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.git_diff import changed_files, changed_lines
from privacy_review_agent.models import Confidence, Finding, ScanResult, Severity
from privacy_review_agent.suppressions import is_suppressed, load_suppressions


@dataclass
class CalibrationMetrics:
    precision: float
    recall: float
    deterministic: bool
    tp: int
    fp: int
    unsafe_file_count: int
    overall_precision: float = 1.0
    overall_recall: float = 1.0
    near_miss_precision: float = 1.0
    near_miss_count: int = 0
    true_case_count: int = 0
    known_gap_count: int = 0
    detectors: dict[str, dict[str, float | int]] = field(default_factory=dict)
    known_gap_misses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "precision": self.precision,
            "recall": self.recall,
            "deterministic": self.deterministic,
            "tp": self.tp,
            "fp": self.fp,
            "unsafe_file_count": self.unsafe_file_count,
            "overall_precision": self.overall_precision,
            "overall_recall": self.overall_recall,
            "near_miss_precision": self.near_miss_precision,
            "near_miss_count": self.near_miss_count,
            "true_case_count": self.true_case_count,
            "known_gap_count": self.known_gap_count,
            "detectors": self.detectors,
            "known_gap_misses": self.known_gap_misses,
        }

    def gate_failures(self) -> list[str]:
        failures: list[str] = []
        if not self.near_miss_precision > 0.90:
            failures.append(f"near-miss precision {self.near_miss_precision} <= 0.90")
        if not self.overall_recall >= 0.80:
            failures.append(f"overall recall {self.overall_recall} < 0.80")
        if not self.deterministic:
            failures.append("output is not deterministic")
        if self.recall != 1.0:
            failures.append(f"unsafe fixture recall {self.recall} != 1.0")
        return failures


class ReviewEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        self.detectors: list[Detector] = [
            SecretsDetector(),
            PiiLoggingDetector(),
            ThirdPartyTransferDetector(),
            PiiInPromptsDetector(),
            MissingRedactionDetector(),
            PolicyBypassDetector(),
        ]

    def scan_ref(
        self,
        base_ref: str,
        head_ref: str,
        baseline_fingerprints: set[str] | None = None,
        suppressions_file: Path = Path(".privacy-review-ignore.yaml"),
    ) -> ScanResult:
        files = changed_files(base_ref, head_ref)
        changed_map = changed_lines(base_ref, head_ref)
        return self.scan_files(
            files,
            changed_map=changed_map,
            baseline_fingerprints=baseline_fingerprints,
            suppressions_file=suppressions_file,
        )

    def scan_files(
        self,
        files: list[Path],
        changed_map: dict[str, set[int]] | None = None,
        baseline_fingerprints: set[str] | None = None,
        suppressions_file: Path = Path(".privacy-review-ignore.yaml"),
    ) -> ScanResult:
        context = DetectorContext(settings=self.settings)
        baseline = baseline_fingerprints or set()
        suppression_policy = load_suppressions(suppressions_file)

        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.scan(files, context))

        deduped: dict[str, Finding] = {}
        for finding in findings:
            deduped.setdefault(finding.fingerprint, finding)

        filtered = list(deduped.values())
        for finding in filtered:
            in_changed_lines = self._in_changed_lines(finding, changed_map)
            finding.blocking = self._is_blocking(finding, in_changed_lines)
            if finding.fingerprint in baseline:
                finding.blocking = False
            if is_suppressed(finding, suppression_policy):
                finding.blocking = False

        return ScanResult(
            findings=sorted(filtered, key=lambda x: (x.file_path, x.line, x.category)),
            meta={
                "scanned_file_count": len(files),
                "baseline_applied": bool(baseline),
                "changed_line_gate": changed_map is not None,
            },
        )

    def run_calibration(self, fixture_set: Path) -> CalibrationMetrics:
        safe_files = self._collect_files(fixture_set / "safe")
        unsafe_files = self._collect_files(fixture_set / "unsafe")

        safe_result = self.scan_files(safe_files)
        unsafe_result = self.scan_files(unsafe_files)

        fp = len(safe_result.findings)
        tp = len(unsafe_result.findings)

        unsafe_hit_files = {finding.file_path for finding in unsafe_result.findings}
        unsafe_file_count = max(len(unsafe_files), 1)

        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = len(unsafe_hit_files) / unsafe_file_count

        # Deterministic check: same input twice should produce identical fingerprints.
        rerun = self.scan_files(unsafe_files)
        stable = [f.fingerprint for f in unsafe_result.findings] == [
            f.fingerprint for f in rerun.findings
        ]

        manifest = fixture_set / "labelled" / "cases.jsonl"
        if not manifest.is_file():
            raise FileNotFoundError(f"calibration corpus manifest not found: {manifest}")
        corpus = score_corpus(self, manifest)
        return self._combine_metrics(
            precision, recall, stable, tp, fp, unsafe_file_count, corpus
        )

    @staticmethod
    def _combine_metrics(
        precision: float,
        recall: float,
        stable: bool,
        tp: int,
        fp: int,
        unsafe_file_count: int,
        corpus: CorpusMetrics,
    ) -> CalibrationMetrics:
        return CalibrationMetrics(
            precision=precision,
            recall=recall,
            deterministic=stable and corpus.deterministic,
            tp=tp,
            fp=fp,
            unsafe_file_count=unsafe_file_count,
            overall_precision=corpus.overall_precision,
            overall_recall=corpus.overall_recall,
            near_miss_precision=corpus.near_miss_precision,
            near_miss_count=corpus.near_miss_count,
            true_case_count=corpus.true_case_count,
            known_gap_count=corpus.known_gap_count,
            detectors=corpus.detectors,
            known_gap_misses=corpus.known_gap_misses,
        )

    def _collect_files(self, root: Path) -> list[Path]:
        if not root.exists():
            return []
        files: list[Path] = []
        for path in root.rglob("*"):
            if path.is_file() and ".git" not in path.parts:
                files.append(path)
        return files

    def _is_blocking(self, finding: Finding, in_changed_lines: bool) -> bool:
        if finding.severity not in {Severity.CRITICAL, Severity.HIGH}:
            return False
        if finding.confidence is not Confidence.HIGH:
            return False
        return in_changed_lines

    def _in_changed_lines(self, finding: Finding, changed_map: dict[str, set[int]] | None) -> bool:
        if changed_map is None:
            return True
        key = finding.file_path
        if key.startswith("./"):
            key = key[2:]
        lines = changed_map.get(key)
        if lines is None:
            key_alt = str(Path(key))
            lines = changed_map.get(key_alt)
        if not lines:
            return False
        return finding.line in lines
