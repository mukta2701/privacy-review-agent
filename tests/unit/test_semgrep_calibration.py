"""Calibration behaviour for the ``semgrep`` detector name.

Uses a fake engine (no semgrep binary needed): case lines carrying
``SEMGREP_SRC`` yield a ``semgrep`` finding, lines carrying ``KEYWORD_SRC``
yield a ``pii_logging`` finding.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

from privacy_review_agent.calibration import DETECTOR_NAMES, score_corpus
from privacy_review_agent.models import Confidence, Finding, Severity


def _encode(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _row(cid, ext, text, expect, kind, tags):
    return json.dumps(
        {
            "id": cid,
            "ext": ext,
            "text_b64": _encode(text),
            "expect": expect,
            "kind": kind,
            "tags": tags,
        }
    )


def _write_manifest(path, rows):
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def _finding(detector, file_path, line):
    return Finding(
        detector=detector,
        category="RAW_PII_LOGGING",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=file_path,
        line=line,
        message=f"{detector} hit",
        evidence="evidence",
        remediation="fix",
    )


class FakeEngine:
    """Maps marker text on a scanned line to a detector finding."""

    def scan_files(self, files):
        findings = []
        for path in files:
            for lineno, line in enumerate(
                Path(str(path)).read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "SEMGREP_SRC" in line:
                    findings.append(_finding("semgrep", str(path), lineno))
                if "KEYWORD_SRC" in line:
                    findings.append(_finding("pii_logging", str(path), lineno))
        return SimpleNamespace(findings=findings)


def _manifest_with_pair(tmp_path):
    return _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row("kw-one", "py", "print(KEYWORD_SRC user.email)", ["pii_logging"], "true", []),
            _row("se-one", "py", "print(SEMGREP_SRC user.email)", ["semgrep"], "true", []),
            _row("nm-one", "py", "print(filename)", [], "near_miss", []),
        ],
    )


def test_detector_names_include_semgrep():
    assert "semgrep" in DETECTOR_NAMES


def test_per_detector_keys_cover_semgrep(tmp_path):
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [_row("kw-one", "py", "print(KEYWORD_SRC user.email)", ["pii_logging"], "true", [])],
    )

    scored = score_corpus(FakeEngine(), manifest)

    assert set(scored.detectors) == set(DETECTOR_NAMES)
    assert scored.detectors["semgrep"] == {
        "precision": 1.0,
        "recall": 1.0,
        "tp": 0,
        "fp": 0,
        "fn": 0,
    }


def test_semgrep_labelled_cases_scored_when_present(monkeypatch, tmp_path):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: "/usr/bin/semgrep")
    scored = score_corpus(FakeEngine(), _manifest_with_pair(tmp_path))

    assert scored.true_case_count == 2
    assert scored.detectors["semgrep"] == {
        "precision": 1.0,
        "recall": 1.0,
        "tp": 1,
        "fp": 0,
        "fn": 0,
    }
    assert scored.overall_recall == 1.0
    assert scored.deterministic is True


def test_semgrep_absent_skips_semgrep_labelled_cases(monkeypatch, tmp_path):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
    scored = score_corpus(FakeEngine(), _manifest_with_pair(tmp_path))

    assert scored.true_case_count == 1
    assert scored.detectors["semgrep"]["tp"] == 0
    assert scored.detectors["semgrep"]["fn"] == 0
    assert scored.overall_recall == 1.0
    assert scored.near_miss_count == 1
    assert scored.near_miss_precision == 1.0
    assert scored.deterministic is True


def test_shadowed_pii_logging_counts_as_keyword_hit(tmp_path):
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [_row("kw-shadow", "py", "print(SEMGREP_SRC user.email)", ["pii_logging"], "true", [])],
    )

    scored = score_corpus(FakeEngine(), manifest)

    assert scored.detectors["pii_logging"]["tp"] == 1
    assert scored.detectors["pii_logging"]["fn"] == 0
    assert scored.detectors["semgrep"]["fp"] == 0
    assert scored.overall_precision == 1.0
    assert scored.overall_recall == 1.0


def test_shadow_credit_applies_to_known_gap_cases(tmp_path):
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row(
                "kg-shadow",
                "py",
                "print(SEMGREP_SRC user.email)",
                ["pii_logging"],
                "true",
                ["known_gap"],
            )
        ],
    )

    scored = score_corpus(FakeEngine(), manifest)

    assert scored.known_gap_misses == []
    assert scored.detectors["semgrep"]["fp"] == 0


def test_shadowed_pii_in_prompts_counts_as_keyword_hit(tmp_path):
    class PromptShadowEngine(FakeEngine):
        def scan_files(self, files):
            result = super().scan_files(files)
            result.findings = [
                finding for finding in result.findings if finding.detector == "semgrep"
            ]
            return result

    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row(
                "kw-shadow-prompts",
                "py",
                "print(SEMGREP_SRC user.email)",
                ["pii_in_prompts"],
                "true",
                [],
            )
        ],
    )

    scored = score_corpus(PromptShadowEngine(), manifest)

    assert scored.detectors["pii_in_prompts"]["tp"] == 1
    assert scored.detectors["pii_in_prompts"]["fn"] == 0
    assert scored.detectors["semgrep"]["fp"] == 0
    assert scored.overall_precision == 1.0
    assert scored.overall_recall == 1.0
