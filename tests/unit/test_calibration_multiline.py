"""Calibration behaviour for multi-line corpus cases.

Uses a fake engine (no semgrep binary needed): case lines carrying
``SEMGREP_SRC`` yield a ``semgrep`` finding on that line.
"""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from privacy_review_agent.calibration import score_corpus
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
        return SimpleNamespace(findings=findings)


def _present(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: "/usr/bin/semgrep")


def test_multiline_case_without_tag_is_rejected(tmp_path):
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row(
                "ml-no-tag",
                "py",
                "print(SEMGREP_SRC user.email)\nprint('done')",
                ["semgrep"],
                "true",
                [],
            )
        ],
    )

    with pytest.raises(ValueError):
        score_corpus(FakeEngine(), manifest)


def test_multiline_case_with_tag_loads(tmp_path, monkeypatch):
    _present(monkeypatch)
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row(
                "ml-ok",
                "py",
                "@mcp.tool\ndef f():\n    return user.email",
                ["semgrep"],
                "true",
                ["multiline"],
            )
        ],
    )

    scored = score_corpus(FakeEngine(), manifest)

    assert scored.true_case_count == 1


def test_finding_on_line_3_credited_to_multiline_case(tmp_path, monkeypatch):
    _present(monkeypatch)
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row(
                "ml-line3",
                "py",
                "@mcp.tool\ndef f():\n    return SEMGREP_SRC user.email",
                ["semgrep"],
                "true",
                ["multiline"],
            )
        ],
    )

    scored = score_corpus(FakeEngine(), manifest)

    assert scored.detectors["semgrep"]["tp"] == 1
    assert scored.detectors["semgrep"]["fn"] == 0


def test_multiline_near_miss_with_finding_counts_as_miss(tmp_path, monkeypatch):
    _present(monkeypatch)
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row(
                "ml-nm",
                "py",
                "@mcp.tool\ndef f():\n    return SEMGREP_SRC user.email",
                [],
                "near_miss",
                ["multiline"],
            )
        ],
    )

    scored = score_corpus(FakeEngine(), manifest)

    assert scored.near_miss_precision == 0.0
    assert scored.detectors["semgrep"]["fp"] == 1


def test_single_line_scoring_is_unchanged(tmp_path, monkeypatch):
    _present(monkeypatch)
    manifest = _write_manifest(
        tmp_path / "cases.jsonl",
        [
            _row(
                "sl-one",
                "py",
                "print(SEMGREP_SRC user.email)",
                ["semgrep"],
                "true",
                [],
            ),
            _row("sl-nm", "py", "print(filename)", [], "near_miss", []),
        ],
    )

    scored = score_corpus(FakeEngine(), manifest)

    assert scored.detectors["semgrep"]["tp"] == 1
    assert scored.detectors["semgrep"]["fn"] == 0
    assert scored.near_miss_precision == 1.0
