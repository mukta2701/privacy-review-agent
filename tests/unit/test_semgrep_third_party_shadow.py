"""Shadow credit for the ``third_party_transfer`` keyword detector.

Uses a fake engine (no semgrep binary needed): a case expecting
``third_party_transfer`` that receives only a ``semgrep`` finding (the
keyword finding was shadowed by the engine) counts as a keyword hit.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

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


def _finding(detector, file_path, line):
    return Finding(
        detector,
        "THIRD_PARTY_PII_TRANSFER",
        Severity.HIGH,
        Confidence.HIGH,
        file_path,
        line,
        f"{detector} hit",
        "evidence",
        "fix",
    )


class TransferShadowEngine:
    """Yields only a ``semgrep`` finding for the shadowed source line."""

    def scan_files(self, files):
        findings = []
        for path in files:
            for lineno, line in enumerate(
                Path(str(path)).read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "SEMGREP_SRC" in line:
                    findings.append(_finding("semgrep", str(path), lineno))
        return SimpleNamespace(findings=findings)


def test_shadowed_third_party_transfer_counts_as_keyword_hit(tmp_path):
    manifest = tmp_path / "cases.jsonl"
    manifest.write_text(
        "\n".join(
            [
                _row(
                    "kw-shadow-transfer",
                    "py",
                    "print(SEMGREP_SRC user.email)",
                    ["third_party_transfer"],
                    "true",
                    [],
                )
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    scored = score_corpus(TransferShadowEngine(), manifest)

    assert scored.detectors["third_party_transfer"]["tp"] == 1
    assert scored.detectors["third_party_transfer"]["fn"] == 0
    assert scored.detectors["semgrep"]["fp"] == 0
    assert scored.overall_precision == 1.0
    assert scored.overall_recall == 1.0
