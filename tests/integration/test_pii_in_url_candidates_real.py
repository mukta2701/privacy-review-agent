"""Real-Semgrep regressions for URL candidate recovery (issue #31).

Skipped when semgrep is absent. Each case pairs a poisoned `internal`
function (same-named helper import, including the issue's `user.id` call
plus a tainted variant) with a clean `profile` function, and asserts the
detector reports exactly the `profile` sink as a canonical
`python-pii-in-url` finding. Also locks the public harness counts and the
unchanged URL fixture through the detector.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

needs_semgrep = pytest.mark.skipif(
    __import__("shutil").which("semgrep") is None, reason="semgrep not installed"
)

ANNOTATION_RE = re.compile(r"^\s*(?:#|//)\s*(ruleid|ok)\s*:\s*(\S+)\s*$")


def _url_hits(result):
    return [
        finding
        for finding in result.findings
        if finding.detector == "semgrep"
        and finding.message.startswith("python-pii-in-url:")
    ]


def _write(tmp_path: Path, name: str, code: str) -> Path:
    target = tmp_path / name
    target.write_text(code, encoding="utf-8")
    return target


@needs_semgrep
def test_flask_redirect_recovered(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write(
        tmp_path,
        "flask_redirect.py",
        "from flask import redirect\n"
        "def internal(user):\n"
        "    from helpers import redirect\n"
        "    seen = redirect(user.id)\n"
        "    return redirect(user.email)\n"
        "def profile(user):\n"
        '    return redirect(f"/profile?email={user.email}")\n',
    )

    hits = _url_hits(ReviewEngine().scan_files([target]))

    assert [hit.line for hit in hits] == [7]
    hit = hits[0]
    assert hit.tier.value == "confirmed"
    assert hit.category == "PII_IN_URL"
    assert hit.severity.value == "high"
    assert hit.confidence.value == "high"
    assert hit.blocking is True


@needs_semgrep
def test_flask_url_for_recovered(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write(
        tmp_path,
        "flask_url_for.py",
        "from flask import url_for\n"
        "def internal(user):\n"
        "    from helpers import url_for\n"
        '    seen = url_for("profile", user_id=user.id)\n'
        '    return url_for("profile", email=user.email)\n'
        "def profile(user):\n"
        '    return url_for("profile", email=user.email)\n',
    )

    hits = _url_hits(ReviewEngine().scan_files([target]))

    assert [hit.line for hit in hits] == [7]
    assert hits[0].category == "PII_IN_URL"
    assert hits[0].tier.value == "confirmed"


@needs_semgrep
def test_django_redirect_recovered(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write(
        tmp_path,
        "django_redirect.py",
        "from django.http import HttpResponseRedirect\n"
        "def internal(user):\n"
        "    from helpers import HttpResponseRedirect\n"
        "    seen = HttpResponseRedirect(user.id)\n"
        "    return HttpResponseRedirect(user.email)\n"
        "def profile(user):\n"
        "    return HttpResponseRedirect(user.email)\n",
    )

    hits = _url_hits(ReviewEngine().scan_files([target]))

    assert [hit.line for hit in hits] == [7]
    assert hits[0].category == "PII_IN_URL"
    assert hits[0].tier.value == "confirmed"


@needs_semgrep
def test_renamed_import_keeps_single_finding(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write(
        tmp_path,
        "renamed_import.py",
        "from flask import redirect\n"
        "def internal(user):\n"
        "    from helpers import redirect as other\n"
        "    return other(user.email)\n"
        "def profile(user):\n"
        "    return redirect(user.email)\n",
    )

    hits = _url_hits(ReviewEngine().scan_files([target]))

    assert len(hits) == 1
    assert hits[0].line == 6
    assert hits[0].category == "PII_IN_URL"
    assert hits[0].severity.value == "high"
    assert hits[0].confidence.value == "high"
    assert hits[0].tier.value == "confirmed"


@needs_semgrep
def test_existing_fixture_annotations_hold():
    from privacy_review_agent.engine import ReviewEngine

    fixture = Path(
        "src/privacy_review_agent/policies/semgrep_rules/python-pii-in-url.py"
    )
    expected = set()
    near_miss = set()
    for lineno, line in enumerate(
        fixture.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = ANNOTATION_RE.match(line)
        if match and match.group(2) == "python-pii-in-url":
            (expected if match.group(1) == "ruleid" else near_miss).add(lineno + 1)
    assert len(expected) == 32
    assert len(near_miss) == 40

    hits = _url_hits(ReviewEngine().scan_files([fixture]))

    assert sorted(hit.line for hit in hits) == sorted(expected)
    assert not any(hit.line in near_miss for hit in hits)


@needs_semgrep
def test_public_harness_counts_unchanged():
    from privacy_review_agent.config import load_settings
    from privacy_review_agent.semgrep_harness import run_rule_tests

    result = run_rule_tests(load_settings().semgrep_rules_dir)

    assert result.rules == 8
    assert result.cases == 359
    assert result.failures == []


@needs_semgrep
def test_public_harness_calibration_serialization():
    from privacy_review_agent.engine import ReviewEngine

    metrics = ReviewEngine().run_calibration(Path("tests/fixtures"))

    assert metrics.semgrep_rule_tests is not None
    assert metrics.semgrep_rule_tests.to_dict() == {
        "rules": 8,
        "cases": 359,
        "failures": [],
    }
