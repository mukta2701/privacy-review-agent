"""Real-Semgrep tests for the shipped PII-logging rule pack.

Skipped when semgrep is absent. Covers the pack harness result and the
end-to-end scan behaviour on logging lines.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")


@needs_semgrep
def test_harness_passes_on_shipped_pack():
    from privacy_review_agent.semgrep_harness import run_rule_tests

    result = run_rule_tests(PACK)

    assert result.failures == []
    assert result.rules >= 2
    assert result.cases > 0


@needs_semgrep
def test_direct_sensitive_logging_is_confirmed_and_shadows_keyword(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text('logger.info(f"login {user.email}")\n', encoding="utf-8")

    result = ReviewEngine().scan_files([target], changed_map={str(target): {1}})

    semgrep_hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit.tier.value == "confirmed"
    assert hit.category == "RAW_PII_LOGGING"
    assert hit.blocking is True
    assert not any(
        f.detector == "pii_logging" and f.line == 1 for f in result.findings
    )


@needs_semgrep
def test_request_headers_logged_from_typescript(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.ts"
    target.write_text("console.log(req.headers)\n", encoding="utf-8")

    result = ReviewEngine().scan_files([target], changed_map={str(target): {1}})

    semgrep_hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    assert semgrep_hits[0].tier.value == "confirmed"
    assert semgrep_hits[0].blocking is True
    assert not any(
        f.detector == "pii_logging" and f.line == 1 for f in result.findings
    )


@needs_semgrep
def test_redacted_value_yields_no_semgrep_finding(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text("logger.info(redact(user.email))\n", encoding="utf-8")

    result = ReviewEngine().scan_files([target])

    assert not any(f.detector == "semgrep" for f in result.findings)


@needs_semgrep
def test_redacted_value_on_keyword_clean_sink_is_fully_silent(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text("logging.warning(redact(user.email))\n", encoding="utf-8")

    result = ReviewEngine().scan_files([target])

    assert result.findings == []
