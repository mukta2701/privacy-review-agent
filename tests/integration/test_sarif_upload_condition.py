"""Contract for the conditional SARIF upload in the privacy-review workflow."""

from pathlib import Path

WORKFLOW = Path(".github/workflows/privacy-review.yml")


def _read():
    return WORKFLOW.read_text(encoding="utf-8")


def _step_block(text, step_name):
    start = text.index(f"name: {step_name}")
    line_start = text.rfind("\n      - ", 0, start)
    next_step = text.find("\n      - ", start)
    if next_step == -1:
        return text[line_start:]
    return text[line_start:next_step]


def test_upload_sarif_step_has_conditional_if():
    text = _read()
    block = _step_block(text, "Upload SARIF")
    assert "if:" in block
    assert "success()" in block
    assert "github.event.repository.private" in block
    assert "vars.PRIVACY_REVIEW_UPLOAD_SARIF == 'true'" in block


def test_notice_step_announces_skip():
    text = _read()
    block = _step_block(text, "Notify SARIF upload skipped")
    assert 'echo "::notice::' in block
    assert "PRIVACY_REVIEW_UPLOAD_SARIF" in block
    assert "continue-on-error" not in block


def test_no_continue_on_error_anywhere():
    assert "continue-on-error" not in _read()


def test_blocking_scan_still_fails_job_at_scan_step():
    text = _read()
    scan_block = _step_block(text, "Run privacy scan")
    assert "if:" not in scan_block
    assert "continue-on-error" not in scan_block
    upload_block = _step_block(text, "Upload SARIF")
    notice_block = _step_block(text, "Notify SARIF upload skipped")
    assert "always()" not in upload_block
    assert "always()" not in notice_block
