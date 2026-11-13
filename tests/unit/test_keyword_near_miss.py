"""Near-miss, true-positive and comment tests for the keyword detectors.

Every test goes through the existing detector ``scan`` API on ``tmp_path``
files, so nothing is added to ``tests/fixtures``.
"""

from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.missing_redaction import MissingRedactionDetector
from privacy_review_agent.detectors.pii_in_prompts import PiiInPromptsDetector
from privacy_review_agent.detectors.pii_logging import PiiLoggingDetector
from privacy_review_agent.detectors.policy_bypass import PolicyBypassDetector
from privacy_review_agent.detectors.third_party_transfer import ThirdPartyTransferDetector

DETECTORS = [
    PiiLoggingDetector(),
    PiiInPromptsDetector(),
    ThirdPartyTransferDetector(),
    MissingRedactionDetector(),
    PolicyBypassDetector(),
]


def _scan_all(path):
    context = DetectorContext(settings=load_settings())
    findings = []
    for detector in DETECTORS:
        findings.extend(detector.scan([path], context))
    return findings


def test_near_miss_words_on_log_sink_lines_yield_no_findings(tmp_path):
    p = tmp_path / "near_miss.js"
    p.write_text(
        "print(filename)\n"
        "console.log(translate(x))\n"
        "logger.info(max_tokens)\n"
        "logger.info(rename)\n"
        "logger.info(latitude)\n"
    )
    assert _scan_all(p) == []


def test_near_miss_words_on_prompt_and_transfer_lines_yield_no_findings(tmp_path):
    p = tmp_path / "near_miss.py"
    p.write_text(
        'prompt = f"Summarize {filename}"\n'
        'requests.post("https://analytics.example.com/collect", json={"filename": filename})\n'
    )
    assert _scan_all(p) == []


def test_full_line_comments_yield_no_keyword_findings(tmp_path):
    p = tmp_path / "commented.js"
    p.write_text(
        "# print(user.email)\n"
        "   # print(user.email)\n"
        "// console.log(req.body)\n"
        "   // console.log(req.body)\n"
    )
    assert _scan_all(p) == []


def test_true_positive_user_name_is_still_found(tmp_path):
    p = tmp_path / "log.js"
    p.write_text("logger.info(userName)")
    findings = PiiLoggingDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "RAW_PII_LOGGING" for f in findings)


def test_true_positive_user_email_is_still_found(tmp_path):
    p = tmp_path / "log.js"
    p.write_text("console.log(user_email)")
    findings = PiiLoggingDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "RAW_PII_LOGGING" for f in findings)


def test_true_positive_first_name_is_still_found(tmp_path):
    p = tmp_path / "log.js"
    p.write_text("logger.info(firstName)")
    findings = PiiLoggingDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "RAW_PII_LOGGING" for f in findings)
