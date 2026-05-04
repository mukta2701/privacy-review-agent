from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.pii_logging import PiiLoggingDetector


def test_flags_raw_request_logging(tmp_path):
    p = tmp_path / "handler.js"
    p.write_text("console.log(req.body)")
    findings = PiiLoggingDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "RAW_PII_LOGGING" for f in findings)
