from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.missing_redaction import MissingRedactionDetector


def test_flags_logging_without_redaction(tmp_path):
    p = tmp_path / "log.ts"
    p.write_text("logger.info({email: user.email, token: authToken})")
    findings = MissingRedactionDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "INSUFFICIENT_REDACTION" for f in findings)
