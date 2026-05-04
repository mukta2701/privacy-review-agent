from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.secrets import SecretsDetector


def test_detects_hardcoded_api_key(tmp_path):
    p = tmp_path / "a.py"
    p.write_text('API_KEY = "sk_test_12345678901234567890"')
    findings = SecretsDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "SECRET_EXPOSURE" for f in findings)
