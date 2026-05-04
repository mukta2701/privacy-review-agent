from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.third_party_transfer import ThirdPartyTransferDetector


def test_flags_external_post_with_email(tmp_path):
    p = tmp_path / "send.py"
    p.write_text('requests.post("https://analytics.example.com", json={"email": user.email})')
    findings = ThirdPartyTransferDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "THIRD_PARTY_PII_TRANSFER" for f in findings)
