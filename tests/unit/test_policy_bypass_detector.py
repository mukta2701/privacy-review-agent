from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.policy_bypass import PolicyBypassDetector


def test_flags_disabled_consent_check(tmp_path):
    p = tmp_path / "privacy.ts"
    p.write_text("if (true) { return sendToVendor(data); } // consent bypass")
    findings = PolicyBypassDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "POLICY_BYPASS" for f in findings)
