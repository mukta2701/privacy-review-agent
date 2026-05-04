from privacy_review_agent.config import load_settings
from privacy_review_agent.detectors.base import DetectorContext
from privacy_review_agent.detectors.pii_in_prompts import PiiInPromptsDetector


def test_flags_raw_pii_in_prompt(tmp_path):
    p = tmp_path / "llm.py"
    p.write_text('prompt = f"Summarize {user.email} {user.phone} {user.message}"')
    findings = PiiInPromptsDetector().scan([p], DetectorContext(settings=load_settings()))
    assert any(f.category == "PII_IN_MODEL_PROMPT" for f in findings)
