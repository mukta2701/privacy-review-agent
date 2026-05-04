from pathlib import Path

import yaml


def test_taxonomy_contains_required_categories():
    tax = yaml.safe_load(Path("src/privacy_review_agent/policies/taxonomy.yaml").read_text())
    ids = {x["id"] for x in tax["categories"]}
    assert "SECRET_EXPOSURE" in ids
    assert "PII_IN_MODEL_PROMPT" in ids
