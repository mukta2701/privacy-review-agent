from __future__ import annotations

import json

from privacy_review_agent.models import ScanResult


def render(result: ScanResult) -> str:
    payload = {
        "meta": result.meta,
        "findings": [finding.to_dict() for finding in result.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
