from __future__ import annotations

import json

from privacy_review_agent.models import ScanResult


def render(result: ScanResult) -> str:
    runs = {
        "tool": {"driver": {"name": "privacy-review-agent", "rules": []}},
        "results": [],
    }

    seen_rules: set[str] = set()
    for finding in result.findings:
        if finding.category not in seen_rules:
            runs["tool"]["driver"]["rules"].append(
                {
                    "id": finding.category,
                    "name": finding.category,
                    "shortDescription": {"text": finding.message},
                }
            )
            seen_rules.add(finding.category)

        runs["results"].append(
            {
                "ruleId": finding.category,
                "level": "error" if finding.blocking else "warning",
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence.value,
                    "severity": finding.severity.value,
                    "fingerprint": finding.fingerprint,
                    "blocking": finding.blocking,
                },
            }
        )

    payload = {"version": "2.1.0", "runs": [runs]}
    return json.dumps(payload, indent=2)
