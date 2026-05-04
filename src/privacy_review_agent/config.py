from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Settings:
    policies_dir: Path
    vendor_allowlist: list[str]
    sensitive_fields: set[str]
    redaction_helpers: set[str]
    bypass_markers: set[str]
    quasi_identifiers: set[str]
    llm_sinks: set[str]
    offline_mode: bool = True
    allow_verifier_egress: bool = False
    security_team_slug: str = ""
    required_rerun_label: str = "privacy-rerun-approved"


DEFAULT_POLICY_DIR = Path(__file__).parent / "policies"


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML mapping in {path}")
    return data


def load_settings(policies_dir: Path | None = None) -> Settings:
    directory = policies_dir or DEFAULT_POLICY_DIR

    vendor = _load_yaml(directory / "vendor_allowlist.yaml")
    sensitive = _load_yaml(directory / "sensitive_fields.yaml")
    redaction = _load_yaml(directory / "redaction_rules.yaml")
    bypass = _load_yaml(directory / "bypass_rules.yaml")
    prompt = _load_yaml(directory / "prompt_rules.yaml")

    return Settings(
        policies_dir=directory,
        vendor_allowlist=[str(item).lower() for item in vendor.get("allowed_domains", [])],
        sensitive_fields={str(item).lower() for item in sensitive.get("fields", [])},
        redaction_helpers={
            str(item).lower() for item in redaction.get("approved_redaction_helpers", [])
        },
        bypass_markers={str(item).lower() for item in bypass.get("bypass_markers", [])},
        quasi_identifiers={str(item).lower() for item in prompt.get("quasi_identifiers", [])},
        llm_sinks={str(item).lower() for item in prompt.get("llm_sinks", [])},
    )
