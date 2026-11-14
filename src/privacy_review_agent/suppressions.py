from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from privacy_review_agent.models import Finding

_INLINE_MARKER = re.compile(r"(?:#|//)\s*privacy-ok:\s*(\S.*)")


def parse_inline_suppression_reason(line: str) -> str | None:
    """Return the `privacy-ok` reason on one source line, or None."""
    match = _INLINE_MARKER.search(line)
    if not match:
        return None
    return match.group(1).strip()


@dataclass
class SuppressionPolicy:
    max_ttl_days: int
    require_github_issue: bool
    entries: list[dict[str, Any]]


def load_suppressions(path: Path) -> SuppressionPolicy:
    if not path.exists():
        return SuppressionPolicy(max_ttl_days=14, require_github_issue=True, entries=[])

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return SuppressionPolicy(
        max_ttl_days=int(raw.get("max_ttl_days", 14)),
        require_github_issue=bool(raw.get("require_github_issue", True)),
        entries=list(raw.get("entries", [])),
    )


def is_suppressed(finding: Finding, policy: SuppressionPolicy) -> bool:
    for entry in policy.entries:
        entry_id = str(entry.get("id", ""))
        if entry_id != finding.fingerprint and entry_id != finding.legacy_fingerprint:
            continue
        if not _entry_valid(entry, policy.max_ttl_days, policy.require_github_issue):
            continue
        return True
    return False


def _entry_valid(entry: dict[str, Any], max_ttl_days: int, require_issue: bool) -> bool:
    required = ["reason", "privacy_approver", "security_approver", "created_on", "expires_on"]
    if any(not entry.get(field) for field in required):
        return False

    if require_issue:
        ticket = str(entry.get("ticket", ""))
        if "github.com" not in ticket or "/issues/" not in ticket:
            return False

    try:
        created = datetime.strptime(str(entry["created_on"]), "%Y-%m-%d").date()
        expires = datetime.strptime(str(entry["expires_on"]), "%Y-%m-%d").date()
    except ValueError:
        return False

    if expires < date.today():
        return False
    if (expires - created).days > max_ttl_days:
        return False
    if entry.get("auto_renew", False):
        return False
    return True
