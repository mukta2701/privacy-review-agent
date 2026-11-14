"""Real-Semgrep tests for the PII-to-telemetry rule.

Skipped when semgrep is absent. Covers every positive and near-miss probe
from the acceptance criteria through ``ReviewEngine().scan_files``, plus the
end-to-end blocking behaviour and the vendor-allowlist no-filter behaviour.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)

# Each block is one probe; the sink (match) line is at the given offset.
POSITIVE_BLOCKS: list[tuple[str, int]] = [
    ('sentry_sdk.set_user({"email": user.email})', 0),
    ('sentry_sdk.set_context("user", {"ssn": user.ssn})', 0),
    ('sentry_sdk.set_tag("email", user.email)', 0),
    ('sentry_sdk.set_tags({"email": user.email})', 0),
    ('sentry_sdk.set_extra("email", user.email)', 0),
    ('sentry_sdk.add_breadcrumb(category="auth", data={"phone": user.phone})', 0),
    ('sentry_sdk.capture_message(f"signup {user.email}")', 0),
    ('sentry_sdk.capture_event({"user": {"ssn": user.ssn}})', 0),
    ('sentry_sdk.set_tag("email", f"{user.email}")', 0),
    ('analytics.identify(user.id, traits={"email": user.email})', 0),
    ('analytics.track("signup", {"email": user.email})', 0),
    ('analytics.page("home", {"email": user.email})', 0),
    ('analytics.screen("home", {"email": user.email})', 0),
    ('analytics.group("org", {"email": user.email})', 0),
    ("analytics.alias(user.id, user.email)", 0),
    ('posthog.capture("signup", properties={"email": user.email})', 0),
    ('posthog.identify(user.id, properties={"email": user.email})', 0),
    ('posthog.set(user.id, {"email": user.email})', 0),
    ('posthog.set_once(user.id, {"email": user.email})', 0),
    ("posthog.alias(user.id, user.email)", 0),
    ('posthog.group_identify("org", {"email": user.email})', 0),
    ('tracer.current_span().set_tag("email", user.email)', 0),
    ('tracer.current_span().set_tags({"email": user.email})', 0),
    ('ddtrace.tracer.current_span().set_tag("email", user.email)', 0),
    ('ddtrace.tracer.current_span().set_tags({"email": user.email})', 0),
    ('sentry_sdk.set_user({"phone": user.phone_number})', 0),
    ('analytics.identify(user.id, traits={"verified": user.emailVerified})', 0),
    (
        "contact = user.email\n"
        'sentry_sdk.set_extra("email", contact)',
        1,
    ),
    (
        'sentry_sdk.set_user(\n    {"email": user.email})',
        0,
    ),
    (
        'client = Posthog("key")\n'
        'client.capture("signup", properties={"email": user.email})',
        1,
    ),
    (
        'client = Posthog("key")\n'
        'client.set_once(user.id, {"email": user.email})',
        1,
    ),
    (
        'client = Posthog("key")\n'
        'client.group_identify("org", {"email": user.email})',
        1,
    ),
    (
        "span = tracer.current_span()\n"
        'span.set_tag("email", user.email)',
        1,
    ),
    (
        "span = tracer.current_span()\n"
        'span.set_tags({"phone": user.phone})',
        1,
    ),
    (
        'span = tracer.trace("op")\n'
        'span.set_tag("email", user.email)',
        1,
    ),
    (
        'span = tracer.trace("op")\n'
        'span.set_tags({"email": user.email})',
        1,
    ),
]

NEAR_MISS_BLOCKS: list[str] = [
    'sentry_sdk.set_user({"id": user.id})',
    "analytics.identify(user_id)",
    "analytics.identify(user.id)",
    'sentry_sdk.set_tag("env", "prod")',
    'analytics.track(user.id, "signup")',
    'sentry_sdk.set_user({"email": redact(user.email)})',
    'posthog.capture("signup", properties={"email": hash(user.email)})',
    'sentry_sdk.set_tag("n", len(user.email))',
    'analytics.track("click", {"n": item.count})',
    'posthog.capture("signup", "user signed up")',
    "sentry_sdk.capture_message(user.email is None)",
    "sentry_sdk.capture_event(user.email == other)",
    "sentry_sdk.capture_message(email.utils.formatdate())",
    'analytics.track("click", {"n": email_count})',
    'sentry_sdk.set_tag("host", settings.EMAIL_HOST)',
    'posthog.capture("event", properties={"p": ssn_pattern})',
    'sentry_sdk.set_extra("kind", user.phone_type)',
    'analytics.identify(user_id, traits={"e": user.email_domain})',
    "posthog.capture(\"event\", properties=emails)",
    'analytics.page("home", {"e": useremail})',
    'cache.set("email", user.email)',
    'metrics.capture("event", {"email": user.email})',
    'widget.set_tag("email", user.email)',
    'other.identify(user.id, traits={"email": user.email})',
    "def _f():\n"
    "    client = make_client()\n"
    '    client.capture("signup", properties={"email": user.email})',
    "def _f():\n"
    "    span = get_span()\n"
    '    span.set_tag("email", user.email)',
    "def _f():\n"
    '    s = requests.Session()\n'
    '    s.post("https://x.example/y", json={"a": 1})',
]


def _write_blocks(tmp_path: Path, name: str, blocks: list[str]) -> Path:
    target = tmp_path / name
    target.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    return target


@needs_semgrep
def test_every_positive_probe_matches_at_its_sink_line(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    lines: list[str] = []
    expected: set[int] = set()
    for block, offset in POSITIVE_BLOCKS:
        expected.add(len(lines) + offset + 1)
        lines.extend(block.splitlines())
    target = _write_blocks(tmp_path, "positives.py", lines)

    result = ReviewEngine().scan_files([target])

    matched = {
        finding.line for finding in result.findings if finding.detector == "semgrep"
    }
    assert matched == expected


@needs_semgrep
def test_no_near_miss_probe_matches(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_blocks(tmp_path, "near_miss.py", NEAR_MISS_BLOCKS)

    result = ReviewEngine().scan_files([target])

    assert not [finding for finding in result.findings if finding.detector == "semgrep"]


@needs_semgrep
def test_end_to_end_finding_is_confirmed_blocking_without_keyword(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text(
        'sentry_sdk.set_user({"email": user.email})\n',
        encoding="utf-8",
    )

    result = ReviewEngine().scan_files([target], changed_map={str(target): {1}})

    semgrep_hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit.tier.value == "confirmed"
    assert hit.category == "THIRD_PARTY_PII_TRANSFER"
    assert hit.blocking is True
    assert not any(
        f.detector == "third_party_transfer" and f.line == 1 for f in result.findings
    )


@needs_semgrep
def test_vendor_allowlist_does_not_suppress_telemetry_finding(tmp_path):
    import dataclasses

    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    settings = dataclasses.replace(
        load_settings(), vendor_allowlist=["api.vendor.example"]
    )
    engine = ReviewEngine(settings)

    target = tmp_path / "app.py"
    target.write_text(
        'sentry_sdk.set_user({"email": user.email})\n',
        encoding="utf-8",
    )

    semgrep_hits = [
        finding
        for finding in engine.scan_files([target]).findings
        if finding.detector == "semgrep"
    ]
    assert len(semgrep_hits) == 1
    assert semgrep_hits[0].category == "THIRD_PARTY_PII_TRANSFER"
