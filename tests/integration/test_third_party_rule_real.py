"""Real-Semgrep tests for the PII-to-third-party rule.

Skipped when semgrep is absent. Covers every positive and near-miss probe
from the acceptance criteria through ``ReviewEngine().scan_files``, plus the
end-to-end blocking and keyword-shadowing behaviour and the vendor-allowlist
post-filter.
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
    ('requests.post("https://api.example.com/x", json={"e": user.email})', 0),
    ('requests.get("https://api.example.com/x", params={"phone": user.phone})', 0),
    ('requests.put("https://api.example.com/x", data={"ssn": user.ssn})', 0),
    ('requests.patch("https://api.example.com/x", data="hi " + user.email)', 0),
    ('requests.delete("https://api.example.com/x", headers=request.headers)', 0),
    (
        'requests.request("GET", "https://api.example.com/x", '
        'params={"n": user.first_name})',
        0,
    ),
    ('httpx.post("https://api.example.com/x", json={"e": user.email})', 0),
    ('httpx.get("https://api.example.com/x", params=f"phone={user.phone}")', 0),
    ('httpx.request("POST", "https://api.example.com/x", json={"e": user.email})', 0),
    ('requests.post("https://api.example.com/x", json="hi {}".format(user.email))', 0),
    ('requests.post("https://api.example.com/x", json="hi %s" % user.email)', 0),
    ('requests.post("https://api.example.com/x", content=user.email)', 0),
    (
        'payload = user.email\n'
        'requests.post("https://api.example.com/x", json=payload)',
        1,
    ),
    ('requests.post(\n    "https://api.example.com/x", json={"e": user.email})', 0),
    ('httpx.post("https://api.example.com/x", json={"e": user.last_name})', 0),
    ('requests.post("https://api.example.com/x", json={"e": user.phone_number})', 0),
    ('requests.post("https://api.example.com/x", json={"e": user.emailVerified})', 0),
    (
        "s1 = requests.Session()\n"
        's1.post("https://api.example.com/x", json={"e": user.email})',
        1,
    ),
    (
        "c1 = httpx.Client()\n"
        'c1.put("https://api.example.com/x", data={"ssn": user.ssn})',
        1,
    ),
    (
        "async def _f():\n"
        "    c2 = httpx.AsyncClient()\n"
        '    await c2.post("https://api.example.com/x", json={"e": user.email})',
        2,
    ),
]

NEAR_MISS_BLOCKS: list[str] = [
    'requests.post("https://api.example.com/x", json={"id": user.id})',
    'requests.post("https://api.example.com/x", json={"n": email_count})',
    'requests.post("https://api.example.com/x", json=settings.EMAIL_HOST)',
    'requests.post("https://api.example.com/x", json={"p": ssn_pattern})',
    'requests.post("https://api.example.com/x", json=redact(user.email))',
    'requests.post("https://api.example.com/x", json=hash(user.email))',
    'requests.post("https://api.example.com/x", json=len(user.email))',
    'requests.post("https://api.example.com/x", json=(user.email is None))',
    'requests.post("https://api.example.com/x", json=(user.email == other))',
    'requests.post("https://api.example.com/x", data=email.utils.formatdate())',
    'other = make()\nother.post("https://api.example.com/x", json={"e": user.email})',
    'Model.objects.post("https://api.example.com/x", email=user.email)',
    'httpx.post("https://api.example.com/x", json={"e": user.email_count})',
    'httpx.post("https://api.example.com/x", json={"e": user.email_domain})',
    'httpx.post("https://api.example.com/x", json={"e": user.phone_type})',
    'httpx.post("https://api.example.com/x", json=emails)',
    'httpx.post("https://api.example.com/x", json=useremail)',
    'def _f():\n    s = requests.Session()\n    s.post("https://x.example/y", json={"a": 1})',
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
def test_end_to_end_finding_is_confirmed_blocking_and_shadows_keyword(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text(
        'requests.post("https://api.vendor.example/x", json={"e": user.email})\n',
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
def test_allowlisted_vendor_url_is_dropped_while_others_report(tmp_path):
    import dataclasses

    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    settings = dataclasses.replace(
        load_settings(), vendor_allowlist=["api.vendor.example"]
    )
    engine = ReviewEngine(settings)

    dropped = tmp_path / "allowlisted.py"
    dropped.write_text(
        'requests.post("https://api.vendor.example/x", json={"e": user.email})\n',
        encoding="utf-8",
    )
    assert not [
        finding
        for finding in engine.scan_files([dropped]).findings
        if finding.detector == "semgrep"
    ]

    reported = tmp_path / "reported.py"
    reported.write_text(
        "\n".join(
            [
                'requests.post("https://other.example/x", json={"e": user.email})',
                'requests.post(url, json={"e": user.email})',
                'requests.post(f"https://api.vendor.example/{kind}", '
                'json={"e": user.email})',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    matched = {
        finding.line
        for finding in engine.scan_files([reported]).findings
        if finding.detector == "semgrep"
    }
    assert matched == {1, 2, 3}


@needs_semgrep
def test_non_ascii_comment_above_allowlisted_call_is_dropped(tmp_path):
    import dataclasses

    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    settings = dataclasses.replace(
        load_settings(), vendor_allowlist=["api.vendor.example"]
    )
    engine = ReviewEngine(settings)

    target = tmp_path / "allowlisted_unicode.py"
    target.write_bytes(
        (
            "# héllo wörld ✓ 日本語 😀\n"
            'requests.post("https://api.vendor.example/x", json={"e": user.email})\n'
        ).encode("utf-8")
    )

    assert not [
        finding
        for finding in engine.scan_files([target]).findings
        if finding.detector == "semgrep"
    ]


@needs_semgrep
def test_crlf_file_allowlisted_call_is_dropped(tmp_path):
    import dataclasses

    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    settings = dataclasses.replace(
        load_settings(), vendor_allowlist=["api.vendor.example"]
    )
    engine = ReviewEngine(settings)

    target = tmp_path / "allowlisted_crlf.py"
    target.write_bytes(
        (
            "# vendor call below\r\n"
            'requests.post("https://api.vendor.example/x", json={"e": user.email})\r\n'
        ).encode("utf-8")
    )

    assert not [
        finding
        for finding in engine.scan_files([target]).findings
        if finding.detector == "semgrep"
    ]
