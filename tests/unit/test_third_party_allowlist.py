"""Unit tests for the third-party-transfer vendor-allowlist filter.

No semgrep binary needed: matches are built directly with span offsets and
the filter is a pure function of (match, file bytes, allowlist). Offsets are
UTF-8 byte offsets, as semgrep emits them.
"""

from __future__ import annotations

from privacy_review_agent.detectors.semgrep import is_allowlisted_transfer
from privacy_review_agent.semgrep_runner import SemgrepMatch

RULE_ID = "python-pii-to-third-party"
ALLOWLIST = ["api.vendor.example"]


def _match(text: str, rule_id: str = RULE_ID) -> tuple[SemgrepMatch, bytes]:
    data = text.encode("utf-8")
    return (
        SemgrepMatch(
            path="app.py",
            rule_id=rule_id,
            line=1,
            message="Personal data sent to a third party without redaction",
            metadata={},
            end_line=text.count("\n") + 1,
            offset=0,
            end_offset=len(data),
        ),
        data,
    )


def test_allowlisted_literal_is_dropped():
    text = 'requests.post("https://api.vendor.example/x", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True


def test_uppercase_host_in_literal_is_dropped():
    text = 'requests.post("https://API.VENDOR.EXAMPLE/x", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True


def test_url_keyword_literal_is_dropped():
    text = 'requests.post(url="https://api.vendor.example/x", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True


def test_url_on_its_own_line_is_dropped():
    text = (
        "requests.post(\n"
        '    "https://api.vendor.example/x", json={"e": user.email})\n'
    )
    data = text.encode("utf-8")
    match = SemgrepMatch(
        path="app.py",
        rule_id=RULE_ID,
        line=1,
        message="m",
        metadata={},
        end_line=2,
        offset=0,
        end_offset=len(data),
    )

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True


def test_url_keyword_on_its_own_line_is_dropped():
    text = (
        "requests.post(\n"
        '    url="https://api.vendor.example/x", json={"e": user.email})\n'
    )
    data = text.encode("utf-8")
    match = SemgrepMatch(
        path="app.py",
        rule_id=RULE_ID,
        line=1,
        message="m",
        metadata={},
        end_line=2,
        offset=0,
        end_offset=len(data),
    )

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True


def test_unlisted_host_is_reported():
    text = 'requests.post("https://other.example/x", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_multiline_unlisted_host_is_reported_on_call_line():
    text = (
        "requests.post(\n"
        '    "https://other.example/x", json={"e": user.email})\n'
    )
    data = text.encode("utf-8")
    match = SemgrepMatch(
        path="app.py",
        rule_id=RULE_ID,
        line=1,
        message="m",
        metadata={},
        end_line=2,
        offset=0,
        end_offset=len(data),
    )

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_variable_url_is_reported():
    text = 'requests.post(url, json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_fstring_url_is_reported():
    text = 'requests.post(f"https://api.vendor.example/{kind}", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_concatenated_url_is_reported():
    text = (
        'requests.post("https://api.vendor.example/" + kind, json={"e": user.email})\n'
    )

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_request_method_uses_second_positional():
    text = 'httpx.request("POST", "https://api.vendor.example/x", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True


def test_request_method_unlisted_second_positional_is_reported():
    text = 'httpx.request("POST", "https://other.example/x", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_scheme_less_literal_is_reported():
    text = 'requests.post("/api/x", json={"e": user.email})\n'

    match, data = _match(text)

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_unparseable_span_is_reported():
    match = SemgrepMatch(
        path="app.py",
        rule_id=RULE_ID,
        line=1,
        message="m",
        metadata={},
        end_line=1,
        offset=10,
        end_offset=5,
    )

    assert is_allowlisted_transfer(match, b"requests.post(url)\n", ALLOWLIST) is False


def test_other_rules_matches_are_untouched():
    text = 'requests.post("https://api.vendor.example/x", json={"e": user.email})\n'

    match, data = _match(text, "python-raw-pii-logging")

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_non_ascii_comment_above_allowlisted_call_is_dropped():
    prefix = "# héllo wörld ✓ 日本語 😀\n"
    call = 'requests.post("https://api.vendor.example/x", json={"e": user.email})'
    data = (prefix + call + "\n").encode("utf-8")
    start = len(prefix.encode("utf-8"))
    match = SemgrepMatch(
        path="app.py",
        rule_id=RULE_ID,
        line=2,
        message="m",
        metadata={},
        end_line=2,
        offset=start,
        end_offset=start + len(call.encode("utf-8")),
    )

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True


def test_non_ascii_prefix_unlisted_host_is_reported():
    prefix = "# héllo wörld ✓ 日本語 😀\n"
    call = 'requests.post("https://other.example/x", json={"e": user.email})'
    data = (prefix + call + "\n").encode("utf-8")
    start = len(prefix.encode("utf-8"))
    match = SemgrepMatch(
        path="app.py",
        rule_id=RULE_ID,
        line=2,
        message="m",
        metadata={},
        end_line=2,
        offset=start,
        end_offset=start + len(call.encode("utf-8")),
    )

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is False


def test_crlf_file_allowlisted_call_is_dropped():
    prefix = "# vendor call below\r\n"
    call = 'requests.post("https://api.vendor.example/x", json={"e": user.email})'
    data = (prefix + call + "\r\n").encode("utf-8")
    start = len(prefix.encode("utf-8"))
    match = SemgrepMatch(
        path="app.py",
        rule_id=RULE_ID,
        line=2,
        message="m",
        metadata={},
        end_line=2,
        offset=start,
        end_offset=start + len(call.encode("utf-8")),
    )

    assert is_allowlisted_transfer(match, data, ALLOWLIST) is True
