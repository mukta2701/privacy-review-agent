"""Real-Semgrep tests for the PII-in-URL rule.

Skipped when semgrep is absent. Covers every sink/flow probe from the
acceptance criteria through ``ReviewEngine().scan_files``, the per-origin
import gates, and the end-to-end blocking behaviour.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)

POSITIVE_IMPORTS = "\n".join(
    [
        "from django.http import HttpResponsePermanentRedirect",
        "from django.http import HttpResponseRedirect",
        "from django.shortcuts import redirect",
        "from flask import redirect",
        "from flask import url_for",
        "from starlette.responses import RedirectResponse",
    ]
)

# Each block is one probe; the sink (match) line is at the given offset.
POSITIVE_BLOCKS: list[tuple[str, int]] = [
    ("def _f1():\n    return flask.redirect(user.email)", 2),
    ('def _f2():\n    return flask.url_for("p", email=user.email)', 2),
    ("def _f3():\n    return redirect(user.email)", 2),
    ("def _f4():\n    return redirect(location=user.email)", 2),
    ('def _f5():\n    return redirect(f"/u/{user.email}")', 2),
    ('def _f6():\n    return redirect("/u/" + user.email)', 2),
    ('def _f7():\n    return redirect("/u/%s" % user.email)', 2),
    ('def _f8():\n    return redirect("/u/{}".format(user.email))', 2),
    ("def _f9():\n    v = user.phone\n    return redirect(v)", 3),
    ("def _f10(email):\n    return redirect(email)", 2),
    ("def _f11():\n    return redirect(user.phone_number)", 2),
    ('def _f12():\n    return redirect(data["email"])', 2),
    ("def _f13():\n    return redirect(req.body)", 2),
    ("def _f14():\n    return redirect(\n        user.email)", 2),
    ('def _f15():\n    return url_for("p", email=user.email)', 2),
    ('def _f16():\n    return url_for("p", email=f"{user.email}")', 2),
    ('def _f17():\n    v = user.email\n    return url_for("p", email=v)', 3),
    ('def _f18():\n    return url_for("p", email=user.emailVerified)', 2),
    ("def _f19():\n    return HttpResponseRedirect(user.email)", 2),
    ("def _f20():\n    return HttpResponsePermanentRedirect(redirect_to=user.email)", 2),
    ("def _f21():\n    return RedirectResponse(user.email)", 2),
    ("def _f22():\n    return RedirectResponse(url=user.email)", 2),
    ("def _f23():\n    return RedirectResponse(request.headers)", 2),
]

NEAR_MISS_BLOCKS: list[str] = [
    "def _g1():\n    return redirect(user.id)",
    "def _g2(user_id):\n    return redirect(user_id)",
    'def _g3():\n    return redirect("/home")',
    'def _g4():\n    return url_for("profile", user_id=user.id)',
    'def _g5():\n    return url_for("home")',
    "def _g6():\n    return redirect(redact(user.email))",
    'def _g7():\n    return url_for("p", email=mask(user.email))',
    "def _g8():\n    return HttpResponseRedirect(hash(user.email))",
    "def _g9():\n    return RedirectResponse(tokenize(user.email))",
    "def _g10():\n    return redirect(len(user.email))",
    "def _g11():\n    return redirect(bool(user.email))",
    "def _g12():\n    return redirect(type(user.email))",
    "def _g13():\n    return redirect(user.email is not None)",
    'def _g14():\n    return url_for("p", c=user.email == other)',
    "def _g15():\n    return redirect(email_count)",
    "def _g16():\n    return redirect(settings.EMAIL_HOST)",
    "def _g17():\n    return redirect(ssn_pattern)",
    "def _g18():\n    return redirect(user.email_domain)",
    "def _g19():\n    return redirect(phone_type)",
    "def _g20():\n    return redirect(user.emails)",
    "def _g21():\n    return redirect(useremail)",
    "def _g22():\n    return redirect(email.header)",
    'def _g23():\n    send(user.email)\n    return redirect("/home")',
]

# (import line, sink line) pairs, each in its own file.
ORIGIN_PROBES: list[tuple[str, str]] = [
    ("from flask import redirect", "return redirect(user.email)"),
    ('from flask import url_for', 'return url_for("p", email=user.email)'),
    ("from django.shortcuts import redirect", "return redirect(user.email)"),
    (
        "from django.http import HttpResponseRedirect",
        "return HttpResponseRedirect(user.email)",
    ),
    (
        "from django.http import HttpResponsePermanentRedirect",
        "return HttpResponsePermanentRedirect(user.email)",
    ),
    (
        "from starlette.responses import RedirectResponse",
        "return RedirectResponse(user.email)",
    ),
    (
        "from fastapi.responses import RedirectResponse",
        "return RedirectResponse(user.email)",
    ),
]


def _write_blocks(tmp_path: Path, name: str, blocks: list[str]) -> Path:
    target = tmp_path / name
    target.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    return target


@needs_semgrep
def test_every_positive_probe_matches_at_its_sink_line(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    lines: list[str] = POSITIVE_IMPORTS.splitlines()
    expected: set[int] = set()
    for block, offset in POSITIVE_BLOCKS:
        expected.add(len(lines) + offset)
        lines.extend(block.splitlines())
    target = _write_blocks(tmp_path, "positives.py", lines)

    result = ReviewEngine().scan_files([target])

    matched = {
        finding.line for finding in result.findings if finding.detector == "semgrep"
    }
    assert matched == expected


@needs_semgrep
def test_each_import_origin_authorizes_its_bare_sink(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    for number, (import_line, sink_line) in enumerate(ORIGIN_PROBES):
        target = tmp_path / f"origin_{number}.py"
        target.write_text(
            f"{import_line}\n\ndef _f():\n    {sink_line}\n",
            encoding="utf-8",
        )

        result = ReviewEngine().scan_files([target])

        matched = {
            finding.line for finding in result.findings if finding.detector == "semgrep"
        }
        assert matched == {4}, import_line


@needs_semgrep
def test_missing_import_produces_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_blocks(
        tmp_path,
        "no_import.py",
        [
            "def _f1():\n    return redirect(user.email)",
            'def _f2():\n    return url_for("p", email=user.email)',
            "def _f3():\n    return HttpResponseRedirect(user.email)",
            "def _f4():\n    return RedirectResponse(user.email)",
        ],
    )

    result = ReviewEngine().scan_files([target])

    assert not [finding for finding in result.findings if finding.detector == "semgrep"]


@needs_semgrep
def test_unrelated_imports_produce_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_blocks(
        tmp_path,
        "unrelated.py",
        [
            "from mylib import redirect\n\ndef _f1():\n    return redirect(user.email)",
            'from helpers import url_for\n\ndef _f2():\n    return url_for("p", email=user.email)',
            "from myapp.http import HttpResponseRedirect\n\n"
            "def _f3():\n    return HttpResponseRedirect(user.email)",
            "from myapp.responses import RedirectResponse\n\n"
            "def _f4():\n    return RedirectResponse(user.email)",
        ],
    )

    result = ReviewEngine().scan_files([target])

    assert not [finding for finding in result.findings if finding.detector == "semgrep"]


@needs_semgrep
def test_home_grown_helpers_produce_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_blocks(
        tmp_path,
        "helpers.py",
        [
            "def redirect(url):\n    return url\n\ndef _f1():\n    return redirect(user.email)",
            'def url_for(endpoint, **values):\n    return endpoint\n\n'
            'def _f2():\n    return url_for("p", email=user.email)',
        ],
    )

    result = ReviewEngine().scan_files([target])

    assert not [finding for finding in result.findings if finding.detector == "semgrep"]


@needs_semgrep
def test_no_near_miss_probe_matches(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    lines: list[str] = POSITIVE_IMPORTS.splitlines()
    lines.extend("\n".join(NEAR_MISS_BLOCKS).splitlines())
    target = _write_blocks(tmp_path, "near_miss.py", lines)

    result = ReviewEngine().scan_files([target])

    assert not [finding for finding in result.findings if finding.detector == "semgrep"]


@needs_semgrep
def test_import_order_gates_bare_redirect(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "order.py"
    target.write_text(
        "def _early():\n"
        "    return redirect(user.email)\n"
        "\n"
        "from flask import redirect\n"
        "\n"
        "def _late():\n"
        "    return redirect(user.email)\n",
        encoding="utf-8",
    )

    result = ReviewEngine().scan_files([target])

    matched = {
        finding.line for finding in result.findings if finding.detector == "semgrep"
    }
    assert matched == {7}


@needs_semgrep
def test_end_to_end_finding_is_confirmed_blocking_without_keyword(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text(
        "from flask import redirect\ndef _f():\n    return redirect(user.email)\n",
        encoding="utf-8",
    )

    result = ReviewEngine().scan_files([target], changed_map={str(target): {3}})

    semgrep_hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit.line == 3
    assert hit.tier.value == "confirmed"
    assert hit.category == "PII_IN_URL"
    assert hit.severity.value == "high"
    assert hit.confidence.value == "high"
    assert hit.blocking is True
    assert not any(f.detector != "semgrep" and f.line == 3 for f in result.findings)
