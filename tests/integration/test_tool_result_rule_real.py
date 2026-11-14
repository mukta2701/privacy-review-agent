"""Real-Semgrep tests for the PII-in-tool-result rule.

Skipped when semgrep is absent. Covers every positive and near-miss probe
from the acceptance criteria through ``ReviewEngine().scan_files``, plus
the end-to-end blocking behaviour and the import-order gate for ``@tool``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)

TOOL_IMPORT = "from langchain_core.tools import tool"

# Each block is one probe; the sink (match) line is at the given offset.
POSITIVE_BLOCKS: list[tuple[str, int]] = [
    ("@mcp.tool\ndef _f1():\n    return user.email", 2),
    ("@mcp.tool()\ndef _f2():\n    return user.email", 2),
    ('@function_tool\ndef _f3():\n    return {"email": user.email}', 2),
    (
        '@function_tool(name_override="x")\n'
        "def _f4():\n"
        "    v = user.phone\n"
        "    return v",
        3,
    ),
    ('@mcp.tool\nasync def _f5():\n    return f"hi {user.email}"', 2),
    (
        "@mcp.tool\n"
        "def _f6():\n"
        "    def _inner():\n"
        "        return user.email\n"
        "    return user.phone",
        4,
    ),
    ("@tool\ndef _f7():\n    return user.email", 2),
    ('@tool("n")\ndef _f8():\n    return user.email', 2),
    ('@app.route("/x")\n@tool\ndef _f9():\n    return user.email', 3),
    ("@mcp.tool\ndef _f10(email):\n    return email", 2),
    ("@mcp.tool\ndef _f11():\n    return req.body", 2),
    ("@mcp.tool\ndef _f12():\n    return [user.ssn]", 2),
    ("@mcp.tool\ndef _f13():\n    if True:\n        return user.email", 3),
    ("@mcp.tool\ndef _f14():\n    for x in y:\n        return user.email", 3),
]

NEAR_MISS_BLOCKS: list[str] = [
    "def _g1():\n    return user.email",
    '@app.route("/x")\ndef _g2():\n    return user.email',
    "@property\ndef _g3(self):\n    return self.email",
    "@pytest.fixture\ndef _g4():\n    return user.email",
    "@mcp.tool()\ndef _g5():\n    return user.id",
    "@mcp.tool()\ndef _g6():\n    return len(user.email)",
    "@function_tool\ndef _g7():\n    return user.email is not None",
    "@mcp.tool()\n"
    "def _g8():\n"
    '    return {"n": email_count, "h": settings.EMAIL_HOST}',
    "@mcp.tool()\ndef _g9():\n    return ssn_pattern",
    "@mcp.tool()\ndef _g10():\n    return redact(user.email)",
    "@mcp.tool()\ndef _g11():\n    send(user.email)\n    return \"sent\"",
    "@mcp.tool()\n"
    "def _g12():\n"
    "    def _inner():\n"
    "        return user.email\n"
    "    return 1",
    "@tool\ndef _g13():\n    return user.email",
    "from mylib import tool\n\n@tool\ndef _g14():\n    return user.email",
    "@registry.tool\ndef _g15():\n    return user.email",
    "@server.tool()\ndef _g16():\n    return user.email",
    "@mcp.tool()\ndef _g17():\n    return user.email_domain",
]


def _write_blocks(tmp_path: Path, name: str, blocks: list[str]) -> Path:
    target = tmp_path / name
    target.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    return target


@needs_semgrep
def test_every_positive_probe_matches_at_its_return_line(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    lines: list[str] = [TOOL_IMPORT]
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
def test_tool_import_from_langchain_tools_also_counts(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "langchain_tools.py"
    target.write_text(
        "from langchain.tools import tool\n\n@tool\ndef _f():\n    return user.email\n",
        encoding="utf-8",
    )

    result = ReviewEngine().scan_files([target])

    matched = {
        finding.line for finding in result.findings if finding.detector == "semgrep"
    }
    assert matched == {5}


@needs_semgrep
def test_no_near_miss_probe_matches(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_blocks(tmp_path, "near_miss.py", NEAR_MISS_BLOCKS)

    result = ReviewEngine().scan_files([target])

    assert not [finding for finding in result.findings if finding.detector == "semgrep"]


@needs_semgrep
def test_import_order_gates_bare_tool(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "order.py"
    target.write_text(
        "@tool\n"
        "def _early():\n"
        "    return user.email\n"
        "\n"
        "from langchain_core.tools import tool\n"
        "\n"
        "@tool\n"
        "def _late():\n"
        "    return user.email\n",
        encoding="utf-8",
    )

    result = ReviewEngine().scan_files([target])

    matched = {
        finding.line for finding in result.findings if finding.detector == "semgrep"
    }
    assert matched == {9}


@needs_semgrep
def test_end_to_end_finding_is_confirmed_blocking_without_keyword(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text(
        "@mcp.tool()\ndef _f():\n    return user.email\n",
        encoding="utf-8",
    )

    result = ReviewEngine().scan_files([target], changed_map={str(target): {3}})

    semgrep_hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit.line == 3
    assert hit.tier.value == "confirmed"
    assert hit.category == "PII_IN_MODEL_PROMPT"
    assert hit.blocking is True
    assert not any(f.detector != "semgrep" and f.line == 3 for f in result.findings)
