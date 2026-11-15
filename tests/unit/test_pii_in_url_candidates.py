"""Unit tests for the internal PII-in-URL candidate pass.

Covers the private candidate rule data (copied sources/sanitisers, exact
bare-sink names, isolation from the public pack) and the pure scope check
``is_recoverable_url_candidate``: span mapping with UTF-8 byte offsets,
function-body scope, local bindings, module import authorisation and
duplicate handling. No semgrep binary needed.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest
import yaml

from privacy_review_agent.detectors.semgrep import (
    URL_CANDIDATE_RULE_ID,
    URL_RULE_ID,
    URL_SINK_NAMES,
    is_recoverable_url_candidate,
)
from privacy_review_agent.semgrep_runner import SemgrepMatch

PACK = Path("src/privacy_review_agent/policies/semgrep_rules")
INTERNAL = Path("src/privacy_review_agent/policies/semgrep_internal")
CANDIDATE_FILE = "python-pii-in-url-candidate.yaml"
PUBLIC_FILE = "python-pii-in-url.yaml"
TOOL_RESULT_FILE = "python-pii-in-tool-result.yaml"

SINK_NAMES = (
    "redirect",
    "url_for",
    "HttpResponseRedirect",
    "HttpResponsePermanentRedirect",
    "RedirectResponse",
)

ORIGIN_TABLE = (
    ("flask", "redirect"),
    ("flask", "url_for"),
    ("django.shortcuts", "redirect"),
    ("django.http", "HttpResponseRedirect"),
    ("django.http", "HttpResponsePermanentRedirect"),
    ("starlette.responses", "RedirectResponse"),
    ("fastapi.responses", "RedirectResponse"),
)


def _candidate_doc() -> dict:
    docs = yaml.safe_load((INTERNAL / CANDIDATE_FILE).read_text(encoding="utf-8"))["rules"]
    assert len(docs) == 1
    return docs[0]


def test_candidate_copies_public_sources_and_sanitisers():
    candidate = _candidate_doc()
    public = yaml.safe_load((PACK / PUBLIC_FILE).read_text(encoding="utf-8"))["rules"][0]
    tool_result = yaml.safe_load((PACK / TOOL_RESULT_FILE).read_text(encoding="utf-8"))["rules"][0]

    assert candidate["pattern-sources"] == public["pattern-sources"]
    assert candidate["pattern-sanitizers"] == public["pattern-sanitizers"]
    assert public["pattern-sources"] == tool_result["pattern-sources"]
    assert public["pattern-sanitizers"] == tool_result["pattern-sanitizers"]


def test_candidate_matches_only_exact_bare_sink_names():
    import re

    candidate = _candidate_doc()
    assert candidate["id"] == URL_CANDIDATE_RULE_ID
    assert candidate["languages"] == ["python"]
    assert candidate["mode"] == "taint"

    regexes = []

    def walk(node):
        if isinstance(node, dict):
            for key, item in node.items():
                if key == "metavariable-regex" and item.get("metavariable") == "$SINK":
                    regexes.append(item["regex"])
                else:
                    walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for sink in candidate.get("pattern-sinks", []):
        walk(sink)
    assert len(regexes) == 1
    for name in SINK_NAMES:
        assert re.fullmatch(regexes[0], name), name
    for other in ("flask.redirect", "bounce", "redirect2", "Redirect", "self.redirect"):
        assert not re.fullmatch(regexes[0], other), other

    code_lines = [
        line
        for line in (INTERNAL / CANDIDATE_FILE).read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]
    code = "\n".join(code_lines)
    assert "flask.redirect" not in code
    assert "django.shortcuts" not in code
    assert "django.http" not in code
    assert "starlette.responses" not in code
    assert "fastapi.responses" not in code


def test_candidate_lives_outside_public_pack():
    assert INTERNAL != PACK
    assert PACK not in INTERNAL.parents
    assert (INTERNAL / CANDIDATE_FILE).is_file()

    from privacy_review_agent.semgrep_runner import load_rules

    public_ids = {rule.id for rule in load_rules(PACK)}
    assert URL_CANDIDATE_RULE_ID not in public_ids
    assert URL_RULE_ID in public_ids
    internal_ids = {rule.id for rule in load_rules(INTERNAL)}
    assert internal_ids == {URL_CANDIDATE_RULE_ID}


def test_sink_name_constant_matches_spec():
    assert URL_SINK_NAMES == frozenset(SINK_NAMES)


# ---------------------------------------------------------------------------
# Pure scope-check helpers
# ---------------------------------------------------------------------------


def _line_starts(data: bytes) -> list[int]:
    starts = []
    pos = 0
    for part in data.split(b"\n"):
        starts.append(pos)
        pos += len(part) + 1
    return starts


def _bare_call_span(
    source: str, name: str = "redirect", index: int = 0
) -> tuple[int, int, int, int, int]:
    """Byte span (line, col0, end_line, end_col0, start, end) of a bare call."""
    data = source.encode("utf-8")
    tree = ast.parse(data.decode("utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    ]
    node = calls[index]
    starts = _line_starts(data)
    start = starts[node.lineno - 1] + node.col_offset
    end = starts[node.end_lineno - 1] + node.end_col_offset
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset, start, end)


def _candidate(
    source: str,
    path: str = "app.py",
    name: str = "redirect",
    index: int = 0,
    rule_id: str = URL_CANDIDATE_RULE_ID,
) -> tuple[bytes, SemgrepMatch]:
    data = source.encode("utf-8")
    line, col, end_line, end_col, start, end = _bare_call_span(source, name, index)
    match = SemgrepMatch(
        path=path,
        rule_id=rule_id,
        line=line,
        message="Personal data placed in a redirect URL",
        metadata={},
        col=col + 1,
        end_line=end_line,
        end_col=end_col + 1,
        offset=start,
        end_offset=end,
    )
    return data, match


def _ordinary(
    source: str,
    path: str = "app.py",
    name: str = "redirect",
    index: int = 0,
    rule_id: str = URL_RULE_ID,
    start: int | None = None,
    end: int | None = None,
) -> SemgrepMatch:
    line, col, end_line, end_col, call_start, call_end = _bare_call_span(source, name, index)
    return SemgrepMatch(
        path=path,
        rule_id=rule_id,
        line=line,
        message="Personal data placed in a redirect URL",
        metadata={},
        col=col + 1,
        end_line=end_line,
        end_col=end_col + 1,
        offset=call_start if start is None else start,
        end_offset=call_end if end is None else end,
    )


CLEAN_FLASK = "from flask import redirect\ndef profile(user):\n    return redirect(user.email)\n"


def test_clean_module_import_recovers():
    data, candidate = _candidate(CLEAN_FLASK)
    assert is_recoverable_url_candidate(candidate, data, []) is True


def test_async_function_recovers():
    source = (
        "from flask import redirect\n"
        "async def profile(user):\n"
        "    return redirect(user.email)\n"
    )
    data, candidate = _candidate(source)
    assert is_recoverable_url_candidate(candidate, data, []) is True


def test_rejects_malformed_input():
    data, candidate = _candidate(CLEAN_FLASK)
    assert is_recoverable_url_candidate(None, data, []) is False
    assert is_recoverable_url_candidate(candidate, None, []) is False
    assert is_recoverable_url_candidate(candidate, "not bytes", []) is False
    assert is_recoverable_url_candidate(candidate, b"\xff\xfe invalid \x80", []) is False
    assert is_recoverable_url_candidate(candidate, b"def broken(:\n", []) is False


def test_rejects_invalid_spans():
    data, candidate = _candidate(CLEAN_FLASK)
    bad = SemgrepMatch(
        path=candidate.path, rule_id=candidate.rule_id, line=1, message="m",
        metadata={}, offset=10, end_offset=5,
    )
    assert is_recoverable_url_candidate(bad, data, []) is False
    past_end = SemgrepMatch(
        path=candidate.path, rule_id=candidate.rule_id, line=1, message="m",
        metadata={}, offset=0, end_offset=len(data) + 100,
    )
    assert is_recoverable_url_candidate(past_end, data, []) is False
    empty = SemgrepMatch(
        path=candidate.path, rule_id=candidate.rule_id, line=1, message="m",
        metadata={}, offset=0, end_offset=0,
    )
    assert is_recoverable_url_candidate(empty, data, []) is False


def test_rejects_span_covering_two_nested_calls():
    source = (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    return redirect(redirect(user.email))\n"
    )
    data = source.encode("utf-8")
    _, outer = _candidate(source, index=0)
    # The outer span contains both the outer and the inner bare call.
    assert outer.offset < _bare_call_span(source, index=1)[4]
    assert is_recoverable_url_candidate(outer, data, []) is False


def test_accepts_inner_of_nested_calls():
    source = (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    return redirect(redirect(user.email))\n"
    )
    data, inner = _candidate(source, index=1)
    assert is_recoverable_url_candidate(inner, data, []) is True


# ---------------------------------------------------------------------------
# Disallowed scopes
# ---------------------------------------------------------------------------

SCOPE_CASES = [
    ("module level", "from flask import redirect\nx = redirect(user.email)\n", False),
    (
        "method",
        (
            "from flask import redirect\n"
            "class C:\n"
            "    def m(self, user):\n"
            "        return redirect(user.email)\n"
        ),
        False,
    ),
    (
        "nested function",
        (
            "from flask import redirect\n"
            "def outer(user):\n"
            "    def inner():\n"
            "        return redirect(user.email)\n"
            "    return inner()\n"
        ),
        False,
    ),
    (
        "lambda",
        (
            "from flask import redirect\n"
            "def profile(user):\n"
            "    f = lambda: redirect(user.email)\n"
            "    return f()\n"
        ),
        False,
    ),
    (
        "comprehension",
        (
            "from flask import redirect\n"
            "def profile(user):\n"
            "    return [redirect(x) for x in [user.email]]\n"
        ),
        False,
    ),
    (
        "decorator",
        "from flask import redirect\n@redirect(user.email)\ndef profile():\n    return 1\n",
        True,  # no bare call to map: candidate builder targets the decorator call
    ),
    (
        "control flow if",
        (
            "from flask import redirect\n"
            "def profile(user):\n"
            "    if user:\n"
            "        return redirect(user.email)\n"
            "    return None\n"
        ),
        True,
    ),
    (
        "control flow for",
        (
            "from flask import redirect\n"
            "def profile(user):\n"
            "    for x in [1]:\n"
            "        return redirect(user.email)\n"
        ),
        True,
    ),
    (
        "control flow try",
        (
            "from flask import redirect\n"
            "def profile(user):\n"
            "    try:\n"
            "        return redirect(user.email)\n"
            "    except ValueError:\n"
            "        return None\n"
        ),
        True,
    ),
    (
        "control flow with",
        (
            "from flask import redirect\n"
            "def profile(user):\n"
            "    with open('f') as fh:\n"
            "        return redirect(user.email)\n"
        ),
        True,
    ),
]


@pytest.mark.parametrize(("label", "source", "expected"), [(c[0], c[1], c[2]) for c in SCOPE_CASES])
def test_scope_cases(label, source, expected):
    if label == "decorator":
        pytest.skip("decorator call is an attribute-form call, covered separately")
    data, candidate = _candidate(source)
    assert is_recoverable_url_candidate(candidate, data, []) is expected


def test_decorator_call_is_dropped():
    source = "from flask import redirect\n@redirect(user.email)\ndef profile():\n    return 1\n"
    data = source.encode("utf-8")
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert len(calls) == 1
    node = calls[0]
    starts = _line_starts(data)
    match = SemgrepMatch(
        path="app.py", rule_id=URL_CANDIDATE_RULE_ID, line=node.lineno,
        message="m", metadata={}, col=node.col_offset + 1,
        end_line=node.end_lineno, end_col=node.end_col_offset + 1,
        offset=starts[node.lineno - 1] + node.col_offset,
        end_offset=starts[node.end_lineno - 1] + node.end_col_offset,
    )
    assert is_recoverable_url_candidate(match, data, []) is False


def test_default_argument_call_is_dropped():
    source = "from flask import redirect\ndef profile(x=redirect(user.email)):\n    return x\n"
    data = source.encode("utf-8")
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert len(calls) == 1
    node = calls[0]
    starts = _line_starts(data)
    match = SemgrepMatch(
        path="app.py", rule_id=URL_CANDIDATE_RULE_ID, line=node.lineno,
        message="m", metadata={}, col=node.col_offset + 1,
        end_line=node.end_lineno, end_col=node.end_col_offset + 1,
        offset=starts[node.lineno - 1] + node.col_offset,
        end_offset=starts[node.end_lineno - 1] + node.end_col_offset,
    )
    assert is_recoverable_url_candidate(match, data, []) is False


# ---------------------------------------------------------------------------
# Multibyte positions
# ---------------------------------------------------------------------------


def test_multibyte_before_and_on_call_line():
    source = (
        "from flask import redirect\n"
        "# caf\u00e9 \u2603\n"
        "def profile(user):\n"
        "    return redirect(user.email)\n"
    )
    data = source.encode("utf-8")
    # Hand-computed UTF-8 byte offsets: L1 "from flask import redirect" is
    # 26 bytes (newline at 26), L2 "# café ☃" is 2+3+2+1+3=11 bytes starting
    # at 27, L3 "def profile(user):" starts at 39, L4 starts at 58, and the
    # call starts 11 bytes into L4 and spans 20 bytes.
    assert data.split(b"\n")[1] == "# caf\xc3\xa9 \xe2\x98\x83".encode("latin1")
    line, col, end_line, end_col, start, end = _bare_call_span(source)
    assert (line, col, start, end) == (4, 11, 69, 89)
    match = SemgrepMatch(
        path="app.py", rule_id=URL_CANDIDATE_RULE_ID, line=line,
        message="m", metadata={}, col=col + 1, end_line=end_line,
        end_col=end_col + 1, offset=start, end_offset=end,
    )
    assert is_recoverable_url_candidate(match, data, []) is True


def test_multibyte_on_call_line_before_call():
    source = (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    x = \u00e9; return redirect(user.email)\n"
    )
    data = source.encode("utf-8")
    line, col, end_line, end_col, start, end = _bare_call_span(source)
    # '    x = \u00e9; return ' is 19 bytes but only 18 characters: the call
    # column in bytes differs from the decoded-character index.
    assert col == 19
    assert data[start:start + 8] == b"redirect"
    match = SemgrepMatch(
        path="app.py", rule_id=URL_CANDIDATE_RULE_ID, line=line,
        message="m", metadata={}, col=col + 1, end_line=end_line,
        end_col=end_col + 1, offset=start, end_offset=end,
    )
    assert is_recoverable_url_candidate(match, data, []) is True


def test_multibyte_with_shadowed_name_stays_silent():
    source = (
        "from flask import redirect\n# caf\u00e9 \u2603\n"
        "def profile(user, redirect):\n    return redirect(user.email)\n"
    )
    data, candidate = _candidate(source)
    assert is_recoverable_url_candidate(candidate, data, []) is False


# ---------------------------------------------------------------------------
# Function-local bindings
# ---------------------------------------------------------------------------

BINDING_CASES = [
    ("posonly", (
        "from flask import redirect\n"
        "def profile(user, redirect, /):\n"
        "    return redirect(user.email)\n"
    )),
    ("arg", (
        "from flask import redirect\n"
        "def profile(redirect):\n"
        "    return redirect(user.email)\n"
    )),
    ("vararg", (
        "from flask import redirect\n"
        "def profile(*redirect):\n"
        "    return redirect(user.email)\n"
    )),
    ("kwonly", (
        "from flask import redirect\n"
        "def profile(*, redirect):\n"
        "    return redirect(user.email)\n"
    )),
    ("kwarg", (
        "from flask import redirect\n"
        "def profile(**redirect):\n"
        "    return redirect(user.email)\n"
    )),
    ("defaulted", (
        "from flask import redirect\n"
        "def profile(redirect=None):\n"
        "    return redirect(user.email)\n"
    )),
    ("import", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    from helpers import redirect\n"
        "    return redirect(user.email)\n"
    )),
    ("import alias", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    from helpers import redirect as redirect\n"
        "    return redirect(user.email)\n"
    )),
    ("import stmt", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    import redirect\n"
        "    return redirect(user.email)\n"
    )),
    ("nested def", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    def redirect(url):\n"
        "        return url\n"
        "    return redirect(user.email)\n"
    )),
    ("nested async def", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    async def redirect(url):\n"
        "        return url\n"
        "    return redirect(user.email)\n"
    )),
    ("nested class", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    class redirect:\n"
        "        pass\n"
        "    return redirect(user.email)\n"
    )),
    ("plain assign", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    redirect = str\n"
        "    return redirect(user.email)\n"
    )),
    ("annotated", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    redirect: str = 'x'\n"
        "    return redirect(user.email)\n"
    )),
    ("augmented", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    redirect = 1\n"
        "    redirect += 2\n"
        "    return redirect(user.email)\n"
    )),
    ("tuple destructure", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    a, redirect = 1, 2\n"
        "    return redirect(user.email)\n"
    )),
    ("starred", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    a, *redirect = [1, 2]\n"
        "    return redirect(user.email)\n"
    )),
    ("walrus", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    x = (redirect := str)\n"
        "    return redirect(user.email)\n"
    )),
    ("for target", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    for redirect in [1]:\n"
        "        pass\n"
        "    return redirect(user.email)\n"
    )),
    ("with target", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    with open('f') as redirect:\n"
        "        pass\n"
        "    return redirect(user.email)\n"
    )),
    ("except name", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError as redirect:\n"
        "        pass\n"
        "    return redirect(user.email)\n"
    )),
    ("match capture", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    match user:\n"
        "        case {'email': redirect}:\n"
        "            pass\n"
        "    return redirect(user.email)\n"
    )),
    ("match as", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    match user:\n"
        "        case str() as redirect:\n"
        "            pass\n"
        "    return redirect(user.email)\n"
    )),
    ("del", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    del redirect\n"
        "    return redirect(user.email)\n"
    )),
    ("global", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    global redirect\n"
        "    return redirect(user.email)\n"
    )),
    ("nonlocal", (
        "from flask import redirect\n"
        "def outer():\n"
        "    redirect = 1\n"
        "    def profile(user):\n"
        "        nonlocal redirect\n"
        "        return redirect(user.email)\n"
    )),
    ("after call", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    x = redirect(user.email)\n"
        "    redirect = str\n"
        "    return x\n"
    )),
    ("conditional branch", (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    if user:\n"
        "        redirect = str\n"
        "    return redirect(user.email)\n"
    )),
]


@pytest.mark.parametrize(("label", "source"), [(c[0], c[1]) for c in BINDING_CASES])
def test_local_binding_rejects(label, source):
    data = source.encode("utf-8")
    if label == "nonlocal":
        _, candidate = _candidate(source, name="redirect", index=0)
        # The call is inside the nested profile; candidate must still drop.
        assert is_recoverable_url_candidate(candidate, data, []) is False
        return
    _, candidate = _candidate(source)
    assert is_recoverable_url_candidate(candidate, data, []) is False


def test_unrelated_alias_does_not_bind():
    source = (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    from helpers import redirect as other\n"
        "    return redirect(user.email)\n"
    )
    data, candidate = _candidate(source)
    assert is_recoverable_url_candidate(candidate, data, []) is True


def test_binding_inside_nested_scope_does_not_bind_outer():
    source = (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    def helper():\n"
        "        redirect = str\n"
        "        return redirect\n"
        "    return redirect(user.email)\n"
    )
    data, candidate = _candidate(source, index=0)
    assert is_recoverable_url_candidate(candidate, data, []) is True


# ---------------------------------------------------------------------------
# Module-level import authorisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("origin", "name"), ORIGIN_TABLE)
def test_origin_table_authorises(origin, name):
    source = f"from {origin} import {name}\ndef profile(user):\n    return {name}(user.email)\n"
    data, candidate = _candidate(source, name=name)
    assert is_recoverable_url_candidate(candidate, data, []) is True


def test_multi_name_import_authorises():
    source = (
        "from flask import redirect, url_for\n"
        "def profile(user):\n"
        "    return redirect(user.email)\n"
    )
    data, candidate = _candidate(source)
    assert is_recoverable_url_candidate(candidate, data, []) is True


MODULE_NEGATIVES = [
    ("no import", "def profile(user):\n    return redirect(user.email)\n"),
    ("late import", (
        "def profile(user):\n"
        "    return redirect(user.email)\n"
        "from flask import redirect\n"
    )),
    ("wrong origin", (
        "from mylib import redirect\n"
        "def profile(user):\n"
        "    return redirect(user.email)\n"
    )),
    (
        "aliased import",
        "from flask import redirect as bounce\ndef profile(user):\n    return bounce(user.email)\n",
    ),
    ("relative import", (
        "from .flask import redirect\n"
        "def profile(user):\n"
        "    return redirect(user.email)\n"
    )),
    ("star import", "from flask import *\ndef profile(user):\n    return redirect(user.email)\n"),
    (
        "conditional import",
        (
            "import sys\n"
            "if sys.version_info >= (3,):\n"
            "    from flask import redirect\n"
            "def profile(user):\n"
            "    return redirect(user.email)\n"
        ),
    ),
    (
        "intervening def",
        (
            "from flask import redirect\n"
            "def redirect(url):\n"
            "    return url\n"
            "def profile(user):\n"
            "    return redirect(user.email)\n"
        ),
    ),
    (
        "intervening assign",
        (
            "from flask import redirect\n"
            "redirect = str\n"
            "def profile(user):\n"
            "    return redirect(user.email)\n"
        ),
    ),
    (
        "import inside function",
        (
            "def setup():\n"
            "    from flask import redirect\n"
            "def profile(user):\n"
            "    return redirect(user.email)\n"
        ),
    ),
    (
        "import inside class",
        (
            "class C:\n"
            "    from flask import redirect\n"
            "def profile(user):\n"
            "    return redirect(user.email)\n"
        ),
    ),
    (
        "later competing rebinding",
        (
            "from flask import redirect\n"
            "from helpers import redirect\n"
            "def profile(user):\n"
            "    return redirect(user.email)\n"
        ),
    ),
]


@pytest.mark.parametrize(("label", "source"), [(c[0], c[1]) for c in MODULE_NEGATIVES])
def test_module_negatives_reject(label, source):
    data = source.encode("utf-8")
    try:
        _, candidate = _candidate(source)
    except (IndexError, SyntaxError):
        # "aliased import" has no bare `bounce`... it does have bounce call but
        # name defaults to redirect; handle explicitly below.
        if label == "aliased import":
            tree = ast.parse(source)
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
            assert calls, label
            pytest.skip("alias call is not a bare sink name")
        raise
    assert is_recoverable_url_candidate(candidate, data, []) is False, label


def test_restored_import_after_def_authorises():
    source = (
        "def redirect(url):\n    return url\n"
        "from flask import redirect\n"
        "def profile(user):\n    return redirect(user.email)\n"
    )
    data, candidate = _candidate(source)
    assert is_recoverable_url_candidate(candidate, data, []) is True


# ---------------------------------------------------------------------------
# Duplicates
# ---------------------------------------------------------------------------


def test_ordinary_match_covering_call_wins():
    data, candidate = _candidate(CLEAN_FLASK)
    ordinary = _ordinary(CLEAN_FLASK)
    assert is_recoverable_url_candidate(candidate, data, [ordinary]) is False


def test_ambiguous_partial_overlap_drops():
    data, candidate = _candidate(CLEAN_FLASK)
    line, col, end_line, end_col, start, end = _bare_call_span(CLEAN_FLASK)
    partial = SemgrepMatch(
        path="app.py", rule_id=URL_RULE_ID, line=line, message="m", metadata={},
        col=col + 1, end_line=end_line, end_col=end_col + 1,
        offset=start + 2, end_offset=end + 50,
    )
    assert is_recoverable_url_candidate(candidate, data, [partial]) is False


def test_distinct_calls_on_one_line_do_not_conflate():
    source = (
        "from flask import redirect\n"
        "def profile(user):\n"
        "    a = redirect(user.email); b = redirect(user.phone)\n"
    )
    data, first = _candidate(source, index=0)
    _, second = _candidate(source, index=1)
    ordinary_first = _ordinary(source, index=0)
    assert is_recoverable_url_candidate(first, data, [ordinary_first]) is False
    assert is_recoverable_url_candidate(second, data, [ordinary_first]) is True


def test_other_file_and_other_rule_matches_are_ignored():
    data, candidate = _candidate(CLEAN_FLASK)
    elsewhere = _ordinary(CLEAN_FLASK, path="other.py")
    assert is_recoverable_url_candidate(candidate, data, [elsewhere]) is True
    other_rule = _ordinary(CLEAN_FLASK, rule_id="python-pii-to-third-party")
    assert is_recoverable_url_candidate(candidate, data, [other_rule]) is True


# ---------------------------------------------------------------------------
# Detector recovery pass (stubbed runner seam, no binary needed)
# ---------------------------------------------------------------------------

RECOVERY_SOURCE = (
    "from flask import redirect\n"
    "def internal(user):\n"
    "    from helpers import redirect\n"
    "    return redirect(user.email)\n"
    "def profile(user):\n"
    "    return redirect(user.email)\n"
)


def _with_public_metadata(candidate: SemgrepMatch) -> SemgrepMatch:
    doc = yaml.safe_load((INTERNAL / CANDIDATE_FILE).read_text(encoding="utf-8"))["rules"][0]
    candidate.message = doc["message"]
    candidate.metadata = dict(doc["metadata"])
    return candidate


def test_recovered_candidate_becomes_canonical_finding(monkeypatch, tmp_path):
    import yaml

    import privacy_review_agent.detectors.semgrep as detector_mod
    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text(RECOVERY_SOURCE, encoding="utf-8")
    _, candidate = _candidate(RECOVERY_SOURCE, path=str(target), index=1)
    candidate.message = yaml.safe_load(
        (INTERNAL / CANDIDATE_FILE).read_text(encoding="utf-8")
    )["rules"][0]["message"]
    candidate.metadata = yaml.safe_load(
        (INTERNAL / CANDIDATE_FILE).read_text(encoding="utf-8")
    )["rules"][0]["metadata"]

    seen_dirs: list[str] = []

    def fake_run(files, rules_dir):
        seen_dirs.append(str(rules_dir))
        if Path(rules_dir).name == "semgrep_internal":
            return [candidate]
        return []

    monkeypatch.setattr(detector_mod, "run_semgrep", fake_run)
    result = ReviewEngine(settings=load_settings()).scan_files([target])

    hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(hits) == 1
    hit = hits[0]
    assert hit.line == 6
    assert hit.message == f"{URL_RULE_ID}: {candidate.message}"
    assert hit.category == "PII_IN_URL"
    assert hit.severity.value == "high"
    assert hit.confidence.value == "high"
    assert hit.tier.value == "confirmed"
    assert hit.evidence == "return redirect(user.email)"
    assert hit.remediation == candidate.metadata["remediation"]
    assert hit.file_path == str(target)
    assert hit.blocking is True
    assert any(Path(d).name == "semgrep_internal" for d in seen_dirs)


def test_repeated_candidate_emits_one_finding(monkeypatch, tmp_path):
    import privacy_review_agent.detectors.semgrep as detector_mod
    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text(RECOVERY_SOURCE, encoding="utf-8")
    _, candidate = _candidate(RECOVERY_SOURCE, path=str(target), index=1)
    _with_public_metadata(candidate)

    def fake_run(files, rules_dir):
        if Path(rules_dir).name == "semgrep_internal":
            return [candidate, candidate]
        return []

    monkeypatch.setattr(detector_mod, "run_semgrep", fake_run)
    result = ReviewEngine(settings=load_settings()).scan_files([target])

    hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(hits) == 1
    assert hits[0].line == 6


def test_pack_without_url_rule_skips_recovery(monkeypatch, tmp_path):
    import yaml

    import privacy_review_agent.detectors.semgrep as detector_mod
    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "other.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "other-rule",
                        "languages": ["python"],
                        "severity": "WARNING",
                        "message": "other",
                        "metadata": {
                            "category": "RAW_PII_LOGGING",
                            "severity": "high",
                            "confidence": "high",
                            "remediation": "fix it",
                        },
                        "patterns": [{"pattern": "print($X)"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    target = tmp_path / "app.py"
    target.write_text(RECOVERY_SOURCE, encoding="utf-8")

    calls: list[str] = []

    def fake_run(files, rules_dir):
        calls.append(str(rules_dir))
        return []

    monkeypatch.setattr(detector_mod, "run_semgrep", fake_run)
    settings = load_settings()
    settings.semgrep_rules_dir = pack
    result = ReviewEngine(settings=settings).scan_files([target])

    assert calls == [str(pack)]
    assert not [f for f in result.findings if f.detector == "semgrep"]


def test_recovery_failure_keeps_primary_findings(monkeypatch, tmp_path, capsys):
    import privacy_review_agent.detectors.semgrep as detector_mod
    from privacy_review_agent.config import load_settings
    from privacy_review_agent.engine import ReviewEngine
    from privacy_review_agent.semgrep_runner import SemgrepFailed

    target = tmp_path / "app.py"
    target.write_text(CLEAN_FLASK, encoding="utf-8")
    ordinary = _ordinary(CLEAN_FLASK, path=str(target))
    _with_public_metadata(ordinary)

    def fake_run(files, rules_dir):
        if Path(rules_dir).name == "semgrep_internal":
            raise SemgrepFailed("boom")
        return [ordinary]

    monkeypatch.setattr(detector_mod, "run_semgrep", fake_run)
    result = ReviewEngine(settings=load_settings()).scan_files([target])

    hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(hits) == 1
    assert hits[0].line == 3
    assert "Semgrep" in capsys.readouterr().err


def test_realpath_identity_counts_as_same_file():
    data, candidate = _candidate(CLEAN_FLASK, path="./app.py")
    ordinary = _ordinary(CLEAN_FLASK, path="app.py")
    assert os.path.realpath("./app.py") == os.path.realpath("app.py")
    assert is_recoverable_url_candidate(candidate, data, [ordinary]) is False
