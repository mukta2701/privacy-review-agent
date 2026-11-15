from __future__ import annotations

import ast
import os
import shutil
import symtable
from collections.abc import Collection, Iterator
from pathlib import Path

import click

from privacy_review_agent.detectors.base import Detector, DetectorContext
from privacy_review_agent.models import Confidence, EvidenceTier, Finding, Severity
from privacy_review_agent.semgrep_runner import (
    SemgrepFailed,
    SemgrepMatch,
    SemgrepNotInstalled,
    SemgrepRule,
    load_rules,
    metadata_problem,
    run_semgrep,
    taxonomy_categories,
)
from privacy_review_agent.utils import extract_domain

MISSING_NOTICE = (
    "Semgrep structural rules were skipped: the `semgrep` binary is not on PATH. "
    "Install it with `pip install 'privacy-review-agent[semgrep]'` to enable them."
)

TRANSFER_RULE_ID = "python-pii-to-third-party"
URL_RULE_ID = "python-pii-in-url"
URL_CANDIDATE_RULE_ID = "python-pii-in-url-candidate"
URL_SINK_NAMES = frozenset(
    {
        "redirect",
        "url_for",
        "HttpResponseRedirect",
        "HttpResponsePermanentRedirect",
        "RedirectResponse",
    }
)
_URL_IMPORT_ORIGINS: dict[str, frozenset[str]] = {
    "flask": frozenset({"redirect", "url_for"}),
    "django.shortcuts": frozenset({"redirect"}),
    "django.http": frozenset(
        {"HttpResponseRedirect", "HttpResponsePermanentRedirect"}
    ),
    "starlette.responses": frozenset({"RedirectResponse"}),
    "fastapi.responses": frozenset({"RedirectResponse"}),
}
INTERNAL_RULES_DIR = Path(__file__).resolve().parent.parent / "policies" / "semgrep_internal"

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_NESTED_SCOPES = (
    *_FUNCTIONS,
    ast.ClassDef,
    ast.Lambda,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)


def _transfer_url_argument(call: ast.Call) -> ast.expr | None:
    """Return the URL argument of a transfer call, if one is present.

    The `url=` keyword wins when present; otherwise the first positional
    argument, or the second one for `.request(...)` (whose first argument
    is the HTTP method).
    """
    for keyword in call.keywords:
        if keyword.arg == "url":
            return keyword.value
    func = call.func
    name = func.attr if isinstance(func, ast.Attribute) else ""
    index = 1 if name == "request" else 0
    if len(call.args) > index:
        return call.args[index]
    return None


def is_allowlisted_transfer(
    match: SemgrepMatch, file_data: bytes, allowlist: Collection[str]
) -> bool:
    """Whether a third-party-transfer match hits an allowlisted vendor.

    Reads the call text from the file bytes using the match span (Semgrep
    offsets are byte offsets) and drops the finding only when the URL
    argument is a plain string literal whose host is in the allowlist.
    Anything else (non-literal URL, unlisted host, literal without a
    scheme, unparseable span, another rule) is reported.
    """
    if match.rule_id != TRANSFER_RULE_ID:
        return False
    try:
        tree = ast.parse(
            file_data[match.offset : match.end_offset].decode("utf-8", errors="replace")
        )
    except (SyntaxError, ValueError):
        return False
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    if not calls:
        return False
    url = _transfer_url_argument(calls[0])
    if not isinstance(url, ast.Constant) or not isinstance(url.value, str):
        return False
    domain = extract_domain(url.value)
    return bool(domain) and domain in allowlist


def is_recoverable_url_candidate(
    candidate: SemgrepMatch,
    file_data: bytes,
    ordinary_matches: Collection[SemgrepMatch],
) -> bool:
    """Whether an internal URL candidate is safe to report as a URL finding.

    Pure: reads only its arguments, never the filesystem or Semgrep. The
    candidate span must identify exactly one bare sink call (half-open
    UTF-8 byte ranges), that call must sit directly in a module-level
    ``def``/``async def`` body, the compiler must resolve the sink name in
    that function to a module global, the last module statement binding
    the name must be a qualifying framework import, and no ordinary
    ``python-pii-in-url`` match may overlap the call. Anything uncertain
    returns False.
    """
    if not isinstance(candidate, SemgrepMatch):
        return False
    if not isinstance(file_data, (bytes, bytearray)):
        return False
    data = bytes(file_data)
    start = candidate.offset
    end = candidate.end_offset
    if type(start) is not int or type(end) is not int:
        return False
    if not 0 <= start < end <= len(data):
        return False
    try:
        text = data.decode("utf-8")
        tree = ast.parse(text)
        table = symtable.symtable(text, "<candidate>", "exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    line_starts = _byte_line_starts(data)
    hits: list[
        tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, int, int]
    ] = []
    for func in tree.body:
        if not isinstance(func, _FUNCTIONS):
            continue
        for node in _own_body_nodes(func):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Name)
                or node.func.id not in URL_SINK_NAMES
            ):
                continue
            span = _call_byte_span(node, line_starts, len(data))
            if span is None:
                continue
            if start <= span[0] and span[1] <= end:
                hits.append((func, node.func.id, span[0], span[1]))
    if len(hits) != 1:
        return False
    if _file_sink_calls_in_span(tree, line_starts, len(data), start, end) != 1:
        return False
    func, sink, call_start, call_end = hits[0]
    if not _resolves_to_module_global(table, func, sink):
        return False
    if not _module_authorises_sink(tree, func, sink):
        return False
    try:
        candidate_real = os.path.realpath(candidate.path)
    except (OSError, ValueError, TypeError):
        return False
    for match in ordinary_matches or []:
        if not isinstance(match, SemgrepMatch):
            continue
        if match.rule_id != URL_RULE_ID:
            continue
        if type(match.offset) is not int or type(match.end_offset) is not int:
            continue
        try:
            if os.path.realpath(match.path) != candidate_real:
                continue
        except (OSError, ValueError, TypeError):
            continue
        if max(match.offset, call_start) < min(match.end_offset, call_end):
            return False
    return True


def _byte_line_starts(data: bytes) -> list[int]:
    """Byte offset of each 1-based line start (half-open UTF-8 ranges)."""
    starts = [0]
    for part in data.split(b"\n")[:-1]:
        starts.append(starts[-1] + len(part) + 1)
    return starts


def _call_byte_span(
    node: ast.AST, line_starts: list[int], data_len: int
) -> tuple[int, int] | None:
    """Half-open UTF-8 byte span of a node, or None when unmappable."""
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", None)
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    if (
        type(lineno) is not int
        or type(end_lineno) is not int
        or type(col) is not int
        or type(end_col) is not int
    ):
        return None
    if not 1 <= lineno <= end_lineno <= len(line_starts):
        return None
    start = line_starts[lineno - 1] + col
    end = line_starts[end_lineno - 1] + end_col
    if not 0 <= start <= end <= data_len:
        return None
    return (start, end)


def _own_body_nodes(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.AST]:
    """Nodes executed in the function's own scope: body only, no nested scopes.

    Decorators, defaults and annotations are not in ``func.body``. Nested
    scopes are skipped whole, including their headers (conservative).
    """
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        if isinstance(node, _NESTED_SCOPES):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _file_sink_calls_in_span(
    tree: ast.Module,
    line_starts: list[int],
    data_len: int,
    start: int,
    end: int,
) -> int:
    """How many bare sink calls anywhere in the file sit inside the span."""
    count = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in URL_SINK_NAMES
        ):
            span = _call_byte_span(node, line_starts, data_len)
            if span is not None and start <= span[0] and span[1] <= end:
                count += 1
    return count


def _resolves_to_module_global(
    table: symtable.SymbolTable,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
) -> bool:
    """The compiler resolves ``name`` in ``func`` to an implicit module global."""
    scopes = [
        child
        for child in table.get_children()
        if isinstance(child, symtable.Function)
        and child.get_name() == func.name
        and child.get_lineno() == func.lineno
    ]
    if len(scopes) != 1:
        return False
    try:
        symbol = scopes[0].lookup(name)
    except KeyError:
        return False
    return (
        symbol.is_global()
        and not symbol.is_declared_global()
        and not symbol.is_local()
        and not symbol.is_parameter()
        and not symbol.is_assigned()
        and not symbol.is_imported()
        and not symbol.is_free()
    )


def _module_scope_nodes(root: ast.AST) -> Iterator[ast.AST]:
    """Nodes whose bindings land in module scope, over-approximated.

    Bodies of def/class are other scopes and are skipped; their headers
    (decorators, defaults, bases, annotations) are walked. Lambdas and
    comprehensions are walked whole, so their private names over-count.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        for field, value in ast.iter_fields(node):
            if field == "body" and isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                continue
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, ast.AST):
                    stack.append(item)


def _statement_binding(stmt: ast.stmt, name: str) -> bool | None:
    """Module binding of ``name``: None for none, True for qualifying import only."""
    verdict: bool | None = None
    for node in _module_scope_nodes(stmt):
        if isinstance(node, ast.alias):
            if node.name == "*":
                return False
            if (node.asname or node.name.split(".")[0]) != name:
                continue
            ok = (
                isinstance(stmt, ast.ImportFrom)
                and stmt.level == 0
                and name in _URL_IMPORT_ORIGINS.get(stmt.module or "", ())
                and node.name == name
                and node.asname is None
            )
            if not ok:
                return False
            verdict = True
            continue
        if isinstance(node, (ast.Attribute, ast.keyword, ast.Constant, ast.arg)):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            continue
        for _, value in ast.iter_fields(node):
            if value == name or (isinstance(value, list) and name in value):
                return False
    return verdict


def _module_authorises_sink(
    tree: ast.Module,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
) -> bool:
    """Whether the last pre-function module binding is a qualifying import."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Global) and name in node.names:
            return False
    if _statement_binding(func, name) is not None:
        return False
    authorised = False
    for stmt in tree.body:
        if stmt is func:
            break
        verdict = _statement_binding(stmt, name)
        if verdict is not None:
            authorised = verdict
    return authorised


def _same_path(left: str, right_real: str) -> bool:
    try:
        return os.path.realpath(left) == right_real
    except (OSError, ValueError, TypeError):
        return False


class SemgrepDetector(Detector):
    name = "semgrep"

    def __init__(self) -> None:
        self._notices: set[str] = set()

    def _notify(self, message: str) -> None:
        if message in self._notices:
            return
        self._notices.add(message)
        click.echo(message, err=True)

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        if shutil.which("semgrep") is None:
            self._notify(MISSING_NOTICE)
            return []
        rules_dir = context.settings.semgrep_rules_dir
        if rules_dir is None:
            return []
        try:
            rules = load_rules(rules_dir)
        except ValueError as exc:
            self._notify(f"Semgrep rules could not be loaded ({exc}); skipping.")
            return []
        if not rules:
            return []
        existing = [path for path in files if path.exists() and path.is_file()]
        if not existing:
            return []
        try:
            matches = run_semgrep(existing, rules_dir)
        except SemgrepNotInstalled:
            self._notify(MISSING_NOTICE)
            return []
        except SemgrepFailed as exc:
            self._notify(f"Semgrep scan failed ({exc}); continuing without findings.")
            return []
        categories = taxonomy_categories()
        by_realpath = {os.path.realpath(str(path)): str(path) for path in existing}
        findings: list[Finding] = []
        for match in matches:
            real = os.path.realpath(match.path)
            if real not in by_realpath:
                continue
            problem = metadata_problem(match.metadata, categories)
            if problem is not None:
                self._notify(f"Semgrep rule {match.rule_id} skipped: {problem}.")
                continue
            data = _read_bytes(by_realpath[real])
            if data is None:
                continue
            lines = data.decode("utf-8", errors="ignore").splitlines()
            if match.line > len(lines):
                continue
            if is_allowlisted_transfer(match, data, context.settings.vendor_allowlist):
                continue
            findings.append(
                Finding(
                    detector=self.name,
                    category=str(match.metadata["category"]),
                    severity=Severity(str(match.metadata["severity"])),
                    confidence=Confidence(str(match.metadata["confidence"])),
                    file_path=by_realpath[real],
                    line=match.line,
                    message=f"{match.rule_id}: {match.message}",
                    evidence=lines[match.line - 1].strip()[:200],
                    remediation=str(match.metadata["remediation"]),
                    tier=EvidenceTier.CONFIRMED,
                )
            )
        findings.extend(
            self._recover_url_findings(existing, matches, rules, by_realpath, categories)
        )
        return sorted(findings, key=lambda finding: (finding.file_path, finding.line))

    def _recover_url_findings(
        self,
        existing: list[Path],
        matches: list[SemgrepMatch],
        rules: list[SemgrepRule],
        by_realpath: dict[str, str],
        categories: set[str],
    ) -> list[Finding]:
        """Recover URL sinks hidden by an unrelated function-local import.

        Runs the private name-only candidate pass and keeps a candidate only
        when the pure scope check confirms it. Never raises: a failed extra
        pass is reported as a notice and recovery is omitted.
        """
        if not any(rule.id == URL_RULE_ID for rule in rules):
            return []
        if not INTERNAL_RULES_DIR.is_dir():
            return []
        try:
            candidates = run_semgrep(existing, INTERNAL_RULES_DIR)
        except (SemgrepNotInstalled, SemgrepFailed) as exc:
            self._notify(f"Semgrep recovery pass failed ({exc}); continuing.")
            return []
        ordinary = [match for match in matches if match.rule_id == URL_RULE_ID]
        recovered: list[Finding] = []
        seen_spans: set[tuple[str, int, int]] = set()
        for candidate in candidates:
            if candidate.rule_id != URL_CANDIDATE_RULE_ID:
                continue
            try:
                real = os.path.realpath(candidate.path)
            except (OSError, ValueError, TypeError):
                continue
            if real not in by_realpath:
                continue
            span = (real, candidate.offset, candidate.end_offset)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            problem = metadata_problem(candidate.metadata, categories)
            if problem is not None:
                self._notify(
                    f"Semgrep rule {candidate.rule_id} skipped: {problem}."
                )
                continue
            data = _read_bytes(by_realpath[real])
            if data is None:
                continue
            lines = data.decode("utf-8", errors="ignore").splitlines()
            if candidate.line > len(lines) or candidate.line < 1:
                continue
            same_file = [
                match
                for match in ordinary
                if _same_path(match.path, real)
            ]
            if not is_recoverable_url_candidate(candidate, data, same_file):
                continue
            recovered.append(
                Finding(
                    detector=self.name,
                    category=str(candidate.metadata["category"]),
                    severity=Severity(str(candidate.metadata["severity"])),
                    confidence=Confidence(str(candidate.metadata["confidence"])),
                    file_path=by_realpath[real],
                    line=candidate.line,
                    message=f"{URL_RULE_ID}: {candidate.message}",
                    evidence=lines[candidate.line - 1].strip()[:200],
                    remediation=str(candidate.metadata["remediation"]),
                    tier=EvidenceTier.CONFIRMED,
                )
            )
        return recovered


def _read_bytes(file_path: str) -> bytes | None:
    try:
        return Path(file_path).read_bytes()
    except OSError:
        return None
