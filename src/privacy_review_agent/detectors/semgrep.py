from __future__ import annotations

import ast
import os
import shutil
from collections.abc import Collection
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
    ``def``/``async def`` body, the containing function must not bind the
    sink name, the last module statement binding the name must be a
    qualifying framework import, and no ordinary ``python-pii-in-url``
    match may overlap the call. Anything uncertain returns False.
    """
    if not isinstance(candidate, SemgrepMatch):
        return False
    if not isinstance(file_data, (bytes, bytearray)):
        return False
    data = bytes(file_data)
    try:
        tree = ast.parse(data.decode("utf-8"))
    except (SyntaxError, ValueError, UnicodeError, RecursionError):
        return False
    start = candidate.offset
    end = candidate.end_offset
    if (
        not isinstance(start, int)
        or not isinstance(end, int)
        or isinstance(start, bool)
        or isinstance(end, bool)
    ):
        return False
    if start < 0 or end <= start or end > len(data):
        return False
    line_starts = _byte_line_starts(data)
    calls = _bare_sink_calls(tree, line_starts, len(data))
    if not calls:
        return False
    contained = [
        (call_start, call_end, node)
        for call_start, call_end, node in calls
        if start <= call_start and call_end <= end
    ]
    if len(contained) != 1:
        return False
    call_start, call_end, node = contained[0]
    func = _containing_top_function(node, tree)
    if func is None:
        return False
    sink = node.func.id if isinstance(node.func, ast.Name) else ""
    if sink not in URL_SINK_NAMES:
        return False
    if _function_binds_name(func, sink):
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
        if not isinstance(match.offset, int) or not isinstance(match.end_offset, int):
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
    starts: list[int] = []
    pos = 0
    for part in data.split(b"\n"):
        starts.append(pos)
        pos += len(part) + 1
    return starts


def _node_span(
    node: ast.AST, line_starts: list[int], data_len: int
) -> tuple[int, int] | None:
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", None)
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    if (
        not isinstance(lineno, int)
        or not isinstance(end_lineno, int)
        or not isinstance(col, int)
        or not isinstance(end_col, int)
        or isinstance(lineno, bool)
    ):
        return None
    if lineno < 1 or end_lineno < lineno:
        return None
    if lineno > len(line_starts) or end_lineno > len(line_starts):
        return None
    start = line_starts[lineno - 1] + col
    end = line_starts[end_lineno - 1] + end_col
    if start < 0 or end < start or end > data_len:
        return None
    return (start, end)


def _bare_sink_calls(
    tree: ast.Module, line_starts: list[int], data_len: int
) -> list[tuple[int, int, ast.Call]] | None:
    """Byte spans of bare sink calls, or None when a span is malformed."""
    calls: list[tuple[int, int, ast.Call]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in URL_SINK_NAMES
        ):
            span = _node_span(node, line_starts, data_len)
            if span is None:
                return None
            calls.append((span[0], span[1], node))
    return calls


def _containing_top_function(
    node: ast.AST, tree: ast.Module
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Nearest module-level function whose body owns the call, else None."""
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    chain: list[ast.AST] = []
    current = parents.get(id(node))
    while current is not None:
        chain.append(current)
        if current is tree:
            break
        current = parents.get(id(current))
    owner: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for ancestor in chain:
        if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = ancestor
            break
        if isinstance(
            ancestor,
            (
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
                ast.ClassDef,
            ),
        ):
            return None
    if owner is None or parents.get(id(owner)) is not tree:
        return None
    child: ast.AST = node
    while parents.get(id(child)) is not owner:
        parent = parents.get(id(child))
        if parent is None:
            return None
        child = parent
    if not any(child is stmt for stmt in owner.body):
        return None
    return owner


def _target_binds_name(target: ast.AST, name: str) -> bool:
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, ast.Starred):
        return _target_binds_name(target.value, name)
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_binds_name(elt, name) for elt in target.elts)
    return False


def _has_walrus_binding(node: ast.AST, name: str) -> bool:
    for child in ast.walk(node):
        if (
            isinstance(child, ast.NamedExpr)
            and isinstance(child.target, ast.Name)
            and child.target.id == name
        ):
            return True
    return False


def _pattern_binds_name(pattern: ast.AST, name: str) -> bool:
    for child in ast.walk(pattern):
        if isinstance(child, ast.MatchAs) and child.name == name:
            return True
        if isinstance(child, ast.MatchStar) and child.name == name:
            return True
        if isinstance(child, ast.MatchMapping) and child.rest == name:
            return True
        if (
            isinstance(child, ast.NamedExpr)
            and isinstance(child.target, ast.Name)
            and child.target.id == name
        ):
            return True
    return False


def _block_binds_name(stmts: list[ast.stmt], name: str) -> bool:
    return any(_scope_binds_name(stmt, name) for stmt in stmts)


def _headers_bind_name(
    node: ast.FunctionDef | ast.AsyncFunctionDef, name: str
) -> bool:
    exprs: list[ast.AST] = list(node.decorator_list)
    args = node.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        if arg.annotation is not None:
            exprs.append(arg.annotation)
    for default in (*args.defaults, *args.kw_defaults):
        if default is not None:
            exprs.append(default)
    for vararg in (args.vararg, args.kwarg):
        if vararg is not None and vararg.annotation is not None:
            exprs.append(vararg.annotation)
    if node.returns is not None:
        exprs.append(node.returns)
    return any(_has_walrus_binding(expr, name) for expr in exprs)


def _class_body_leaks_name(node: ast.ClassDef, name: str) -> bool:
    """Whether a walrus in a class body binds the name in the outer scope."""
    stack: list[ast.AST] = list(node.body)
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _headers_bind_name(current, name):
                return True
            continue
        if (
            isinstance(current, ast.NamedExpr)
            and isinstance(current.target, ast.Name)
            and current.target.id == name
        ):
            return True
        stack.extend(ast.iter_child_nodes(current))
    return False


def _scope_binds_name(stmt: ast.stmt, name: str) -> bool:
    """Whether a statement binds (or may bind) the name in its own scope."""
    if isinstance(stmt, ast.Import):
        for alias in stmt.names:
            bound = alias.asname if alias.asname else alias.name.split(".")[0]
            if bound == name:
                return True
        return False
    if isinstance(stmt, ast.ImportFrom):
        for alias in stmt.names:
            if alias.name == "*":
                return True
            bound = alias.asname if alias.asname else alias.name
            if bound == name:
                return True
        return False
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if stmt.name == name:
            return True
        return _headers_bind_name(stmt, name)
    if isinstance(stmt, ast.ClassDef):
        if stmt.name == name:
            return True
        exprs: list[ast.AST] = (
            list(stmt.decorator_list)
            + list(stmt.bases)
            + [keyword.value for keyword in stmt.keywords]
        )
        if any(_has_walrus_binding(expr, name) for expr in exprs):
            return True
        return _class_body_leaks_name(stmt, name)
    if isinstance(stmt, ast.Return):
        return stmt.value is not None and _has_walrus_binding(stmt.value, name)
    if isinstance(stmt, ast.Delete):
        return any(_target_binds_name(target, name) for target in stmt.targets)
    if isinstance(stmt, ast.Assign):
        if any(_target_binds_name(target, name) for target in stmt.targets):
            return True
        return _has_walrus_binding(stmt.value, name)
    if hasattr(ast, "TypeAlias") and isinstance(stmt, ast.TypeAlias):
        target = stmt.name
        if isinstance(target, ast.Name) and target.id == name:
            return True
        return _has_walrus_binding(stmt.value, name)
    if isinstance(stmt, ast.AugAssign):
        if _target_binds_name(stmt.target, name):
            return True
        return _has_walrus_binding(stmt.value, name)
    if isinstance(stmt, ast.AnnAssign):
        if _target_binds_name(stmt.target, name):
            return True
        if stmt.annotation is not None and _has_walrus_binding(
            stmt.annotation, name
        ):
            return True
        return stmt.value is not None and _has_walrus_binding(stmt.value, name)
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        if _target_binds_name(stmt.target, name):
            return True
        if _has_walrus_binding(stmt.iter, name):
            return True
        return _block_binds_name(stmt.body, name) or _block_binds_name(
            stmt.orelse, name
        )
    if isinstance(stmt, (ast.While, ast.If)):
        if _has_walrus_binding(stmt.test, name):
            return True
        return _block_binds_name(stmt.body, name) or _block_binds_name(
            stmt.orelse, name
        )
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if item.optional_vars is not None and _target_binds_name(
                item.optional_vars, name
            ):
                return True
            if _has_walrus_binding(item.context_expr, name):
                return True
        return _block_binds_name(stmt.body, name)
    if hasattr(ast, "TryStar") and isinstance(stmt, (ast.Try, ast.TryStar)):
        return _try_binds_name(stmt, name)
    if isinstance(stmt, ast.Try):
        return _try_binds_name(stmt, name)
    if isinstance(stmt, ast.Match):
        if _has_walrus_binding(stmt.subject, name):
            return True
        for case in stmt.cases:
            if _pattern_binds_name(case.pattern, name):
                return True
            if case.guard is not None and _has_walrus_binding(case.guard, name):
                return True
            if _block_binds_name(case.body, name):
                return True
        return False
    if isinstance(stmt, ast.Raise):
        for expr in (stmt.exc, stmt.cause):
            if expr is not None and _has_walrus_binding(expr, name):
                return True
        return False
    if isinstance(stmt, ast.Assert):
        if _has_walrus_binding(stmt.test, name):
            return True
        return stmt.msg is not None and _has_walrus_binding(stmt.msg, name)
    if isinstance(stmt, ast.Expr):
        return _has_walrus_binding(stmt.value, name)
    if isinstance(stmt, (ast.Global, ast.Nonlocal)):
        return name in stmt.names
    if isinstance(stmt, (ast.Pass, ast.Break, ast.Continue)):
        return False
    return True


def _try_binds_name(stmt: ast.stmt, name: str) -> bool:
    body: list[ast.stmt] = getattr(stmt, "body", [])
    orelse: list[ast.stmt] = getattr(stmt, "orelse", [])
    finalbody: list[ast.stmt] = getattr(stmt, "finalbody", [])
    if _block_binds_name(body, name):
        return True
    for handler in getattr(stmt, "handlers", []):
        handler_type = getattr(handler, "type", None)
        if handler_type is not None and _has_walrus_binding(handler_type, name):
            return True
        if getattr(handler, "name", None) == name:
            return True
        if _block_binds_name(getattr(handler, "body", []), name):
            return True
    return _block_binds_name(orelse, name) or _block_binds_name(finalbody, name)


def _function_binds_name(
    func: ast.FunctionDef | ast.AsyncFunctionDef, name: str
) -> bool:
    args = func.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        if arg.arg == name:
            return True
    for vararg in (args.vararg, args.kwarg):
        if vararg is not None and vararg.arg == name:
            return True
    return _block_binds_name(func.body, name)


def _module_authorises_sink(
    tree: ast.Module,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
) -> bool:
    """Whether the last pre-function module binding is a qualifying import."""
    index = next((i for i, stmt in enumerate(tree.body) if stmt is func), None)
    if index is None:
        return False
    authorised = False
    for stmt in tree.body[:index]:
        if (
            isinstance(stmt, ast.ImportFrom)
            and stmt.level == 0
            and (stmt.module or "") in _URL_IMPORT_ORIGINS
            and name in _URL_IMPORT_ORIGINS[stmt.module or ""]
        ):
            bound_unaliased = any(
                alias.name == name and not alias.asname for alias in stmt.names
            )
            binds_name = any(
                (alias.asname if alias.asname else alias.name) == name
                or alias.name == "*"
                for alias in stmt.names
            )
            if bound_unaliased:
                authorised = True
            elif binds_name:
                authorised = False
            continue
        if _scope_binds_name(stmt, name):
            authorised = False
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
