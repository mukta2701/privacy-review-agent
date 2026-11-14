# Semgrep rule pack

Structural rules for the `semgrep` detector: a sensitive value reaching a
Python or JS/TS logging sink is a blocking `RAW_PII_LOGGING` finding,
personal data sent to a model call is a blocking `PII_IN_MODEL_PROMPT`
finding, personal data placed in a redirect URL or a generated link is a
blocking `PII_IN_URL` finding, and personal data sent through a Python
`requests`/`httpx` call
or to an error-tracking or analytics SDK is a blocking
`THIRD_PARTY_PII_TRANSFER` finding (the SDK rule has no vendor allowlist;
the `requests`/`httpx` rule drops allowlisted URLs). Single-function taint
mode, our own rules only.

## Rules

- `python-raw-pii-logging` (`python-raw-pii-logging.yaml`, cases in
  `python-raw-pii-logging.py`): `print(...)` and the `debug`, `info`,
  `warning`, `error`, `exception`, `critical` level methods on `logging`,
  `logger` and `log`.
- `js-ts-raw-pii-logging` (`js-ts-raw-pii-logging.yaml`, cases in
  `js-ts-raw-pii-logging.js` and `js-ts-raw-pii-logging.ts`):
  `console.log/info/warn/error/debug` and the `debug`, `info`, `warn`,
  `error`, `log` level methods on `logger` and `log`.
- `python-pii-in-model-prompt` (`python-pii-in-model-prompt.yaml`, cases in
  `python-pii-in-model-prompt.py`): OpenAI `chat.completions`
  (`create`/`parse`/`stream`), `beta.chat.completions` (`parse`/`stream`),
  `responses` (`create`/`parse`/`stream`) and `completions.create`; Anthropic
  `messages.create`/`stream` (only with a visible `model=` keyword, so a
  Twilio-style SMS `messages.create(to=..., body=...)` does not match);
  Google `generate_content`, `models.generate_content`, and `send_message`
  only on a chat assigned in the same function from `start_chat(...)` or
  `chats.create(...)`.
- `python-pii-to-third-party` (`python-pii-to-third-party.yaml`, cases in
  `python-pii-to-third-party.py`): `requests.get/post/put/patch/delete/request`
  and `httpx.get/post/put/patch/delete/request` (any tainted argument counts),
  plus the same six methods on a session or client assigned in the same
  function from `requests.Session()`, `httpx.Client()` or
  `httpx.AsyncClient()`.
- `python-pii-to-telemetry` (`python-pii-to-telemetry.yaml`, cases in
  `python-pii-to-telemetry.py`): `sentry_sdk` error-tracking calls
  (`set_user`/`set_context`/`set_tag`/`set_tags`/`set_extra`/
  `add_breadcrumb`/`capture_message`/`capture_event`), `analytics`
  (Segment) calls (`identify`/`track`/`page`/`screen`/`group`/`alias`),
  `posthog` calls (`capture`/`identify`/`set`/`set_once`/`alias`/
  `group_identify`) and the same six methods on a client assigned in the
  same function from `Posthog(...)`, and Datadog `set_tag`/`set_tags` on
  `tracer.current_span()` / `ddtrace.tracer.current_span()` directly or on
  a span assigned in the same function from `tracer.current_span()` or
  `tracer.trace(...)`.
- `python-pii-in-tool-result` (`python-pii-in-tool-result.yaml`, cases in
  `python-pii-in-tool-result.py`): the `return` value of a function
  decorated as an agent or MCP tool — `@mcp.tool` / `@mcp.tool(...)`
  (FastMCP / MCP Python SDK), `@function_tool` / `@function_tool(...)`
  (OpenAI Agents SDK), and `@tool` / `@tool(...)` (LangChain) — as blocking
  `PII_IN_MODEL_PROMPT`, because a tool result goes back into the model's
  context.
- `python-pii-in-url` (`python-pii-in-url.yaml`, cases in
  `python-pii-in-url.py`): personal data placed in a framework redirect
  URL or a generated link — Flask `redirect(...)` / `flask.redirect(...)`,
  Django `redirect(...)` (`django.shortcuts`), `HttpResponseRedirect(...)`
  / `HttpResponsePermanentRedirect(...)` (`django.http`), Starlette or
  FastAPI `RedirectResponse(...)`, and Flask `url_for(...)` /
  `flask.url_for(...)` (extra keyword arguments become URL parameters) —
  as blocking `PII_IN_URL`, because URLs end up in access logs, browser
  history and `Referer` headers. Sinks are written fully qualified and
  Semgrep resolves bare calls through their imports; a bare name bound in
  the calling function (parameter, import, helper, or reassignment), or
  shadowed at module level without a later qualifying import, does not
  block.

A source is a sensitive attribute, key or variable name, or a raw request
body or headers (`req.body`, `request.body`, `req.headers`,
`request.headers`), passed directly, interpolated (f-string, template
literal, concatenation) or through a tainted local variable in the same
function. Multi-line calls match once, on the line where the call starts.

The model-prompt rule reuses the logging rule's sources, explicit suffix
allowlist and sanitisers unchanged (same `pattern-sources` and
`pattern-sanitizers` blocks, so the same names match and the same
near-misses stay silent). Only the sinks are new. It does not cover
LangChain or LlamaIndex call sites, JS/TS model calls, the deprecated
legacy completion call, or `**kwargs`-only Anthropic calls with no visible
`model=` keyword.

The third-party rule reuses the model-prompt rule's sources, explicit
suffix allowlist and sanitisers unchanged (same `pattern-sources` and
`pattern-sanitizers` blocks). After Semgrep runs, the detector drops a
finding when the call's URL is a plain string literal whose host is in
`policies/vendor_allowlist.yaml` (`allowed_domains`, exact lowercased host
match); any other URL (non-literal, unlisted host, no `http(s)://` scheme)
is reported. It does not cover JS/TS `fetch`/`axios`, error-tracking and
analytics SDKs (see `python-pii-to-telemetry`), `aiohttp`/`urllib`, sessions
not assigned in the same function or opened with `with ... as`, URLs that
are not string literals (they are never allowlisted), and severity does not
vary by vendor.

The telemetry rule reuses the third-party rule's sources, explicit suffix
allowlist and sanitisers unchanged (same `pattern-sources` and
`pattern-sanitizers` blocks). The vendor allowlist does not apply: SDK
calls carry no URL, so every match is reported. It does not cover JS/TS
SDKs, whole user objects (`vars(user)`, `user.__dict__`,
`user.to_dict()`), Sentry `scope.set_user` / `push_scope` receivers,
Datadog `appsec` / `statsd`, spans opened with `with ... as`, spans or
clients not assigned in the same function, or per-vendor allowlisting.

The tool-result rule reuses the telemetry rule's sources, explicit suffix
allowlist and sanitisers unchanged (same `pattern-sources` and
`pattern-sanitizers` blocks). It reports personal data anywhere in the
returned expression — direct, interpolated, nested in a dict or list
literal, or through a tainted local variable — including a tool parameter
named like a source, and returns placed in `if`/`for` blocks. Bare `@tool`
only counts when the file imports `tool` from `langchain_core.tools` or
`langchain.tools` before the function: without that gate any in-house
`@tool` decorator (registries, CLI helpers) would be a blocking,
high-confidence finding. Its category is `PII_IN_MODEL_PROMPT`, which
already exists in `policies/taxonomy.yaml`, so the taxonomy does not
change. It does not cover MCP client `call_tool` arguments, tool schemas
or definitions that declare personal fields, JS/TS SDKs, LlamaIndex,
CrewAI or Anthropic tool runners, tools registered without a decorator
(`Tool(func=...)`, `mcp.add_tool`), receivers other than `mcp` (for example
`@server.tool()`), aliased imports (`import ... as`), imports placed inside
functions or after the tool, `tool` imported from anywhere but the two
LangChain modules, generators/`yield`, whole user objects (`vars(user)`,
`user.to_dict()`), or returns inside nested helpers.

The URL rule reuses the tool-result rule's sources, explicit suffix
allowlist and sanitisers unchanged (same `pattern-sources` and
`pattern-sanitizers` blocks). It reports personal data anywhere in a sink
argument — direct, interpolated (f-string, concatenation, `%` formatting,
`.format(...)`), or through a tainted local variable — including attribute,
key and bare-variable sources, permitted suffixed names such as
`user.phone_number`, `user.ssn_last4` and `user.emailVerified`, and raw
request bodies and headers. Multi-line calls match once, on the line where
the call starts. Its category is `PII_IN_URL` (`severity_default: high` in
`policies/taxonomy.yaml`), because a same-site redirect URL still leaks
into access logs, browser history and `Referer` headers and none of the
existing categories fit. The vendor allowlist does not apply: every match
is reported. It does not cover cookies or cookie flags, JS/TS sinks,
standalone URL construction not passed to a listed sink, Django
`reverse(...)`, `requests`/`httpx` query parameters (already covered by
`python-pii-to-third-party`), aliased or late imports as authorisation for
earlier calls, imports inside functions, arbitrary receiver methods such as
`self.redirect(...)`, or cross-function taint. Known resolution gaps
 (all single-function, file-local analysis): a module-level reassignment
 before the framework import still suppresses the finding even though the
 import restores the binding; an import of the same name from another
 module in an earlier function suppresses a later bare call; star imports
 (`from flask import *`) are not tracked as authorising imports; a function
 parameter or local variable named `flask` does not stop a literal
 `flask.redirect(...)` call from matching; and rebinding inside `if`/`try`
 blocks, `global` declarations, or `del` statements is not modelled (an
 `if`-guarded reassignment in the same function suppresses the finding,
 while the `try`/`global`/`del` forms still report).

## YAML-data convention

The sink list, the sensitive-name list and the sanitiser list live in the
rule YAML, so they change without code changes: `pattern-sinks` holds the
sink calls, `pattern-sanitizers` holds the redaction helpers (each as a
function and as a method), and the `metavariable-regex` alternation holds
the sensitive names with identifier-part boundaries (snake_case, camelCase,
attribute and key forms, like the keyword detector).

Only unambiguous personal data blocks: `email`, `phone`, `first_name`,
`last_name` and `ssn`, plus raw request bodies and headers (`req.body`,
`request.body`, `req.headers`, `request.headers`), which stay explicit
sources. Everything else from `policies/sensitive_fields.yaml` is out
because ordinary code kept matching it; the keyword detector still flags
those advisory. Dropped: standalone `name`, `message`, `body`; the
identifier-only `user_id`, `customer_id`; `upload`, `chat`, `location`,
`lat`, `lon`, standalone `headers`; and `token`, `address`, `cookie`,
`transcript`, `passport`, `authorization` (lexer tokens, network addresses,
design cookies, library sessions and the like). Plurals (`emails`) and
run-together lowercase (`useremail`) do not match, so the existing `kg-*`
known gaps stay gaps.

Attribute and key names must start with the sensitive name; explicitly
allowed suffixes are `_number`/`Number` (phone, email), `_last4`/`Last4`
(ssn, email), `_verified`/`Verified` and `_address`/`Address` (email), so
`user.phone_number`, `user.ssn_last4`, `user.emailVerified` and
`user.email_address` match while `email_count`, `settings.EMAIL_HOST`,
`ssn_pattern` and `phone_type` do not. A bare `email` used as a module
object (`email.utils.formatdate()`) is not a source. Values merely derived
from a sensitive name do not block either: `len()`/`bool()`/`type()`
(`Boolean()` and `.length` in JS/TS) sanitise, and `is None` / `is not None` /
`==` / `!=` / `in` (`==` / `!=` / `===` / `!==`) comparisons and `typeof` do
not taint.

Sanitisers are the approved redaction helpers from
`policies/redaction_rules.yaml` (`redact`, `mask`, `hash`, `tokenize`):
a value passed through one is not reported.

## Layout

- One rule file per rule: `<name>.yaml` (or `<name>.yml`).
- Test files live beside the rule: `<name>.py`, `<name>.js` or `<name>.ts`.
- A positive case is the line after a `# ruleid: <id>` (or `// ruleid: <id>`)
  comment: the rule must match that line.
- A near-miss case is the line after a `# ok: <id>` (or `// ok: <id>`)
  comment: the rule must not match that line.

## Required metadata

Every rule must carry this metadata:

```yaml
metadata:
  category: RAW_PII_LOGGING # an id from `policies/taxonomy.yaml` (`RAW_PII_LOGGING`, `PII_IN_MODEL_PROMPT`, `PII_IN_URL` or `THIRD_PARTY_PII_TRANSFER`)
  severity: high # critical | high | medium | low
  confidence: high # high | medium | low
  remediation: Redact or mask PII before logging. # non-empty
```

The rule-test harness (`privacy_review_agent.semgrep_harness`) checks the
layout and the metadata, and `calibrate` fails the release gate when a rule
test fails.
