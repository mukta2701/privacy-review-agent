# Semgrep rule pack

Structural rules for the `semgrep` detector: a sensitive value reaching a
Python or JS/TS logging sink is a blocking `RAW_PII_LOGGING` finding.
Single-function taint mode, our own rules only.

## Rules

- `python-raw-pii-logging` (`python-raw-pii-logging.yaml`, cases in
  `python-raw-pii-logging.py`): `print(...)` and the `debug`, `info`,
  `warning`, `error`, `exception`, `critical` level methods on `logging`,
  `logger` and `log`.
- `js-ts-raw-pii-logging` (`js-ts-raw-pii-logging.yaml`, cases in
  `js-ts-raw-pii-logging.js` and `js-ts-raw-pii-logging.ts`):
  `console.log/info/warn/error/debug` and the `debug`, `info`, `warn`,
  `error`, `log` level methods on `logger` and `log`.

A source is a sensitive attribute, key or variable name, or a raw request
body or headers (`req.body`, `request.body`, `req.headers`,
`request.headers`), passed directly, interpolated (f-string, template
literal, concatenation) or through a tainted local variable in the same
function. Multi-line calls match once, on the line where the call starts.

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
  category: RAW_PII_LOGGING # an id from `policies/taxonomy.yaml`
  severity: high # critical | high | medium | low
  confidence: high # high | medium | low
  remediation: Redact or mask PII before logging. # non-empty
```

The rule-test harness (`privacy_review_agent.semgrep_harness`) checks the
layout and the metadata, and `calibrate` fails the release gate when a rule
test fails.
