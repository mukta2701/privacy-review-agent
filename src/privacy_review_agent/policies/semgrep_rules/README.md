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

The names come from `policies/sensitive_fields.yaml`, minus entries too
generic for a blocking finding: standalone `name`, `message` and `body`
are excluded, as are the identifier-only `user_id` and `customer_id`.
Plurals (`emails`, `tokens`) and run-together lowercase (`useremail`,
`accesstoken`) do not match, so the existing `kg-*` known gaps stay gaps.

Dropped after probing ordinary code (a bare or qualified use still matched,
so the name is out; the keyword detector still flags these advisory):
`upload` (`upload.id`, `upload_dir`), `chat` (`chat.id`), `location`
(`file.location`), `lat`/`lon` (bare coordinates in telemetry), and
standalone `headers` (`response.headers`). Raw request bodies and headers
(`req.body`, `request.body`, `req.headers`, `request.headers`) stay explicit
sources.

Kept: `email`, `phone`, `first_name`, `last_name`, `address`, `ssn`,
`passport`, `cookie`, `token`, `authorization` and `transcript`. A leading
`_` still separates (`user_email`, `access_token`), but a trailing `_` or
alnum ends the name, so `token_count`, `upload_dir` and `cookie_policy` do
not match. An exact `token` (or `authToken`, `user.token`) still blocks: it
is credential-like often enough to warrant a blocking finding, while
suffixed and plural forms stay silent.

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
