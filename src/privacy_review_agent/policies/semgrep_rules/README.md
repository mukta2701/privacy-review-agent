# Semgrep rule pack

Optional structural rules for the `semgrep` detector. The shipped pack is
empty on purpose: real privacy rules land in their own issues.

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
