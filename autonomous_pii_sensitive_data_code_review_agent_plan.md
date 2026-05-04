# Autonomous Code Review Agent for PII, Sensitive Data, and Policy Risk Exposure

## Purpose

This document defines a step-by-step implementation plan for building an autonomous code review agent that reviews pull requests for:

- Personally identifiable information (PII) exposure
- Sensitive data leakage
- Secrets in code
- Unsafe logging
- Third-party data transfer risk
- LLM prompt privacy risk
- Consent, retention, deletion, access-control, and policy-bypass risk

The recommended design is a **hybrid reviewer**:

```text
Deterministic scanners + custom policy rules + LLM semantic review + human escalation
```

The agent should not be a pure LLM reviewer. Static tools should handle high-confidence detection, while the LLM should reason over context and explain nuanced policy risks.

---

# 1. MVP Scope

Start with a narrow, high-value scope.

The first version should detect:

1. **Secrets in code**
   - API keys
   - access tokens
   - private keys
   - database passwords
   - OAuth secrets
   - signing keys

2. **Raw PII logging**
   - `console.log(req.body)`
   - `logger.info(user)`
   - logging raw headers, cookies, tokens, request payloads, chat messages, uploads, or customer records

3. **Unsafe third-party transfer**
   - sending email, phone, name, address, user messages, IDs, or location data to analytics, ad tech, LLM APIs, webhooks, or external vendors

4. **PII in prompts**
   - raw personal data passed into LLM prompts without redaction, minimization, or approval

5. **Missing redaction or masking**
   - logs, telemetry, error reporting, support tooling, analytics, or audit events containing sensitive fields

6. **Dangerous policy bypasses**
   - disabling consent checks
   - skipping privacy filters
   - suppressing redaction
   - hardcoded allow/deny bypasses

---

# 2. Risk Taxonomy

Create a standard set of categories so every finding is classified consistently.

```yaml
risk_categories:
  - id: SECRET_EXPOSURE
    description: Secret, credential, key, or token committed to code.

  - id: RAW_PII_LOGGING
    description: Personal or sensitive data is logged before redaction.

  - id: THIRD_PARTY_PII_TRANSFER
    description: PII is sent to an external vendor or API without clear approval.

  - id: PII_IN_MODEL_PROMPT
    description: Raw PII or sensitive user content is included in an LLM prompt.

  - id: SENSITIVE_DATA_STORAGE
    description: Sensitive data is stored without clear need, encryption, retention, or access controls.

  - id: POLICY_BYPASS
    description: Privacy, safety, consent, access, or redaction controls are bypassed.

  - id: INSUFFICIENT_REDACTION
    description: Redaction, hashing, masking, or tokenization is incomplete or absent.

  - id: EXCESSIVE_COLLECTION
    description: Code collects more personal data than needed for the feature.

  - id: WEAK_RETENTION_OR_DELETION
    description: Sensitive data appears to lack retention, deletion, or cleanup handling.
```

---

# 3. Severity and Confidence Model

Separate severity from confidence.

A finding can be severe but uncertain. For example:

> This looks like a user location field sent to analytics.

Severity may be `high`, but confidence may be `medium`.

```yaml
severity:
  critical:
    meaning: Immediate credential compromise, legal/compliance exposure, or broad sensitive-data leak.
  high:
    meaning: Likely privacy/security violation affecting real user data.
  medium:
    meaning: Risky pattern that may expose sensitive data depending on context.
  low:
    meaning: Best-practice issue, cleanup suggestion, or weak signal.

confidence:
  high:
    meaning: Direct evidence in code.
  medium:
    meaning: Strong contextual evidence, but some uncertainty.
  low:
    meaning: Suspicious pattern requiring human review.
```

## Merge-Blocking Policy

| Severity | Confidence | Action |
|---|---:|---|
| Critical | High | Block merge |
| Critical | Medium | Block or require security approval |
| High | High | Block merge |
| High | Medium | Require privacy/security review |
| Medium | Any | Comment only |
| Low | Any | Suggestion only |

For the MVP, only block:

1. confirmed secrets,
2. raw sensitive request/response logging,
3. clear PII transfer to an unapproved third party,
4. obvious raw PII in LLM prompts.

---

# 4. Policy Rulebook

Create a machine-readable policy rulebook.

Suggested structure:

```text
privacy-review-agent/
  policies/
    pii-policy.yaml
    logging-policy.yaml
    vendor-policy.yaml
    llm-policy.yaml
    suppressions-policy.yaml
```

Example policy:

```yaml
rules:
  - id: no-raw-request-logging
    category: RAW_PII_LOGGING
    severity: high
    description: Do not log raw request bodies, headers, cookies, tokens, or uploaded content.
    bad_patterns:
      - logger.info(req.body)
      - logger.debug(request.headers)
      - console.log(ctx.request.body)
    good_patterns:
      - logger.info({ userId: hashUserId(user.id), action: "login" })
      - logger.info(redactRequest(req))
    required_fix:
      - Use explicit allowlisted fields.
      - Apply redaction before logging.
      - Never log authorization headers, cookies, or raw payloads.

  - id: no-secrets-in-code
    category: SECRET_EXPOSURE
    severity: critical
    description: Do not commit credentials, tokens, private keys, or signing secrets.
    required_fix:
      - Remove the secret from code.
      - Rotate the credential.
      - Move configuration to an approved secret manager.

  - id: no-unapproved-pii-to-third-party
    category: THIRD_PARTY_PII_TRANSFER
    severity: high
    description: Do not send PII to unapproved third-party services.
    required_fix:
      - Minimize data.
      - Redact direct identifiers.
      - Confirm vendor approval.
      - Confirm consent or other valid basis.

  - id: no-raw-pii-in-llm-prompts
    category: PII_IN_MODEL_PROMPT
    severity: high
    description: Do not include raw personal data in model prompts unless explicitly approved.
    required_fix:
      - Redact or tokenize PII before prompt construction.
      - Use allowlisted fields only.
      - Add test coverage for prompt redaction.
```

---

# 5. System Architecture

Use this architecture:

```text
GitHub / GitLab PR
      ↓
Webhook or CI job
      ↓
Repo checkout in sandbox
      ↓
Diff collector
      ↓
Static scanners
      ↓
Custom policy rules
      ↓
Context retriever
      ↓
LLM semantic reviewer
      ↓
Finding normalizer
      ↓
Deduplication + severity ranking
      ↓
PR comments / SARIF / dashboard
      ↓
Human escalation if needed
```

For GitHub, support:

- PR summary comments
- Inline PR comments
- SARIF output
- Optional GitHub Checks API status

---

# 6. Tooling

## Secret Scanning

Use:

```text
Gitleaks
```

Purpose:

```text
SECRET_EXPOSURE
```

Example conceptual command:

```bash
gitleaks detect --source . --report-format json --report-path gitleaks.json
```

Normalize Gitleaks output into the shared finding schema.

Important: never post the full secret value in PR comments, logs, prompts, or dashboards. Mask secrets.

Example:

```text
Detected possible API key ending in ...9xQ2.
Do not expose the full value in logs or comments.
```

## Static Policy Scanning

Use:

```text
Semgrep
```

Purpose:

```text
RAW_PII_LOGGING
PII_IN_MODEL_PROMPT
POLICY_BYPASS
THIRD_PARTY_PII_TRANSFER
SENSITIVE_DATA_STORAGE
```

## LLM Semantic Review

Use the LLM after deterministic scanners have narrowed the review scope.

The LLM should receive:

- policy rules,
- changed hunk,
- nearby context,
- scanner findings,
- vendor registry,
- redaction helper registry,
- expected JSON schema.

The LLM must return structured JSON only.

---

# 7. Finding Schema

Every finding should follow this shape:

```json
{
  "finding_id": "string",
  "rule_id": "no-raw-request-logging",
  "category": "RAW_PII_LOGGING",
  "severity": "high",
  "confidence": "high",
  "blocking": true,
  "file": "src/api/users.ts",
  "line_start": 42,
  "line_end": 45,
  "title": "Raw request body logged before redaction",
  "evidence": "The code logs req.body directly.",
  "risk_explanation": "Request bodies may contain email, phone, address, tokens, or user-generated sensitive content.",
  "recommended_fix": "Log only allowlisted fields or apply redactRequestBody(req.body) before logging.",
  "suggested_patch": null,
  "requires_human_review": false
}
```

## Review Summary Schema

```json
{
  "review_id": "pr-123-sha-abc",
  "repo": "org/repo",
  "pull_request": 123,
  "commit_sha": "abc123",
  "status": "failed",
  "blocking_findings": 2,
  "non_blocking_findings": 5,
  "findings": []
}
```

Supported statuses:

```text
passed
passed_with_comments
needs_human_review
failed
scanner_error
```

---

# 8. Repository Structure

Suggested implementation structure:

```text
privacy-review-agent/
  src/
    main.py
    config.py
    git_provider/
      github.py
      gitlab.py
    scanners/
      gitleaks.py
      semgrep.py
      regex_pii.py
    policy/
      loader.py
      evaluator.py
    context/
      diff_parser.py
      code_retriever.py
      symbol_extractor.py
    llm/
      reviewer.py
      schemas.py
      prompts.py
    findings/
      normalize.py
      dedupe.py
      severity.py
      sarif.py
    output/
      pr_comment.py
      github_checks.py
      dashboard.py
  policies/
    pii-policy.yaml
    logging-policy.yaml
    vendor-policy.yaml
    llm-policy.yaml
  semgrep-rules/
    no-raw-request-logging.yaml
    no-raw-headers-logging.yaml
    no-pii-to-analytics.yaml
    no-raw-pii-in-prompts.yaml
  tests/
    fixtures/
    unit/
    integration/
```

---

# 9. PR Diff Collection

For each PR, collect:

```text
repo name
PR number
base commit
head commit
changed files
added lines
deleted lines
file language
full file content for changed files
nearby context around changed lines
```

Analyze these file types initially:

```text
.ts
.tsx
.js
.jsx
.py
.go
.java
.kt
.rb
.php
.cs
```

Skip by default:

```text
node_modules/
dist/
build/
coverage/
vendor/
generated/
*.lock
*.min.js
```

Exception: secrets scanning should still inspect all files unless explicitly excluded.

---

# 10. Semgrep Rules

Start with high-signal rules.

## Raw Request Body Logging

```yaml
rules:
  - id: no-raw-request-body-logging
    message: Raw request body is logged. Use redaction or explicit allowlisted fields.
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: logger.$LEVEL($REQ.body)
          - pattern: console.$LEVEL($REQ.body)
          - pattern: $LOGGER.$LEVEL($REQ.body)
      - metavariable-regex:
          metavariable: $LEVEL
          regex: log|info|debug|warn|error
    metadata:
      category: RAW_PII_LOGGING
      policy_rule: no-raw-request-logging
```

## Raw Headers Logging

```yaml
rules:
  - id: no-raw-headers-logging
    message: Raw headers may contain cookies, authorization tokens, IPs, and identifiers.
    severity: ERROR
    languages: [javascript, typescript, python]
    patterns:
      - pattern-either:
          - pattern: logger.$LEVEL($REQ.headers)
          - pattern: console.$LEVEL($REQ.headers)
          - pattern: print($REQ.headers)
    metadata:
      category: RAW_PII_LOGGING
      policy_rule: no-raw-request-logging
```

## Raw User Object in LLM Prompt

```yaml
rules:
  - id: no-raw-user-object-in-llm-prompt
    message: Raw user object appears to be included in an LLM prompt.
    severity: WARNING
    languages: [javascript, typescript, python]
    patterns:
      - pattern-either:
          - pattern: |
              $CLIENT.chat.completions.create({
                messages: [..., { role: "user", content: $USER }]
              })
          - pattern: |
              $MODEL.generate($USER)
    metadata:
      category: PII_IN_MODEL_PROMPT
      policy_rule: no-raw-pii-in-llm-prompts
```

---

# 11. Suspicious Field Detector

Build a lightweight detector for identifiers like:

```text
email
phone
name
firstName
lastName
address
dob
dateOfBirth
ssn
nationalId
passport
ipAddress
deviceId
cookie
authorization
token
password
secret
apiKey
location
latitude
longitude
biometric
health
diagnosis
child
minor
```

This detector should not block by itself. It should decide which code hunks deserve LLM review.

Example output:

```json
{
  "file": "src/analytics/events.ts",
  "line": 88,
  "signals": ["email", "analytics.track", "userId"],
  "reason": "Possible PII transfer to analytics"
}
```

---

# 12. Context Retrieval

For each suspicious changed hunk, collect:

1. changed lines,
2. 30–80 lines around the changed code,
3. function/class containing the change,
4. import statements,
5. definitions of called privacy helpers,
6. vendor client definitions,
7. data model/schema for relevant objects,
8. nearby tests.

Example context bundle:

```text
Changed code:
  analytics.track("signup", { email: user.email })

Additional context:
  analytics.ts imports Segment client
  user.email comes from User model
  no redaction helper is called
  vendor allowlist does not mention Segment for email
```

---

# 13. LLM Reviewer

The LLM should only review scoped context bundles, not the entire repository.

## Prompt Template

```text
You are a privacy, security, and policy code-review agent.

Review the supplied code change for:
- PII exposure
- sensitive data leakage
- secrets
- unsafe logging
- third-party data sharing
- LLM prompt privacy risks
- consent, retention, deletion, access-control, or policy bypass risks

Rules:
- Only report findings supported by concrete evidence.
- Do not speculate.
- Cite the exact file and line range.
- Separate severity from confidence.
- Use the supplied policy rule IDs.
- If evidence is weak, mark confidence low or return no finding.
- Do not include full secrets in the output.
- Return only JSON matching the schema.
```

## Structured Output Schema

```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "rule_id": { "type": "string" },
          "category": {
            "type": "string",
            "enum": [
              "SECRET_EXPOSURE",
              "RAW_PII_LOGGING",
              "THIRD_PARTY_PII_TRANSFER",
              "PII_IN_MODEL_PROMPT",
              "SENSITIVE_DATA_STORAGE",
              "POLICY_BYPASS",
              "INSUFFICIENT_REDACTION",
              "EXCESSIVE_COLLECTION",
              "WEAK_RETENTION_OR_DELETION"
            ]
          },
          "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"]
          },
          "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"]
          },
          "file": { "type": "string" },
          "line_start": { "type": "integer" },
          "line_end": { "type": "integer" },
          "title": { "type": "string" },
          "evidence": { "type": "string" },
          "risk_explanation": { "type": "string" },
          "recommended_fix": { "type": "string" },
          "blocking": { "type": "boolean" },
          "requires_human_review": { "type": "boolean" }
        },
        "required": [
          "rule_id",
          "category",
          "severity",
          "confidence",
          "file",
          "line_start",
          "line_end",
          "title",
          "evidence",
          "risk_explanation",
          "recommended_fix",
          "blocking",
          "requires_human_review"
        ]
      }
    }
  },
  "required": ["findings"]
}
```

---

# 14. Normalization, Deduplication, and Ranking

All findings should pass through one normalizer.

Inputs:

```text
Gitleaks findings
Semgrep findings
regex/keyword signals
LLM findings
```

Output:

```text
same schema
same severity scale
same category list
same blocking policy
same PR comment format
```

Deduplication key:

```text
file + line range + rule_id + category
```

If two tools find the same issue, merge them and increase confidence where appropriate.

Example:

```text
Semgrep found raw logging.
LLM confirmed request body may contain PII.
Final confidence: high.
```

---

# 15. PR Output

## Inline Finding Comment

Example:

```text
High risk: raw request body is logged before redaction.

This logs `req.body` directly. Request bodies may contain email addresses, phone numbers, tokens, message content, or other personal data.

Policy: no-raw-request-logging

Recommended fix:
Log only explicit safe fields, or call `redactRequestBody(req.body)` before logging.

Blocking: yes
```

## PR Summary Comment

```markdown
## Privacy and sensitive-data review

Status: Failed

Blocking findings:
1. Critical: possible API key committed in `config.ts`
2. High: raw request body logged in `src/api/signup.ts`

Non-blocking findings:
1. Medium: email sent to analytics event in `src/analytics/events.ts`

Required action:
- Remove and rotate the exposed secret.
- Redact or remove raw request body logging.
- Confirm whether analytics vendor is approved for email transfer.
```

---

# 16. SARIF Output

Convert findings to SARIF so code scanning tools can display them.

Mapping:

```text
ruleId → policy rule ID
level → error/warning/note
message → finding title
location → file and line range
properties → category, confidence, blocking
```

Recommended severity mapping:

| Severity | SARIF Level |
|---|---|
| critical | error |
| high | error |
| medium | warning |
| low | note |

---

# 17. Suppression Handling

Developers need an escape hatch, but suppressions must be controlled.

Valid example:

```ts
// privacy-review-ignore no-raw-request-logging
// reason: request body is already redacted by sanitizeRequestBody above
logger.info(sanitizeRequestBody(req.body));
```

Rules:

1. suppression must specify a rule ID,
2. suppression must include a meaningful reason,
3. suppression cannot suppress secrets,
4. suppression cannot suppress critical findings without security approval,
5. suppressions may expire after a configurable period.

Invalid example:

```ts
// privacy-review-ignore
logger.info(req.body);
```

Invalid because there is no rule ID or reason.

Also invalid:

```ts
// privacy-review-ignore no-raw-request-logging
// reason: safe
logger.info(req.body);
```

Invalid because the reason is not meaningful.

---

# 18. Vendor Registry

Create a vendor registry to define approved data sharing.

```yaml
vendors:
  - id: segment
    name: Segment
    approved: true
    allowed_data:
      - user_id
      - event_name
      - plan_type
    prohibited_data:
      - email
      - phone
      - address
      - raw_message
      - government_id
      - access_token

  - id: sentry
    name: Sentry
    approved: true
    allowed_data:
      - error_type
      - stack_trace
      - service_name
    prohibited_data:
      - request_body
      - authorization_header
      - cookie
      - password
      - token

  - id: unknown_webhook
    approved: false
    allowed_data: []
```

The agent should flag:

```ts
analytics.track("signup", {
  email: user.email
});
```

Because email is not approved for this analytics vendor.

---

# 19. Redaction Utility Registry

Teach the agent which helper functions are safe.

```yaml
safe_redaction_functions:
  - redact
  - redactPII
  - sanitizeRequestBody
  - maskEmail
  - hashUserId
  - tokenize
  - removeSensitiveFields

unsafe_or_insufficient_functions:
  - JSON.stringify
  - String
  - toString
```

The agent should distinguish between:

```ts
logger.info(req.body);
```

and:

```ts
logger.info(redactRequestBody(req.body));
```

---

# 20. Test Fixtures

Create fixture PRs and expected outputs.

```text
tests/fixtures/
  secrets/
    api_key_in_config.ts
    private_key_in_env.py
  logging/
    raw_request_body.ts
    redacted_request_body.ts
    raw_headers.py
  analytics/
    email_to_segment.ts
    hashed_id_to_segment.ts
  llm/
    prompt_with_email.ts
    prompt_with_redacted_email.ts
  suppressions/
    valid_suppression.ts
    invalid_suppression.ts
```

Example expected finding:

```yaml
fixture: logging/raw_request_body.ts
expected:
  - rule_id: no-raw-request-logging
    category: RAW_PII_LOGGING
    severity: high
    confidence: high
    blocking: true
```

Run fixture tests on every agent change.

---

# 21. Accuracy Evaluation

Track:

```text
true positives
false positives
false negatives
developer dismissals
suppression rate
average comments per PR
block rate
time to review
```

Important metrics:

```text
false-positive rate for blocking findings
number of repeated noisy rules
number of findings overturned by humans
number of true incidents caught before merge
```

Prioritize:

```text
high precision for blocking findings
medium recall for non-blocking findings
```

A noisy merge blocker will get disabled.

---

# 22. Rollout Plan

## Stage 1: Silent Mode

Duration: 1–2 weeks.

The agent runs but does not comment.

Goal:

```text
Measure noise before developers see it.
```

## Stage 2: Comment-Only Mode

The agent posts PR summaries but does not block.

Goal:

```text
Collect developer feedback and tune rules.
```

## Stage 3: Limited Blocking

Block only:

```text
confirmed secrets
raw request logging
raw headers/cookies logging
high-confidence PII to unapproved vendor
```

## Stage 4: Full Policy Mode

Add:

```text
PII in prompts
consent bypasses
retention issues
deletion issues
data minimization
model safety/policy exposure
```

---

# 23. Human Review Workflow

Set `needs_human_review: true` when:

1. severity is high but confidence is medium,
2. policy context is missing,
3. vendor approval is unclear,
4. code changes consent/deletion/retention logic,
5. LLM prompt includes user data but the use case may be approved,
6. suppression is questionable.

Possible reviewers:

```text
privacy engineer
security engineer
legal/compliance owner
data governance owner
```

---

# 24. Agent Security and Privacy

The agent itself must not become a privacy risk.

Requirements:

```text
least-privilege GitHub/GitLab token
no production data access
short log retention
secret masking in logs
no full secret values in prompts
encrypted storage
audit trail for findings and suppressions
restricted dashboard access
sandboxed repo checkout
network egress controls
```

Before LLM review:

1. detect secrets,
2. replace secrets with placeholders,
3. preserve enough context for review.

Example:

```text
sk_live_51H8... → <REDACTED_STRIPE_SECRET>
```

---

# 25. GitHub Actions Integration

Example workflow:

```yaml
name: Privacy Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  privacy-review:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repo
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run privacy review agent
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          docker run --rm \
            -e GITHUB_TOKEN \
            -e OPENAI_API_KEY \
            -v "$PWD:/repo" \
            privacy-review-agent:latest \
            review-pr --repo /repo
```

Later, consider a GitHub App for richer permissions, installation management, and central configuration.

---

# 26. CLI Commands

Add local commands:

```bash
privacy-agent scan --repo .
privacy-agent scan-pr --base main --head feature-branch
privacy-agent test-fixtures
privacy-agent explain-finding finding.json
privacy-agent generate-sarif findings.json > privacy-review.sarif
privacy-agent post-github-comment findings.json
```

---

# 27. Autofix Strategy

Start with suggested patches only.

Good suggested patches:

## Raw Logging

From:

```ts
logger.info(req.body);
```

To:

```ts
logger.info(redactRequestBody(req.body));
```

## Email in Analytics

From:

```ts
analytics.track("signup", { email: user.email });
```

To:

```ts
analytics.track("signup", { userId: hashUserId(user.id) });
```

## Raw Prompt

From:

```ts
const prompt = `Summarize support request from ${user.email}: ${message}`;
```

To:

```ts
const prompt = `Summarize support request from user ${hashUserId(user.id)}: ${redactPII(message)}`;
```

Do not auto-apply fixes until developers trust the agent.

---

# 28. LLM-App-Specific Policy Review

Add special rules for model-related code.

Look for:

```text
system prompts
developer prompts
user prompts
tool outputs
retrieval snippets
conversation history
file uploads
support tickets
customer records
medical/legal/financial content
moderation bypasses
```

Risk patterns:

```text
Prompt includes raw PII
Prompt asks model to infer sensitive attributes
Prompt includes credentials or internal policy
Prompt disables safety filters
Tool sends private data to external endpoint
RAG retrieves documents without access control
Model output is used for high-impact decisions without human review
```

Example policy rules:

```yaml
- id: no-sensitive-attribute-inference
  category: POLICY_BYPASS
  severity: high
  description: Do not infer or classify sensitive attributes unless explicitly approved.

- id: no-raw-customer-records-in-prompt
  category: PII_IN_MODEL_PROMPT
  severity: high
  description: Do not place raw customer records into model prompts without minimization and approval.

- id: rag-requires-access-control
  category: POLICY_BYPASS
  severity: high
  description: Retrieved documents must be filtered by user authorization before being sent to a model.
```

---

# 29. Operational Ownership

Assign owners for:

```text
agent engineering
privacy policy
security policy
vendor allowlist
suppression approvals
incident handling
developer support
```

Without ownership, the agent will become stale.

## Suggested SLAs

```text
Critical finding: reviewed within 4 business hours
High finding: reviewed within 1 business day
Medium finding: reviewed within 3 business days
Suppression request: reviewed within 2 business days
```

---

# 30. Recommended Build Order

## Week 1: Foundations

1. Create risk taxonomy.
2. Write policy YAML.
3. Create finding JSON schema.
4. Build CLI skeleton.
5. Add diff parser.
6. Add Gitleaks integration.
7. Normalize Gitleaks findings.

Deliverable:

```text
CLI can scan repo and report secrets in standard JSON.
```

## Week 2: Static Privacy Rules

1. Add Semgrep integration.
2. Write first 5 Semgrep rules:
   - raw request body logging
   - raw headers logging
   - raw cookies logging
   - raw user object in prompt
   - email/phone sent to analytics
3. Add SARIF output.
4. Add test fixtures.

Deliverable:

```text
Agent can find obvious logging and PII transfer issues.
```

## Week 3: LLM Review

1. Add context retriever.
2. Add LLM structured output.
3. Add deduplication.
4. Add severity/confidence ranking.
5. Add PR summary generation.

Deliverable:

```text
Agent can reason over suspicious diffs and produce structured findings.
```

## Week 4: GitHub Integration

1. Add GitHub Actions workflow.
2. Add PR summary comment.
3. Add inline comments.
4. Upload SARIF.
5. Run in silent mode on selected repos.

Deliverable:

```text
Agent runs on PRs but does not block.
```

## Week 5: Tuning

1. Review false positives.
2. Tune Semgrep rules.
3. Add suppressions.
4. Add vendor registry.
5. Add redaction helper registry.
6. Add dashboard or simple report.

Deliverable:

```text
Agent is accurate enough for comment-only production use.
```

## Week 6: Limited Blocking

1. Enable blocking for confirmed secrets.
2. Enable blocking for raw request/header/cookie logging.
3. Enable blocking for high-confidence PII to unapproved vendors.
4. Add human override workflow.
5. Document developer guidance.

Deliverable:

```text
Agent becomes a controlled merge gate.
```

---

# 31. Production Checklist

```text
[ ] Written policy rulebook
[ ] Finding schema
[ ] Severity/confidence model
[ ] Gitleaks integration
[ ] Semgrep integration
[ ] Custom Semgrep rules
[ ] Regex/keyword signal detector
[ ] Context retriever
[ ] LLM structured reviewer
[ ] Secret redaction before LLM calls
[ ] Deduplication
[ ] PR comments
[ ] SARIF output
[ ] Suppression handling
[ ] Vendor registry
[ ] Redaction helper registry
[ ] Test fixtures
[ ] False-positive review process
[ ] Human escalation process
[ ] Audit logs
[ ] Least-privilege GitHub/GitLab permissions
[ ] Rollout plan
[ ] Developer documentation
```

---

# 32. What the MVP Should Block

Only block these at first:

```text
1. Hardcoded secrets
2. Raw request body logging
3. Raw headers/cookies logging
4. Raw access token or authorization logging
5. High-confidence PII sent to unapproved third party
6. Raw PII included in LLM prompts without redaction
```

Everything else should be advisory until enough accuracy data exists.

---

# 33. Expected Mature Behavior

A mature version of the agent should produce findings like this:

```text
This PR introduces a new analytics event that sends user.email to Segment.
The vendor registry allows user_id and event_name for Segment, but not email.
The code does not call a redaction, hashing, or tokenization helper.
This is a high-severity, high-confidence privacy finding.
Recommended fix: replace email with hashUserId(user.id), or request explicit vendor approval.
```

That level of specificity is the goal.

---

# 34. Codex Implementation Prompt

Use the following prompt when attaching this plan to Codex:

```text
You are implementing an autonomous code review agent for PII, sensitive data, secrets, unsafe logging, third-party data sharing, LLM prompt privacy risk, and policy exposure.

Use the attached Markdown plan as the implementation specification.

Start by building the MVP in this order:
1. Repository skeleton
2. Policy YAML loader
3. Finding schema
4. Diff parser
5. Gitleaks scanner integration
6. Semgrep scanner integration
7. Normalizer and deduper
8. SARIF output
9. Test fixtures
10. CLI command: privacy-agent scan --repo .

Do not build the LLM reviewer first. The first milestone is a deterministic scanner pipeline that emits normalized JSON findings and SARIF.

Prioritize correctness, testability, and low false positives for blocking findings.
```
