# Autonomous PII & Sensitive Data Review Agent Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a production-grade autonomous code review agent that detects secrets, PII exposure, unsafe third-party transfer, prompt privacy leakage, missing redaction, and policy bypasses in pull requests.

**Architecture:** Use a hybrid pipeline: deterministic scanners for high-confidence findings plus policy-aware semantic analysis for context-sensitive risks. Operate offline-first by default (no code leaves runner), with optional LLM analysis behind explicit opt-in. Normalize everything into a single finding schema, then enforce org policy with merge gates, suppressions, and audit trails. Run locally (CLI), in GitHub Actions CI, and optionally as a PR bot.

**Tech Stack:** Python 3.12, Ruff, Pytest, Semgrep rules, Gitleaks, detect-secrets entropy checks, optional LLM provider adapter (opt-in only), GitHub Actions, SARIF output.

---

## Scope Lock (MVP)

The MVP must detect and report these categories:

1. Secrets in code.
2. Raw PII logging.
3. Unsafe third-party transfer.
4. PII in LLM prompts.
5. Missing redaction or masking.
6. Dangerous policy bypasses.

Out of scope for MVP: runtime traffic inspection, DLP across data warehouses, enterprise SIEM connectors.

## Baseline Quality Bar

1. Precision target: >= 0.85 on curated fixtures.
2. Recall target: >= 0.80 on curated fixtures.
3. P95 runtime: <= 120 seconds for 1k changed files.
4. Deterministic output for same commit + config.
5. Every finding has file path, line, category, severity, confidence, evidence, remediation.

## Interview Decisions (Locked on 2026-05-04)

1. Compliance basis: GDPR, CCPA/CPRA, HIPAA, SOC 2, PCI DSS, and internal policy docs.
2. Default transfer policy: block any external destination unless explicitly allowlisted.
3. Secrets in PR diffs: confirmed secrets are immediate hard block.
4. Prompt privacy: block direct identifiers and quasi-identifiers unless redacted/approved.
5. SCM scope for MVP: GitHub only.
6. Language strategy: language-agnostic baseline, first-class TypeScript/JavaScript and Python in phase 1.
7. Runtime mode: offline-first by default; LLM semantic analysis opt-in.
8. Suppression governance: dual approval (Privacy + Security), max 14-day expiry, no auto-renew, GitHub Issue required.
9. Notification channel: GitHub PR comments only.
10. Merge gates: block only `critical/high` findings with `high` confidence.
11. Blocking scope: changed PR lines only; baseline snapshot findings are non-blocking context.
12. Baseline mode: required; enforce only new regressions after snapshot.
13. Secret validation: verify secret validity when possible for supported key types.
14. Pass control: require manual rerun approval before check can pass after blocking findings are fixed.
15. Rerun approval mechanism: label-based approval in GitHub.
16. Rerun authorization default until team slug provided: fail-closed.
17. Rollout strategy: one pilot repository first, then org-wide expansion.
18. Runner choice for MVP: GitHub-hosted runners.

## Repository Layout (Target)

```text
privacy-review-agent/
  pyproject.toml
  README.md
  .pre-commit-config.yaml
  src/privacy_review_agent/
    __init__.py
    cli.py
    config.py
    models.py
    engine.py
    git_diff.py
    reporters/
      json_reporter.py
      sarif_reporter.py
      markdown_reporter.py
    detectors/
      base.py
      secrets.py
      pii_logging.py
      third_party_transfer.py
      pii_in_prompts.py
      missing_redaction.py
      policy_bypass.py
    policies/
      taxonomy.yaml
      vendor_allowlist.yaml
      sensitive_fields.yaml
      redaction_rules.yaml
      bypass_rules.yaml
      prompt_rules.yaml
  rules/
    semgrep/
      pii_logging.yml
      third_party_transfer.yml
      pii_in_prompts.yml
      missing_redaction.yml
      policy_bypass.yml
  tests/
    unit/
    integration/
    fixtures/
      safe/
      unsafe/
```

---

### Task 1: Bootstrap Project and Guardrails

**Files:**
- Create: `pyproject.toml`
- Create: `.pre-commit-config.yaml`
- Create: `src/privacy_review_agent/__init__.py`
- Create: `tests/unit/test_smoke.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_smoke.py
from privacy_review_agent import __version__

def test_package_loads():
    assert __version__
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_smoke.py -v`
Expected: FAIL with import/module error.

**Step 3: Write minimal implementation**

```python
# src/privacy_review_agent/__init__.py
__version__ = "0.1.0"
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_smoke.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add pyproject.toml .pre-commit-config.yaml src/privacy_review_agent/__init__.py tests/unit/test_smoke.py
git commit -m "chore: bootstrap project skeleton and quality tooling"
```

### Task 2: Define Canonical Finding Model

**Files:**
- Create: `src/privacy_review_agent/models.py`
- Create: `tests/unit/test_models.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.models import Finding, Severity, Confidence

def test_finding_serializes():
    finding = Finding(
        detector="secrets",
        category="SECRET_EXPOSURE",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line=10,
        message="Hardcoded API key",
        evidence="sk_live_...",
        remediation="Move to secret manager and rotate key",
    )
    assert finding.to_dict()["category"] == "SECRET_EXPOSURE"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_models.py -v`
Expected: FAIL (missing model types).

**Step 3: Write minimal implementation**

```python
from dataclasses import dataclass
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class Finding:
    detector: str
    category: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line: int
    message: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_models.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/privacy_review_agent/models.py tests/unit/test_models.py
git commit -m "feat: add canonical finding schema"
```

### Task 3: Add Policy Packs (Taxonomy + Sensitive Fields + Vendors)

**Files:**
- Create: `src/privacy_review_agent/policies/taxonomy.yaml`
- Create: `src/privacy_review_agent/policies/sensitive_fields.yaml`
- Create: `src/privacy_review_agent/policies/vendor_allowlist.yaml`
- Create: `tests/unit/test_policy_files.py`

**Step 1: Write the failing test**

```python
import yaml
from pathlib import Path


def test_taxonomy_contains_required_categories():
    tax = yaml.safe_load(Path("src/privacy_review_agent/policies/taxonomy.yaml").read_text())
    ids = {x["id"] for x in tax["categories"]}
    assert "SECRET_EXPOSURE" in ids
    assert "PII_IN_MODEL_PROMPT" in ids
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_policy_files.py -v`
Expected: FAIL (missing files).

**Step 3: Write minimal implementation**

```yaml
# taxonomy.yaml
categories:
  - id: SECRET_EXPOSURE
  - id: RAW_PII_LOGGING
  - id: THIRD_PARTY_PII_TRANSFER
  - id: PII_IN_MODEL_PROMPT
  - id: INSUFFICIENT_REDACTION
  - id: POLICY_BYPASS
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_policy_files.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/privacy_review_agent/policies tests/unit/test_policy_files.py
git commit -m "feat: add core policy packs"
```

### Task 4: Implement Secrets Detector (Gitleaks + Regex Fallback)

**Files:**
- Create: `src/privacy_review_agent/detectors/secrets.py`
- Create: `tests/unit/test_secrets_detector.py`
- Create: `tests/fixtures/unsafe/hardcoded_keys.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.detectors.secrets import SecretsDetector


def test_detects_hardcoded_api_key(tmp_path):
    p = tmp_path / "a.py"
    p.write_text('API_KEY = "sk_test_12345678901234567890"')
    findings = SecretsDetector().scan_files([p])
    assert any(f.category == "SECRET_EXPOSURE" for f in findings)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_secrets_detector.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# secrets.py
# 1) Try gitleaks JSON output when binary exists.
# 2) Fallback to curated regex set for common key formats.
# 3) Add validity-verification hooks for supported secret types (off by default unless verifier is configured).
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_secrets_detector.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/privacy_review_agent/detectors/secrets.py tests/unit/test_secrets_detector.py tests/fixtures/unsafe/hardcoded_keys.py
git commit -m "feat: implement secrets detector"
```

### Task 5: Implement Raw PII Logging Detector (Semgrep Rules)

**Files:**
- Create: `rules/semgrep/pii_logging.yml`
- Create: `src/privacy_review_agent/detectors/pii_logging.py`
- Create: `tests/unit/test_pii_logging_detector.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.detectors.pii_logging import PiiLoggingDetector


def test_flags_raw_request_logging(tmp_path):
    p = tmp_path / "handler.js"
    p.write_text("console.log(req.body)")
    findings = PiiLoggingDetector().scan_files([p])
    assert any(f.category == "RAW_PII_LOGGING" for f in findings)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_pii_logging_detector.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```yaml
# semgrep rule pattern examples
patterns:
  - pattern: console.log(req.body)
  - pattern: logger.info($USER)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_pii_logging_detector.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add rules/semgrep/pii_logging.yml src/privacy_review_agent/detectors/pii_logging.py tests/unit/test_pii_logging_detector.py
git commit -m "feat: add raw pii logging detection"
```

### Task 6: Implement Unsafe Third-Party Transfer Detector

**Files:**
- Create: `rules/semgrep/third_party_transfer.yml`
- Create: `src/privacy_review_agent/detectors/third_party_transfer.py`
- Create: `tests/unit/test_third_party_transfer_detector.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.detectors.third_party_transfer import ThirdPartyTransferDetector


def test_flags_external_post_with_email(tmp_path):
    p = tmp_path / "send.py"
    p.write_text('requests.post("https://analytics.example.com", json={"email": user.email})')
    findings = ThirdPartyTransferDetector().scan_files([p])
    assert any(f.category == "THIRD_PARTY_PII_TRANSFER" for f in findings)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_third_party_transfer_detector.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# Detector logic
# - Identify network sink calls.
# - Detect sensitive field keys/variables.
# - Compare destination against vendor allowlist.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_third_party_transfer_detector.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add rules/semgrep/third_party_transfer.yml src/privacy_review_agent/detectors/third_party_transfer.py tests/unit/test_third_party_transfer_detector.py
git commit -m "feat: add third-party transfer risk detector"
```

### Task 7: Implement PII-in-Prompt Detector

**Files:**
- Create: `rules/semgrep/pii_in_prompts.yml`
- Create: `src/privacy_review_agent/detectors/pii_in_prompts.py`
- Create: `tests/unit/test_pii_in_prompts_detector.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.detectors.pii_in_prompts import PiiInPromptsDetector


def test_flags_raw_pii_in_prompt(tmp_path):
    p = tmp_path / "llm.py"
    p.write_text('prompt = f"Summarize {user.email} {user.phone}"')
    findings = PiiInPromptsDetector().scan_files([p])
    assert any(f.category == "PII_IN_MODEL_PROMPT" for f in findings)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_pii_in_prompts_detector.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# Detector logic
# - Find prompt construction sinks for common SDKs.
# - Inspect interpolated fields for sensitive keys.
# - Include quasi-identifiers (free-form user messages, chat transcripts, support text) in risk checks.
# - Downgrade severity when approved redaction helper is present.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_pii_in_prompts_detector.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add rules/semgrep/pii_in_prompts.yml src/privacy_review_agent/detectors/pii_in_prompts.py tests/unit/test_pii_in_prompts_detector.py
git commit -m "feat: add pii-in-prompt detection"
```

### Task 8: Implement Missing Redaction Detector

**Files:**
- Create: `rules/semgrep/missing_redaction.yml`
- Create: `src/privacy_review_agent/detectors/missing_redaction.py`
- Create: `tests/unit/test_missing_redaction_detector.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.detectors.missing_redaction import MissingRedactionDetector


def test_flags_logging_without_redaction(tmp_path):
    p = tmp_path / "log.ts"
    p.write_text("logger.info({email: user.email, token: authToken})")
    findings = MissingRedactionDetector().scan_files([p])
    assert any(f.category == "INSUFFICIENT_REDACTION" for f in findings)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_missing_redaction_detector.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# Detector logic
# - Recognize log/telemetry/event sinks.
# - Match sensitive keys in payload shape.
# - Skip when value is wrapped by redact/hash/tokenize helpers.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_missing_redaction_detector.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add rules/semgrep/missing_redaction.yml src/privacy_review_agent/detectors/missing_redaction.py tests/unit/test_missing_redaction_detector.py
git commit -m "feat: add missing redaction detector"
```

### Task 9: Implement Policy Bypass Detector

**Files:**
- Create: `rules/semgrep/policy_bypass.yml`
- Create: `src/privacy_review_agent/detectors/policy_bypass.py`
- Create: `tests/unit/test_policy_bypass_detector.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.detectors.policy_bypass import PolicyBypassDetector


def test_flags_disabled_consent_check(tmp_path):
    p = tmp_path / "privacy.ts"
    p.write_text("if (true) { return sendToVendor(data); } // consent bypass")
    findings = PolicyBypassDetector().scan_files([p])
    assert any(f.category == "POLICY_BYPASS" for f in findings)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_policy_bypass_detector.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# Detector logic
# - Detect hardcoded bypass booleans and bypass flags.
# - Detect suppression of privacy/redaction checks.
# - Mark confidence medium when semantic proof is partial.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_policy_bypass_detector.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add rules/semgrep/policy_bypass.yml src/privacy_review_agent/detectors/policy_bypass.py tests/unit/test_policy_bypass_detector.py
git commit -m "feat: add dangerous policy bypass detector"
```

### Task 10: Build Orchestration Engine + Changed-File Diff Mode

**Files:**
- Create: `src/privacy_review_agent/engine.py`
- Create: `src/privacy_review_agent/git_diff.py`
- Create: `tests/integration/test_engine_diff_scan.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.engine import ReviewEngine


def test_engine_scans_only_changed_files(fake_repo):
    engine = ReviewEngine()
    result = engine.scan_ref(base_ref="origin/main", head_ref="HEAD")
    assert result.meta["scanned_file_count"] >= 1
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_engine_diff_scan.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# engine.py
# - Load enabled detectors from config.
# - Collect changed files via git diff.
# - Aggregate and de-duplicate findings.
# - Enforce blocking only for findings mapped to changed PR lines.
# - Optionally include baseline snapshot findings as non-blocking context in report output.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_engine_diff_scan.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/privacy_review_agent/engine.py src/privacy_review_agent/git_diff.py tests/integration/test_engine_diff_scan.py
git commit -m "feat: add orchestrator and diff-based scanning"
```

### Task 11: Add CLI + Exit Code Policy Gates

**Files:**
- Create: `src/privacy_review_agent/cli.py`
- Create: `src/privacy_review_agent/config.py`
- Create: `tests/integration/test_cli_exit_codes.py`

**Step 1: Write the failing test**

```python
from click.testing import CliRunner
from privacy_review_agent.cli import main


def test_cli_blocks_on_critical_high_confidence():
    r = CliRunner().invoke(main, ["scan", "--path", "tests/fixtures/unsafe"])
    assert r.exit_code == 2
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_cli_exit_codes.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# Exit codes
# 0 = no blocking findings
# 1 = runtime/config error
# 2 = policy gate blocked merge
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_cli_exit_codes.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/privacy_review_agent/cli.py src/privacy_review_agent/config.py tests/integration/test_cli_exit_codes.py
git commit -m "feat: add cli and policy gate exit codes"
```

### Task 12: Add JSON, SARIF, and Markdown Reporters

**Files:**
- Create: `src/privacy_review_agent/reporters/json_reporter.py`
- Create: `src/privacy_review_agent/reporters/sarif_reporter.py`
- Create: `src/privacy_review_agent/reporters/markdown_reporter.py`
- Create: `tests/unit/test_reporters.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.reporters.sarif_reporter import to_sarif


def test_sarif_contains_rule_id(sample_finding):
    sarif = to_sarif([sample_finding])
    assert "SECRET_EXPOSURE" in sarif
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_reporters.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# Reporters must include
# - category as rule id
# - severity/confidence metadata
# - file and line location
# - remediation guidance
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_reporters.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/privacy_review_agent/reporters tests/unit/test_reporters.py
git commit -m "feat: add json sarif markdown reporters"
```

### Task 13: Build Suppression and Approval Workflow

**Files:**
- Create: `.privacy-review-ignore.yaml`
- Create: `src/privacy_review_agent/suppressions.py`
- Create: `tests/unit/test_suppressions.py`

**Step 1: Write the failing test**

```python
from privacy_review_agent.suppressions import is_suppressed


def test_finding_suppressed_with_expiry():
    assert is_suppressed(
        finding_id="abc123",
        suppression={
            "id": "abc123",
            "expires_on": "2099-01-01",
            "privacy_approver": "privacy.lead",
            "security_approver": "security.lead",
            "ticket": "https://github.com/org/repo/issues/123",
        },
    )
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_suppressions.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# suppression requirements
# - reason
# - privacy_approver
# - security_approver
# - expires_on
# - ticket reference (GitHub Issue URL)
# - max_ttl_days = 14
# - reject auto-renew and expired suppressions
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_suppressions.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add .privacy-review-ignore.yaml src/privacy_review_agent/suppressions.py tests/unit/test_suppressions.py
git commit -m "feat: add governed suppression workflow"
```

### Task 14: CI Integration for Daily Org Workflow

**Files:**
- Create: `.github/workflows/privacy-review.yml`
- Create: `tests/integration/test_ci_contract.py`
- Modify: `README.md`

**Step 1: Write the failing test**

```python
from pathlib import Path


def test_ci_workflow_exists():
    assert Path('.github/workflows/privacy-review.yml').exists()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_ci_contract.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```yaml
name: privacy-review
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest  # GitHub-hosted runner for MVP
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -e .
      - run: privacy-review-agent scan --base-ref origin/main --head-ref HEAD --format sarif --output results.sarif
      - run: privacy-review-agent enforce-rerun-approval --required-label privacy-rerun-approved
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_ci_contract.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add .github/workflows/privacy-review.yml tests/integration/test_ci_contract.py README.md
git commit -m "feat: add ci workflow for autonomous privacy review"
```

### Task 15: Calibration Pack + Release Criteria

**Files:**
- Create: `tests/fixtures/unsafe/*.py`
- Create: `tests/fixtures/safe/*.py`
- Create: `docs/operations/calibration.md`
- Create: `docs/operations/runbook.md`

**Step 1: Write the failing test**

```python
from privacy_review_agent.engine import ReviewEngine


def test_precision_and_recall_targets(calibration_suite):
    m = ReviewEngine().run_calibration(calibration_suite)
    assert m["precision"] >= 0.85
    assert m["recall"] >= 0.80
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_calibration.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# Calibration runner
# - Execute detector suite against labeled fixtures.
# - Produce confusion matrix per category.
# - Fail release if quality bar misses target.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_calibration.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/fixtures docs/operations/calibration.md docs/operations/runbook.md tests/integration/test_calibration.py
git commit -m "feat: add calibration harness and operations runbook"
```

---

## Daily Operations Model

1. Developers run local pre-commit checks for fast feedback.
2. CI performs full diff-based scan on every pull request.
3. Blocking findings stop merge automatically.
4. Blocking decisions apply only to changed PR lines; baseline findings are context-only.
5. Security + Privacy dual approvers handle suppressions with <=14-day TTL and GitHub Issue trace.
6. Security team provides manual rerun approval label before previously blocked checks can pass.
7. Weekly calibration run updates precision/recall dashboard.

## Governance Rules (Must Enforce)

1. No permanent suppressions.
2. Every suppression must include privacy approver + security approver + expiry + GitHub Issue.
3. Critical/high findings require explicit reviewer resolution.
4. Vendor allowlist changes require privacy-team approval.
5. Prompt-safety rules cannot be disabled outside admin-controlled config.
6. External destinations are blocked by default unless in explicit allowlist.
7. Rerun approval is label-gated and fail-closed until authorized team slug is configured.

## Implementation Sequence

1. Execute Tasks 1-5 (foundation + core detection).
2. Execute Tasks 6-9 (contextual privacy risks).
3. Execute Tasks 10-12 (orchestration + outputs).
4. Execute Tasks 13-15 (governance + CI + quality calibration).

## Required Skills During Execution

1. `@superpowers:executing-plans` for task-by-task execution.
2. `@superpowers:test-driven-development` before each detector implementation.
3. `@superpowers:systematic-debugging` on any failing or flaky test.
4. `@superpowers:verification-before-completion` before claiming done.
5. `@superpowers:requesting-code-review` before merge.

## Risks and Mitigations

1. High false positives in semantic detectors.
Mitigation: stronger fixture corpus + confidence scoring + governed suppressions.

2. Toolchain drift across languages/frameworks.
Mitigation: keep semgrep rulepacks versioned and language-scoped.

3. Performance regression on large PRs.
Mitigation: diff-only scans + parallel detector execution + caching.

4. Policy ambiguity between teams.
Mitigation: machine-readable policy packs + documented gate matrix.

5. Delay in providing GitHub team slug/pilot repository/retention settings.
Mitigation: treat these as launch-blocking inputs and fail closed until supplied.

## Pending Launch Inputs (Required Before Go-Live)

1. Authorized GitHub team slug for rerun label application (format `org/team-slug`).
2. Pilot repository path (format `org/repo`).
3. Scan artifact retention policy (choose `30`, `90`, or `365` days).

---

## Definition of Done

1. All 6 risk categories detected and reported with evidence.
2. Merge gate enforces blocking only for `critical/high` with `high` confidence on changed PR lines.
3. CI workflow operational on pull requests.
4. Calibration suite meets precision/recall targets.
5. Runbook documents setup, triage, suppression, and escalation.
