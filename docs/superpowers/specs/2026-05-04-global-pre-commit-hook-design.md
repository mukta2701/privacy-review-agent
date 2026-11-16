# Design: Global Pre-commit Hook for Privacy Review Agent

**Date:** 2026-05-04  
**Author:** Mukta Choudhury  
**Status:** Approved

---

## Goal

Make `privacy-review-agent` run automatically before every `git commit` on Mukta's Mac — across all repos, existing and future — without any per-project setup.

## Scope

- Personal use only (single machine, single user)
- Applies to all repos via global git hooks directory
- Blocks commits with CRITICAL/HIGH severity findings
- Warns (but allows) commits with MEDIUM/LOW severity findings
- Not org-ready yet — no GitHub App, no API, no multi-user support

---

## Architecture

```
git commit
    │
    ▼
~/.git-hooks/pre-commit        ← shell script (to be created)
    │
    │  git diff --cached --name-only --diff-filter=ACM
    │  (get staged code files only)
    │
    ▼
privacy-review-agent scan      ← existing Python CLI
    │
    ├── exit 2 (CRITICAL/HIGH) → commit BLOCKED
    ├── exit 0 + warnings      → commit ALLOWED, MEDIUM/LOW printed
    └── exit 0 clean           → commit ALLOWED, silent
    
~/.gitconfig
    core.hooksPath = ~/.git-hooks   ← one global setting (to be added)
```

**Key insight:** `core.hooksPath` is a native git setting. When set globally, git uses that directory for hooks in every repo on the machine — no per-project `.git/hooks/` setup needed.

---

## The Hook Script (`~/.git-hooks/pre-commit`)

```bash
#!/bin/bash

# Get staged files (Added, Copied, Modified — not Deleted)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

# Filter to code files only (skip images, binaries, lock files, etc.)
CODE_FILES=$(echo "$STAGED_FILES" | grep -E '\.(py|js|ts|tsx|jsx|yaml|yml|json|rb|go|java|env)$' || true)

if [ -z "$CODE_FILES" ]; then
    exit 0
fi

BLOCK=0

for file in $CODE_FILES; do
    if [ -f "$file" ]; then
        privacy-review-agent scan --path "$file" --format md
        if [ $? -eq 2 ]; then
            BLOCK=1
        fi
    fi
done

if [ $BLOCK -eq 1 ]; then
    echo ""
    echo "Commit blocked: fix the critical/high risks above."
    echo "To suppress a false positive: add an entry to .privacy-review-ignore.yaml"
    echo "To skip this check for an emergency: git commit --no-verify"
    exit 1
fi

exit 0
```

### Blocking logic

| Finding severity | Confidence | Outcome |
|---|---|---|
| CRITICAL or HIGH | HIGH | Commit blocked (exit 1) |
| MEDIUM or LOW | any | Warning printed, commit allowed |
| None | — | Silent, commit allowed |

This matches the existing agent blocking policy in `engine.py._is_blocking()` — no changes needed to the Python code.

---

## Installation Steps (One-Time)

```bash
# 1. Install the agent globally
cd /path/to/shiny-invention
pip install -e .

# 2. Create the global hooks directory
mkdir -p ~/.git-hooks

# 3. Write the pre-commit script (content from above)
# (implementation plan will handle this with a write command)

# 4. Make it executable (required — git won't run it otherwise)
chmod +x ~/.git-hooks/pre-commit

# 5. Register it globally with git
git config --global core.hooksPath ~/.git-hooks
```

---

## Behavior Reference

**Normal commit (clean code):**
```
$ git commit -m "add feature"
[main abc1234] add feature
```
Nothing printed. Fast.

**Commit with MEDIUM/LOW warning:**
```
$ git commit -m "add feature"
## Privacy Review: 1 finding(s)
- [MEDIUM] PII in log statement — user.email in logger.info (line 42)
[main abc1234] add feature
```
Warning visible, commit goes through.

**Commit with CRITICAL/HIGH block:**
```
$ git commit -m "add feature"
## Privacy Review: 1 finding(s)
- [CRITICAL] Secret exposed — STRIPE_SECRET_KEY hardcoded (line 10)

Commit blocked: fix the critical/high risks above.
To suppress a false positive: add an entry to .privacy-review-ignore.yaml
To skip this check for an emergency: git commit --no-verify
```
Commit rejected.

**Emergency bypass:**
```bash
git commit --no-verify -m "emergency fix"
```

---

## False Positive Handling

If the agent flags something that is not actually a risk, add a suppression entry to `.privacy-review-ignore.yaml` in the repo root:

```yaml
entries:
  - id: <fingerprint from JSON output>
    reason: "This is a test fixture, not real PII"
    privacy_approver: Mukta
    created_on: 2026-05-04
    expires_on: 2026-11-04
```

The finding will be ignored on future scans of that repo.

---

## What This Does NOT Cover (Future Phases)

- GitHub PR-level scanning (requires GitHub Actions setup)
- LLM semantic review (planned, not built)
- Org-wide rollout (requires `pre-commit` framework or GitHub App)
- Dashboard / metrics tracking
- Autofix suggestions applied automatically

---

## Files Changed

| File | Change |
|---|---|
| `~/.git-hooks/pre-commit` | New — the hook script |
| `~/.gitconfig` | Modified — add `core.hooksPath` |
| `shiny-invention/` source | No changes needed |
