# Global Pre-commit Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `privacy-review-agent` as a global git pre-commit hook on Mukta's Mac so every `git commit` on any repo automatically scans staged files — blocking CRITICAL/HIGH risks, warning on MEDIUM/LOW.

**Architecture:** A shell script at `~/.git-hooks/pre-commit` collects staged code files via `git diff --cached`, passes each to the existing `privacy-review-agent scan` CLI, and exits 1 (block) if any file returns exit code 2. Git is pointed at this directory globally via `core.hooksPath` in `~/.gitconfig`.

**Tech Stack:** Bash (hook script), Python/Click (existing CLI), Git global config

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `~/.git-hooks/pre-commit` | CREATE | The hook script git runs before every commit |
| `~/.gitconfig` | MODIFY | Add `core.hooksPath = ~/.git-hooks` |
| `/tmp/hook-test/test_hook.sh` | CREATE (temp) | Integration test script — deleted after testing |
| `shiny-invention/` source | NO CHANGES | Agent CLI already works as-is |

---

## Task 1: Verify the Agent Is Globally Accessible

**Why this matters:** The hook script calls `privacy-review-agent` by name. If it's not on your PATH, the hook silently does nothing — the worst possible failure mode. We verify first.

**Files:**
- No file changes — this is a verification step only

- [ ] **Step 1: Check if the agent is already installed**

```bash
which privacy-review-agent
```

Expected: a path like `/usr/local/bin/privacy-review-agent` or `~/Library/Python/3.x/bin/privacy-review-agent`

If you see `privacy-review-agent not found`, proceed to Step 2. If you see a path, skip to Step 3.

- [ ] **Step 2: Install the agent (only if Step 1 failed)**

```bash
cd /path/to/privacy-review-agent
pip install -e .
```

Expected output includes: `Successfully installed privacy-review-agent-0.1.0`

- [ ] **Step 3: Verify it works from your home directory**

```bash
cd ~
privacy-review-agent --version
```

Expected: `privacy-review-agent, version 0.1.0`

If this fails, your pip bin directory is not on your PATH. Fix by adding this to your `~/.zshrc`:
```bash
export PATH="$HOME/Library/Python/3.11/bin:$PATH"
```
Then run `source ~/.zshrc` and retry Step 3.

---

## Task 2: Write the Integration Test (Before the Hook Exists)

**Why TDD here:** We write a test that expects the hook to block a bad commit. Right now it will fail (because the hook doesn't exist yet). After Task 3, it will pass. This proves the hook is actually doing something.

**Files:**
- Create: `/tmp/hook-test/test_hook.sh`

- [ ] **Step 1: Create a temp test directory and init a git repo**

```bash
mkdir -p /tmp/hook-test
cd /tmp/hook-test
git init
git config user.email "mukta@test.local"
git config user.name "Mukta Test"
```

Expected: `Initialized empty Git repository in /tmp/hook-test/.git/`

- [ ] **Step 2: Point this temp repo at the (not-yet-created) global hooks directory**

```bash
cd /tmp/hook-test
git config core.hooksPath ~/.git-hooks
```

No output expected. This tells the test repo to use the global hooks folder — even before we set it globally.

- [ ] **Step 3: Write the test script**

```bash
cat > /tmp/hook-test/test_hook.sh << 'EOF'
#!/bin/bash
set -e

cd /tmp/hook-test
echo "=== TEST 1: Bad file should be BLOCKED ==="

# Write a file with a hardcoded secret (triggers CRITICAL finding)
cat > bad_file.py << 'PYEOF'
import requests
STRIPE_SECRET_KEY = "STRIPE_KEY_PLACEHOLDER"
response = requests.get("https://api.stripe.com", headers={"Authorization": STRIPE_SECRET_KEY})
PYEOF

git add bad_file.py
git commit -m "should be blocked" 2>&1
EXIT=$?

if [ $EXIT -ne 0 ]; then
    echo "PASS: commit was correctly blocked (exit $EXIT)"
else
    echo "FAIL: commit was NOT blocked (exit $EXIT) — hook may not be installed"
    exit 1
fi

# Clean up staging
git reset HEAD bad_file.py 2>/dev/null || true
rm -f bad_file.py

echo ""
echo "=== TEST 2: Clean file should be ALLOWED ==="

cat > clean_file.py << 'PYEOF'
def greet(name: str) -> str:
    return f"Hello, {name}!"
PYEOF

git add clean_file.py
git commit -m "clean commit should pass" 2>&1
EXIT=$?

if [ $EXIT -eq 0 ]; then
    echo "PASS: clean commit was correctly allowed (exit $EXIT)"
else
    echo "FAIL: clean commit was wrongly blocked (exit $EXIT)"
    exit 1
fi

echo ""
echo "All tests passed!"
EOF
chmod +x /tmp/hook-test/test_hook.sh
```

No output expected.

- [ ] **Step 4: Run the test — expect it to FAIL right now**

```bash
cd /tmp/hook-test
bash test_hook.sh
```

Expected: `FAIL: commit was NOT blocked` — because the hook script doesn't exist yet. This is correct. The test is working as a red test.

---

## Task 3: Create the Hooks Directory and Write the Hook Script

**Files:**
- Create: `~/.git-hooks/pre-commit`

- [ ] **Step 1: Create the global hooks directory**

```bash
mkdir -p ~/.git-hooks
```

No output expected.

- [ ] **Step 2: Write the hook script**

```bash
cat > ~/.git-hooks/pre-commit << 'EOF'
#!/bin/bash
# Privacy review hook — runs privacy-review-agent on staged code files.
# Blocks commits with CRITICAL/HIGH findings. Warns on MEDIUM/LOW.

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

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
EOF
```

No output expected.

- [ ] **Step 3: Make it executable**

```bash
chmod +x ~/.git-hooks/pre-commit
```

No output expected. This step is required — git silently ignores hook scripts that aren't executable.

- [ ] **Step 4: Verify the file looks right**

```bash
cat ~/.git-hooks/pre-commit
```

Expected: the full script content from Step 2.

```bash
ls -la ~/.git-hooks/pre-commit
```

Expected: permissions start with `-rwxr-xr-x` (the `x` bits confirm it's executable).

---

## Task 4: Configure Git Globally

**Files:**
- Modify: `~/.gitconfig`

- [ ] **Step 1: Set the global hooks path**

```bash
git config --global core.hooksPath ~/.git-hooks
```

No output expected.

- [ ] **Step 2: Verify the setting was saved**

```bash
git config --global core.hooksPath
```

Expected: `~/.git-hooks`

- [ ] **Step 3: Check ~/.gitconfig directly to confirm**

```bash
grep -A1 "\[core\]" ~/.gitconfig
```

Expected to see something like:
```
[core]
    hooksPath = ~/.git-hooks
```

---

## Task 5: Run the Integration Tests — Expect Them to Pass

**Files:**
- No file changes — verification only

- [ ] **Step 1: Re-run the test script**

```bash
cd /tmp/hook-test
bash test_hook.sh
```

Expected output:
```
=== TEST 1: Bad file should be BLOCKED ===
## Privacy Review ...
[CRITICAL] ...

Commit blocked: fix the critical/high risks above.
...
PASS: commit was correctly blocked (exit 1)

=== TEST 2: Clean file should be ALLOWED ===
[main abc1234] clean commit should pass
PASS: clean commit was correctly allowed (exit 0)

All tests passed!
```

If TEST 1 still shows FAIL (commit not blocked): confirm `privacy-review-agent` is on PATH (`which privacy-review-agent`) and that the hook is executable (`ls -la ~/.git-hooks/pre-commit`).

- [ ] **Step 2: Clean up the temp test directory**

```bash
rm -rf /tmp/hook-test
```

---

## Task 6: Smoke Test on shiny-invention Itself

**Why:** Confirms the hook works on a real repo with real git history, not just the temp throwaway repo.

**Files:**
- No changes — test only

- [ ] **Step 1: Navigate to the project**

```bash
cd /path/to/privacy-review-agent
```

- [ ] **Step 2: Stage a known-dangerous fixture and attempt commit**

```bash
git add tests/fixtures/unsafe/hardcoded_keys.py
git commit -m "test: should be blocked by hook"
```

Expected: commit is blocked with a privacy review error message about the hardcoded secret.

- [ ] **Step 3: Unstage the file**

```bash
git reset HEAD tests/fixtures/unsafe/hardcoded_keys.py
```

Expected: `Unstaged changes after reset: M tests/fixtures/unsafe/hardcoded_keys.py`

- [ ] **Step 4: Stage a clean file and commit for real**

```bash
git add docs/superpowers/plans/2026-05-04-global-pre-commit-hook.md
git commit -m "docs: add implementation plan for global pre-commit hook"
```

Expected: commit goes through cleanly (the plan document has no secrets or PII).

---

## Done — What You Now Have

After completing all tasks:

- Every `git commit` on your Mac (any repo, any project) automatically scans staged code files
- CRITICAL/HIGH risks block the commit with a clear message
- MEDIUM/LOW risks print a warning but let the commit through
- Clean commits are silent and fast
- You can bypass in emergencies with `git commit --no-verify`
- False positives can be suppressed via `.privacy-review-ignore.yaml` in any repo

## Future Upgrades (When Ready)

| Upgrade | What it adds |
|---|---|
| Connect Semgrep rules | Deeper pattern matching beyond regex |
| `pre-commit` framework | Share hook with teammates via `.pre-commit-config.yaml` |
| GitHub Actions workflow | Scan PRs on GitHub, not just local commits |
| LLM semantic review | Understand context, not just patterns |
