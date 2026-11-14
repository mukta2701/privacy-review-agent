# Runbook

## Daily Usage

1. Run scanner in PR CI.
2. Triage blocking findings first.
3. Use short-lived suppressions only when justified.

## Suppression Requirements

- privacy_approver and security_approver are required.
- GitHub issue link is required.
- Maximum TTL is 14 days.
- Auto-renew is disallowed.

## Review Modes

- `org` (default) and `personal`, via `--mode` or `PRIVACY_REVIEW_MODE`.
- `personal` mode honours trailing `# privacy-ok: <reason>` /
  `// privacy-ok: <reason>` markers on a finding's own line. The finding stays
  visible in md, json and sarif reports, marked suppressed with its reason.
- `org` mode ignores inline markers completely.
- `personal` mode with an empty `SECURITY_TEAM_SLUG` skips rerun approval
  (exit 0). `org` mode with an empty slug fails closed (exit 2).

## Launch Blockers

- `SECURITY_TEAM_SLUG` must be configured.
- Pilot repository must be explicitly selected.
