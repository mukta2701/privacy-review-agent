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

## Launch Blockers

- `SECURITY_TEAM_SLUG` must be configured.
- Pilot repository must be explicitly selected.
