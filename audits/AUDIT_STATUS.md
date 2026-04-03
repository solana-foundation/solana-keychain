# Audit Status

Last updated: 2026-04-03

## Current Baseline

- Auditor: Accretion
- Report: `audits/2026-accretion-solana-foundation-solana-keychain-audit-A26SFR2.pdf`
- Audited-through commit: `475beb7c372e805e081ebcd85d84923460267da6`
- Compare unaudited delta: https://github.com/solana-foundation/solana-keychain/compare/475beb7c372e805e081ebcd85d84923460267da6...main

Audit scope is commit-based. Commits after the audited-through SHA are considered unaudited until a new audit or mitigation review updates this file.

## Branch and Release Model

- `main` is the integration branch and may contain audited and unaudited commits.
- Stable production releases are immutable tags/releases (for example `v1.0.0`).
- Audited baselines are tracked by commit SHA plus immutable tags/releases, not by long-lived release branches.

## Verification Commands

```bash
# Count commits after the audited baseline
git rev-list --count 475beb7c372e805e081ebcd85d84923460267da6..main

# Inspect commit list since audited baseline
git log --oneline 475beb7c372e805e081ebcd85d84923460267da6..main

# Inspect file-level diff since audited baseline
git diff --name-status 475beb7c372e805e081ebcd85d84923460267da6..main
```

## Maintenance Rules

When a new audit is completed:

1. Add the new report to `audits/`.
2. Update `Audited-through commit` and `Compare unaudited delta`.
3. Tag audited release commit(s) (for example `vX.Y.Z`).
4. Update README and release notes links if needed.
