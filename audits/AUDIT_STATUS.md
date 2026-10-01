# Audit Status

Last updated: 2026-10-01

## Current Baseline

- Auditor: OtterSec
- Report: `audits/2026-ottersec-solana-foundation-solana-keychain-audit.pdf`
- Audited commit: `e685e353b6bc12f7d31d96aa324964f3c1e7ffd7`
- Audited-through commit (remediation review): `8ea75de5c47fb3d22d704ab175cbe10483db2ff2`
- Compare unaudited delta: https://github.com/solana-foundation/solana-keychain/compare/8ea75de5c47fb3d22d704ab175cbe10483db2ff2...main

Audit scope is commit-based. Commits after the audited-through SHA are considered unaudited until a new audit or mitigation review updates this file.

### Language scope

The audit covered the Rust, TypeScript, Python and Go implementations. All 27
findings (4 medium, 15 low, 8 informational) are resolved as of the
audited-through commit.

The Ledger backend (`rust/src/ledger` and Ledger-related changes) was excluded
from scope and is **unaudited**.

## Previous Audits

- Accretion, `audits/2026-accretion-solana-foundation-solana-keychain-audit-A26SFR2.pdf`,
  audited through `475beb7c372e805e081ebcd85d84923460267da6` (Rust and TypeScript only).

## Branch and Release Model

- `main` is the integration branch and may contain audited and unaudited commits.
- Stable production releases are immutable tags/releases (for example `v1.0.0`).
- Audited baselines are tracked by commit SHA plus immutable tags/releases, not by long-lived release branches.

## Verification Commands

```bash
# Count commits after the audited baseline
git rev-list --count 8ea75de5c47fb3d22d704ab175cbe10483db2ff2..main

# Inspect commit list since audited baseline
git log --oneline 8ea75de5c47fb3d22d704ab175cbe10483db2ff2..main

# Inspect file-level diff since audited baseline
git diff --name-status 8ea75de5c47fb3d22d704ab175cbe10483db2ff2..main
```

## Maintenance Rules

When a new audit is completed:

1. Add the new report to `audits/`.
2. Update `Audited-through commit` and `Compare unaudited delta`.
3. Tag audited release commit(s) (for example `vX.Y.Z`).
4. Update README and release notes links if needed.
