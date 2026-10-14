# PipeJack Deployment Kit — Upstream Baseline and Source Provenance

**Document Version:** 1.0.0  
**Target Deployment Repository:** `ramKarthik57/pipejack-deployment-kit`  
**Upstream Monorepo:** `https://github.com/ramKarthik57/pipejack-platform`  
**Verification Date:** 2026-10-14  

---

## 1. Upstream Commits and Branch Reconciliation

### Baseline Identifiers

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **Upstream Repository** | `https://github.com/ramKarthik57/pipejack-platform.git` | Primary showcase monorepo |
| **Target Repository** | `https://github.com/ramKarthik57/pipejack-deployment-kit.git` | Standalone two-VM installation package |
| **Upstream `main` HEAD** | `918a3c5` | Current canonical commit on remote `origin/main` |
| **VM1 Branch** | `feature/vm1-final-source-audit` | Audit branch identified in VM1 inventory |
| **VM1 Commit SHA** | `e94b79f53278acdaedeba43353349e8a4eaa432e` | Head of VM1 audit branch |
| **Reconciliation Merge** | `ce45b1a` | Git merge integrating `feature/vm1-final-source-audit` into `main` |

---

## 2. Reconciliation Analysis

The VM1 handoff report (`/home/ubuntu/PIPEJACK_VM1_INVENTORY.md` and `.json`) noted that commit `e94b79f` on branch `feature/vm1-final-source-audit` contained important path fixes in `attacks/` and the restored `evil-pkg` security fixture, cautioning that these might not yet be present on `main`.

An independent Git graph inspection on VM2 confirms:
1. `git merge-base origin/main e94b79f` evaluates to `e94b79f53278acdaedeba43353349e8a4eaa432e`.
2. Commit `ce45b1a` merged `feature/vm1-final-source-audit` directly into `main`.
3. All file changes introduced in `e94b79f` are present in `origin/main`:
   - `security-fixtures/evil-pkg/` exists and is tracked.
   - `attacks/*/build.sh` dynamic path resolution (`$SRC/../../applications/...` with fallback to `~/banking-api`) is intact.
   - `attacks/run-all.sh` directory discovery is intact.
   - `scripts/pipejack-upload.sh` terminal formatting is intact.

### Commits on `main` Ahead of `e94b79f`

The following subsequent commits on `main` provide further stabilization:
- `ce45b1a` — Merge branch 'feature/vm1-final-source-audit' into main
- `07b108b` — fix(scripts): resolve custom-ci source path correctly in deploy-ci.sh
- `26c53b5` — chore: reconcile banking-api pom separation and finalize release report
- `fbab01c` — feat: harden repository documentation, architecture diagrams, community standards, and CI workflow
- `331c661` — chore(release): finalize repository truth, research framing, Go 1.25 toolchain, and verified evidence
- `d1c0a80` — ci: activate GitHub Actions CI workflow under .github/workflows/pipejack-ci.yml
- `95d8b4f` — docs(security): tighten security invariants, remove imprecise claims, and publish release certification review
- `03ba234` — docs: update PIPEJACK_FINAL_RELEASE_REVIEW.md with canonical commit SHA
- `add3e6f` — docs: update certification document commit and CI wording to continuous workflow status
- `918a3c5` — feat(demo-console): streamline 3-app playground (Banking, Calculator, Payment), fix quarantine-tamper & Node egress timing, and update README

---

## 3. Authoritative Source Selection

Because `origin/main` at `918a3c5` contains the full set of changes from `e94b79f` plus subsequent validated fixes for the demo console server, quarantine timing, and CI pipeline, **`918a3c5` is chosen as the authoritative baseline for packaging**.

No force-pushes, rebase operations, or destructive history rewrites were performed on the original `pipejack-platform` repository. The deployment kit preserves the exact source state of all functional modules.

---

## 4. Integrity and Cryptographic Checksums

Key modules packaged into this deployment kit correspond directly to their upstream checksums:

| Module | Canonical SHA256 Sum (main.go / primary file) | Upstream Match Verified |
| :--- | :--- | :--- |
| `services/custom-ci/main.go` | `2e47e335da4b3a6efba3e6a25cfda0b0eb10776991ee767425f190eec2ea4131` | Yes |
| `demo/demo-console/server.py` | `6b9fae21db7c7a7266a0d6bc9f04128f6e2b9c7cf6572eb0f1fece5cfca3c0b0` | Yes |
| `core/pipejack/cmd/pipejackd/main.go` | `1daaa38bf113a30c5e9334ca6d5815340ca32ce6bf5c59f0f972bca5201ec3a6` | Yes |
| `core/pipejack/cmd/proctree/main.go` | `83907ebc3479e001a75046e7f098555e51147043329ebc0ff6b1429986b6279f` | Yes |
| `scripts/pipejack-upload.sh` | `db0be48897cbb159bb3298dd81ae39b8296a2f8d3886f4cb6fe583348f076e2c` | Yes |
