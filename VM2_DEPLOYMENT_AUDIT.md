# PipeJack Deployment Kit — VM2 Live Deployment Audit

**Audited Host:** VM2 — Security Orchestrator, CI Engine, Attestation & Demo Host  
**Audit Timestamp:** 2026-10-14T15:20:00+05:30  
**Audit Engineer:** Lead Integration Agent  
**Audit Status:** COMPLETE — LIVE VERIFIED  

---

## 1. Host Identification & OS Baseline

- **Hostname:** `ubuntu`
- **Current User:** `ubuntu` (UID: 1000, GID: 1000)
- **Architecture:** `x86_64`
- **Kernel:** `Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`
- **Operating System:** Ubuntu 26.04 LTS (`resolute`)
- **Disk Utilization:**
  - Root Filesystem (`/`): `/dev/sda2`, Size: 59 GB, Used: 44 GB, Available: 13 GB (78% utilized).
  - Recommended minimum for fresh installation: 25–40 GB free space.

---

## 2. Network Topology & Port Bindings

### Network Interfaces
1. **`ens33` (Inter-VM Private Network):**
   - IPv4 Address: `192.168.88.133/24`
   - Target Peer (VM1): `192.168.88.132` (Ping RTT: ~0.4ms; SSH: Active & Verified).
2. **`ens37` (Host / Management NAT Network):**
   - IPv4 Address: `192.168.152.130/24`
   - Default Gateway: `192.168.152.2` via `ens37` (metric 101).
3. **`docker0` (Docker Bridge):**
   - IPv4 Address: `172.17.0.1/16`

### Active Listening Ports

| Port | Protocol | Service / Process | Process PID | Health / Status | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **8888** | TCP | `pipejack-ci` | 3267 | `HTTP 200 {"status":"ok"}` on `/health` | Core CI build orchestrator & upload ingestion |
| **8090** | TCP | `python3 server.py` | 3268 | `HTTP 200` on `/`, `/api/status` | Interactive Web Demo Console |
| **5000** | TCP | Docker `registry:2` | Docker container | `HTTP 200` on `/v2/` | Local container registry for allowed/quarantine images |
| **22** | TCP | `sshd` | System | Active | OpenSSH Server (supports key-based auth) |

---

## 3. Active Systemd Services

### `pipejack-ci.service`
- **Unit Path:** `/etc/systemd/system/pipejack-ci.service`
- **Status:** Active (running)
- **Working Directory:** `/home/ubuntu/custom-ci`
- **Binary:** `/usr/local/bin/pipejack-ci` (Size: ~9.7 MB, compiled from `services/custom-ci`)
- **Environment File:** `/etc/pipejack/ci.env`
  - `PIPEJACK_PORT=8888`
  - `PIPEJACK_ENFORCE=1`
  - `PIPEJACK_FAST=0`
  - `PIPEJACK_DEV=0`
- **Supplementary Groups:** `docker` (permits communication over `/var/run/docker.sock`)
- **Logs:** `/var/log/pipejack-ci.log`

### `pipejack-demo-console.service`
- **Unit Path:** `/etc/systemd/system/pipejack-demo-console.service`
- **Status:** Active (running)
- **Working Directory:** `/home/ubuntu/pipejack-demo-console`
- **Command:** `/usr/bin/python3 -u /home/ubuntu/pipejack-demo-console/server.py`
- **Dependencies:** `After=network.target pipejack-ci.service`, `Wants=pipejack-ci.service`
- **Logs:** `/home/ubuntu/pipejack-demo-console/console.log`

---

## 4. Docker & Registry Infrastructure

- **Docker Version:** `Docker 29.6.1, build 8900f1d`
- **Registry Container:**
  - Name: `registry`
  - Image: `registry:2`
  - Status: Up and running
  - Port Mapping: `0.0.0.0:5000->5000/tcp`
- **Build Container Cache:**
  - Maven build container: `maven:3.8-eclipse-temurin-17`
  - Node.js build container: Node 18 runtime
  - Python build container: Python 3.12 runtime

---

## 5. Attestation Ledger & Cryptographic Keys

- **Ed25519 Signing Key:**
  - Private Key Path: `/home/ubuntu/.pipejack/attest-key` (File Mode: `0600`, Redacted)
  - Public Key Path: `/home/ubuntu/.pipejack/attest-key.pub` (File Mode: `0644`)
  - Verification: Generated locally if absent; never committed to git.
- **Attestation Ledger:**
  - Directory: `/home/ubuntu/pipejack-attestations/`
  - Index File: `/home/ubuntu/pipejack-attestations/index.json`
  - Active Records: 408 verified cryptographic attestation records chaining Merkle roots, process tree scans, and network decisions.

---

## 6. Real Test Coverage Summary

1. **`services/custom-ci` Unit Tests (100% Pass):**
   - `TestQuarantine_BlockedWithQuarantineSuccess` (PASS)
   - `TestQuarantine_BlockedWithQuarantineBuildFailure` (PASS)
   - `TestQuarantine_BlockedWithMissingDockerfile` (PASS)
   - `TestBuild_CleanSuccessRemainsAllow` (PASS)
   - `TestBuild_CleanBuildFailureReturnsError` (PASS)
2. **`core/pipejack` Unit Tests (100% Pass):**
   - `fschecker` (11 tests pass: Merkle tree baseline, deterministic output, multi-change, ignore prefixes)
   - `internal/anomaly` (9 tests pass: Z-score, threshold, warming up, full cycle)
   - `internal/egressfw` (3 tests pass: IPv4, IPv6 loopback, spec parsing)
   - `internal/netmon` (8 tests pass: clean, violation, wildcard, missing fields)
   - `internal/pdp` (6 tests pass: process violation, fs violation, wildcard glob)
   - `proctree` (8 tests pass: cgroup scanning, allowlist deduplication)

---

## 7. Security Observations & Operational Constraints

1. **Demo Console WebSocket Terminals:**
   - The endpoints `/ws/terminal/vm1` and `/ws/terminal/vm2` provide interactive PTY terminals to facilitate live demonstrations.
   - **Risk:** Unauthenticated terminal execution if exposed to an open network.
   - **Mitigation:** The console must only bind to or be accessible via the isolated host/VMware private network (`192.168.88.0/24`, `192.168.152.0/24`, or `127.0.0.1`). Public internet exposure is strictly prohibited.
2. **Idempotent Key Retention:**
   - Re-running installers must preserve `/home/ubuntu/.pipejack/attest-key` and `/home/ubuntu/pipejack-attestations/` so existing chain integrity is not broken.
