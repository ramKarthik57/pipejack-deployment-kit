# Security Policy and Lab Operational Guidelines

## 1. Scope & Research Lab Notice

The **PipeJack Deployment Kit** is designed for controlled cybersecurity research, academic demonstration, and defensive CI/CD evaluation in an isolated laboratory environment.

> [!WARNING]
> This repository contains functional attack scenarios (`attacks/`) and malicious supply-chain fixtures (`security-fixtures/`). These fixtures are strictly intended for testing detection and enforcement capabilities within an isolated testbed. Never deploy or execute these fixtures on production networks, public infrastructure, or systems you do not own.

---

## 2. Security Invariants & Credential Handling

### Zero Secrets in Repository
1. **Private Signing Keys:**
   - The Ed25519 signing key (`~/.pipejack/attest-key`) used to sign build attestations is **never** committed to Git.
   - The installer dynamically generates a local private key on VM2 with restrictive permissions (`0600`) if absent.
2. **SSH Credentials:**
   - No private SSH keys (`id_rsa`, `id_ed25519`) or host keys are packaged into this kit.
   - Users must configure their own SSH keys between their management workstation and virtual machines.
3. **Environment Files:**
   - Only non-sensitive example templates (`.env.example`) are tracked in version control.
   - Production secrets and passwords must reside outside the repository.

---

## 3. Demo Console Security Architecture & Network Exposure

The Web Demo Console (`server.py`, default port `8090`) provides a graphical visualization interface for PipeJack build attestations, telemetry diffs, and interactive terminal sessions (`/ws/terminal/vm1` and `/ws/terminal/vm2`).

### Default Network Binding & REST Behavior
- **Default Listening Interface:** Binds to `0.0.0.0:8090` by default (configurable via `PIPEJACK_CONSOLE_HOST` and `PIPEJACK_CONSOLE_PORT` in `/etc/systemd/system/pipejack-demo-console.service`).
- **Unauthenticated REST API:** All REST endpoints (including `/api/status`, `/api/scenarios`, `/api/audit-logs`, `/api/terminal/access-check`) are **unauthenticated** by design for low-friction lab research and emit `Access-Control-Allow-Origin: *`.
- **Interactive PTY WebSockets:** The terminal endpoints spawn interactive Bash PTY sessions. To safeguard these sessions, `server.py` enforces:
  1. **Client IP Subnet Filtering:** Only connections from permitted subnets (default: `127.0.0.0/8`, `192.168.88.0/24`, `192.168.152.0/24`, `::1/128`, or custom `PIPEJACK_ALLOWED_NETWORKS`) can open a terminal. Unauthorized IPs receive `HTTP 403 Forbidden`.
  2. **Anti-CSWSH Origin Validation:** The `Origin` header must match the expected `Host` header or loopback/lab subnets. Third-party web origins (e.g. `http://evil-attacker.com`) are rejected with `HTTP 403 Forbidden`.

### Operational Lab Constraints & Mandatory Isolation
- **Private Lab Network Only:** The Demo Console must only run on private host-only or VMware NAT networks (`192.168.88.0/24`, `192.168.152.0/24`, `127.0.0.1`).
- **Never Expose Publicly:** Do NOT expose port `8090` to the public internet, shared corporate networks, or public reverse proxies without adding an external authenticating reverse proxy (e.g., mTLS or HTTP Basic Auth).
- **Loopback-Only Hardening:** For local-only access, configure `PIPEJACK_CONSOLE_HOST="127.0.0.1"` in `/etc/systemd/system/pipejack-demo-console.service`.

---

## 4. Policy Enforcement Models

PipeJack supports two enforcement postures configured in `/etc/pipejack/ci.env`:

- **Enforcement Active (`PIPEJACK_ENFORCE=1` — Default):**
  - Any policy violation (unauthorized process execution, Merkle filesystem mutation, or unauthorized egress socket connection) immediately triggers a **BLOCK** verdict.
  - Build execution is halted, Docker deployment is aborted, the image is quarantined in the local registry with a `-quarantine` tag, and an HTTP 403 Forbidden is returned to the client.
- **Audit / Detection Only (`PIPEJACK_ENFORCE=0`):**
  - Violations are detected, logged, and signed into the cryptographic attestation ledger, but the build pipeline returns HTTP 200 pass. Useful for baseline profiling.

---

## 5. Vulnerability Reporting

If you discover a security flaw or unintended vulnerability in the PipeJack core engine or deployment kit that goes beyond the documented lab research scope, please submit a responsible disclosure report directly via GitHub Security Advisories on this repository.
