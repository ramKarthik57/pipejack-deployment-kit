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

## 3. Demo Console Security Restrictions & Known Limitations

The Web Demo Console (`server.py`, port `8090`) includes interactive WebSocket PTY terminal endpoints (`/ws/terminal/vm1` and `/ws/terminal/vm2`) to enable real-time visualization of build telemetry and kernel diffs.

### Operational Constraints & Risks
- **No Inherent Web Authentication:** By design for low-friction lab evaluation, the console does not require a web login.
- **Remote Command Execution Risk:** Any client that can reach port `8090` has shell access through the web terminals.
- **Mandatory Isolation:**
  - The Demo Console **must only bind to or be accessed via a private host-only or NAT network** (`192.168.88.0/24`, `127.0.0.1`, or host VMware virtual switches).
  - Do **not** expose port `8090` to the public internet, corporate LANs, or untrusted Wi-Fi networks.
  - Do **not** place port `8090` behind an unauthenticated public reverse proxy.

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
