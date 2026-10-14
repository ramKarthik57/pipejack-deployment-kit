# PipeJack Deployment Kit — Comprehensive Source Mapping

**Target Repository:** `pipejack-deployment-kit`  
**Upstream Repository:** `https://github.com/ramKarthik57/pipejack-platform`  
**Upstream Base Revision:** `918a3c5` (incorporating `feature/vm1-final-source-audit` @ `e94b79f` via merge `ce45b1a`)  
**Audit Date:** 2026-10-14  

---

## 1. Architectural Separation Overview

PipeJack is designed as a two-node Zero-Trust CI/CD Attestation & Security Pipeline:
- **VM1 (Developer / Client Node — default IP: `192.168.88.132`):** Houses workload code, attack simulation fixtures, adversarial regression test runners, dynamic archive builders, and the streaming multipart upload utility (`pipejack-upload.sh`). VM1 does **not** run Docker, Java, or the CI daemon; it acts as a lightweight client.
- **VM2 (Security Orchestrator / CI Node — default IP: `192.168.88.133`):** Houses the Go-based CI engine (`pipejack-ci`), eBPF kernel security instrumentation (`core/pipejack`, `cilium-ebpf`, `golang-sys`), declarative YAML policies, local container registry (`registry:2` on `:5000`), cryptographic attestation ledger (`~/.pipejack/attest-key`, `pipejack-attestations/`), and the Web Demo Console (`:8090`).

The deployment kit decomposes the upstream monorepo into dedicated, reproducible role directories (`vm1/` and `vm2/`), shared templates (`shared/`, `config/`), Windows PowerShell orchestration (`windows/`), automated test validators (`tests/`), and operations documentation (`docs/`).

---

## 2. Comprehensive Component Mapping Table

| Upstream / Source Path | Kit Destination Path | Purpose / Description | Required VM Role | Source Provenance | Installation Behavior | Notes & Caveats |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `applications/banking-api/` | `vm1/applications/banking-api/` | Java 17 Spring Boot Banking API reference application (clean & malicious `pom.xml`, `build-tarballs.sh`) | VM1 (Client) | `origin/main` (`918a3c5`), reconciled from `e94b79f` | Installed to `~/banking-api`. Tarballs dynamically built on demand. | No Java/Maven required on VM1; compilation happens on VM2. |
| `applications/calculator-api/` | `vm1/applications/calculator-api/` | Java Spring Boot AST Calculator service with `build-tarball.sh` | VM1 (Client) | `origin/main` (`918a3c5`) | Installed to `~/calculator-api`. Symlinked as `spring-calc` if legacy compatibility requested. | Standardized from VM1 legacy `spring-calc`. |
| `applications/nodejs-app/` | `vm1/applications/nodejs-app/` | Node.js 18 Express sample merchant checkout workload | VM1 (Client) | `origin/main` (`918a3c5`) | Installed to `~/nodejs-app`. Tarball built via `build-tarball.sh`. | Clean reference application. |
| `applications/python-app/` | `vm1/applications/python-app/` | Python 3.12 Flask fraud inference microservice workload | VM1 (Client) | `origin/main` (`918a3c5`) | Installed to `~/python-app`. Tarball built via `build-tarball.sh`. | Clean reference application. |
| `attacks/01-shell-exec/` | `vm1/attacks/01-shell-exec/` | Scenario 1: Unauthorized process execution (`sh -c 'curl ...'`) | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Installed to `~/attacks/01-shell-exec/`. | Resolves banking-api dynamically via `../../applications/` or `~/banking-api`. |
| `attacks/02-http-exfil/` | `vm1/attacks/02-http-exfil/` | Scenario 2: Network socket exfiltration to unauthorized IP `10.255.255.1:80` | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Installed to `~/attacks/02-http-exfil/`. | Triggers network filter block. |
| `attacks/03-fs-tamper/` | `vm1/attacks/03-fs-tamper/` | Scenario 3: Build-time filesystem tampering and source AST modification | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Installed to `~/attacks/03-fs-tamper/`. | Triggers Merkle root mismatch block. |
| `attacks/04-base64-shell/` | `vm1/attacks/04-base64-shell/` | Scenario 4: Encoded payload deobfuscation and evasion attempt | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Installed to `~/attacks/04-base64-shell/`. | Triggers process differ block. |
| `attacks/05-multi-stage/` | `vm1/attacks/05-multi-stage/` | Scenario 5: Correlated multi-sensor attack (process + network + filesystem) | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Installed to `~/attacks/05-multi-stage/`. | Triggers multi-violation block. |
| `attacks/06-slow-exfil/` | `vm1/attacks/06-slow-exfil/` | Scenario 6: Rate-limited egress network exfiltration | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Installed to `~/attacks/06-slow-exfil/`. | Triggers egress socket violation block. |
| `attacks/07-anomaly/` | `vm1/attacks/07-anomaly/` | Scenario 7: Statistical variance anomaly injection | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Installed to `~/attacks/07-anomaly/`. | Produces advisory warning or block per policy. |
| `attacks/run-all.sh` | `vm1/attacks/run-all.sh` | Master adversarial regression test suite runner | VM1 (Client) | `origin/main` (`918a3c5`), hardened in `e94b79f` | Executable permissions (`0755`). Targets `$VM2:8888/upload`. | Supports `VM2` env var override. |
| `security-fixtures/evil-pkg/` | `vm1/security-fixtures/evil-pkg/` | Postinstall malicious hook package fixture | VM1 (Client) | Restored in `e94b79f`, merged to `main` | Installed to `~/security-fixtures/evil-pkg/`. | Used for supply-chain postinstall testing. |
| `security-fixtures/nodejs-malicious/` | `vm1/security-fixtures/nodejs-malicious/` | Node.js supply-chain exfiltration fixture with `build-tarball.sh` | VM1 (Client) | `origin/main` (`918a3c5`) | Installed to `~/nodejs-malicious/`. | Generates malicious node package. |
| `security-fixtures/python-malicious/` | `vm1/security-fixtures/python-malicious/` | Python `setup.py` build socket exfiltration fixture | VM1 (Client) | `origin/main` (`918a3c5`) | Installed to `~/python-malicious/`. | Generates malicious python package. |
| `security-fixtures/vuln-app/` | `vm1/security-fixtures/vuln-app/` | Vulnerability testbed application fixture | VM1 (Client) | `origin/main` (`918a3c5`) | Installed to `~/vuln-app/`. | Used in quarantine test suites. |
| `scripts/pipejack-upload.sh` | `vm1/scripts/pipejack-upload.sh` | ANSI terminal telemetry streaming uploader | VM1 (Client) | `origin/main` (`918a3c5`) | Installed to `~/pipejack-upload.sh` (`0755`). | Uploads tarballs to `http://$CI_ENDPOINT`. |
| `core/pipejack/` | `vm2/core/pipejack/` | Core security engine: `pipejackd`, `proctree`, `ebpfctrl`, `fschecker`, `internal/` (pdp, egressfw, netmon, anomaly) | VM2 (Server) | `origin/main` (`918a3c5`) | Compiled during VM2 setup. | Standalone Go module replacing local deps. |
| `core/cilium-ebpf/` | `vm2/core/cilium-ebpf/` | Local fork of `cilium/ebpf` v0.22.0 required by `core/pipejack` | VM2 (Server) | `origin/main` (`918a3c5`) | Referenced via `replace` directive in `core/pipejack/go.mod`. | Preserves offline build capability. |
| `core/golang-sys/` | `vm2/core/golang-sys/` | Local fork of `golang.org/x/sys` v0.43.0 required by `cilium-ebpf` | VM2 (Server) | `origin/main` (`918a3c5`) | Referenced via `replace` directive in `core/pipejack/go.mod`. | Preserves offline build capability. |
| `services/custom-ci/` | `vm2/services/custom-ci/` | Main CI Server orchestrator (`main.go`, `attest.go`, `verify-attest.go`, `quarantine_test.go`) | VM2 (Server) | `origin/main` (`918a3c5`) | Compiled to `/usr/local/bin/pipejack-ci`. Working directory `/home/ubuntu/custom-ci`. | Full quarantine, multi-lang build, and attestation. |
| `deployment/docker/` | `vm2/deployment/docker/` | Application container Dockerfiles (`Dockerfile.app`, `Dockerfile.calc`, `Dockerfile.python`, `Dockerfile.spring`) | VM2 (Server) | `origin/main` (`918a3c5`) | Copied to `/home/ubuntu/custom-ci/`. | Used during container packaging. |
| `deployment/policies/` | `vm2/deployment/policies/` | Active security policy YAML files (`policy-banking.yaml`, `policy-node.yaml`, `policy-python.yaml`, `policy-spring.yaml`) | VM2 (Server) | `origin/main` (`918a3c5`) | Copied to `/home/ubuntu/custom-ci/`. | Defines process, net, and FS rules. |
| `deployment/systemd/` | `vm2/deployment/systemd/` | Systemd service unit files and default environment file | VM2 (Server) | `origin/main` (`918a3c5`) | Installed to `/etc/systemd/system/` and `/etc/pipejack/ci.env`. | Configures daemon execution and restarts. |
| `demo/demo-console/` | `vm2/demo/demo-console/` | Interactive Web Demo Console server (`server.py`, `static/`, `prepare-demo.sh`) | VM2 (Server) | `origin/main` (`918a3c5`) | Installed to `/home/ubuntu/pipejack-demo-console/`. Started as systemd service. | Untracked mp4 omitted from kit; artifacts built on setup. |
| `scripts/deploy-ci.sh` | `vm2/scripts/deploy-ci.sh` | Rebuild and redeployment script for `pipejack-ci` | VM2 (Server) | `origin/main` (`918a3c5`) | Executable utility for fast developer iteration on VM2. | Safe to rerun repeatedly. |
| *New* | `vm1/install.sh` | Automated VM1 role installer | VM1 (Client) | Developed for deployment kit | Installs dependencies, sets paths, configures endpoint, builds initial tarballs. | Robust Bash, `--dry-run`, `--help`. |
| *New* | `vm2/install.sh` | Automated VM2 role installer | VM2 (Server) | Developed for deployment kit | Configures Docker, registry, builds CI, installs systemd units, validates health. | Idempotent, preserves keys, `--help`. |
| *New* | `windows/setup-pipejack.ps1` | Windows master orchestrator | Windows Host | Developed for deployment kit | Validates preflight, transfers kits, executes remote installers, captures logs. | OpenSSH client, configurable IPs. |
| *New* | `windows/preflight.ps1` | Windows connectivity & prerequisite validator | Windows Host | Developed for deployment kit | Checks SSH, IP ping, remote OS version, disk space. | Safe read-only checks. |
| *New* | `windows/verify-pipejack.ps1` | End-to-end post-deployment verifier | Windows Host | Developed for deployment kit | Tests HTTP 8888, 8090, 5000, runs sample upload, checks attestation. | Verifies real verdicts. |
| *New* | `tests/validate-layout.sh` | Staging repository layout & secret validator | All / CI | Developed for deployment kit | Verifies required files, permissions, no forbidden files or committed secrets. | Automated test. |
| *New* | `tests/validate-installers.sh` | Bash & installer syntax / argument validator | All / CI | Developed for deployment kit | Tests `--help`, `--check` / dry-run on both installers. | Automated test. |
| *New* | `tests/smoke-test.sh` | Live integration smoke test | VM2 / CI | Developed for deployment kit | Verifies unit tests, running services, and upload pipeline. | Non-destructive. |

---

## 3. Provenance and Authority Summary

- **Upstream Monorepo:** `ramKarthik57/pipejack-platform` (commit `918a3c5`) is the authoritative source for all core, application, and service files.
- **VM1 Audit Reconciliation:** Commit `e94b79f` on `feature/vm1-final-source-audit` was merged into `main` at commit `ce45b1a`. All fixes—specifically the hardened relative paths in `attacks/*/build.sh`, the restored `evil-pkg` fixture, and the updated `pipejack-upload.sh`—are incorporated into `main`.
- **Packaging Principle:** The deployment kit contains real, functioning source files rather than stubs or mockups, ensuring that an installation builds identical binaries to the live production environment.
