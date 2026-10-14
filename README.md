# PipeJack Deployment Kit

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Topology](https://img.shields.io/badge/Topology-Two--VM_Ubuntu_24.04%2F26.04-orange.svg)](#2-architecture--topology)
[![Orchestration](https://img.shields.io/badge/Orchestrator-PowerShell_%2B_Bash-green.svg)](#5-installation-workflows)

> **Automated Two-VM Deployment, Reconstruction & Recovery Package for the PipeJack Zero-Trust CI/CD Security Platform.**

---

## 1. Project Purpose & Repository Relationship

The **PipeJack Deployment Kit** (`ramKarthik57/pipejack-deployment-kit`) is the standalone, reproducible installation and recovery package for the PipeJack platform.

- **Primary Upstream Monorepo:** [`ramKarthik57/pipejack-platform`](https://github.com/ramKarthik57/pipejack-platform) serves as the upstream development showcase and canonical source repository.
- **This Deployment Kit:** Provides the self-contained directory structure, role-separated packages (`vm1/` and `vm2/`), automated Linux installers, Windows PowerShell orchestration, and validation test suites required to recreate or recover the functioning two-node system from scratch without manually sorting through monorepo code.

---

## 2. Architecture & Topology

PipeJack operates across two dedicated virtual machines hosted in VMware (or any virtualization provider):

```
┌────────────────────────────────────────┐       ┌──────────────────────────────────────────────────┐
│   VM1 — Developer / Workload Client    │       │     VM2 — Security Orchestrator & Attestation     │
│   (192.168.88.132)                     │       │     (192.168.88.133)                             │
│                                        │       │                                                  │
│   • Workload Applications:             │       │   • PipeJack CI Server (:8888)                   │
│     - Java Spring Banking API          │       │     - Multipart Streaming Ingestion              │
│     - Java AST Calculator API          │       │     - Policy Decision Point (PDP)                │
│     - Node.js Merchant Checkout        │       │     - Ephemeral Container Build Runner           │
│     - Python Fraud Inference           │       │   • Multi-Sensor Kernel Instrumentation:         │
│   • 7 Adversarial Attack Scenarios     │       │     - Process Tree Differ (cgroup v2)            │
│   • Malicious Supply-Chain Fixtures    │       │     - Filesystem Baseline Merkle Differ          │
│   • Dynamic Tarball Generators         │       │     - Network Socket Egress Filter               │
│   • pipejack-upload.sh Utility         │       │     - Statistical Anomaly Engine                 │
│                                        │       │   • Local Docker Registry (:5000)                │
│   (Client node: No Docker/Java/Maven)  │       │   • Ed25519 Attestation Ledger (~/pipejack-attest)│
│                                        │       │   • Interactive Web Demo Console (:8090)         │
└──────────────────┬─────────────────────┘       └─────────────────────────┬────────────────────────┘
                   │                                                       │
                   │  1. HTTP Multipart POST /upload (tarball stream)      │
                   ├──────────────────────────────────────────────────────►│
                   │                                                       │
                   │  2. Build execution, sensor trace, attestation sign   │
                   │     (Maven / npm / pip inside ephemeral container)    │
                   │                                                       │
                   │  3. HTTP 200 (ALLOW) or HTTP 403 (BLOCK / Quarantine) │
                   │◄──────────────────────────────────────────────────────┤
```

### Network Interfaces & Dual-Adapter Setup
Both virtual machines utilize two network interfaces:
1. **`ens33` — Private Inter-VM Network (`192.168.88.0/24`):** Isolated host-only network carrying build uploads, inter-VM SSH, and attack testing traffic.
2. **`ens37` — Management / NAT Network (`192.168.152.0/24`):** Outbound internet access via DHCP for OS packages and Docker base images, plus access to the Web Demo Console from your host browser.

---

## 3. Hardware & System Prerequisites

Based on live benchmark measurements:

| Requirement | VM1 (Client) | VM2 (Orchestrator) | Windows Host Workstation |
| :--- | :--- | :--- | :--- |
| **CPU** | 2 cores | 4 cores (recommended for container builds) | 4+ physical cores |
| **RAM** | 4 GB | 8 GB (Docker daemon + JVM build containers) | 16 GB+ total host RAM |
| **Storage** | 20 GB free | 40 GB free (Docker container image layers) | 10 GB free |
| **Operating System**| Ubuntu 24.04 LTS or 22.04 LTS (x86_64)| Ubuntu 24.04 LTS or 22.04 LTS (x86_64)| Windows 10/11 with OpenSSH Client |
| **Toolchain** | Client tools (git, curl, jq, nodejs, python3) | Go >= 1.23 required (Go 1.25.0 tested) + Docker | OpenSSH Client, PowerShell 5.1/7.x |
| **Virtualization** | VMware Workstation Pro / Player or Fusion | VMware Workstation Pro / Player or Fusion | Hardware virtualization (VT-x / AMD-V) enabled |

> [!NOTE]
> - **Go Toolchain:** Compiling the custom CI orchestrator (`pipejack-ci`) requires Go 1.23+. The reference machine runs **Go 1.25.0** (`go version go1.25.0 linux/amd64`). `vm2/install.sh` automatically fetches and installs Go 1.25.0 if Go is missing or < 1.23.
> - **PowerShell Compatibility:** Automation scripts (`windows/*.ps1`) strictly adhere to Windows PowerShell 5.1 syntax verified by static AST analysis (0 syntax errors, 0 ternary operators, 0 pipeline chain operators). Native Windows PowerShell 5.1 runtime engine execution remains **PENDING** verification on a Microsoft Windows host (automated regression testing is executed via PowerShell 7 `pwsh 7.4.6` on Linux).
> - **Archive Generation:** VM1 is provisioned as a lightweight developer client (Docker, Java, and Maven are deliberately omitted from VM1). Generating all 15 workload and attack tarballs using `build-all-tarballs.sh` performs clean directory packaging via `tar` and `npm pack`. Configurable output destinations are supported via `--output-dir` or `PIPEJACK_OUTPUT_DIR`.
> - **Demo Console Network Scope:** The Demo Console web server binds to `0.0.0.0:8090` by default. While WebSocket terminal sessions enforce IP ACL and Origin validation, all REST API endpoints are unauthenticated with `Access-Control-Allow-Origin: *`. The platform must strictly reside on private isolated lab networks.
> - **Verification Status:** Components and mock installation contracts have been audited and verified on the reference lab nodes. End-to-end automated installation on clean, blank virtual machines from bare ISOs remains **PENDING** operator execution. See [`docs/FRESH_INSTALL.md`](docs/FRESH_INSTALL.md) for the fresh installation guide and acceptance checklist.

---

## 4. Repository Layout

```
pipejack-deployment-kit/
├── README.md                 # Primary documentation and walkthrough
├── LICENSE                   # Apache 2.0 open-source license
├── SECURITY.md               # Security disclosure & isolated lab notice
├── SOURCE_MAPPING.md         # Component provenance & path mappings
├── UPSTREAM_BASELINE.md      # Commit SHAs & upstream reconciliation
├── VM2_DEPLOYMENT_AUDIT.md   # Live deployment state & port audit
├── MANIFEST.md               # Cryptographic SHA256 file manifest
├── .gitignore                # Git exclusion rules (zero secret leaks)
├── config/
│   ├── defaults.env.example  # Master environment configuration
│   └── README.md
├── vm1/                      # VM1 Client Package
│   ├── README.md
│   ├── install.sh            # Automated VM1 role installer
│   ├── applications/         # Workloads (banking, calc, node, python)
│   ├── attacks/              # Attack scenarios 01 to 07 & run-all.sh
│   ├── security-fixtures/    # evil-pkg, malicious fixtures, vuln-app
│   ├── scripts/              # pipejack-upload.sh, build-all-tarballs.sh
│   └── config/               # vm1.env.example, bashrc.snippet
├── vm2/                      # VM2 Orchestrator Package
│   ├── README.md
│   ├── install.sh            # Automated VM2 role installer
│   ├── core/                 # pipejack eBPF, fschecker, PDP, proctree
│   ├── services/custom-ci/   # Go CI engine, attestation, quarantine
│   ├── deployment/           # Dockerfiles, policies, systemd units
│   ├── demo/demo-console/    # Interactive Web Console & live terminals
│   ├── scripts/              # deploy-ci.sh, health-check.sh, prepare-demo.sh
│   └── config/               # vm2.env.example, ci.env.example
├── windows/                  # Windows Host PowerShell Automation
│   ├── setup-pipejack.ps1    # Master deployment orchestrator
│   ├── preflight.ps1         # Connectivity & prerequisite validator
│   ├── verify-pipejack.ps1   # Post-deployment end-to-end smoke test
│   └── README.md
├── shared/                   # Shared Templates
│   ├── README.md
│   └── templates/            # Netplan YAMLs & hosts configuration
├── tests/                    # Automated Test Suites
│   ├── validate-layout.sh    # Layout, permission & secret scanner
│   ├── validate-installers.sh# Bash -n, CLI args & YAML parser test
│   └── smoke-test.sh         # Go unit tests, vet & live upload test
└── docs/                     # Operational Documentation
    ├── ARCHITECTURE.md       # Pipeline lifecycle & sensor details
    ├── FRESH_INSTALL.md      # Step-by-step fresh VM guide & acceptance checklist
    ├── NETWORKING.md         # Network routing & port forwarding
    ├── TROUBLESHOOTING.md    # Symptoms & resolution matrix
    └── RECOVERY.md           # Disaster recovery & ledger reset guide
```

---

## 5. Installation Workflows

### Method A: Automated Deployment from Windows (Recommended)

From your Windows workstation with VMware running both booted VMs:

```powershell
# 1. Clone the deployment kit
git clone https://github.com/ramKarthik57/pipejack-deployment-kit.git
cd pipejack-deployment-kit\windows

# 2. Run Preflight Checks (Validates SSH, IPs, and disk space)
.\preflight.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133

# 3. Optional Dry-Run (Read-only preview; no files transferred, no system changes)
.\setup-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133 -DryRun

# 4. Execute Full Two-VM Installation
.\setup-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133

# 5. Run Verification (Strictly validates endpoints and attestation ledger)
.\verify-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133
```

> [!TIP]
> **Understanding `-DryRun`:**
> When `-DryRun` is passed, `setup-pipejack.ps1` runs in strictly non-modifying preview mode:
> - Performs read-only network and SSH preflight connectivity checks.
> - **Does not** transfer packages or files via SCP.
> - **Does not** create or remove remote staging directories.
> - **Does not** execute remote bash installer scripts.
> - **Does not** modify system state, start Docker containers, or restart systemd services.
> - Prints an itemized preview of all deployment actions that would occur during a live run.

---

### Method B: Direct Linux Installation (Without Windows Orchestration)

You can install each role directly on its respective Ubuntu machine.

#### Step 1: Install VM2 (Security Orchestrator) First
On VM2 (`192.168.88.133`):
```bash
cd pipejack-deployment-kit/vm2
chmod +x install.sh scripts/*.sh demo/demo-console/*.sh
./install.sh
```
Verify VM2 service health:
```bash
./scripts/health-check.sh
```

#### Step 2: Install VM1 (Workload Client)
On VM1 (`192.168.88.132`):
```bash
cd pipejack-deployment-kit/vm1
chmod +x install.sh scripts/*.sh attacks/*.sh applications/*/*.sh
./install.sh --ci-endpoint http://192.168.88.133:8888/upload

# Reload shell environment to enable 'upload' alias
source ~/.bashrc
```

---

## 6. Accessing the Web Demo Console

Once VM2 is installed, access the browser interface:
- **Local / Host URL:** [http://192.168.88.133:8090](http://192.168.88.133:8090)
- **NAT Fallback URL:** `http://<VM2_NAT_IP>:8090` (Check IP with `ip -4 addr show ens37`)

### Console Features
- **Live Telemetry:** Real-time process violation counters, network socket blocks, and Merkle diff tables.
- **Interactive PTY Terminals:** Dual embedded xterm.js terminals connected directly to VM1 and VM2.
- **One-Click Scenarios:** Launch clean builds or attacks directly from the web interface.

> [!WARNING]
> The Demo Console provides interactive root-capable terminal access. **Never** expose port `8090` to untrusted public networks. Keep it restricted to the private host-only or NAT lab network.

---

## 7. Submitting Workloads & Verifying Security Controls

### 1. Submit a Clean Workload (Expected: ALLOW)
On VM1:
```bash
upload /tmp/banking-api-clean.tar.gz
```
**Expected Pipeline Output:**
```
  Verdict:        ALLOW
  Action:         image published to localhost:5000/banking-api, deployed
  Attestation:    Signed Ed25519 digest recorded in ledger
  HTTP Status:    200 OK
```

### 2. Submit a Malicious Workload (Expected: BLOCK & Quarantine)
On VM1:
```bash
# Scenario 1: Unauthorized Shell Execution
cd ~/attacks/01-shell-exec
./build.sh
upload /tmp/attack-01-shell-exec.tar.gz
```
**Expected Pipeline Output:**
```
  Verdict:        BLOCK
  Violations:     Unauthorized process spawned (/bin/sh, /usr/bin/curl)
  Action:         Build aborted; image quarantined (localhost:5000/banking-api:...-quarantine)
  HTTP Status:    403 Forbidden
```

### 3. Run the Full Adversarial Regression Suite
On VM1:
```bash
cd ~/attacks
./run-all.sh
```
Executes all 7 scenarios against the live CI engine and prints an ANSI verdict matrix.

---

## 8. Verifying CI Health and Docker Registry

From any machine on the lab network:
```bash
# Probe CI Engine Health
curl -s http://192.168.88.133:8888/health
# Expected: {"status":"ok","service":"pipejack-ci",...}

# Probe Demo Console Status
curl -s http://192.168.88.133:8090/api/status
# Expected: {"ci_healthy":true,"attestation_count":...,"enforcement_mode":"Enabled"}

# Probe Local Docker Registry
curl -s -I http://192.168.88.133:5000/v2/
# Expected: HTTP/1.1 200 OK (Docker-Distribution-Api-Version: registry/2.0)
```

---

## 9. Running Verification Tests

The kit includes automated self-test scripts in `tests/`:

```bash
# 1. Validate Layout, Permissions, and Secret Absence
./tests/validate-layout.sh

# 2. Validate Shell Syntax, Installer Options, and Policy YAMLs
./tests/validate-installers.sh

# 3. Run Integration Smoke Tests (Go tests, vet, and live upload pipeline)
./tests/smoke-test.sh

# 4. Run Fresh-Install Blocker Regression Tests (Contract layout, PS5.1 AST, ACLs)
./tests/test-fresh-install-blockers.sh
```

---

## 10. Troubleshooting & Common Issues

| Problem | Cause | Resolution |
| :--- | :--- | :--- |
| **`Connection refused on port 8888`** | `pipejack-ci.service` is inactive or crashed | Check `sudo systemctl status pipejack-ci` and view logs at `sudo tail -n 50 /var/log/pipejack-ci.log`. Restart with `sudo systemctl restart pipejack-ci`. |
| **`Connection refused on port 5000`** | `registry:2` container is stopped | Run `docker start registry` or `docker run -d -p 5000:5000 --restart=always --name registry registry:2`. |
| **`Upload timed out after 180s`** | Maven build container slow to download plugins | Verify VM2 has internet access via `ens37`. Check container logs with `docker logs -f $(docker ps -lq)`. |
| **`Permission denied on attest-key`** | Key file permissions too open or wrong owner | Run `chmod 700 ~/.pipejack && chmod 600 ~/.pipejack/attest-key`. |
| **`SSH connection timeout from Windows`** | VMware network adapter disconnected or firewall | Verify VM IP addresses in VMware (`ip a`). Ensure adapter is set to Host-Only or NAT. |

For detailed recovery procedures and ledger rotation, see [`docs/RECOVERY.md`](docs/RECOVERY.md) and [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

---

## 11. What This Deployment Kit Does NOT Automate

To ensure host operating system stability and avoid destructive virtualization actions:
1. **VM Creation:** Does not automatically create `.vmx` virtual machine disks or download ISOs. You must create two basic Ubuntu VMs in VMware.
2. **Host Network Card Modifications:** Does not alter host Windows routing tables or VMware virtual switches.
3. **Cloud Key Vault Integration:** Keys are managed locally on VM2 in accordance with lab research requirements.

---

## 12. License & Author

- **License:** Apache License 2.0 (see [LICENSE](LICENSE))
- **Author & Maintainer:** Ram Karthik ([@ramKarthik57](https://github.com/ramKarthik57))
- **Showcase Repository:** [`ramKarthik57/pipejack-platform`](https://github.com/ramKarthik57/pipejack-platform)
