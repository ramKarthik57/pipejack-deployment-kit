# PipeJack VM2 — Orchestrator, Policy Engine & Demo Console

This directory contains the server-side modules, security engine, local Docker registry configuration, attestation verification tools, Demo Console web application, and automated installer for **VM2** (the server/orchestrator machine).

---

## 1. Architectural Role

VM2 is the central security orchestrator in the PipeJack architecture:
- **Default IP Address:** `192.168.88.133`
- **Core Components Hosted on VM2:**
  - **PipeJack CI Server (`pipejack-ci`):** Listens on port `8888`. Accepts multipart HTTP build archive uploads from VM1, unpacks in isolated build environments, executes multi-sensor security scans (process tree, Merkle tree diff, network filter), and generates Ed25519-signed attestations.
  - **eBPF Security Instrumentation (`core/pipejack`):** Process tree monitoring, network socket egress filters, and Merkle tree filesystem baseline checkers.
  - **Local Docker Registry:** Listens on port `5000` (Docker Distribution v2 API). Stores allowed production images and tagged quarantine images.
  - **Attestation Ledger:** Cryptographic hash-chained JSON ledger under `/home/ubuntu/pipejack-attestations/` signed by the private key in `/home/ubuntu/.pipejack/attest-key`.
  - **Web Demo Console:** Listens on port `8090`. Provides interactive telemetry visualization, live terminals, and one-click test execution.

---

## 2. Directory Layout

```
vm2/
├── README.md                 # This documentation
├── install.sh                # Automated VM2 installer script
├── core/                     # eBPF security core engine
│   ├── pipejack/             # Core daemon, proctree, fschecker, PDP
│   ├── cilium-ebpf/          # Vendored eBPF library
│   └── golang-sys/           # Vendored low-level syscalls
├── services/
│   └── custom-ci/            # Go CI server implementation & unit tests
├── deployment/
│   ├── docker/               # Container packaging Dockerfiles
│   ├── policies/             # Active declarative YAML security policies
│   └── systemd/              # Systemd unit files (pipejack-ci, demo-console)
├── demo/
│   └── demo-console/         # Web Demo Console application & static assets
├── scripts/
│   ├── deploy-ci.sh          # Quick recompile & redeploy utility
│   ├── prepare-demo.sh       # Dynamic scenario bundle generator
│   └── health-check.sh       # Multi-service health probe
└── config/
    ├── vm2.env.example       # Example host environment variables
    └── ci.env.example        # Systemd service environment file
```

---

## 3. Installation Instructions

### Automated Installation
Execute the installer on VM2:
```bash
# Preflight dry-run verification
./install.sh --dry-run

# Full installation and service startup
./install.sh
```

### Toolchain Prerequisites
- **Go Toolchain:** Go 1.23 or newer is required to compile the `pipejack-ci` server (the binary uses modern language features and toolchain libraries). The environment was tested and validated with **Go 1.25.0** (`go version go1.25.0 linux/amd64`).
- **Automatic Toolchain Acquisition:** If Go is missing or older than 1.23, `vm2/install.sh` automatically downloads and configures the official Go 1.25.0 tarball to `/usr/local/go` and links `/usr/local/bin/go`.

### Options
- `--dry-run`: Verifies OS distribution, disk space, and prerequisites without modifying system state.
- `--skip-build`: Skips compiling Go source binaries if `/usr/local/bin/pipejack-ci` is already present.
- `--no-restart`: Deploys files without restarting running systemd services.
- `--ci-port <PORT>`: Sets custom HTTP port for CI server (default: 8888).
- `--console-port <PORT>`: Sets custom HTTP port for Demo Console (default: 8090).

---

## 4. Operational Verification

Run the built-in health check script to probe all services:
```bash
./scripts/health-check.sh
```

Expected output:
```
[+] 1/3 Checking PipeJack CI Server (port 8888)...
  [OK] CI Server is HEALTHY
[+] 2/3 Checking PipeJack Demo Console (port 8090)...
  [OK] Demo Console is HEALTHY
[+] 3/3 Checking Local Docker Registry (port 5000)...
  [OK] Docker Registry is HEALTHY (Docker Distribution API v2 operational)
```

### Demo Console Access Control & Security Hardening
The Demo Console web application (`vm2/demo/demo-console/server.py`) includes interactive terminal sessions over WebSocket endpoints (`/ws/terminal/vm1` and `/ws/terminal/vm2`). To safeguard against unauthorized command execution in shared or bridge network configurations, the following controls are enforced:

- **Client IP Subnet Restriction:** Inbound terminal WebSocket requests are restricted by default to loopback and private lab subnets: `127.0.0.0/8`, `192.168.88.0/24`, `192.168.152.0/24`, and `::1/128`. Any connection attempt from an unauthorized client IP is rejected with `HTTP 403 Forbidden`.
- **WebSocket Origin Validation:** All WebSocket upgrade requests validate the `Origin` header (when sent by browsers) against the expected host header and permitted lab subnets to prevent Cross-Site WebSocket Hijacking (CSWSH). Non-browser CLI tools and automated test clients that do not send an Origin header are accepted provided the client IP is permitted. Third-party web origins are rejected with `HTTP 403 Forbidden`.
- **Configurable Environment Variables:**
  - `PIPEJACK_ALLOWED_NETWORKS`: Comma-separated list of allowed CIDRs/IPs (default: `127.0.0.0/8,192.168.88.0/24,192.168.152.0/24,::1/128`), or `*` to disable restriction.
  - `PIPEJACK_CONSOLE_HOST`: Network interface to bind (default: `0.0.0.0`). Set to `127.0.0.1` for loopback-only access.
  - `PIPEJACK_CONSOLE_PORT`: HTTP listening port (default: `8090`).
  These variables are configured in `/etc/systemd/system/pipejack-demo-console.service`.
- **Access Check Diagnostic Endpoint:** Query `http://<VM2_IP>:8090/api/terminal/access-check` to view your client IP, current network policy, and authorization status.
- **REST API vs WebSocket Distinction:** The console binds to `0.0.0.0:8090` by default. While WebSocket terminal endpoints enforce client IP ACL and Origin checks, all REST API routes (e.g. `/api/status`, `/api/scenarios`) are unauthenticated with `Access-Control-Allow-Origin: *` to facilitate evaluation. The Demo Console is strictly intended for isolated private lab networks.
