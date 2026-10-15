# PipeJack Two-Node Network Topology & Isolation Guide

## 1. Network Topology Architecture

PipeJack is designed with a dual-network interface architecture separating administrative and package management traffic from private inter-VM security traffic:

```
[ Host Machine (Windows / VMware Workstation) ]
       │                                     │
       │ Host-Only Virtual Switch (VMnet1)   │ NAT Virtual Switch (VMnet8 / Default)
       │ Subnet: 192.168.88.0/24             │ Subnet: 192.168.152.0/24 (DHCP)
       │                                     │
       ▼                                     ▼
 ┌───────────────┐                     ┌───────────────┐
 │   VM1 Client  │                     │  VM2 Server   │
 │               │                     │               │
 │ Private IF:   │◄─── Inter-VM ──────►│ Private IF:   │
 │ 192.168.88.132│    Private Lab Net  │ 192.168.88.133│
 │               │                     │               │
 │ NAT IF:       │                     │ NAT IF:       │
 │ 192.168.152.x │                     │ 192.168.152.x │
 └───────────────┘                     └───────────────┘
```

---

## 2. Interface Responsibilities

### 1. Private Inter-VM Lab Interface (`192.168.88.0/24`)
- **Interface Name:** Typically `ens33` or `ens34` (auto-detected).
- **Static IP:** `192.168.88.132` (VM1 Client) | `192.168.88.133` (VM2 Server).
- **Traffic Carried:**
  - Streaming build archive uploads: VM1 -> VM2 (`http://192.168.88.133:8888/upload`).
  - Inter-VM SSH administration (VM1 -> VM2 passwordless Ed25519 authentication).
  - Malicious attack simulation tests: All attack payloads (out-of-band socket exfiltration, reverse shells) are targeted against or contained within this network.
- **Security Rule:** This interface must **never** have a default internet gateway. It is strictly dedicated to inter-node communication.

### 2. Management / NAT Interface (`192.168.152.0/24` or DHCP)
- **Interface Name:** Typically `ens37` or `ens38` (auto-detected).
- **Route Metric:** `101` (higher priority default gateway).
- **Traffic Carried:**
  - Ubuntu OS package updates (`apt-get install`).
  - Docker base image downloads (`maven:3.8`, `node:18`, `python:3.12`, `registry:2`).
  - Access to the Web Demo Console from the Windows host browser (`http://192.168.88.133:8090`).

---

## 3. Automated Guest Network Bootstrapper (`bootstrap-network.sh`)

To eliminate manual configuration errors and interface name guessing on fresh VMs, use `shared/bootstrap-network.sh`.

### Downloading on Fresh Ubuntu Guests

Before the repository is cloned onto the guests, obtain the script directly from the onboarding branch using `curl`:

**On VM2 (Server Orchestrator - `192.168.88.133`):**
```bash
curl -fsSL https://raw.githubusercontent.com/ramKarthik57/pipejack-deployment-kit/feat/fresh-two-vm-onboarding/shared/bootstrap-network.sh -o bootstrap-network.sh
chmod +x bootstrap-network.sh
sudo ./bootstrap-network.sh --role vm2
```

**On VM1 (Workload Client - `192.168.88.132`):**
```bash
curl -fsSL https://raw.githubusercontent.com/ramKarthik57/pipejack-deployment-kit/feat/fresh-two-vm-onboarding/shared/bootstrap-network.sh -o bootstrap-network.sh
chmod +x bootstrap-network.sh
sudo ./bootstrap-network.sh --role vm1
```

*(If the repository is already cloned locally on the guest, you can run `sudo bash shared/bootstrap-network.sh --role <vm1|vm2>` directly.)*

### Key Capabilities & Safety Guarantees:
1. **Dynamic Interface Auto-Discovery & Ambiguity Rejection:**
   Scans `/sys/class/net/*` (ignoring loopback, docker, and virtual bridges) to automatically identify which interface has the default route (NAT) and which adapter is connected to the Host-Only network.
   - **Ambiguity Guard:** If multiple non-NAT candidate interfaces exist, or if no interface holds a default IPv4 route, the script refuses to guess and aborts with exit code 1 unless explicit `--nat-iface <dev>` and `--private-iface <dev>` flags are provided.
2. **Subnet Conflict Detection:**
   Validates that the NAT interface is not mistakenly placed on `192.168.88.0/24`. If a conflict is detected, it aborts cleanly with remediation guidance before altering network settings.
3. **Automated Configuration Backup & Clean Rollback:**
   Backs up all existing `/etc/netplan/*.yaml` files to `/etc/netplan/pipejack-backup-<timestamp>/` preserving original file permissions and contents.
   - If syntax verification fails, `netplan apply` fails, or `netplan try` is rejected or times out, the script triggers an atomic rollback that restores all original files and removes temporary/disabled files without leaving `.disabled` artifacts behind.
4. **Syntax Validation & Safe Application:**
   Generates `/etc/netplan/01-pipejack-netcfg.yaml` and verifies it using `netplan generate`. In interactive sessions, it tests connectivity using `netplan try --timeout 30`. In non-interactive (`--force`) sessions, it applies after validation.
5. **Dry-Run Preview:**
   Allows previewing generated Netplan YAML without modifying host state via `--dry-run`.

---

## 4. Network Isolation and Security Invariants

### 1. Preventing Public Exposure
The PipeJack services must remain restricted to private addresses:
- **Port 8888 (`pipejack-ci`):** Ingests arbitrary code archives. Exposure to untrusted networks could allow arbitrary build execution.
- **Port 8090 (`pipejack-demo-console`):** Contains interactive WebSocket PTY terminal endpoints (`/ws/terminal/vm1` and `/ws/terminal/vm2`). Must only be accessible to authorized lab operators.
- **Port 5000 (`registry:2`):** Docker registry for internal pipeline artifacts.

### 2. VMware Virtual Network Configuration
To replicate this network in VMware Workstation / Player:
1. Open **Virtual Network Editor** (`Edit -> Virtual Network Editor`).
2. Verify or add **VMnet8** (NAT) or **VMnet1** (Host-Only).
3. If using custom subnets, update `config/defaults.env.example` and pass `--ci-endpoint` during installation:
   ```bash
   ./install.sh --ci-endpoint http://<YOUR_VM2_IP>:8888/upload
   ```

---

## 5. Port Forwarding and Remote Access Options

If you need to access the Demo Console from your host browser and the Host-Only network is not directly routable from Windows:

### Option A: Use the NAT IP Directly (Recommended)
Query the NAT interface IP on VM2:
```bash
ip -4 addr show ens37
```
If VM2's NAT IP is `192.168.152.130`, browse directly to:
```
http://192.168.152.130:8090
```

### Option B: SSH Local Port Forwarding
From your Windows host machine, forward port 8090 over SSH:
```powershell
ssh -L 8090:127.0.0.1:8090 ubuntu@192.168.152.130
```
Then open `http://localhost:8090` in your host browser.
