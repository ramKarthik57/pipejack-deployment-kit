# PipeJack Two-Node Network Topology & Isolation Guide

## 1. Network Topology Architecture

PipeJack is designed with a dual-network interface architecture separating administrative and package management traffic from private inter-VM security traffic:

```
[ Host Machine (Windows / VMware Workstation) ]
       │                                     │
       │ Host-Only Virtual Switch (VMnet8)   │ NAT Virtual Switch (VMnet1 / Default)
       │ Subnet: 192.168.88.0/24             │ Subnet: 192.168.152.0/24 (DHCP)
       │                                     │
       ▼                                     ▼
 ┌───────────────┐                     ┌───────────────┐
 │   VM1 Client  │                     │  VM2 Server   │
 │               │                     │               │
 │ ens33:        │◄─── Inter-VM ──────►│ ens33:        │
 │ 192.168.88.132│    Private Lab Net  │ 192.168.88.133│
 │               │                     │               │
 │ ens37:        │                     │ ens37:        │
 │ 192.168.152.x │                     │ 192.168.152.x │
 └───────────────┘                     └───────────────┘
```

---

## 2. Interface Responsibilities

### 1. `ens33` — Private Inter-VM Lab Network (`192.168.88.0/24`)
- **Type:** Host-Only or dedicated isolated virtual switch.
- **Traffic Carried:**
  - Streaming build archive uploads: VM1 -> VM2 (`http://192.168.88.133:8888/upload`).
  - Inter-VM SSH administration (VM1 -> VM2 passwordless Ed25519 authentication).
  - Malicious attack simulation tests: All attack payloads (out-of-band socket exfiltration, reverse shells) are targeted against or contained within this network.
- **Security Rule:** This interface should **never** have a default internet gateway. It is strictly for node-to-node communication.

### 2. `ens37` — Management / NAT Interface (`192.168.152.0/24`)
- **Type:** VMware NAT (provides default route via `192.168.152.2` with metric 101).
- **Traffic Carried:**
  - Ubuntu OS package updates (`apt-get install`).
  - Docker base image downloads (`maven:3.8`, `node:18`, `python:3.12`, `registry:2`).
  - Access to the Web Demo Console from the Windows host browser (`http://192.168.88.133:8090` or `http://192.168.152.130:8090`).

---

## 3. Network Isolation and Security Invariants

### 1. Preventing Public Exposure
The PipeJack services must remain restricted to private addresses:
- **Port 8888 (`pipejack-ci`):** Ingests arbitrary code archives. Exposure to untrusted networks could allow arbitrary build execution.
- **Port 8090 (`pipejack-demo-console`):** Contains unauthenticated WebSocket PTY terminal endpoints (`/ws/terminal/vm1` and `/ws/terminal/vm2`). Must only be accessible to authorized lab operators.
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

## 4. Port Forwarding and Remote Access Options

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
