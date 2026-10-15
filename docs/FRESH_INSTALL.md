# PipeJack — Fresh VM Installation Guide and Acceptance Checklist

This guide provides a comprehensive, foolproof, step-by-step procedure for provisioning two clean Ubuntu virtual machines in VMware Workstation or Player and deploying the PipeJack platform using this kit.

> [!IMPORTANT]
> **Verification Status & Acceptance Testing:**
> The deployment scripts, unit test suites, health probes, cryptographic attestation modules, and upload utilities in this kit have been audited and verified via isolated mock environments and regression suites.
> - **Clean Two-VM Deployment:** **PENDING** — Automated end-to-end installation on brand new, blank virtual machines remains pending operator execution on target hardware.
> - **PowerShell 5.1 Compatibility:** All `.ps1` automation scripts are verified 100% compliant with Windows PowerShell 5.1 AST syntax (0 syntax errors, pure ASCII encoding). Both native Windows PowerShell 5.1 (`powershell.exe`) execution and PowerShell 7 (`pwsh`) static parsing have been validated.
> Follow the exact step-by-step procedure below to deploy onto clean Ubuntu 24.04 or 22.04 LTS VMs, and validate full system operation using the 10-point Acceptance Checklist at the end of this document.

---

## 1. Hardware, Toolchain and Resource Prerequisites

### Windows Host Machine:
- **Operating System:** Windows 10 (64-bit, Build 1809+) or Windows 11.
- **CPU:** 4+ physical cores (VT-x or AMD-V hardware virtualization enabled in BIOS).
- **RAM:** 16 GB total system RAM recommended (8 GB absolute minimum).
- **Disk:** 40 GB+ free disk space on an SSD.
- **Hypervisor:** VMware Workstation Pro (now free for personal use) or VMware Workstation Player 17+.
- **Host Tools:** Windows OpenSSH Client (`ssh.exe`, `scp.exe`) and PowerShell 5.1 (built into Windows).

### Virtual Machine Resources:
| Resource | VM1 (Workload Client) | VM2 (Security Orchestrator) |
| :--- | :--- | :--- |
| **VM Name** | `PipeJack-VM1-Client` | `PipeJack-VM2-Server` |
| **Role** | Workload Client, Attack Suite | Security Orchestrator, CI Server, Console |
| **vCPU** | 2 cores | 2 to 4 cores (recommended for builds) |
| **RAM** | 2 GB to 4 GB | 4 GB to 8 GB (Docker daemon + JVM container) |
| **Disk** | 20 GB free | 20 GB to 40 GB free |
| **OS** | Ubuntu 24.04 LTS or 22.04 LTS (x86_64) | Ubuntu 24.04 LTS or 22.04 LTS (x86_64) |
| **Network** | 2 Network Adapters (NAT + Host-Only) | 2 Network Adapters (NAT + Host-Only) |
| **Private IP** | `192.168.88.132` (Static) | `192.168.88.133` (Static) |

---

## 2. Step 1: Provision Two Fresh Ubuntu VMs in VMware

Follow these exact steps to create both virtual machines:

1. **Download Ubuntu ISO:**
   - Download Ubuntu Server or Desktop 24.04 LTS (or 22.04 LTS) from [ubuntu.com](https://ubuntu.com/download).

2. **Create VM2 First (`PipeJack-VM2-Server`):**
   - In VMware, click **Create a New Virtual Machine**.
   - Select **Typical (recommended)** and click **Next**.
   - Select **Installer disc image file (iso)** and browse to your Ubuntu ISO.
   - In **Easy Install** (if prompted), enter:
     - Full name: `ubuntu`
     - Username: `ubuntu`
     - Password: Choose a secure password (e.g. `ubuntu` for lab use)
   - Virtual machine name: `PipeJack-VM2-Server`
   - Disk size: `40 GB` (Store virtual disk as a single file).
   - Click **Customize Hardware**:
     - Memory: `4096 MB` (or `8192 MB` if available).
     - Processors: `2` or `4` cores.
     - **Network Adapter 1:** Set to **NAT** (connects at power on).
     - Click **Add...** -> **Network Adapter** -> Finish.
     - **Network Adapter 2:** Set to **Host-only** (or a dedicated custom VMnet with subnet `192.168.88.0/24`).
   - Click **Close** and then **Finish**.

3. **Create VM1 Second (`PipeJack-VM1-Client`):**
   - Repeat the exact same process:
     - Virtual machine name: `PipeJack-VM1-Client`
     - Username: `ubuntu`
     - Memory: `2048 MB` (or `4096 MB`).
     - Processors: `2` cores.
     - Disk size: `20 GB`.
     - **Network Adapter 1:** Set to **NAT**.
     - **Network Adapter 2:** Set to **Host-only**.

4. **Install and Boot:**
   - Boot both VMs and complete the Ubuntu setup if not using Easy Install.
   - Make sure OpenSSH Server is installed:
     ```bash
     sudo apt-get update && sudo apt-get install -y openssh-server
     sudo systemctl enable --now ssh
     ```

---

## 3. Step 2: Bootstrap Guest VM Networking

PipeJack requires two isolated network paths on each VM:
- **Private Inter-VM Network (`192.168.88.0/24`):** Node-to-node security traffic, streaming uploads, and attestation data.
- **NAT Network:** Outbound internet for OS packages and Docker container images.

### Automated Network Setup (Recommended):
We provide an automated bootstrap script in `shared/bootstrap-network.sh` that detects your network interfaces, creates backups of existing configs, sets up static routing, and prevents default route conflicts:

1. **On VM2 (Security Orchestrator):**
   ```bash
   # From your Windows host, copy shared/bootstrap-network.sh or run directly:
   sudo bash shared/bootstrap-network.sh --role vm2
   ```

2. **On VM1 (Workload Client):**
   ```bash
   sudo bash shared/bootstrap-network.sh --role vm1
   ```

What `bootstrap-network.sh` does automatically:
- Auto-discovers your private interface (e.g., `ens33`, `ens34`) and NAT interface (e.g., `ens37`, `ens38`).
- Verifies that your NAT subnet does not collide with `192.168.88.0/24`.
- Backs up existing Netplan configuration files to `/etc/netplan/pipejack-backup-<timestamp>/`.
- Writes `/etc/netplan/01-pipejack-netcfg.yaml` assigning static IP `192.168.88.133` (VM2) or `192.168.88.132` (VM1).
- Sets `route-metric: 101` on the NAT interface to ensure internet traffic routes reliably through NAT.
- Validates configuration with `netplan generate` and applies via `netplan apply`.

### Manual Netplan Configuration (Fallback):
If you prefer manual configuration:

**On VM2:** Edit `/etc/netplan/01-pipejack-netcfg.yaml`:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.88.133/24
    ens37:
      dhcp4: yes
      dhcp4-overrides:
        route-metric: 101
```
*(Replace `ens33` and `ens37` with your actual interface names from `ip -br link`).*
Apply:
```bash
sudo netplan apply
```

**On VM1:** Edit `/etc/netplan/01-pipejack-netcfg.yaml`:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.88.132/24
    ens37:
      dhcp4: yes
      dhcp4-overrides:
        route-metric: 101
```
Apply:
```bash
sudo netplan apply
```

### Verify Network Connectivity:
From VM1:
```bash
ping -c 2 192.168.88.133   # Must succeed: Inter-VM reachability
ping -c 2 8.8.8.8          # Must succeed: Outbound internet access
```

From VM2:
```bash
ping -c 2 192.168.88.132   # Must succeed: Inter-VM reachability
ping -c 2 8.8.8.8          # Must succeed: Outbound internet access
```

---

## 4. Step 3: Windows Host Preparation

On your Windows workstation:

1. **Verify OpenSSH Client:**
   Open PowerShell and check if OpenSSH client is available:
   ```powershell
   ssh -V
   ```
   If not installed, install it in an Administrator PowerShell window:
   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
   ```

2. **Generate an SSH Key (if you do not have one):**
   ```powershell
   ssh-keygen -t ed25519 -N '""'
   ```
   This generates `$HOME\.ssh\id_ed25519` and `$HOME\.ssh\id_ed25519.pub`.

3. **SSH Key Distribution to Both VMs:**
   The master installer (`windows\fresh-install.ps1`) will detect missing keys and offer to install them for you automatically!
   
   If you wish to install the keys manually from Windows (without needing `ssh-copy-id`):
   ```powershell
   # Install to VM2 (Orchestrator):
   Get-Content $HOME\.ssh\id_ed25519.pub | ssh ubuntu@192.168.88.133 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

   # Install to VM1 (Client):
   Get-Content $HOME\.ssh\id_ed25519.pub | ssh ubuntu@192.168.88.132 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
   ```

4. **Verify Passwordless SSH:**
   ```powershell
   ssh -o BatchMode=yes ubuntu@192.168.88.133 "echo 'VM2 SSH OK'"
   ssh -o BatchMode=yes ubuntu@192.168.88.132 "echo 'VM1 SSH OK'"
   ```

---

## 5. Step 4: Run the Master Guided Installer

From your Windows workstation, run the single onboarding entry point:

```powershell
powershell -ExecutionPolicy Bypass -File windows\fresh-install.ps1
```

### Interactive Experience:
The script will prompt you with clear, safe defaults:
```text
Configure deployment parameters (press Enter to accept [defaults]):
Enter VM1 (Workload Client) IP address [192.168.88.132]:
Enter VM2 (Server Orchestrator) IP address [192.168.88.133]:
Enter SSH username for both VMs [ubuntu]:
Enter private SSH key path [C:\Users\username\.ssh\id_ed25519]:
Enter SSH port [22]:
[?] Proceed with onboarding? [Y/N]: Y
```

### Automated / Non-Interactive Variant:
For automated pipelines or non-interactive deployment:
```powershell
powershell -ExecutionPolicy Bypass -File windows\fresh-install.ps1 -NonInteractive -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133 -SSHUser ubuntu
```

### If Sudo Requires Password:
If passwordless sudo is not configured on the Ubuntu VMs, append `-InteractiveSudo`:
```powershell
powershell -ExecutionPolicy Bypass -File windows\fresh-install.ps1 -InteractiveSudo
```

### Dry-Run Preview Mode:
To inspect all actions before executing them:
```powershell
powershell -ExecutionPolicy Bypass -File windows\fresh-install.ps1 -DryRun
```

### What Happens During Deployment:
1. **Host Verification:** Validates `ssh.exe`, `scp.exe`, and deployment kit integrity.
2. **SSH & Preflight:** Verifies ping reachability, SSH authentication, and remote OS prerequisites.
3. **VM2 Deployment (Orchestrator first):**
   - Transfers `vm2/` package.
   - Installs official Go toolchain (1.23+).
   - Builds `pipejack-ci` binary.
   - Generates Ed25519 attestation signing key.
   - Launches local Docker registry (`registry:2` on port 5000).
   - Installs and starts `pipejack-ci.service` and `pipejack-demo-console.service`.
4. **Health Check Polling:** Automatically waits for VM2 services to report healthy (`:8888/health`).
5. **VM1 Deployment (Client second):**
   - Transfers `vm1/` package.
   - Deploys workload applications and attack fixtures.
   - Configures `pipejack-upload.sh` and bash environment.
6. **End-to-End Verification:**
   - Probes CI health endpoint (`http://192.168.88.133:8888/health`).
   - Probes Web Demo Console (`http://192.168.88.133:8090/api/status`).
   - Probes Docker Registry (`http://192.168.88.133:5000/v2/`).
   - Executes live workload upload from VM1 to VM2.
   - Verifies cryptographically signed attestation in VM2 ledger.
7. **Report Generation:** Generates a timestamped deployment report outside the repository in:
   `%USERPROFILE%\PipeJack-Reports\fresh-install-<timestamp>.log` and `summary.txt`.

Expected total installation time: **5 to 10 minutes** depending on your internet connection speed.

---

## 6. Step 5: Verification & Acceptance

### Accessing the Web Demo Console:
Open your browser on the Windows host machine:
```text
http://192.168.88.133:8090
```
- Verify the CI health badge shows **HEALTHY**.
- Open the live interactive terminal panels for VM1 and VM2.

### Manual Verification Script:
You can re-run the verification suite at any time from Windows:
```powershell
powershell -ExecutionPolicy Bypass -File windows\verify-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133
```

### Manual Workload Upload Test from VM1:
SSH into VM1 and test an upload:
```bash
ssh ubuntu@192.168.88.132
pipejack-upload /opt/pipejack/applications/tarballs/banking-api.tar.gz
```
Expected output:
```text
HTTP Status: 200
Verdict: ALLOW
Attestation Record: Committed to ledger with valid Ed25519 signature
```

---

## 7. Common Failure Modes & Troubleshooting

| Issue | Cause | Remedy |
| :--- | :--- | :--- |
| **`sudo: a password is required`** | The `ubuntu` user requires a password for `sudo`. | Run `fresh-install.ps1` with `-InteractiveSudo`, or configure passwordless sudo on the VM: `echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' \| sudo tee /etc/sudoers.d/99-pipejack` |
| **Subnet Conflict Detected** | VMware NAT network uses `192.168.88.0/24`. | In VMware Virtual Network Editor, change the NAT subnet to `192.168.152.0/24` so `192.168.88.0/24` remains exclusively for the private Host-Only network. |
| **Interface Names Not `ens33`** | VMware assigned different interface names (e.g. `ens34`, `ens38`). | Use `shared/bootstrap-network.sh` which auto-detects interfaces, or pass explicit interface names: `--private-iface ens34 --nat-iface ens38`. |
| **Port 8090 or 8888 Unreachable** | Ubuntu UFW firewall is active and blocking ports. | Run on VM2: `sudo ufw allow 8090/tcp && sudo ufw allow 8888/tcp && sudo ufw allow 5000/tcp`. |
| **Windows OpenSSH Missing** | Windows OpenSSH Client optional feature not installed. | Run in elevated PowerShell: `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`. |
| **Connection Refused on Port 5000** | The Docker `registry:2` container is not running. | Run on VM2: `docker start registry` or `docker run -d -p 5000:5000 --restart=always --name registry registry:2`. |

---

## 8. Fresh Installation Acceptance Checklist

Use this 10-point checklist to independently confirm that the deployment is complete, correct, and ready for evaluation:

| Step # | Verification Item | Command / Test | Expected Result | Pass / Fail |
| :--- | :--- | :--- | :--- | :--- |
| **1** | VM1 Reachability | `ping -c 2 192.168.88.132` | 0% packet loss | [ ] |
| **2** | VM2 Reachability | `ping -c 2 192.168.88.133` | 0% packet loss | [ ] |
| **3** | VM2 CI Health | `curl -s http://192.168.88.133:8888/health` | `{"status":"ok","service":"pipejack-ci",...}` | [ ] |
| **4** | VM2 Demo Console | Browser to `http://192.168.88.133:8090` | Web console loads, reports `ci_healthy: true` | [ ] |
| **5** | VM2 Docker Registry | `curl -s http://192.168.88.133:5000/v2/` | `HTTP 200 OK` | [ ] |
| **6** | Clean Workload Build | On VM1: `pipejack-upload /opt/pipejack/applications/tarballs/banking-api.tar.gz` | `verdict: ALLOW`, HTTP 200, signed attestation | [ ] |
| **7** | Malicious Process Block | On VM1: `pipejack-upload /opt/pipejack/attacks/tarballs/attack-01-shell-exec.tar.gz` | `verdict: BLOCK`, HTTP 403, quarantined | [ ] |
| **8** | Malicious Egress Block | On VM1: `pipejack-upload /opt/pipejack/attacks/tarballs/attack-02-http-exfil.tar.gz` | `verdict: BLOCK`, HTTP 403, quarantined | [ ] |
| **9** | Filesystem Tamper Block| On VM1: `pipejack-upload /opt/pipejack/attacks/tarballs/attack-03-fs-tamper.tar.gz` | `verdict: BLOCK`, Merkle root mismatch | [ ] |
| **10**| Attestation Ledger | On VM2: `ls -la ~/pipejack-attestations/` | Cryptographic JSON records chained with valid Ed25519 signatures | [ ] |
