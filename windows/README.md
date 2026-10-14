# PipeJack — Windows PowerShell Deployment Automation

This directory contains PowerShell orchestration scripts for deploying, verifying, and recovering the PipeJack two-node Zero-Trust security platform from a Windows host machine running VMware Workstation or Hyper-V.

---

## 1. Prerequisites on Windows Host

1. **Operating System:** Windows 10 (Build 1809+) or Windows 11.
2. **PowerShell:** PowerShell 5.1 (built-in) or PowerShell 7.x.
3. **OpenSSH Client:**
   - Verify by running `ssh.exe -V` in PowerShell.
   - If missing, enable via:
     `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`
4. **Target Virtual Machines:**
   - Two running Ubuntu VMs (VM1: `192.168.88.132`, VM2: `192.168.88.133`).
   - SSH access configured (password or Ed25519/RSA public key added to `~/.ssh/authorized_keys`).

---

## 2. Script Overview

| Script | Purpose |
| :--- | :--- |
| `preflight.ps1` | Verifies Windows OpenSSH, local repository layout, network reachability, and remote VM SSH access. |
| `setup-pipejack.ps1` | Master deployment script. Transfers role-specific kits (`vm1/` and `vm2/`), executes installers, and verifies services. |
| `verify-pipejack.ps1` | Post-deployment smoke test. Checks HTTP `:8888`, `:8090`, `:5000`, and executes a live sample upload from VM1. |

---

## 3. Quick Start Deployment

Open PowerShell as an Administrator or regular user with SSH access, navigate to this directory, and run:

```powershell
# 1. Run Preflight Check
.\preflight.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133

# 2. Run Dry-Run (Check Mode without changes)
.\setup-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133 -DryRun

# 3. Execute Full Deployment
.\setup-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133

# 4. Verify System
.\verify-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133
```

### Specifying SSH Key Authentication
If using a specific private key:
```powershell
.\setup-pipejack.ps1 -SSHKey "$HOME\.ssh\id_ed25519" -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133
```

### Supported Parameters
- `-VM1_IP`: IPv4 of VM1 (default: `192.168.88.132`)
- `-VM2_IP`: IPv4 of VM2 (default: `192.168.88.133`)
- `-SSHUser`: Username on VMs (default: `ubuntu`)
- `-SSHKey`: Optional path to private SSH key
- `-DryRun`: Executes in safe, non-modifying preview mode. Performs read-only preflight connectivity checks, does not transfer files, does not create or delete remote directories, does not execute installation scripts, and does not alter running services. Prints a full execution plan of what live deployment would execute.
- `-InteractiveSudo`: Allocates an interactive pseudo-terminal (`ssh -t`) during remote installation to prompt for your sudo password if passwordless sudo is not configured on the target Ubuntu nodes. If passwordless sudo is not active and `-InteractiveSudo` is omitted, the script fails fast with clear guidance.
- `-SkipVM1`: Skip VM1 client deployment
- `-SkipVM2`: Skip VM2 server deployment
- `-SkipPreflight`: Skip preflight connectivity checks
- `-Force`: Bypasses the interactive confirmation prompt

---

## 4. Post-Deployment Access

Once `setup-pipejack.ps1` completes:
- **Interactive Web Demo Console:** [http://192.168.88.133:8090](http://192.168.88.133:8090)
- **CI Server Health:** [http://192.168.88.133:8888/health](http://192.168.88.133:8888/health)
- **Docker Registry:** [http://192.168.88.133:5000/v2/](http://192.168.88.133:5000/v2/)
