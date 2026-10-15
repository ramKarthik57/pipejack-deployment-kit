# PipeJack — Windows PowerShell Deployment Automation

This directory contains PowerShell orchestration scripts for deploying, verifying, and recovering the PipeJack two-node Zero-Trust security platform from a Windows host machine running VMware Workstation or Hyper-V.

---

## 1. Prerequisites on Windows Host

1. **Operating System:** Windows 10 (Build 1809+) or Windows 11 (for Windows PowerShell 5.1 runtime).
2. **PowerShell Engine:**
   - **Windows PowerShell 5.1 (Built-in baseline):** All automation scripts are verified 100% compliant with PS 5.1 syntax via static AST inspection (0 syntax errors, 0 ternary operators, 0 pipeline chain operators `&&`/`||`). Native runtime execution on the Windows PowerShell 5.1 engine (`powershell.exe`) and PowerShell 7 (`pwsh`) have been validated.
   - **Pure ASCII Encoding:** All scripts are 100% pure ASCII to avoid Windows PowerShell 5.1 ANSI (CP1252) BOM-less tokenization bugs.
3. **Paths with Spaces:** All scripts support kit roots and SSH key paths containing spaces (e.g. `C:\My Projects\PipeJack Kit\` and `C:\Keys\id ed25519`) using discrete argument arrays for `ssh` and `scp`.
4. **OpenSSH Client:**
   - Verify by running `ssh.exe -V` in PowerShell.
   - If missing, enable via:
     `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`
5. **Target Virtual Machines:**
   - Two running Ubuntu VMs (VM1: `192.168.88.132`, VM2: `192.168.88.133`).
   - SSH access configured (password or Ed25519/RSA public key added to `~/.ssh/authorized_keys`).

---

## 2. Script Overview

| Script | Purpose |
| :--- | :--- |
| `fresh-install.ps1` | **Master Onboarding Entrypoint.** Guided, interactive installer that coordinates preflight, VM2 deployment first, health polling, VM1 deployment second, verification, and audit report generation outside the repo. |
| `preflight.ps1` | Verifies Windows OpenSSH tools, local repository layout, network reachability, and remote VM SSH access. |
| `setup-pipejack.ps1` | Master deployment script. Transfers role-specific kits (`vm1/` and `vm2/`), executes installers, and verifies services. |
| `verify-pipejack.ps1` | Post-deployment smoke test. Checks HTTP `:8888`, `:8090`, `:5000`, and executes a live sample upload from VM1. |

---

## 3. Quick Start: Fresh Two-VM Onboarding

Because onboarding automation (`fresh-install.ps1` and `bootstrap-network.sh`) is published on the `feat/fresh-two-vm-onboarding` branch, clone that specific branch on the Windows host:

```powershell
git clone --branch feat/fresh-two-vm-onboarding --single-branch https://github.com/ramKarthik57/pipejack-deployment-kit.git
cd pipejack-deployment-kit
powershell.exe -ExecutionPolicy Bypass -File .\windows\fresh-install.ps1
```

Or run non-interactively with explicit arguments:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\fresh-install.ps1 -NonInteractive -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133
```

> [!IMPORTANT]
> **Hard VM2 Deployment Gate:** `fresh-install.ps1` deploys VM2 first and immediately polls all three core services: CI server (`:8888`), Demo Console (`:8090`), and Docker Registry (`:5000`). If any service is unhealthy, the installer fails fast and aborts immediately without attempting VM1 deployment or verification.

### Parameters Supported by `fresh-install.ps1`:
- `-VM1_IP`: IPv4 of VM1 (default: `192.168.88.132`)
- `-VM2_IP`: IPv4 of VM2 (default: `192.168.88.133`)
- `-SSHUser`: Username on VMs (default: `ubuntu`)
- `-SSHKey`: Optional path to private SSH key (e.g. `$HOME\.ssh\id_ed25519`)
- `-SSHPort`: SSH port number (default: `22`)
- `-NonInteractive`: Runs directly with provided or default parameters without prompting
- `-DryRun`: Executes in safe, non-modifying preview mode without touching VM state
- `-InteractiveSudo`: Allocates an interactive pseudo-terminal (`ssh -t`) during installation to prompt for sudo password if passwordless sudo is not configured
- `-SkipVM1`: Skip VM1 client deployment
- `-SkipVM2`: Skip VM2 server deployment
- `-SkipVerify`: Skip post-deployment verification
- `-ReportDir`: Directory where audit logs are preserved (defaults to `$HOME\PipeJack-Reports`)

---

## 4. Component-by-Component Execution

If you prefer to run each step individually:

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

---

## 5. Post-Deployment Access

Once deployment completes:
- **Interactive Web Demo Console:** [http://192.168.88.133:8090](http://192.168.88.133:8090)
- **CI Server Health:** [http://192.168.88.133:8888/health](http://192.168.88.133:8888/health)
- **Docker Registry:** [http://192.168.88.133:5000/v2/](http://192.168.88.133:5000/v2/)
