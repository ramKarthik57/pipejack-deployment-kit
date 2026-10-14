# PipeJack — Fresh VM Installation Guide and Acceptance Checklist

This guide provides step-by-step instructions for provisioning two clean Ubuntu virtual machines in VMware Workstation / Fusion / Player and deploying the PipeJack platform using this kit.

> [!NOTE]
> **Verification Status:** The scripts in this kit have been tested and verified against the live reference VMs. If you are deploying onto brand new, completely fresh virtual machines, follow this guide and execute the acceptance checklist at the end of this document.

---

## 1. Hardware and Resource Prerequisites

Each virtual machine should meet the following minimum resource requirements:

| Resource | VM1 (Workload Client) | VM2 (Security Orchestrator) |
| :--- | :--- | :--- |
| **vCPU** | 2 cores | 4 cores (recommended for concurrent builds) |
| **RAM** | 4 GB | 8 GB (Docker engine + JVM build container) |
| **Disk** | 20 GB | 40 GB (Docker cache + image storage) |
| **OS** | Ubuntu 24.04 LTS or 22.04 LTS (x86_64) | Ubuntu 24.04 LTS or 22.04 LTS (x86_64) |
| **Network** | 2 Network Adapters (Host-Only + NAT) | 2 Network Adapters (Host-Only + NAT) |

---

## 2. Step 1: Virtual Machine Creation in VMware

1. Open **VMware Workstation** or **VMware Player**.
2. Create two new virtual machines using the Ubuntu Server or Desktop ISO:
   - Name VM 1: `PipeJack-VM1-Client`
   - Name VM 2: `PipeJack-VM2-Server`
3. Configure **Two Network Adapters** on each VM:
   - **Network Adapter 1 (Inter-VM Private Lab Network):**
     - Select **Host-only** or a custom virtual switch (e.g., `VMnet8` / `VMnet2`).
     - Subnet: `192.168.88.0/24`.
   - **Network Adapter 2 (NAT / Management Network):**
     - Select **NAT**.
     - Provides outbound internet access for `apt-get` and Docker Hub downloads.
4. Complete Ubuntu OS installation with:
   - Username: `ubuntu`
   - Password: (Choose a secure password)
   - Enable OpenSSH Server during installation.

---

## 3. Step 2: Configure Static IP Addresses (Netplan)

On each virtual machine, configure static IP addresses on the private lab interface (`ens33`).

### On VM1:
Edit `/etc/netplan/01-netcfg.yaml` (see `shared/templates/01-netplan-vm1.yaml.example`):
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

### On VM2:
Edit `/etc/netplan/01-netcfg.yaml` (see `shared/templates/01-netplan-vm2.yaml.example`):
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
Apply:
```bash
sudo netplan apply
```

### Verify Inter-VM Reachability:
From VM1:
```bash
ping -c 2 192.168.88.133
```
From VM2:
```bash
ping -c 2 192.168.88.132
```

---

## 4. Step 3: Configure SSH Authentication

From your Windows host (or management machine):
```powershell
# Copy public key to both VMs
ssh-copy-id ubuntu@192.168.88.132
ssh-copy-id ubuntu@192.168.88.133
```
Verify passwordless login:
```powershell
ssh ubuntu@192.168.88.132 "hostname"
ssh ubuntu@192.168.88.133 "hostname"
```

Also configure inter-VM authentication from VM1 to VM2:
On VM1:
```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
ssh-copy-id ubuntu@192.168.88.133
```

---

## 5. Step 4: Automated Deployment via Windows PowerShell

From your Windows host machine:
```powershell
# Navigate to deployment kit directory
cd pipejack-deployment-kit\windows

# Run Preflight Verification
.\preflight.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133

# Execute Master Deployment
.\setup-pipejack.ps1 -VM1_IP 192.168.88.132 -VM2_IP 192.168.88.133
```

---

## 6. Step 5: Alternative Manual Installation (Without Windows)

If you prefer to deploy directly from Linux without PowerShell:

### 1. On VM2 (Server Orchestrator):
Copy the `vm2/` folder to VM2 and run:
```bash
cd vm2
chmod +x install.sh scripts/*.sh demo/demo-console/*.sh
./install.sh
```
Verify services:
```bash
./scripts/health-check.sh
```

### 2. On VM1 (Client Node):
Copy the `vm1/` folder to VM1 and run:
```bash
cd vm1
chmod +x install.sh scripts/*.sh attacks/*.sh applications/*/*.sh
./install.sh --ci-endpoint http://192.168.88.133:8888/upload
```
Activate environment:
```bash
source ~/.bashrc
```

---

## 7. Fresh Installation Acceptance Checklist

| Step # | Verification Item | Command / Test | Expected Result | Pass / Fail |
| :--- | :--- | :--- | :--- | :--- |
| **1** | VM1 Reachability | `ping -c 2 192.168.88.132` | 0% packet loss | [ ] |
| **2** | VM2 Reachability | `ping -c 2 192.168.88.133` | 0% packet loss | [ ] |
| **3** | VM2 CI Health | `curl http://192.168.88.133:8888/health` | `{"status":"ok","service":"pipejack-ci",...}` | [ ] |
| **4** | VM2 Demo Console | `curl http://192.168.88.133:8090/api/status` | `{"ci_healthy":true,"attestation_count":...}` | [ ] |
| **5** | VM2 Docker Registry | `curl http://192.168.88.133:5000/v2/` | `HTTP 200 OK` | [ ] |
| **6** | Clean Workload Build | On VM1: `upload /tmp/banking-api-clean.tar.gz` | `verdict: ALLOW`, HTTP 200, signed attestation | [ ] |
| **7** | Malicious Process Block | On VM1: `(cd ~/attacks/01-shell-exec && ./build.sh && upload /tmp/attack-01*.tar.gz)` | `verdict: BLOCK`, HTTP 403, quarantined | [ ] |
| **8** | Malicious Egress Block | On VM1: `(cd ~/attacks/02-http-exfil && ./build.sh && upload /tmp/attack-02*.tar.gz)` | `verdict: BLOCK`, HTTP 403, quarantined | [ ] |
| **9** | Filesystem Tamper Block| On VM1: `(cd ~/attacks/03-fs-tamper && ./build.sh && upload /tmp/attack-03*.tar.gz)` | `verdict: BLOCK`, Merkle root mismatch | [ ] |
| **10**| Attestation Ledger | On VM2: `ls -la ~/pipejack-attestations/` | New JSON records created and chained | [ ] |
