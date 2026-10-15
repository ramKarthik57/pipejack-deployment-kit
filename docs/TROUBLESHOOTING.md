# PipeJack Troubleshooting Guide and Diagnostic Matrix

## 1. Quick Diagnostic Checklist

When encountering issues with the PipeJack deployment, execute these triage commands on the respective virtual machines:

### On VM2 (Server Orchestrator):
```bash
# 1. Run Built-in Health Probe
/home/ubuntu/pipejack-deployment-kit/vm2/scripts/health-check.sh

# 2. Check Systemd Units
sudo systemctl status pipejack-ci.service --no-pager
sudo systemctl status pipejack-demo-console.service --no-pager

# 3. Check Live Logs
sudo tail -n 50 /var/log/pipejack-ci.log
tail -n 50 /home/ubuntu/pipejack-demo-console/console.log

# 4. Check Docker Containers & Registry
docker ps -a
curl -s http://127.0.0.1:5000/v2/
```

### On VM1 (Client Node):
```bash
# 1. Test Network Reachability to VM2
ping -c 2 192.168.88.133
curl -s http://192.168.88.133:8888/health

# 2. Verify Upload Aliases and Environment
echo $CI_ENDPOINT
which upload
```

---

## 2. Common Symptoms and Resolutions Matrix

| Symptom / Error Message | Likely Cause | Exact Diagnostic Command | Remediation Action |
| :--- | :--- | :--- | :--- |
| **`sudo: a password is required`** | Remote user requires password for sudo; script cannot escalate non-interactively. | Run on VM: `sudo -n true` (exits 1 if password needed) | Either run `fresh-install.ps1` or `setup-pipejack.ps1` with `-InteractiveSudo` to enter your password interactively, or configure passwordless sudo on the VM: `echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' \| sudo tee /etc/sudoers.d/99-pipejack`. |
| **`OpenSSH client tools (ssh, scp) were not found`** | Windows OpenSSH Client optional feature is not installed. | In PowerShell: `Get-Command ssh.exe` | Run in an elevated PowerShell: `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`. |
| **`ssh-copy-id : The term 'ssh-copy-id' is not recognized`** | Windows does not include the Unix `ssh-copy-id` utility. | In PowerShell: `ssh-copy-id` | `fresh-install.ps1` automatically detects and installs public keys. To copy manually from Windows: `Get-Content ~/.ssh/id_ed25519.pub \| ssh user@vm "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"`. |
| **`Subnet conflict detected: NAT interface on 192.168.88.0/24`** | VMware NAT network was assigned the same subnet as the private lab. | Run `ip -4 addr` | Open VMware Virtual Network Editor and change the NAT subnet to `192.168.152.0/24` so `192.168.88.0/24` is used exclusively for the Host-Only network. |
| **`Interface ens33 does not exist`** | Ubuntu assigned a different network adapter name (e.g. `ens34`, `ens38`). | Run `ip -br link` | Run `sudo bash shared/bootstrap-network.sh --role <vm1\|vm2>`, which auto-detects physical adapters. |
| **`curl: (7) Failed to connect to 192.168.88.133 port 8888: Connection refused`** | `pipejack-ci.service` is stopped, crashed on startup, or failed to bind. | `sudo systemctl status pipejack-ci` | Check `/var/log/pipejack-ci.log`. If port 8888 is held by a stale process, kill it with `sudo fuser -k 8888/tcp` and restart service (`sudo systemctl restart pipejack-ci`). |
| **`Port 8090, 8888, or 5000 connection timed out`** | Ubuntu UFW firewall is active and blocking traffic. | `sudo ufw status` | Allow required ports: `sudo ufw allow 8090/tcp && sudo ufw allow 8888/tcp && sudo ufw allow 5000/tcp`. |
| **`Docker build failed: Cannot connect to the Docker daemon`** | Docker service is inactive or `pipejack-ci` user lacks group permissions. | `sudo systemctl status docker && id -nG ubuntu` | Ensure Docker is running (`sudo systemctl start docker`) and `ubuntu` is in `docker` group (`sudo usermod -aG docker ubuntu`). Ensure `SupplementaryGroups=docker` is in systemd unit. |
| **`Registry check failed: Connection refused on port 5000`** | The `registry:2` container is stopped or exited. | `docker ps -a \| grep registry` | Restart registry container: `docker start registry` or re-create via `docker run -d -p 5000:5000 --restart=always --name registry registry:2`. |
| **`Build fails with: key: open /home/ubuntu/.pipejack/attest-key: permission denied`** | Incorrect permissions on the Ed25519 signing key directory or file. | `ls -la ~/.pipejack` | Key must be owned by the user running the service with mode 0600: `chmod 700 ~/.pipejack && chmod 600 ~/.pipejack/attest-key`. |
| **`Upload hangs or times out after 180 seconds`** | Maven build container downloading dependencies slowly or frozen in container. | `docker ps` | Inspect active container logs with `docker logs -f <container-id>`. Ensure VM2 has outbound internet on NAT for first-time Maven dependency downloads. |
| **`Demo Console: 501 Unsupported method ('HEAD')`** | Client sent HTTP HEAD request instead of GET/POST. | `curl -I http://localhost:8090/` | Python's BaseHTTP server does not implement `do_HEAD`. Use `curl -s http://localhost:8090/` or open in web browser. |
| **`Attestation chain broken / prev_hash mismatch`** | Manual modification or deletion of attestation files in `~/pipejack-attestations/`. | `cat ~/pipejack-attestations/index.json` | Regenerate index or clean ledger. Note: Do not manually edit attestation JSON files. |
| **`SSH authentication failed: Permission denied (publickey)`** | SSH key not in `~/.ssh/authorized_keys` or file permissions too open. | `ls -ld ~/.ssh ~/.ssh/authorized_keys` | Fix permissions: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`. |

---

## 3. Where to Find Deployment Logs and Reports

All automated onboarding runs using `windows\fresh-install.ps1` preserve full diagnostic transcripts outside the Git repository:

- **Log File Directory:** `%USERPROFILE%\PipeJack-Reports\` (e.g. `C:\Users\<username>\PipeJack-Reports\`)
- **Detailed Session Log:** `fresh-install-YYYYMMDD-HHmmss.log`
- **Summary Report:** `fresh-install-YYYYMMDD-HHmmss-summary.txt`

Review these files if any deployment step fails to pinpoint the exact failing command and exit code.

---

## 4. Repairing a Partially Failed Installation

If an installation was interrupted (e.g., due to network disruption or reboot):

### On VM2:
```bash
cd /home/ubuntu/pipejack-deployment-kit/vm2
# Re-run the installer safely; it is fully idempotent
sudo ./install.sh
```

### On VM1:
```bash
cd /home/ubuntu/pipejack-deployment-kit/vm1
# Re-run the client installer safely
./install.sh --ci-endpoint http://192.168.88.133:8888/upload
```
