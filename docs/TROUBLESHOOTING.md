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
| **`curl: (7) Failed to connect to 192.168.88.133 port 8888: Connection refused`** | `pipejack-ci.service` is stopped, crashed on startup, or failed to bind. | `sudo systemctl status pipejack-ci` | Check `/var/log/pipejack-ci.log`. If port 8888 is held by a stale process, kill it with `sudo fuser -k 8888/tcp` and restart service (`sudo systemctl restart pipejack-ci`). |
| **`Docker build failed: Cannot connect to the Docker daemon`** | Docker service is inactive or `pipejack-ci` user lacks group permissions. | `sudo systemctl status docker && id -nG ubuntu` | Ensure Docker is running (`sudo systemctl start docker`) and `ubuntu` is in `docker` group (`sudo usermod -aG docker ubuntu`). Ensure `SupplementaryGroups=docker` is in systemd unit. |
| **`Registry check failed: Connection refused on port 5000`** | The `registry:2` container is stopped or exited. | `docker ps -a | grep registry` | Restart registry container: `docker start registry` or re-create via `docker run -d -p 5000:5000 --restart=always --name registry registry:2`. |
| **`Build fails with: key: open /home/ubuntu/.pipejack/attest-key: permission denied`** | Incorrect permissions on the Ed25519 signing key directory or file. | `ls -la ~/.pipejack` | Key must be owned by the user running the service with mode 0600: `chmod 700 ~/.pipejack && chmod 600 ~/.pipejack/attest-key`. |
| **`Upload hangs or times out after 180 seconds`** | Maven build container downloading dependencies slowly or frozen in container. | `docker ps` | Inspect active container logs with `docker logs -f <container-id>`. Ensure VM2 has outbound internet on `ens37` for first-time Maven dependency downloads. |
| **`Demo Console: 501 Unsupported method ('HEAD')`** | Client sent HTTP HEAD request instead of GET/POST. | `curl -I http://localhost:8090/` | Python's BaseHTTP server does not implement `do_HEAD`. Use `curl -s http://localhost:8090/` or open in web browser. |
| **`Attestation chain broken / prev_hash mismatch`** | Manual modification or deletion of attestation files in `~/pipejack-attestations/`. | `cat ~/pipejack-attestations/index.json` | Regenerate index or clean ledger. Note: Do not manually edit attestation JSON files. |
| **`SSH authentication failed: Permission denied (publickey)`** | SSH key not in `~/.ssh/authorized_keys` or file permissions too open. | `ls -ld ~/.ssh ~/.ssh/authorized_keys` | Fix permissions: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`. Re-run `ssh-copy-id`. |

---

## 3. Repairing a Partially Failed Installation

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
./install.sh --ci-endpoint http://192.168.88.133:8888/upload
```
