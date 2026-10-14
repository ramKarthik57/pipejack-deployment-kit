# PipeJack Recovery and Disaster Recovery Procedures

## 1. Principles of Recovery

1. **Idempotence:** The installer scripts (`vm1/install.sh` and `vm2/install.sh`) are designed to be rerun without causing destructive data loss or corrupting existing configurations.
2. **Key Material Preservation:** The signing key (`~/.pipejack/attest-key`) and attestation records (`~/pipejack-attestations/`) represent the cryptographic history of the node. Reinstallation must never overwrite them unless explicitly instructed.
3. **Container State Recovery:** Build containers in PipeJack are disposable by design; application state is stored as images in the local Docker registry (`localhost:5000`).

---

## 2. Recovery Scenarios and Step-by-Step Actions

### Scenario 1: Resetting the Attestation Ledger
If test runs generated invalid or corrupt attestation chains and you wish to start a clean ledger:
```bash
# 1. Stop CI Server
sudo systemctl stop pipejack-ci.service

# 2. Archive existing attestation records
tar -czf ~/pipejack-attestations-backup-$(date +%s).tar.gz ~/pipejack-attestations/

# 3. Clear attestation records while retaining the directory
rm -rf ~/pipejack-attestations/*.json

# 4. Restart CI Server (creates fresh index.json on next build)
sudo systemctl start pipejack-ci.service
```

### Scenario 2: Regenerating the Ed25519 Signing Key
If the private key is lost or compromised:
```bash
# 1. Stop CI service
sudo systemctl stop pipejack-ci.service

# 2. Back up old key if present
mv ~/.pipejack/attest-key ~/.pipejack/attest-key.bak-$(date +%s) 2>/dev/null || true

# 3. Generate a new key pair
python3 -c "
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
priv = ed25519.Ed25519PrivateKey.generate()
with open('/home/ubuntu/.pipejack/attest-key', 'wb') as f:
    f.write(priv.private_bytes_raw())
with open('/home/ubuntu/.pipejack/attest-key.pub', 'w') as f:
    f.write(priv.public_key().public_bytes_raw().hex())
"
chmod 600 ~/.pipejack/attest-key
chmod 644 ~/.pipejack/attest-key.pub

# 4. Restart CI service
sudo systemctl start pipejack-ci.service
```

### Scenario 3: Cleaning Docker Containers and Quarantined Images
If disk space on VM2 becomes constrained due to accumulated build layers and quarantined images:
```bash
# 1. Remove stopped build containers
docker container prune -f

# 2. Remove dangling image layers
docker image prune -f

# 3. Remove quarantined test images
docker images | grep quarantine | awk '{print $3}' | xargs -r docker rmi -f || true
```

---

## 3. What the Deployment Kit Does NOT Automate

To maintain host safety and avoid unexpected hardware or virtualization changes:
1. **VMware Virtual Machine Creation:** The deployment kit does **not** create or reconfigure VMware `.vmx` files or virtual disks. You must provision two basic Ubuntu virtual machines.
2. **Host Network Routing:** The deployment kit does **not** alter Windows host route tables or VMware virtual network adapters.
3. **Public Cloud / Production Secret Management:** The kit does **not** integrate with HashiCorp Vault or AWS KMS; keys are managed locally within the lab environment.
