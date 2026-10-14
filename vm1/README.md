# PipeJack VM1 — Developer Workload & Attack Client

This directory contains the files, applications, security fixtures, attack suites, and automated installer for **VM1** (the client/developer machine).

---

## 1. Architectural Role

VM1 functions as the lightweight client machine in the PipeJack two-node topology:
- **Default IP Address:** `192.168.88.132`
- **Responsibilities:**
  - Developing and hosting application workloads (`banking-api`, `calculator-api`, `nodejs-app`, `python-app`).
  - Housing adversarial attack regression suites (Scenarios 01 through 07 in `attacks/`).
  - Packaging workloads into tarballs dynamically via `build-all-tarballs.sh` or individual `build.sh` scripts.
  - Streaming build archives to VM2 via `pipejack-upload.sh`.
- **Deliberate Design Constraint:**
  - VM1 does **not** host Docker, Java, Maven, or the PipeJack CI daemon.
  - All container compilation, policy enforcement, eBPF telemetry, and image signing occur isolated on VM2.

---

## 2. Directory Layout

```
vm1/
├── README.md                 # This documentation
├── install.sh                # Automated VM1 installer script
├── applications/             # Workload reference applications
│   ├── banking-api/          # Java 17 Spring Boot banking service
│   ├── calculator-api/       # Java Spring Boot AST calculator service
│   ├── nodejs-app/           # Node.js 18 Express sample checkout app
│   └── python-app/           # Python 3.12 Flask fraud inference app
├── attacks/                  # 7 Adversarial attack scenarios & runner
│   ├── 01-shell-exec/        # Unauthorized shell execution
│   ├── 02-http-exfil/        # Out-of-band network socket exfiltration
│   ├── 03-fs-tamper/         # Build-time filesystem tampering
│   ├── 04-base64-shell/      # Encoded evasion payload
│   ├── 05-multi-stage/       # Correlated multi-sensor attack
│   ├── 06-slow-exfil/        # Rate-limited egress channel
│   ├── 07-anomaly/           # Statistical variance injection
│   ├── README.md             # Attack documentation
│   └── run-all.sh            # Master regression test runner
├── security-fixtures/        # Reusable attack fixtures
│   ├── evil-pkg/             # NPM postinstall hook backdoor fixture
│   ├── nodejs-malicious/     # Node.js supply-chain exfil fixture
│   ├── python-malicious/     # Python setup.py socket exfil fixture
│   └── vuln-app/             # Vulnerability testbed fixture
├── scripts/
│   ├── pipejack-upload.sh    # ANSI streaming multipart uploader
│   └── build-all-tarballs.sh # Tarball generator for all 15 workload/attack fixtures
└── config/
    ├── vm1.env.example       # Example environment variables
    └── bashrc.snippet        # Aliases and shell exports
```

> [!NOTE]
> **Archive Generation Dependencies:** While VM1 is configured as a lightweight developer client that can host and upload prebuilt archives, regenerating all 15 workload and attack tarballs from scratch using `build-all-tarballs.sh` requires `default-jdk` (Java 17+), `maven`, and `npm` on the machine running the builder. Individual bash/python fixtures do not require Java.


---

## 3. Installation Instructions

### Automated Installation
Run the installer directly on VM1:
```bash
# Check mode / preflight dry-run
./install.sh --dry-run

# Full installation targeting default CI endpoint (192.168.88.133:8888)
./install.sh

# Or specify a custom VM2 CI endpoint
./install.sh --ci-endpoint http://192.168.88.133:8888/upload
```

### Options
- `--dry-run`: Preflight check only; verifies OS, disk, and network reachability without writing changes.
- `--ci-endpoint <URL>`: Points `pipejack-upload.sh` to your VM2 CI server.
- `--target-dir <DIR>`: Sets installation directory (defaults to `$HOME`).
- `--skip-build`: Skips pre-generating tarballs in `/tmp`.

---

## 4. Usage Workflow

1. **Activate Shell Aliases:**
   ```bash
   source ~/.bashrc
   ```
2. **Build and Upload a Clean Application:**
   ```bash
   upload /tmp/banking-api-clean.tar.gz
   # Expected result: HTTP 200 ALLOW with signed attestation digest
   ```
3. **Execute the Full Adversarial Regression Suite:**
   ```bash
   cd ~/attacks
   ./run-all.sh
   # Expected result: Scenarios 01-06 blocked (HTTP 403), Scenario 07 anomaly warning
   ```
