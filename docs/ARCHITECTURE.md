# PipeJack Architecture and Pipeline Lifecycle Specification

## 1. System Overview

PipeJack is a Zero-Trust CI/CD pipeline security architecture designed to detect, block, quarantine, and attest software supply-chain compromises in real time during the build execution phase.

```
┌────────────────────────────────────────┐       ┌──────────────────────────────────────────────────┐
│   VM1 — Developer / Workload Client    │       │     VM2 — Security Orchestrator & Attestation     │
│   (192.168.88.132)                     │       │     (192.168.88.133)                             │
│                                        │       │                                                  │
│   • Workload Sources (Java, Node, Py)  │       │   • PipeJack CI Server (:8888)                   │
│   • Adversarial Attacks (01 - 07)      │       │     - Multipart Streaming Ingestion              │
│   • Ephemeral Archive Builders         │       │     - Containerized Isolated Build Runner        │
│   • pipejack-upload.sh Utility         │       │     - Policy Decision Point (PDP)                │
│                                        │       │   • Multi-Sensor Kernel Instrumentation:         │
│                                        │       │     - Process Tree Differ (cgroup v2)            │
│                                        │       │     - Filesystem Baseline Merkle Differ          │
│                                        │       │     - Network Socket Egress Filter               │
│                                        │       │     - Statistical Anomaly Engine                 │
│                                        │       │   • Local Docker Registry (:5000)                │
│                                        │       │   • Ed25519 Attestation Ledger (~/pipejack-attest)│
│                                        │       │   • Interactive Web Demo Console (:8090)         │
└──────────────────┬─────────────────────┘       └─────────────────────────┬────────────────────────┘
                   │                                                       │
                   │  1. HTTP Multipart POST /upload (tarball stream)      │
                   ├──────────────────────────────────────────────────────►│
                   │                                                       │
                   │  2. Build execution, sensor trace, attestation sign   │
                   │     (Maven / npm / pip inside ephemeral container)    │
                   │                                                       │
                   │  3. HTTP 200 (ALLOW) or HTTP 403 (BLOCK / Quarantine) │
                   │◄──────────────────────────────────────────────────────┤
                   │                                                       │
                   ▼                                                       ▼
```

---

## 2. End-to-End Pipeline Lifecycle

1. **Package Creation (VM1):**
   - The developer or attack script compiles the workload into an in-memory or ephemeral gzip tarball (`/tmp/*.tar.gz`).
   - Archives contain application sources, dependency manifests (`pom.xml`, `package.json`, `requirements.txt`), and optional build hooks.
2. **Streaming Ingestion (VM1 -> VM2):**
   - `pipejack-upload.sh` streams the archive via HTTP multipart POST to `http://192.168.88.133:8888/upload`.
   - The CI engine streams ANSI status frames back to the client terminal in real time.
3. **Workspace Isolation & Baseline Snapshotting (VM2):**
   - The CI server allocates a clean workspace under `/tmp/pipejack-<build-id>`.
   - The archive is extracted with path sanitization (guarding against directory traversal).
   - **Pre-Build Merkle Tree:** `fschecker` walks the workspace directory and computes a cryptographic SHA256 Merkle root.
4. **Instrumented Build Execution (VM2):**
   - An isolated build container (e.g. `maven:3.8-eclipse-temurin-17`, `node:18`, or `python:3.12`) is spawned.
   - The workspace is mounted into the container.
   - Concurrently, the PipeJack sensor sidecar attaches to the container's cgroup v2 hierarchy and network namespace.
5. **Multi-Sensor Security Trace (VM2):**
   - **Process Differ:** Tracks all `execve` events within the container cgroup. Flags unauthorized shells (`/bin/sh`, `/bin/bash`), network tools (`curl`, `nc`, `wget`), or untracked child processes.
   - **Network Filter:** Monitors all socket connect requests. Flags unauthorized egress attempts to external or non-whitelisted destinations (such as `10.255.255.1:80`).
   - **Filesystem Differ:** Walks the workspace post-build and calculates the post-build Merkle root. Identifies injected backdoors, AST mutations, or altered build artifacts.
   - **Anomaly Detector:** Evaluates execution metrics against rolling statistical baselines (Z-score calculation).
6. **Policy Decision Point (PDP) Evaluation (VM2):**
   - Declarative policy rules loaded from `/home/ubuntu/custom-ci/policy-<lang>.yaml` are evaluated against the sensor findings.
   - If any violation is found under `PIPEJACK_ENFORCE=1`:
     - **Verdict:** `BLOCK`
     - **Action:** If quarantine is enabled, the compromised build container is committed and pushed to the local registry with tag `<image>:<build-id>-quarantine`. The container is never deployed.
     - **Response:** HTTP 403 Forbidden with diagnostic error JSON.
   - If no violations are found:
     - **Verdict:** `ALLOW`
     - **Action:** The verified image is tagged and pushed to the local registry (`localhost:5000/<app>:<build-id>`) and deployed.
     - **Response:** HTTP 200 OK with build ID and attestation metadata.
7. **Cryptographic Attestation Chaining (VM2):**
   - An immutable JSON attestation record is generated containing:
     - `build_id`, `timestamp`, `project`
     - `pre_merkle` and `post_merkle` SHA256 hashes
     - Process, filesystem, and network violation lists
     - `prev_hash` (forming an append-only cryptographic hash chain)
     - `self_hash` (SHA256 of canonical representation)
     - `signature` (Ed25519 signature generated with local private key)
   - Recorded in `/home/ubuntu/pipejack-attestations/<build-id>.json`.

---

## 3. Core Component Subsystems

### 1. `core/pipejack/proctree`
Provides process tree difference detection. Inspects `/sys/fs/cgroup/` scopes to enumerate all active processes belonging to a build container. Normalizes binary paths, matches against permitted compiler toolchain allowlists, and extracts anomalous process spawns.

### 2. `core/pipejack/fschecker`
Builds deterministic Merkle trees of source directories. Ignores expected ephemeral build output directories (e.g., `target/`, `node_modules/`, `__pycache__/`) while detecting unauthorized mutations to source code, configurations, or binary dependencies.

### 3. `core/pipejack/internal/pdp`
The Policy Decision Point parses YAML specifications containing:
- `allowed_processes`: Whitelist of valid executables (e.g., `mvn`, `javac`, `node`, `python3`).
- `forbidden_processes`: Explicitly blocked binaries (e.g., `curl`, `sh`, `bash`, `nc`).
- `network_egress`: Permitted outbound destinations (default: none / loopback only).
- `actions_on_violation`: Quarantine and blocking rules.

### 4. `demo/demo-console`
The web console provides a browser interface for running demonstrations, monitoring running containers, inspecting attestation chains, and viewing active process trees.
