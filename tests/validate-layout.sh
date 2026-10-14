#!/usr/bin/env bash
# PipeJack Deployment Kit — Layout and Security Validator
# Validates directory structure, required files, executable permissions, and checks for sensitive artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo " PIPEJACK DEPLOYMENT KIT — LAYOUT & INTEGRITY VALIDATOR"
echo " Target Root: $ROOT_DIR"
echo "============================================================"

FAILURES=0

# 1. Required Files Validation
REQUIRED_FILES=(
    "README.md"
    "LICENSE"
    "SECURITY.md"
    "SOURCE_MAPPING.md"
    "UPSTREAM_BASELINE.md"
    "VM2_DEPLOYMENT_AUDIT.md"
    "MANIFEST.md"
    ".gitignore"
    "config/defaults.env.example"
    "config/README.md"
    "vm1/README.md"
    "vm1/install.sh"
    "vm1/scripts/pipejack-upload.sh"
    "vm1/scripts/build-all-tarballs.sh"
    "vm1/attacks/run-all.sh"
    "vm1/attacks/01-shell-exec/build.sh"
    "vm1/security-fixtures/evil-pkg/package.json"
    "vm1/applications/banking-api/pom.xml"
    "vm1/applications/calculator-api/pom.xml"
    "vm1/applications/nodejs-app/package.json"
    "vm1/applications/python-app/requirements.txt"
    "vm2/README.md"
    "vm2/install.sh"
    "vm2/services/custom-ci/main.go"
    "vm2/services/custom-ci/attest.go"
    "vm2/services/custom-ci/quarantine_test.go"
    "vm2/core/pipejack/go.mod"
    "vm2/core/cilium-ebpf/go.mod"
    "vm2/core/golang-sys/go.mod"
    "vm2/deployment/docker/Dockerfile.app"
    "vm2/deployment/policies/policy-banking.yaml"
    "vm2/deployment/systemd/pipejack-ci.service"
    "vm2/deployment/systemd/pipejack-demo-console.service"
    "vm2/demo/demo-console/server.py"
    "vm2/demo/demo-console/prepare-demo.sh"
    "vm2/scripts/health-check.sh"
    "vm2/scripts/demo-status-helper.sh"
    "windows/setup-pipejack.ps1"
    "windows/preflight.ps1"
    "windows/verify-pipejack.ps1"
    "windows/README.md"
    "shared/README.md"
    "shared/templates/01-netplan-vm1.yaml.example"
    "shared/templates/01-netplan-vm2.yaml.example"
    "shared/templates/hosts.example"
    "tests/validate-layout.sh"
    "tests/validate-installers.sh"
    "tests/smoke-test.sh"
    "tests/test-fresh-install-blockers.sh"
    "docs/ARCHITECTURE.md"
    "docs/FRESH_INSTALL.md"
    "docs/NETWORKING.md"
    "docs/TROUBLESHOOTING.md"
    "docs/RECOVERY.md"
)

echo
echo "[+] 1/4 Checking Required Repository Files..."
for rf in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$ROOT_DIR/$rf" ]; then
        echo "  [-] MISSING REQUIRED FILE: $rf"
        FAILURES=$((FAILURES + 1))
    fi
done
if [ $FAILURES -eq 0 ]; then
    echo "  [OK] All ${#REQUIRED_FILES[@]} required root and sub-component files are present."
fi

# 2. Executable Permissions Validation
echo
echo "[+] 2/4 Checking Executable Permissions on Scripts..."
EXEC_SCRIPTS=(
    "vm1/install.sh"
    "vm1/scripts/pipejack-upload.sh"
    "vm1/scripts/build-all-tarballs.sh"
    "vm1/attacks/run-all.sh"
    "vm1/attacks/01-shell-exec/build.sh"
    "vm1/attacks/01-shell-exec/attack.sh"
    "vm1/applications/banking-api/build-tarballs.sh"
    "vm2/install.sh"
    "vm2/scripts/health-check.sh"
    "vm2/scripts/deploy-ci.sh"
    "vm2/scripts/demo-status-helper.sh"
    "vm2/demo/demo-console/prepare-demo.sh"
    "tests/validate-layout.sh"
    "tests/validate-installers.sh"
    "tests/smoke-test.sh"
    "tests/test-fresh-install-blockers.sh"
)

EXEC_FAILURES=0
for es in "${EXEC_SCRIPTS[@]}"; do
    if [ -f "$ROOT_DIR/$es" ]; then
        if [ ! -x "$ROOT_DIR/$es" ]; then
            echo "  [-] FILE NOT EXECUTABLE: $es"
            EXEC_FAILURES=$((EXEC_FAILURES + 1))
        fi
    fi
done
if [ $EXEC_FAILURES -eq 0 ]; then
    echo "  [OK] All installer, build, and test scripts have executable permissions (0755)."
else
    FAILURES=$((FAILURES + EXEC_FAILURES))
fi

# 3. Forbidden Files & Artifact Audit (No tarballs, logs, secrets, pids, __pycache__)
echo
echo "[+] 3/4 Auditing for Forbidden or Ephemeral Artifacts..."
FORBIDDEN_PATTERNS=(
    "*.tar.gz"
    "*.log"
    "*.pid"
    "*.tmp"
    ".DS_Store"
    "id_rsa"
    "id_ed25519"
    "attest-key"
)

SEC_FAILURES=0
for pat in "${FORBIDDEN_PATTERNS[@]}"; do
    # Search tracked or staged files matching pattern (excluding templates, docs, and test fixtures in cilium-ebpf)
    found=$(find "$ROOT_DIR" -type f -name "$pat" ! -path "*/.git/*" ! -path "*/docs/*" ! -path "*/shared/templates/*" ! -path "*/testdata/*" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "  [-] FORBIDDEN ARTIFACT DETECTED: $found"
        SEC_FAILURES=$((SEC_FAILURES + 1))
    fi
done

# Check for __pycache__
pycache_dirs=$(find "$ROOT_DIR" -type d -name "__pycache__" 2>/dev/null || true)
if [ -n "$pycache_dirs" ]; then
    echo "  [-] FORBIDDEN __pycache__ DIRECTORY DETECTED: $pycache_dirs"
    SEC_FAILURES=$((SEC_FAILURES + 1))
fi

if [ $SEC_FAILURES -eq 0 ]; then
    echo "  [OK] Zero forbidden ephemeral files, credentials, or caches detected."
else
    FAILURES=$((FAILURES + SEC_FAILURES))
fi

# 4. Sensitive Secret Scanning
echo
echo "[+] 4/4 Scanning for Hardcoded Secrets and Tokens..."
SECRET_PATTERNS=(
    "-----BEGIN OPENSSH PRIVATE KEY-----"
    "-----BEGIN RSA PRIVATE KEY-----"
    "ghp_[a-zA-Z0-9]{36}"
    "github_pat_[a-zA-Z0-9_]{82}"
)

TOKEN_FAILURES=0
for spat in "${SECRET_PATTERNS[@]}"; do
    match=$(grep -rnE "$spat" "$ROOT_DIR" --exclude-dir=".git" --exclude-dir="docs" --exclude="validate-layout.sh" 2>/dev/null || true)
    if [ -n "$match" ]; then
        echo "  [-] CRITICAL: Sensitive secret pattern matched: $match"
        TOKEN_FAILURES=$((TOKEN_FAILURES + 1))
    fi
done

if [ $TOKEN_FAILURES -eq 0 ]; then
    echo "  [OK] Secret scanning clean: No private keys or GitHub personal tokens found."
else
    FAILURES=$((FAILURES + TOKEN_FAILURES))
fi

echo
echo "============================================================"
if [ $FAILURES -eq 0 ]; then
    echo " [PASSED] Repository layout, file permissions, and safety checks PASSED."
    echo "============================================================"
    exit 0
else
    echo " [FAILED] $FAILURES layout or safety check failure(s) detected!"
    echo "============================================================"
    exit 1
fi
