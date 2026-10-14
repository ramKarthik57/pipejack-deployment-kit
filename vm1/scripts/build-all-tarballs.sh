#!/usr/bin/env bash
# PipeJack VM1 — Dynamic Workload and Attack Tarball Generator
# Builds all clean and malicious tarballs dynamically without committing archives to git.
# Fails honestly if any builder fails or any expected archive is missing or corrupted.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo " PIPEJACK VM1 — DYNAMIC ARCHIVE GENERATION"
echo " Base Directory: $BASE_DIR"
echo "============================================================"

# List of expected generated archives
EXPECTED_ARCHIVES=(
    "/tmp/banking-api-clean.tar.gz"
    "/tmp/banking-api-malicious.tar.gz"
    "/tmp/calculator-api.tar.gz"
    "/tmp/nodejs-app-clean.tar.gz"
    "/tmp/python-app-clean.tar.gz"
    "/tmp/nodejs-app-malicious.tar.gz"
    "/tmp/python-app-malicious.tar.gz"
    "$BASE_DIR/security-fixtures/evil-pkg/evil-pkg-1.0.0.tgz"
    "/tmp/attack-01-shell-exec.tar.gz"
    "/tmp/attack-02-http-exfil.tar.gz"
    "/tmp/attack-03-fs-tamper.tar.gz"
    "/tmp/attack-04-base64-shell.tar.gz"
    "/tmp/attack-05-multi-stage.tar.gz"
    "/tmp/attack-06-slow-exfil.tar.gz"
    "/tmp/attack-07-anomaly.tar.gz"
)

# Clean only target files that will be generated (do not delete unrelated files in /tmp)
for arch in "${EXPECTED_ARCHIVES[@]}"; do
    rm -f "$arch"
done

FAILURES=0

run_builder() {
    local label="$1"
    local dir="$2"
    local cmd="$3"
    local log_file
    log_file=$(mktemp)

    echo -n "  -> $label: "
    if (cd "$dir" && $cmd > "$log_file" 2>&1); then
        echo "OK"
        rm -f "$log_file"
        return 0
    else
        local ec=$?
        echo "FAILED (Exit code: $ec)"
        echo "     Log output from $label:"
        sed 's/^/       | /' "$log_file" >&2
        rm -f "$log_file"
        FAILURES=$((FAILURES + 1))
        return 1
    fi
}

# 1. Applications
echo
echo "[+] 1/3 Building Application Packages..."
if [ -d "$BASE_DIR/applications/banking-api" ]; then
    run_builder "banking-api (clean & malicious)" "$BASE_DIR/applications/banking-api" "./build-tarballs.sh" || true
fi

if [ -d "$BASE_DIR/applications/calculator-api" ]; then
    run_builder "calculator-api" "$BASE_DIR/applications/calculator-api" "./build-tarball.sh" || true
fi

if [ -d "$BASE_DIR/applications/nodejs-app" ]; then
    run_builder "nodejs-app" "$BASE_DIR/applications/nodejs-app" "./build-tarball.sh" || true
fi

if [ -d "$BASE_DIR/applications/python-app" ]; then
    run_builder "python-app" "$BASE_DIR/applications/python-app" "./build-tarball.sh" || true
fi

# 2. Security Fixtures
echo
echo "[+] 2/3 Building Security Fixture Packages..."
if [ -d "$BASE_DIR/security-fixtures/nodejs-malicious" ]; then
    run_builder "nodejs-malicious" "$BASE_DIR/security-fixtures/nodejs-malicious" "./build-tarball.sh" || true
fi

if [ -d "$BASE_DIR/security-fixtures/python-malicious" ]; then
    run_builder "python-malicious" "$BASE_DIR/security-fixtures/python-malicious" "./build-tarball.sh" || true
fi

if [ -d "$BASE_DIR/security-fixtures/evil-pkg" ]; then
    if command -v npm >/dev/null 2>&1; then
        run_builder "evil-pkg" "$BASE_DIR/security-fixtures/evil-pkg" "./build.sh" || true
    else
        echo "  -> evil-pkg: SKIPPED (npm not installed; required for fixture packaging)"
    fi
fi

# 3. Attacks
echo
echo "[+] 3/3 Building Adversarial Attack Scenarios (01 to 07)..."
for scenario_dir in "$BASE_DIR"/attacks/[0-9]*/; do
    if [ -d "$scenario_dir" ] && [ -f "$scenario_dir/build.sh" ]; then
        sname=$(basename "$scenario_dir")
        run_builder "scenario $sname" "$scenario_dir" "./build.sh" || true
    fi
done

# 4. Strict Validation of Freshly Generated Archives
echo
echo "============================================================"
echo " VERIFYING FRESHLY GENERATED ARTIFACTS"
echo "============================================================"
MISSING=0
VALID_COUNT=0

for arch in "${EXPECTED_ARCHIVES[@]}"; do
    if [ ! -f "$arch" ]; then
        echo "  [-] MISSING EXPECTED ARTIFACT: $arch"
        MISSING=$((MISSING + 1))
    else
        # Verify archive integrity
        if tar -tzf "$arch" >/dev/null 2>&1; then
            sz=$(ls -lh "$arch" | awk '{print $5}')
            echo "  [OK] $arch ($sz) - Valid gzip archive"
            VALID_COUNT=$((VALID_COUNT + 1))
        else
            echo "  [-] CORRUPT ARTIFACT DETECTED: $arch (tar -tzf failed)"
            MISSING=$((MISSING + 1))
        fi
    fi
done

echo
echo "============================================================"
echo " SUMMARY: $VALID_COUNT/${#EXPECTED_ARCHIVES[@]} valid artifacts generated. ($FAILURES build errors, $MISSING missing/corrupt)"
echo "============================================================"

if [ $FAILURES -gt 0 ] || [ $MISSING -gt 0 ]; then
    echo "[-] ERROR: Archive generation failed. See error logs above." >&2
    exit 1
else
    echo "[+] SUCCESS: All required workload and attack archives are valid."
    exit 0
fi
