#!/usr/bin/env bash
# PipeJack VM1 — Dynamic Workload and Attack Tarball Generator
# Builds all clean and malicious tarballs dynamically without committing archives to git.
# Supports both source checkout layout (vm1/scripts/...) and installed layout ($TARGET_DIR/...).
# Fails honestly if any builder fails, any input is missing, or any expected archive is invalid.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve BASE_DIR across source checkout and installed layouts
if [ -d "$SCRIPT_DIR/attacks" ] && ([ -d "$SCRIPT_DIR/applications" ] || [ -d "$SCRIPT_DIR/banking-api" ]); then
    BASE_DIR="$SCRIPT_DIR"
elif [ -d "$SCRIPT_DIR/../attacks" ] && ([ -d "$SCRIPT_DIR/../applications" ] || [ -d "$SCRIPT_DIR/../banking-api" ]); then
    BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -n "${TARGET_DIR:-}" ] && [ -d "$TARGET_DIR" ]; then
    BASE_DIR="$TARGET_DIR"
else
    BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

find_app_dir() {
    local app="$1"
    if [ -d "$BASE_DIR/applications/$app" ]; then
        echo "$BASE_DIR/applications/$app"
    elif [ -d "$BASE_DIR/$app" ]; then
        echo "$BASE_DIR/$app"
    elif [ -d "$SCRIPT_DIR/applications/$app" ]; then
        echo "$SCRIPT_DIR/applications/$app"
    elif [ -d "$SCRIPT_DIR/$app" ]; then
        echo "$SCRIPT_DIR/$app"
    else
        echo ""
    fi
}

find_fixture_dir() {
    local fix="$1"
    if [ -d "$BASE_DIR/security-fixtures/$fix" ]; then
        echo "$BASE_DIR/security-fixtures/$fix"
    elif [ -d "$BASE_DIR/$fix" ]; then
        echo "$BASE_DIR/$fix"
    elif [ -d "$SCRIPT_DIR/security-fixtures/$fix" ]; then
        echo "$SCRIPT_DIR/security-fixtures/$fix"
    elif [ -d "$SCRIPT_DIR/$fix" ]; then
        echo "$SCRIPT_DIR/$fix"
    else
        echo ""
    fi
}

find_attacks_dir() {
    if [ -d "$BASE_DIR/attacks" ]; then
        echo "$BASE_DIR/attacks"
    elif [ -d "$SCRIPT_DIR/attacks" ]; then
        echo "$SCRIPT_DIR/attacks"
    else
        echo ""
    fi
}

EVIL_PKG_DIR="$(find_fixture_dir "evil-pkg")"
if [ -z "$EVIL_PKG_DIR" ]; then
    EVIL_PKG_ARCHIVE="/tmp/evil-pkg-1.0.0.tgz"
else
    EVIL_PKG_ARCHIVE="$EVIL_PKG_DIR/evil-pkg-1.0.0.tgz"
fi

echo "============================================================"
echo " PIPEJACK VM1 — DYNAMIC ARCHIVE GENERATION"
echo " Working Base Directory: $BASE_DIR"
echo "============================================================"

# List of 15 expected generated archives
EXPECTED_ARCHIVES=(
    "/tmp/banking-api-clean.tar.gz"
    "/tmp/banking-api-malicious.tar.gz"
    "/tmp/calculator-api.tar.gz"
    "/tmp/nodejs-app-clean.tar.gz"
    "/tmp/python-app-clean.tar.gz"
    "/tmp/nodejs-app-malicious.tar.gz"
    "/tmp/python-app-malicious.tar.gz"
    "$EVIL_PKG_ARCHIVE"
    "/tmp/attack-01-shell-exec.tar.gz"
    "/tmp/attack-02-http-exfil.tar.gz"
    "/tmp/attack-03-fs-tamper.tar.gz"
    "/tmp/attack-04-base64-shell.tar.gz"
    "/tmp/attack-05-multi-stage.tar.gz"
    "/tmp/attack-06-slow-exfil.tar.gz"
    "/tmp/attack-07-anomaly.tar.gz"
)

# Clean only target files that will be generated to prevent stale archives masking failures
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
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
        echo "FAILED (Input directory missing: '$dir')"
        FAILURES=$((FAILURES + 1))
        rm -f "$log_file"
        return 0
    fi

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
        return 0
    fi
}

# 1. Applications
echo
echo "[+] 1/3 Building Application Packages..."
BANKING_DIR="$(find_app_dir "banking-api")"
CALC_DIR="$(find_app_dir "calculator-api")"
NODE_DIR="$(find_app_dir "nodejs-app")"
PYTHON_DIR="$(find_app_dir "python-app")"

run_builder "banking-api (clean & malicious)" "$BANKING_DIR" "./build-tarballs.sh"
run_builder "calculator-api" "$CALC_DIR" "./build-tarball.sh"
run_builder "nodejs-app" "$NODE_DIR" "./build-tarball.sh"
run_builder "python-app" "$PYTHON_DIR" "./build-tarball.sh"

# 2. Security Fixtures
echo
echo "[+] 2/3 Building Security Fixture Packages..."
NODE_MAL_DIR="$(find_fixture_dir "nodejs-malicious")"
PYTHON_MAL_DIR="$(find_fixture_dir "python-malicious")"

run_builder "nodejs-malicious" "$NODE_MAL_DIR" "./build-tarball.sh"
run_builder "python-malicious" "$PYTHON_MAL_DIR" "./build-tarball.sh"

if [ -n "$EVIL_PKG_DIR" ] && [ -d "$EVIL_PKG_DIR" ]; then
    if command -v npm >/dev/null 2>&1; then
        run_builder "evil-pkg" "$EVIL_PKG_DIR" "./build.sh"
    else
        echo "  -> evil-pkg: FAILED (npm not installed; required for fixture packaging)"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "  -> evil-pkg: FAILED (Fixture directory missing)"
    FAILURES=$((FAILURES + 1))
fi

# 3. Attacks
echo
echo "[+] 3/3 Building Adversarial Attack Scenarios (01 to 07)..."
ATTACKS_DIR="$(find_attacks_dir)"
if [ -n "$ATTACKS_DIR" ] && [ -d "$ATTACKS_DIR" ]; then
    for scenario_dir in "$ATTACKS_DIR"/[0-9]*/; do
        if [ -d "$scenario_dir" ] && [ -f "$scenario_dir/build.sh" ]; then
            sname=$(basename "$scenario_dir")
            run_builder "scenario $sname" "$scenario_dir" "./build.sh"
        fi
    done
else
    echo "  [-] Attack scenarios directory missing: '$ATTACKS_DIR'"
    FAILURES=$((FAILURES + 1))
fi

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
    elif [ ! -s "$arch" ]; then
        echo "  [-] ZERO-BYTE ARTIFACT DETECTED: $arch"
        MISSING=$((MISSING + 1))
    else
        # Verify archive integrity via gzip header and tar structure
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
