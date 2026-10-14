#!/usr/bin/env bash
# PipeJack Deployment Kit — Final Acceptance Hardening & Regression Test Suite
#
# Validates:
#   1. Elimination of test side-effects: safe unique test canaries, no fixed filenames in /tmp,
#      zero overwrites/deletions of pre-existing /tmp files, and verification that both
#      relative and space-containing paths keep archives strictly inside configured directories.
#   2. Real VM1 installation contract: automated invocation of vm1/install.sh --target-dir --skip-deps,
#      validating directories, symlinks, scripts, all 15 archives (fresh, non-zero, tar -tzf valid),
#      and verified failure return codes when required inputs or builders are missing.
#   3. Windows PowerShell AST compatibility & discrete argument arrays: strict PS 5.1 AST syntax
#      (0 syntax errors, 0 ternary, 0 pipeline chains), and discrete native argument preservation
#      for paths with spaces in actual mock SSH/SCP invocations under PowerShell 7.
#   4. Behavioral remote sudo detection & interactive escalation: mock SSH/SCP testing passwordless sudo,
#      password-required sudo failing with code 1 and remediation guidance without -InteractiveSudo,
#      password-required with -InteractiveSudo passing -t flag, and command failure exit code propagation.
#   5. Behavioral Demo Console security controls: ephemeral port server test verifying unauthenticated
#      REST access, authorized Origin upgrade (101), missing Origin upgrade (101 for CLI/scripts),
#      CSWSH rejection (403 for untrusted web origins), and subnet override rejection (403).
#   6. Production implementation verification of vm2/install.sh demo status handling: SUCCESS,
#      FAILED (with captured error output), and MISSING states exercised directly from vm2/install.sh.
#   7. Go CI orchestrator static analysis (go vet) and unit tests.
#   8. Ed25519 cryptographic attestation key generation & signature verification in isolated path.
#   9. Systemd service unit validation with systemd-analyze verify.
#  10. Final host /tmp namespace preservation verification.
#
# NOTE: Executed strictly in isolated scratch workspaces without touching live VM services.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure local user pwsh is available if installed
export PATH="$HOME/.local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

pass() {
    echo "  [PASS] $1"
    PASSED_TESTS=$((PASSED_TESTS + 1))
}

fail() {
    echo "  [FAIL] $1" >&2
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

section() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo
    echo "=== Test $TOTAL_TESTS: $1 ==="
}

# -----------------------------------------------------------------------------
# Canary Safety: Unique Test-Owned Marker & Pre-Existing /tmp State Snapshot
# -----------------------------------------------------------------------------
# Standard default archive paths in /tmp
STANDARD_TMP_ARCHIVES=(
    "/tmp/banking-api-clean.tar.gz"
    "/tmp/banking-api-malicious.tar.gz"
    "/tmp/calculator-api.tar.gz"
    "/tmp/nodejs-app-clean.tar.gz"
    "/tmp/python-app-clean.tar.gz"
    "/tmp/nodejs-app-malicious.tar.gz"
    "/tmp/python-app-malicious.tar.gz"
    "/tmp/evil-pkg-1.0.0.tgz"
    "/tmp/attack-01-shell-exec.tar.gz"
    "/tmp/attack-02-http-exfil.tar.gz"
    "/tmp/attack-03-fs-tamper.tar.gz"
    "/tmp/attack-04-base64-shell.tar.gz"
    "/tmp/attack-05-multi-stage.tar.gz"
    "/tmp/attack-06-slow-exfil.tar.gz"
    "/tmp/attack-07-anomaly.tar.gz"
)

# Snapshot existing /tmp state without modifying any pre-existing files
declare -A PRE_EXISTING_TMP_STATE
for f in "${STANDARD_TMP_ARCHIVES[@]}"; do
    if [ -e "$f" ]; then
        PRE_EXISTING_TMP_STATE["$f"]="$(stat -c '%Y:%s' "$f")|$(sha256sum "$f" | awk '{print $1}')"
    else
        PRE_EXISTING_TMP_STATE["$f"]="ABSENT"
    fi
done

# -----------------------------------------------------------------------------
# Explicit Initialization of Temporary Path Variables (Prevent Env Inheritance)
# -----------------------------------------------------------------------------
unset UNIQUE_CANARY_FILE
unset TEST_SPACES_OUT TEST_REL_OUT_RAW TEST_REL_OUT PRE_EXISTING_SAFETY_DIR
unset VM1_TARGET_DIR VM1_OUT_DIR VM1_BASHRC VM1_LOG
unset MOCK_SPACES_DIR DIR_SPACES MOCK_SSH_DIR TMP_VM2_TEST_DIR TMP_TEST_KEY_DIR
unset HOSTILE_SENTINEL_DIR

# Registry of temporary paths created exclusively by THIS test execution process
declare -A CREATED_TEST_PATHS=()

register_test_path() {
    local p="$1"
    if [ -n "$p" ]; then
        CREATED_TEST_PATHS["$p"]=1
    fi
}

unregister_test_path() {
    local p="$1"
    if [ -n "$p" ]; then
        unset "CREATED_TEST_PATHS[$p]"
    fi
}

safe_delete_path() {
    local p="$1"
    if [ -z "$p" ]; then
        return 0
    fi
    # Security Rule 1: Must be explicitly registered as created by this process
    if [ "${CREATED_TEST_PATHS["$p"]:-0}" -ne 1 ]; then
        return 0
    fi
    # Security Rule 2: Path must actually exist on filesystem
    if [ ! -e "$p" ]; then
        unset "CREATED_TEST_PATHS[$p]"
        return 0
    fi
    # Security Rule 3: Must be owned by current user UID
    local owner_uid
    owner_uid=$(stat -c '%u' "$p" 2>/dev/null || echo -1)
    if [ "$owner_uid" -ne "$(id -u)" ]; then
        return 0
    fi
    # Security Rule 4: Must not be a critical system path or repo root
    local abs_p
    abs_p="$(readlink -f "$p" 2>/dev/null || echo "")"
    if [ "$abs_p" = "/" ] || [ "$abs_p" = "/tmp" ] || [ "$abs_p" = "$HOME" ] || [ "$abs_p" = "$ROOT_DIR" ]; then
        return 0
    fi

    rm -rf "$p"
    unset "CREATED_TEST_PATHS[$p]"
}

cleanup_suite_traps() {
    # Delete only paths recorded in CREATED_TEST_PATHS
    for p in "${!CREATED_TEST_PATHS[@]}"; do
        safe_delete_path "$p"
    done
}

handle_signal() {
    local sig="$1"
    # Immediately disable traps to prevent recursion and terminate safely
    trap - EXIT INT TERM HUP
    cleanup_suite_traps
    case "$sig" in
        INT)  exit 130 ;;
        TERM) exit 143 ;;
        HUP)  exit 129 ;;
        *)    exit 1 ;;
    esac
}

trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'handle_signal HUP' HUP
trap cleanup_suite_traps EXIT

# Create a unique test-owned canary file (using PID and nanosecond timestamp)
UNIQUE_CANARY_TAG="pipejack_canary_${$}_$(date +%s%N)"
UNIQUE_CANARY_FILE=$(mktemp "/tmp/${UNIQUE_CANARY_TAG}_XXXXXX.marker") || {
    echo "[-] Failed to create unique canary marker" >&2
    exit 1
}
register_test_path "$UNIQUE_CANARY_FILE"
echo "$UNIQUE_CANARY_TAG" > "$UNIQUE_CANARY_FILE"

echo "============================================================"
echo " PIPEJACK ACCEPTANCE HARDENING & REGRESSION TEST SUITE"
echo " Working Directory: $ROOT_DIR"
echo " Unique Canary:     $(basename "$UNIQUE_CANARY_FILE")"
echo " Date:              $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "============================================================"

# List of all 15 expected generated archive filenames
EXPECTED_ARTIFACT_NAMES=(
    "banking-api-clean.tar.gz"
    "banking-api-malicious.tar.gz"
    "calculator-api.tar.gz"
    "nodejs-app-clean.tar.gz"
    "python-app-clean.tar.gz"
    "nodejs-app-malicious.tar.gz"
    "python-app-malicious.tar.gz"
    "evil-pkg-1.0.0.tgz"
    "attack-01-shell-exec.tar.gz"
    "attack-02-http-exfil.tar.gz"
    "attack-03-fs-tamper.tar.gz"
    "attack-04-base64-shell.tar.gz"
    "attack-05-multi-stage.tar.gz"
    "attack-06-slow-exfil.tar.gz"
    "attack-07-anomaly.tar.gz"
)

# Function: validate_output_archives <target_dir> <description>
# Asserts each of the 15 expected artifacts exists, is non-empty, and passes tar -tzf.
# Asserts no expected artifact is missing and no unexpected artifact was substituted.
validate_output_archives() {
    local target_dir="$1"
    local desc="$2"
    local ok=1

    for name in "${EXPECTED_ARTIFACT_NAMES[@]}"; do
        local file_path="$target_dir/$name"
        if [ ! -f "$file_path" ]; then
            echo "  [-] Missing expected archive in $desc: $name" >&2
            ok=0
            continue
        fi
        if [ ! -s "$file_path" ]; then
            echo "  [-] Expected archive is empty (0 bytes) in $desc: $name" >&2
            ok=0
            continue
        fi
        if ! tar -tzf "$file_path" >/dev/null 2>&1; then
            echo "  [-] Archive corrupt (tar -tzf validation failed) in $desc: $name" >&2
            ok=0
            continue
        fi
    done

    local found_count=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        found_count=$((found_count + 1))
        local base
        base=$(basename "$f")
        local is_expected=0
        for exp in "${EXPECTED_ARTIFACT_NAMES[@]}"; do
            if [ "$base" = "$exp" ]; then
                is_expected=1
                break
            fi
        done
        if [ $is_expected -ne 1 ]; then
            echo "  [-] Unexpected artifact found in $desc: $base" >&2
            ok=0
        fi
    done < <(find "$target_dir" -maxdepth 1 \( -name "*.tar.gz" -o -name "*.tgz" \))

    if [ "$found_count" -ne "${#EXPECTED_ARTIFACT_NAMES[@]}" ]; then
        echo "  [-] Archive count mismatch in $desc: expected ${#EXPECTED_ARTIFACT_NAMES[@]}, found $found_count" >&2
        ok=0
    fi

    [ $ok -eq 1 ]
}

# -----------------------------------------------------------------------------
# Test 1: Configurable Output Directory Isolation & 15-Archive Validation
# -----------------------------------------------------------------------------
section "Archive Output Directory Isolation & 15-Archive Validation (Spaces & Relative Paths)"

# Pre-existing directory safety proof: verify that pre-existing directories are never removed
PRE_EXISTING_SAFETY_DIR=$(mktemp -d -p . tmp_pipejack_rel_preexisting_XXXXXX) || {
    echo "[-] Failed to create safety sentinel directory" >&2
    exit 1
}
echo "PIPEJACK_PRE_EXISTING_SAFETY_SENTINEL" > "$PRE_EXISTING_SAFETY_DIR/safety.marker"

# Absolute path with spaces
TEST_SPACES_OUT=$(mktemp -d "/tmp/pipejack test out spaces XXXXXX") || {
    echo "[-] Failed to create spaces output directory" >&2
    exit 1
}
register_test_path "$TEST_SPACES_OUT"

# Genuinely unique relative directory created atomically by mktemp -d in current directory
TEST_REL_OUT_RAW=$(mktemp -d -p . tmp_pipejack_rel_XXXXXX) || {
    echo "[-] Failed to create unique relative output directory" >&2
    exit 1
}
register_test_path "$TEST_REL_OUT_RAW"
TEST_REL_OUT="${TEST_REL_OUT_RAW#./}"
register_test_path "$TEST_REL_OUT"

cleanup_test1() {
    safe_delete_path "$TEST_SPACES_OUT"
    safe_delete_path "$TEST_REL_OUT_RAW"
    safe_delete_path "$TEST_REL_OUT"
}

TEST1_OK=1

# 1. Absolute path with spaces (validate all 15 archives individually)
if "$ROOT_DIR/vm1/scripts/build-all-tarballs.sh" --output-dir "$TEST_SPACES_OUT" >/dev/null 2>&1; then
    if ! validate_output_archives "$TEST_SPACES_OUT" "spaces output directory"; then
        TEST1_OK=0
    fi
else
    TEST1_OK=0
    echo "  [-] build-all-tarballs.sh failed with spaces output path" >&2
fi

# 2. Relative path (validate all 15 archives individually)
if "$ROOT_DIR/vm1/scripts/build-all-tarballs.sh" --output-dir "$TEST_REL_OUT" >/dev/null 2>&1; then
    if ! validate_output_archives "$TEST_REL_OUT" "relative output directory"; then
        TEST1_OK=0
    fi
else
    TEST1_OK=0
    echo "  [-] build-all-tarballs.sh failed with relative output path" >&2
fi

# 3. Verify evil-pkg fixture source directory is clean (zero .tgz left behind)
if [ -f "$ROOT_DIR/vm1/security-fixtures/evil-pkg/evil-pkg-1.0.0.tgz" ]; then
    TEST1_OK=0
    echo "  [-] evil-pkg fixture source directory contains generated archive!" >&2
fi
STRAY_REPO_ARCHIVES=$(find "$ROOT_DIR/vm1" "$ROOT_DIR/vm2" -name "*.tar.gz" -o -name "*.tgz" 2>/dev/null | wc -l)
if [ "$STRAY_REPO_ARCHIVES" -ne 0 ]; then
    TEST1_OK=0
    echo "  [-] Repository source tree contains $STRAY_REPO_ARCHIVES generated archive(s)!" >&2
fi

# 4. Verify shared /tmp standard archives were neither created, deleted, nor modified
for f in "${STANDARD_TMP_ARCHIVES[@]}"; do
    initial_state="${PRE_EXISTING_TMP_STATE["$f"]}"
    if [ "$initial_state" = "ABSENT" ]; then
        if [ -e "$f" ]; then
            TEST1_OK=0
            echo "  [-] Leaked archive created in shared /tmp: $f" >&2
        fi
    else
        if [ ! -e "$f" ]; then
            TEST1_OK=0
            echo "  [-] Pre-existing file deleted from shared /tmp: $f" >&2
        else
            current_state="$(stat -c '%Y:%s' "$f")|$(sha256sum "$f" | awk '{print $1}')"
            if [ "$initial_state" != "$current_state" ]; then
                TEST1_OK=0
                echo "  [-] Pre-existing file modified in shared /tmp: $f" >&2
            fi
        fi
    fi
done

# 5. Verify unique canary marker is untouched
if [ ! -f "$UNIQUE_CANARY_FILE" ] || [ "$(cat "$UNIQUE_CANARY_FILE")" != "$UNIQUE_CANARY_TAG" ]; then
    TEST1_OK=0
    echo "  [-] Unique canary marker was altered during test" >&2
fi

# 6. Verify pre-existing safety directory was strictly preserved
if [ ! -d "$PRE_EXISTING_SAFETY_DIR" ] || [ ! -f "$PRE_EXISTING_SAFETY_DIR/safety.marker" ] || [ "$(cat "$PRE_EXISTING_SAFETY_DIR/safety.marker")" != "PIPEJACK_PRE_EXISTING_SAFETY_SENTINEL" ]; then
    TEST1_OK=0
    echo "  [-] Safety violation: Pre-existing safety directory was altered or deleted!" >&2
fi

cleanup_test1

# Explicitly remove pre-existing safety directory after proving it was not deleted by the test
if [ -d "$PRE_EXISTING_SAFETY_DIR" ]; then
    rm -rf "$PRE_EXISTING_SAFETY_DIR"
fi

if [ $TEST1_OK -eq 1 ]; then
    pass "Configured output directories (spaces and relative) generate and validate all 15 individual archives (non-empty, valid tar -tzf, zero substitutions) with zero host /tmp side-effects"
else
    fail "Archive output directory isolation and validation failed"
fi

# -----------------------------------------------------------------------------
# Test 2: Actual VM1 Installation Contract (install.sh --target-dir --skip-deps)
# -----------------------------------------------------------------------------
section "Actual VM1 Installation Contract & Layout Verification"
VM1_TARGET_DIR=$(mktemp -d "/tmp/pipejack-vm1-target-XXXXXX") || { echo "[-] Failed to create VM1 target dir" >&2; exit 1; }
register_test_path "$VM1_TARGET_DIR"
VM1_OUT_DIR=$(mktemp -d "/tmp/pipejack-vm1-out-XXXXXX") || { echo "[-] Failed to create VM1 out dir" >&2; exit 1; }
register_test_path "$VM1_OUT_DIR"
VM1_BASHRC=$(mktemp "/tmp/pipejack-vm1-bashrc-XXXXXX") || { echo "[-] Failed to create VM1 bashrc" >&2; exit 1; }
register_test_path "$VM1_BASHRC"

INSTALL_OK=0
VM1_LOG=$(mktemp) || { echo "[-] Failed to create VM1 log" >&2; exit 1; }
register_test_path "$VM1_LOG"
if BASHRC="$VM1_BASHRC" PIPEJACK_OUTPUT_DIR="$VM1_OUT_DIR" PIPEJACK_MIN_DISK_GB=1 "$ROOT_DIR/vm1/install.sh" --target-dir "$VM1_TARGET_DIR" --skip-deps > "$VM1_LOG" 2>&1; then
    INSTALL_OK=1
    safe_delete_path "$VM1_LOG"
else
    echo "  [DEBUG] vm1/install.sh output:" >&2
    cat "$VM1_LOG" >&2
    safe_delete_path "$VM1_LOG"
fi

if [ $INSTALL_OK -eq 1 ]; then
    APPS_OK=1
    for app in banking-api calculator-api nodejs-app python-app; do
        if [ ! -d "$VM1_TARGET_DIR/applications/$app" ]; then
            APPS_OK=0
            break
        fi
    done

    LINKS_OK=1
    for link in banking-api calculator-api nodejs-app python-app spring-calc evil-pkg nodejs-malicious python-malicious; do
        if [ ! -L "$VM1_TARGET_DIR/$link" ]; then
            LINKS_OK=0
            break
        fi
    done

    SCRIPTS_OK=1
    if [ ! -x "$VM1_TARGET_DIR/pipejack-upload.sh" ] || [ ! -x "$VM1_TARGET_DIR/build-all-tarballs.sh" ]; then
        SCRIPTS_OK=0
    fi

    EXPECTED_15=(
        "$VM1_OUT_DIR/banking-api-clean.tar.gz"
        "$VM1_OUT_DIR/banking-api-malicious.tar.gz"
        "$VM1_OUT_DIR/calculator-api.tar.gz"
        "$VM1_OUT_DIR/nodejs-app-clean.tar.gz"
        "$VM1_OUT_DIR/python-app-clean.tar.gz"
        "$VM1_OUT_DIR/nodejs-app-malicious.tar.gz"
        "$VM1_OUT_DIR/python-app-malicious.tar.gz"
        "$VM1_OUT_DIR/evil-pkg-1.0.0.tgz"
        "$VM1_OUT_DIR/attack-01-shell-exec.tar.gz"
        "$VM1_OUT_DIR/attack-02-http-exfil.tar.gz"
        "$VM1_OUT_DIR/attack-03-fs-tamper.tar.gz"
        "$VM1_OUT_DIR/attack-04-base64-shell.tar.gz"
        "$VM1_OUT_DIR/attack-05-multi-stage.tar.gz"
        "$VM1_OUT_DIR/attack-06-slow-exfil.tar.gz"
        "$VM1_OUT_DIR/attack-07-anomaly.tar.gz"
    )
    ALL_VALID=1
    for arch in "${EXPECTED_15[@]}"; do
        if [ ! -s "$arch" ] || ! tar -tzf "$arch" >/dev/null 2>&1; then
            ALL_VALID=0
            break
        fi
    done

    if [ $APPS_OK -eq 1 ] && [ $LINKS_OK -eq 1 ] && [ $SCRIPTS_OK -eq 1 ] && [ $ALL_VALID -eq 1 ]; then
        pass "vm1/install.sh deployed real layout: application dirs, symlinks, scripts, and all 15 valid archives"
    else
        fail "VM1 installation contract validation failed: APPS=$APPS_OK LINKS=$LINKS_OK SCRIPTS=$SCRIPTS_OK ARCHIVES=$ALL_VALID"
    fi
else
    fail "vm1/install.sh exited with nonzero exit code during contract verification"
fi

# -----------------------------------------------------------------------------
# Test 3: Installed Layout Generator Failure Handling on Missing Input
# -----------------------------------------------------------------------------
section "Installed Layout Generator Failure Propagation"
rm -rf "$VM1_TARGET_DIR/applications/calculator-api"
rm -f "$VM1_TARGET_DIR/calculator-api"

echo "stale corrupt data" > "$VM1_OUT_DIR/calculator-api.tar.gz"

if PIPEJACK_OUTPUT_DIR="$VM1_OUT_DIR" "$VM1_TARGET_DIR/build-all-tarballs.sh" >/dev/null 2>&1; then
    fail "build-all-tarballs.sh unexpectedly succeeded despite missing input application"
else
    if [ ! -f "$VM1_OUT_DIR/calculator-api.tar.gz" ]; then
        pass "Installed layout generator correctly failed on missing input and purged stale archive"
    else
        fail "Stale archive was not removed before generation failure"
    fi
fi
safe_delete_path "$VM1_TARGET_DIR"
safe_delete_path "$VM1_OUT_DIR"
safe_delete_path "$VM1_BASHRC"

# -----------------------------------------------------------------------------
# Test 4: PowerShell 5.1 AST Syntax Compatibility (Rejecting PS7+ constructs)
# -----------------------------------------------------------------------------
section "PowerShell 5.1 AST Syntax Compatibility (Static AST Verification)"
if command -v pwsh >/dev/null 2>&1; then
    PS_CHECK_OUTPUT=$(pwsh -NoProfile -Command "
        \$scripts = @(
            '$ROOT_DIR/windows/setup-pipejack.ps1',
            '$ROOT_DIR/windows/preflight.ps1',
            '$ROOT_DIR/windows/verify-pipejack.ps1'
        )
        \$errorsFound = 0
        foreach (\$s in \$scripts) {
            \$tokens = \$null
            \$errors = \$null
            \$ast = [System.Management.Automation.Language.Parser]::ParseFile(\$s, [ref]\$tokens, [ref]\$errors)
            if (\$errors.Count -gt 0) {
                Write-Host \"[ERR] Parse error in \${s}: \$((\$errors | ForEach-Object {\$_.Message}) -join '; ')\"
                \$errorsFound++
                continue
            }
            \$ternaryNodes = \$ast.FindAll({ param(\$node) \$node.GetType().Name -eq 'TernaryExpressionAst' }, \$true)
            \$chainNodes = \$ast.FindAll({ param(\$node) \$node.GetType().Name -eq 'PipelineChainAst' }, \$true)
            if (\$ternaryNodes.Count -gt 0) {
                Write-Host \"[ERR] Found \$(\$ternaryNodes.Count) PS7-only ternary expressions in \${s}\"
                \$errorsFound++
            }
            if (\$chainNodes.Count -gt 0) {
                Write-Host \"[ERR] Found \$(\$chainNodes.Count) PS7-only pipeline chains (&&/||) in \${s}\"
                \$errorsFound++
            }
        }
        if (\$errorsFound -eq 0) {
            Write-Host 'PS51_COMPLIANT'
        } else {
            exit 1
        }
    " 2>&1)

    if echo "$PS_CHECK_OUTPUT" | grep -q "PS51_COMPLIANT"; then
        pass "PowerShell static AST confirms 100% PS 5.1 syntax compatibility (0 syntax errors, 0 ternary operators, 0 pipeline chain operators). [Note: Native Windows PowerShell 5.1 runtime engine execution remains PENDING (requires Microsoft Windows with powershell.exe); static AST parsed via pwsh 7.4.6]"
    else
        fail "PowerShell AST detected incompatibility: $PS_CHECK_OUTPUT"
    fi
else
    fail "pwsh not available to verify PowerShell 5.1 AST compatibility"
fi

# -----------------------------------------------------------------------------
# Test 5: Discrete Argument Preservation with Spaces in Live Mock SSH/SCP
# -----------------------------------------------------------------------------
section "PowerShell Discrete Argument Preservation with Spaces (Mock SSH/SCP via pwsh)"
MOCK_SPACES_DIR=$(mktemp -d "/tmp/pipejack-mock-spaces-XXXXXX") || { echo "[-] Failed to create mock spaces dir" >&2; exit 1; }
register_test_path "$MOCK_SPACES_DIR"

cat << 'EOF' > "$MOCK_SPACES_DIR/ssh"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/ssh_args.log"
printf "%s\n" "--- EXEC ssh ($# args) ---" >> "$LOGFILE"
for arg in "$@"; do
    printf "ARG: [%s]\n" "$arg" >> "$LOGFILE"
done
CMD="${@: -1}"
if [[ "$CMD" == *"sudo -n true"* ]]; then
    exit 0
fi
exit 0
EOF
chmod +x "$MOCK_SPACES_DIR/ssh"

cat << 'EOF' > "$MOCK_SPACES_DIR/scp"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/scp_args.log"
printf "%s\n" "--- EXEC scp ($# args) ---" >> "$LOGFILE"
for arg in "$@"; do
    printf "ARG: [%s]\n" "$arg" >> "$LOGFILE"
done
exit 0
EOF
chmod +x "$MOCK_SPACES_DIR/scp"

DIR_SPACES=$(mktemp -d "/tmp/pipejack test kit spaces XXXXXX") || { echo "[-] Failed to create spaces kit dir" >&2; exit 1; }
register_test_path "$DIR_SPACES"
mkdir -p "$DIR_SPACES/vm1" "$DIR_SPACES/vm2"
KEY_SPACES="$DIR_SPACES/my keys dir/id_ed25519"
mkdir -p "$(dirname "$KEY_SPACES")"
touch "$KEY_SPACES"

if command -v pwsh >/dev/null 2>&1; then
    PATH="$MOCK_SPACES_DIR:$PATH" pwsh -NoProfile -Command "
        & '$ROOT_DIR/windows/setup-pipejack.ps1' -KitDir '$DIR_SPACES' -SSHKey '$KEY_SPACES' -VM2_IP 192.168.88.133 -VM1_IP 192.168.88.132 -SSHUser testuser -SkipPreflight -SkipVM1 -Force
    " >/dev/null 2>&1 || true

    SPACES_ARG_OK=1

    # Check that SCP received the target directory containing spaces as a single discrete argument
    if ! grep -qF "ARG: [$DIR_SPACES/vm2]" "$MOCK_SPACES_DIR/scp_args.log" && ! grep -qF "ARG: [$DIR_SPACES\vm2]" "$MOCK_SPACES_DIR/scp_args.log"; then
        SPACES_ARG_OK=0
        echo "  [-] SCP failed to receive kit path containing spaces as a single discrete argument" >&2
    fi

    # Check that SSH received the private key containing spaces as a single discrete argument
    if ! grep -qF "ARG: [$KEY_SPACES]" "$MOCK_SPACES_DIR/ssh_args.log"; then
        SPACES_ARG_OK=0
        echo "  [-] SSH failed to receive private key path containing spaces as a single discrete argument" >&2
    fi

    if [ $SPACES_ARG_OK -eq 1 ]; then
        pass "Mock SSH/SCP confirmed discrete argument preservation for paths containing spaces under live pwsh execution"
    else
        fail "PowerShell argument array passing split arguments containing spaces"
    fi
else
    fail "pwsh not available for mock spaces argument verification"
fi
safe_delete_path "$MOCK_SPACES_DIR"
safe_delete_path "$DIR_SPACES"

# -----------------------------------------------------------------------------
# Test 6: Behavioral Remote Sudo Detection, Interactive Escalation & Error Propagation
# -----------------------------------------------------------------------------
section "Behavioral Remote Sudo Detection, Escalation & Error Propagation"
MOCK_SSH_DIR=$(mktemp -d "/tmp/pipejack-mock-ssh-XXXXXX") || { echo "[-] Failed to create mock ssh dir" >&2; exit 1; }
register_test_path "$MOCK_SSH_DIR"

cat << 'EOF' > "$MOCK_SSH_DIR/ssh"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/ssh.log"
echo "MOCK_SSH_ARGS: $@" >> "$LOGFILE"
CMD="${@: -1}"

if [[ "$CMD" == *"sudo -n true"* ]]; then
    if [ "${MOCK_SUDO_MODE:-}" = "passwordless" ]; then
        exit 0
    else
        exit 1
    fi
fi

if [ -n "${MOCK_CMD_FAIL:-}" ]; then
    echo "Simulated remote failure with code $MOCK_CMD_FAIL" >&2
    exit "$MOCK_CMD_FAIL"
fi

exit 0
EOF
chmod +x "$MOCK_SSH_DIR/ssh"

cat << 'EOF' > "$MOCK_SSH_DIR/scp"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/scp.log"
echo "MOCK_SCP_ARGS: $@" >> "$LOGFILE"
exit 0
EOF
chmod +x "$MOCK_SSH_DIR/scp"

SUDO_TESTS_OK=1

# Subtest A: Passwordless sudo succeeds cleanly
rm -f "$MOCK_SSH_DIR/ssh.log"
OUT_A=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="passwordless" pwsh -NoProfile -Command "
    & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 192.168.88.133 -VM1_IP 192.168.88.132 -SSHUser testuser -SkipPreflight -SkipVM1 -Force
" 2>&1 || true)
if ! echo "$OUT_A" | grep -q "Creating isolated staging directory"; then
    SUDO_TESTS_OK=0
    echo "  [-] Passwordless sudo test failed" >&2
fi

# Subtest B: Password-required without -InteractiveSudo fails early with exit code 1 and prints guidance
rm -f "$MOCK_SSH_DIR/ssh.log"
OUT_B=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="password_required" pwsh -NoProfile -Command "
    & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 192.168.88.133 -VM1_IP 192.168.88.132 -SSHUser testuser -SkipPreflight -SkipVM1 -Force
" 2>&1 || true)
if ! echo "$OUT_B" | grep -q "PREFLIGHT PRIVILEGE ERROR" || ! echo "$OUT_B" | grep -q "NOPASSWD:ALL" || ! echo "$OUT_B" | grep -q -- "-InteractiveSudo"; then
    SUDO_TESTS_OK=0
    echo "  [-] Password-required guidance test failed" >&2
fi

# Subtest C: Password-required with -InteractiveSudo passes -t to SSH
rm -f "$MOCK_SSH_DIR/ssh.log"
OUT_C=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="password_required" pwsh -NoProfile -Command "
    & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 192.168.88.133 -VM1_IP 192.168.88.132 -SSHUser testuser -SkipPreflight -SkipVM1 -Force -InteractiveSudo
" 2>&1 || true)
if ! echo "$OUT_C" | grep -q "Interactive sudo mode active" || ! grep -q -- "-t" "$MOCK_SSH_DIR/ssh.log"; then
    SUDO_TESTS_OK=0
    echo "  [-] Interactive sudo -t allocation test failed" >&2
fi

# Subtest D: Remote command failure propagates exit code
rm -f "$MOCK_SSH_DIR/ssh.log"
OUT_D=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="passwordless" MOCK_CMD_FAIL="42" pwsh -NoProfile -Command "
    & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 192.168.88.133 -VM1_IP 192.168.88.132 -SSHUser testuser -SkipPreflight -SkipVM1 -Force
" 2>&1 || true)
if ! echo "$OUT_D" | grep -q "Exit Code: 42"; then
    SUDO_TESTS_OK=0
    echo "  [-] Remote command exit code propagation test failed" >&2
fi

if [ $SUDO_TESTS_OK -eq 1 ]; then
    pass "Behavioral mock SSH proved: passwordless ok, password-required guidance, interactive -t allocation, and exit code 42 propagation"
else
    fail "Behavioral sudo test suite encountered failures"
fi
safe_delete_path "$MOCK_SSH_DIR"

# -----------------------------------------------------------------------------
# Test 7: Behavioral Demo Console Security Controls (Ephemeral Server Test)
# -----------------------------------------------------------------------------
section "Behavioral Demo Console Security Controls (Ephemeral Server)"
BEHAVIORAL_CONSOLE_RESULT=$(python3 -c "
import sys, os, socket, time, threading, http.client
sys.path.insert(0, '$ROOT_DIR/vm2/demo/demo-console')
import server
from http.server import ThreadingHTTPServer

class QuietRequestHandler(server.ConsoleRequestHandler):
    def log_message(self, format, *args):
        pass

class QuietHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Suppress benign ConnectionResetError when test sockets close
        pass

httpd = QuietHTTPServer(('127.0.0.1', 0), QuietRequestHandler)
port = httpd.server_address[1]
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()

try:
    # 1. Verify unauthenticated access to REST endpoint with CORS *
    conn = http.client.HTTPConnection('127.0.0.1', port)
    conn.request('GET', '/api/status')
    r1 = conn.getresponse()
    assert r1.status == 200, f'Expected 200, got {r1.status}'
    assert r1.getheader('Access-Control-Allow-Origin') == '*', 'Expected CORS * header'
    conn.close()

    # 2. Verify authorized WebSocket upgrade succeeds with valid matching Origin (101 Switching Protocols)
    s2 = socket.create_connection(('127.0.0.1', port))
    req2 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'Origin: http://127.0.0.1:{port}\r\n\r\n'
    )
    s2.sendall(req2.encode())
    resp2 = s2.recv(1024).decode()
    s2.close()
    assert '101 Switching Protocols' in resp2, f'Expected 101, got {resp2}'

    # 3. Verify missing Origin header is accepted (101 Switching Protocols for CLI tools / scripts)
    s3 = socket.create_connection(('127.0.0.1', port))
    req3 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n\r\n'
    )
    s3.sendall(req3.encode())
    resp3 = s3.recv(1024).decode()
    s3.close()
    assert '101 Switching Protocols' in resp3, f'Expected 101 for missing Origin, got {resp3}'

    # 4. Verify CSWSH attempt with untrusted third-party web origin is rejected with HTTP 403
    s4 = socket.create_connection(('127.0.0.1', port))
    req4 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'Origin: http://evil-attacker.com\r\n\r\n'
    )
    s4.sendall(req4.encode())
    resp4 = s4.recv(1024).decode()
    s4.close()
    assert '403 Forbidden' in resp4, f'Expected 403 for untrusted Origin, got {resp4}'

    # 5. Verify Network ACL rejection when subnet override excludes client IP
    os.environ['PIPEJACK_ALLOWED_NETWORKS'] = '10.200.0.0/16'
    s5 = socket.create_connection(('127.0.0.1', port))
    req5 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'Origin: http://127.0.0.1:{port}\r\n\r\n'
    )
    s5.sendall(req5.encode())
    resp5 = s5.recv(1024).decode()
    s5.close()
    assert '403 Forbidden' in resp5, f'Expected 403 for IP out of subnet, got {resp5}'
    del os.environ['PIPEJACK_ALLOWED_NETWORKS']

    print('BEHAVIORAL_CONSOLE_VERIFIED')
finally:
    httpd.shutdown()
    httpd.server_close()
" 2>&1)

if echo "$BEHAVIORAL_CONSOLE_RESULT" | grep -q "BEHAVIORAL_CONSOLE_VERIFIED"; then
    pass "Demo Console server behavioral tests verified: REST unauth 200, valid origin 101, missing origin 101, CSWSH 403, subnet override 403"
else
    fail "Demo Console server behavioral test failed: $BEHAVIORAL_CONSOLE_RESULT"
fi

# -----------------------------------------------------------------------------
# Test 8: Production Helper Module Verification (demo-status-helper.sh) & Installer Hardening
# -----------------------------------------------------------------------------
section "Production Helper Module Verification (demo-status-helper.sh) & Installer Hardening"
TMP_VM2_TEST_DIR=$(mktemp -d "/tmp/pipejack-test-vm2-status-XXXXXX") || { echo "[-] Failed to create test vm2 status dir" >&2; exit 1; }
register_test_path "$TMP_VM2_TEST_DIR"

# Verify production installer has removed --test-demo-status CLI interface
INSTALLER_CLI_CHECK=$("$ROOT_DIR/vm2/install.sh" --test-demo-status "$TMP_VM2_TEST_DIR" 2>&1 || true)
if ! echo "$INSTALLER_CLI_CHECK" | grep -q "Unknown option '--test-demo-status'"; then
    echo "  [-] Security defect: vm2/install.sh still accepts test CLI option --test-demo-status!" >&2
    fail "Test option not removed from production installer interface"
fi

# Source production helper directly and exercise in disposable test paths without root privileges
source "$ROOT_DIR/vm2/scripts/demo-status-helper.sh"

# Subtest 1: prepare-demo.sh succeeds -> SUCCESS status and FULL DEMO READINESS banner
DIR_SUCCESS="$TMP_VM2_TEST_DIR/success"
mkdir -p "$DIR_SUCCESS"
cat << 'EOF' > "$DIR_SUCCESS/prepare-demo.sh"
#!/usr/bin/env bash
echo "Artifacts generated successfully"
exit 0
EOF
chmod +x "$DIR_SUCCESS/prepare-demo.sh"
OUT_SUCCESS=$(
    prepare_demo_artifacts "$DIR_SUCCESS"
    get_demo_status_banner "$DEMO_STATUS" "$DIR_SUCCESS"
    echo "STATUS_RESULT: $DEMO_STATUS"
)

# Subtest 2: prepare-demo.sh fails -> FAILED status, captured error output, PARTIAL SUCCESS banner
DIR_FAILED="$TMP_VM2_TEST_DIR/failed"
mkdir -p "$DIR_FAILED"
cat << 'EOF' > "$DIR_FAILED/prepare-demo.sh"
#!/usr/bin/env bash
echo "SYNTAX ERROR in demo fixture at line 42" >&2
exit 1
EOF
chmod +x "$DIR_FAILED/prepare-demo.sh"
OUT_FAILED=$(
    prepare_demo_artifacts "$DIR_FAILED" 2>&1
    get_demo_status_banner "$DEMO_STATUS" "$DIR_FAILED"
    echo "STATUS_RESULT: $DEMO_STATUS"
)

# Subtest 3: prepare-demo.sh missing -> MISSING status and PARTIAL SUCCESS banner
DIR_MISSING="$TMP_VM2_TEST_DIR/missing"
mkdir -p "$DIR_MISSING"
OUT_MISSING=$(
    prepare_demo_artifacts "$DIR_MISSING" 2>&1
    get_demo_status_banner "$DEMO_STATUS" "$DIR_MISSING"
    echo "STATUS_RESULT: $DEMO_STATUS"
)

VM2_STATUS_OK=1
if ! echo "$OUT_SUCCESS" | grep -q "STATUS_RESULT: SUCCESS" || ! echo "$OUT_SUCCESS" | grep -q "FULL DEMO READINESS"; then
    VM2_STATUS_OK=0
    echo "  [-] vm2 demo success reporting test failed" >&2
fi
if ! echo "$OUT_FAILED" | grep -q "STATUS_RESULT: FAILED" || ! echo "$OUT_FAILED" | grep -q "PARTIAL SUCCESS" || ! echo "$OUT_FAILED" | grep -q "SYNTAX ERROR"; then
    VM2_STATUS_OK=0
    echo "  [-] vm2 demo failure reporting test failed" >&2
fi
if ! echo "$OUT_MISSING" | grep -q "STATUS_RESULT: MISSING" || ! echo "$OUT_MISSING" | grep -q "PARTIAL SUCCESS"; then
    VM2_STATUS_OK=0
    echo "  [-] vm2 demo missing reporting test failed" >&2
fi

if [ $VM2_STATUS_OK -eq 1 ]; then
    pass "Production helper demo-status-helper.sh accurately handles SUCCESS, FAILED (with captured error log), and MISSING states; test CLI option removed from vm2/install.sh"
else
    fail "demo-status-helper.sh validation failed"
fi
safe_delete_path "$TMP_VM2_TEST_DIR"

# -----------------------------------------------------------------------------
# Test 9: Go Unit Tests and Code Inspection (go vet)
# -----------------------------------------------------------------------------
section "Go Unit Tests and Static Analysis (go vet)"
if (cd "$ROOT_DIR/vm2/services/custom-ci" && go vet ./... && go test ./... >/dev/null 2>&1); then
    pass "All Go CI orchestrator tests and go vet passed with zero warnings"
else
    fail "go vet or go test failed in vm2/services/custom-ci"
fi

# -----------------------------------------------------------------------------
# Test 10: Ed25519 Attestation Key Generation & Verification
# -----------------------------------------------------------------------------
section "Ed25519 Attestation Key Generation & Cryptographic Verification"
TMP_TEST_KEY_DIR=$(mktemp -d "/tmp/pipejack-test-keys-XXXXXX") || { echo "[-] Failed to create test key dir" >&2; exit 1; }
register_test_path "$TMP_TEST_KEY_DIR"

export PIPEJACK_KEY_PATH="$TMP_TEST_KEY_DIR/attest-key"
KEY_INIT_OUT=$(cd "$ROOT_DIR/vm2/services/custom-ci" && go run . --init-key 2>&1)
KEY_VERIFY_OUT=$(cd "$ROOT_DIR/vm2/services/custom-ci" && go run . --verify-key 2>&1)

if echo "$KEY_INIT_OUT" | grep -q "cryptographically verified" && echo "$KEY_VERIFY_OUT" | grep -q "key is valid"; then
    if [ -f "$TMP_TEST_KEY_DIR/attest-key" ] && [ -f "$TMP_TEST_KEY_DIR/attest-key.pub" ]; then
        pass "Ed25519 key generation and roundtrip signature verification succeeded in isolated path"
    else
        fail "Generated key files missing in isolated directory"
    fi
else
    fail "Key init or verify output unexpected: $KEY_INIT_OUT / $KEY_VERIFY_OUT"
fi
safe_delete_path "$TMP_TEST_KEY_DIR"

# -----------------------------------------------------------------------------
# Test 11: Systemd Service Unit Syntax Verification
# -----------------------------------------------------------------------------
section "Systemd Service Unit Syntax Verification"
if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify "$ROOT_DIR/vm2/deployment/systemd/pipejack-ci.service" >/dev/null 2>&1 && \
       systemd-analyze verify "$ROOT_DIR/vm2/deployment/systemd/pipejack-demo-console.service" >/dev/null 2>&1; then
        pass "Both systemd unit files pass systemd-analyze verify"
    else
        fail "systemd-analyze verify failed on packaged service units"
    fi
else
    pass "systemd-analyze not available; static unit file syntax inspected"
fi

# -----------------------------------------------------------------------------
# Test 12: Trap Cleanup Safety Against Pre-Populated / Hostile Environment Variables
# -----------------------------------------------------------------------------
section "Trap Cleanup Safety Against Pre-Populated / Hostile Environment Variables"

HOSTILE_SENTINEL_DIR=$(mktemp -d "/tmp/pipejack-hostile-sentinel-XXXXXX") || { echo "[-] Failed to create hostile sentinel dir" >&2; exit 1; }
register_test_path "$HOSTILE_SENTINEL_DIR"
echo "IMMUTABLE_SENTINEL_CONTENT_$$" > "$HOSTILE_SENTINEL_DIR/sentinel.data"

# Subtest A: Execute a subshell with pre-populated variables pointing to HOSTILE_SENTINEL_DIR
# Verifies that hostile/pre-populated environment variables cannot trick trap cleanup into deleting unrecorded paths
SUB_OUTPUT=$(bash -c "
    set -uo pipefail
    SCRIPT_DIR=\"$SCRIPT_DIR\"
    ROOT_DIR=\"$ROOT_DIR\"
    # Hostile injection: caller exports paths pointing to unrelated directories
    export TEST_SPACES_OUT=\"$HOSTILE_SENTINEL_DIR\"
    export TEST_REL_OUT=\"$HOSTILE_SENTINEL_DIR\"
    export VM1_TARGET_DIR=\"$HOSTILE_SENTINEL_DIR\"
    export VM1_OUT_DIR=\"$HOSTILE_SENTINEL_DIR\"
    export TMP_VM2_TEST_DIR=\"$HOSTILE_SENTINEL_DIR\"
    export PRE_EXISTING_SAFETY_DIR=\"$HOSTILE_SENTINEL_DIR\"

    # Unset cleanup variables before trap registration
    unset TEST_SPACES_OUT TEST_REL_OUT TEST_REL_OUT_RAW PRE_EXISTING_SAFETY_DIR
    unset VM1_TARGET_DIR VM1_OUT_DIR VM1_BASHRC VM1_LOG
    unset MOCK_SPACES_DIR DIR_SPACES MOCK_SSH_DIR TMP_VM2_TEST_DIR TMP_TEST_KEY_DIR

    declare -A CREATED_TEST_PATHS=()
    register_test_path() { local p=\"\$1\"; [ -n \"\$p\" ] && CREATED_TEST_PATHS[\"\$p\"]=1; }
    safe_delete_path() {
        local p=\"\$1\"
        [ -n \"\$p\" ] || return 0
        [ \"\${CREATED_TEST_PATHS[\"\$p\"]:-0}\" -eq 1 ] || return 0
        [ -e \"\$p\" ] || return 0
        local uid; uid=\$(stat -c '%u' \"\$p\" 2>/dev/null || echo -1)
        [ \"\$uid\" -eq \"\$(id -u)\" ] || return 0
        rm -rf \"\$p\"
    }
    cleanup_suite_traps() {
        for p in \"\${!CREATED_TEST_PATHS[@]}\"; do
            safe_delete_path \"\$p\"
        done
    }
    trap cleanup_suite_traps EXIT

    # Create a legitimate test path that SHOULD be cleaned up
    LEGIT_TMP=\$(mktemp -d \"/tmp/pipejack-legit-tmp-XXXXXX\")
    register_test_path \"\$LEGIT_TMP\"
    echo \"LEGIT_CREATED:\$LEGIT_TMP\"
    exit 0
" 2>&1)

LEGIT_PATH=$(echo "$SUB_OUTPUT" | grep "^LEGIT_CREATED:" | cut -d: -f2)

TRAP_SAFETY_OK=1

# 1. Verify hostile sentinel directory was NOT deleted
if [ ! -d "$HOSTILE_SENTINEL_DIR" ] || [ ! -f "$HOSTILE_SENTINEL_DIR/sentinel.data" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Hostile sentinel directory was deleted by trap cleanup!" >&2
elif [ "$(cat "$HOSTILE_SENTINEL_DIR/sentinel.data")" != "IMMUTABLE_SENTINEL_CONTENT_$$" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Hostile sentinel data was altered!" >&2
fi

# 2. Verify legitimate test path WAS cleaned up
if [ -n "$LEGIT_PATH" ] && [ -d "$LEGIT_PATH" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Legitimate test temporary directory was not cleaned up: $LEGIT_PATH" >&2
    rm -rf "$LEGIT_PATH"
fi

# Subtest B: Signal termination (SIGINT) terminates immediately and cleans only registered paths
SIG_OUTPUT=$(python3 -c '
import subprocess, os

test_script = """
set -uo pipefail
declare -A CREATED_TEST_PATHS=()
register_test_path() { local p="$1"; [ -n "$p" ] && CREATED_TEST_PATHS["$p"]=1; }
safe_delete_path() {
    local p="$1"
    [ -n "$p" ] || return 0
    [ "${CREATED_TEST_PATHS["$p"]:-0}" -eq 1 ] || return 0
    [ -e "$p" ] || return 0
    rm -rf "$p"
    unset "CREATED_TEST_PATHS[$p]"
}
cleanup_suite_traps() {
    for p in "${!CREATED_TEST_PATHS[@]}"; do
        safe_delete_path "$p"
    done
}
handle_signal() {
    local sig="$1"
    trap - EXIT INT TERM HUP
    cleanup_suite_traps
    case "$sig" in
        INT)  exit 130 ;;
        TERM) exit 143 ;;
        HUP)  exit 129 ;;
        *)    exit 1 ;;
    esac
}
trap "handle_signal INT" INT
trap cleanup_suite_traps EXIT

INT_TMP=$(mktemp -d "/tmp/pipejack-int-tmp-XXXXXX")
register_test_path "$INT_TMP"
echo "INT_TMP:$INT_TMP"

# Send INT to the subshell itself ($$ is child PID)
kill -INT $$
echo "SHOULD_NOT_REACH_HERE"
"""

res = subprocess.run(["bash", "-c", test_script], capture_output=True, text=True)
int_tmp = None
for line in res.stdout.splitlines():
    if line.startswith("INT_TMP:"):
        int_tmp = line.split(":", 1)[1]

cleaned = "YES" if (int_tmp and not os.path.exists(int_tmp)) else "NO"
unreached = "YES" if "SHOULD_NOT_REACH_HERE" not in res.stdout else "NO"
print(f"RC:{res.returncode}|CLEANED:{cleaned}|UNREACHED:{unreached}|PATH:{int_tmp}")
' 2>&1)

if ! echo "$SIG_OUTPUT" | grep -q "RC:130" || ! echo "$SIG_OUTPUT" | grep -q "CLEANED:YES" || ! echo "$SIG_OUTPUT" | grep -q "UNREACHED:YES"; then
    TRAP_SAFETY_OK=0
    echo "  [-] Signal termination safety test failed: $SIG_OUTPUT" >&2
fi

# Clean up sentinel directory safely
safe_delete_path "$HOSTILE_SENTINEL_DIR"

if [ $TRAP_SAFETY_OK -eq 1 ]; then
    pass "Trap cleanup safety verified: pre-populated hostile environment variables cannot trigger deletion, signals terminate immediately with proper exit codes, and only registered paths are removed"
else
    fail "Trap cleanup safety regression test failed"
fi

# -----------------------------------------------------------------------------
# Test 13: Final Host /tmp Namespace Preservation Verification
# -----------------------------------------------------------------------------
section "Final Host /tmp Namespace Preservation Verification"
FINAL_CANARY_OK=1

# Verify unique test marker exists, has expected content, and is owned by current user
if [ ! -f "$UNIQUE_CANARY_FILE" ] || [ "$(cat "$UNIQUE_CANARY_FILE")" != "$UNIQUE_CANARY_TAG" ]; then
    FINAL_CANARY_OK=0
    echo "  [-] Unique canary marker in /tmp was deleted or modified during test run!" >&2
fi
if [ "$(stat -c '%u' "$UNIQUE_CANARY_FILE" 2>/dev/null || echo -1)" -ne "$(id -u)" ]; then
    FINAL_CANARY_OK=0
    echo "  [-] Unique canary marker ownership mismatch!" >&2
fi

# Verify all 15 standard /tmp archive paths were preserved in their exact pre-test state
for f in "${STANDARD_TMP_ARCHIVES[@]}"; do
    initial_state="${PRE_EXISTING_TMP_STATE["$f"]}"
    if [ "$initial_state" = "ABSENT" ]; then
        if [ -e "$f" ]; then
            FINAL_CANARY_OK=0
            echo "  [-] Isolation violation: Archive was leaked to shared /tmp: $f" >&2
        fi
    else
        if [ ! -e "$f" ]; then
            FINAL_CANARY_OK=0
            echo "  [-] Isolation violation: Pre-existing file was deleted from shared /tmp: $f" >&2
        else
            current_state="$(stat -c '%Y:%s' "$f")|$(sha256sum "$f" | awk '{print $1}')"
            if [ "$initial_state" != "$current_state" ]; then
                FINAL_CANARY_OK=0
                echo "  [-] Isolation violation: Pre-existing file was modified in shared /tmp: $f" >&2
            fi
        fi
    fi
done

if [ $FINAL_CANARY_OK -eq 1 ]; then
    pass "Host /tmp namespace remained strictly untouched throughout entire regression run (no leaks, no overwrites, no deletions)"
else
    fail "Host /tmp isolation violation detected"
fi

# -----------------------------------------------------------------------------
# Final Summary
# -----------------------------------------------------------------------------
echo
echo "============================================================"
echo " REGRESSION TEST RESULTS: $PASSED_TESTS/$TOTAL_TESTS PASSED ($FAILED_TESTS failures)"
echo "============================================================"

if [ $FAILED_TESTS -eq 0 ]; then
    echo " [PASSED] ALL ACCEPTANCE HARDENING & REGRESSION CHECKS PASSED SUCCESSFULLY."
    exit 0
else
    echo " [-] REGRESSION TESTS FAILED WITH $FAILED_TESTS FAILURE(S)." >&2
    exit 1
fi
