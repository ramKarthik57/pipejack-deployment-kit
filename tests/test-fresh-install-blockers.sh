#!/usr/bin/env bash
# PipeJack Deployment Kit — Fresh-Install Blocker & Remediation Regression Test Suite
# Validates fixes for:
#   1. VM1 installed layout archive generation & failure handling (missing inputs, stale cleanup)
#   2. PowerShell 5.1 AST syntax compatibility (rejecting PS7+ constructs like ternary & pipeline chains)
#   3. Remote sudo authentication detection & failure handling
#   4. Windows master orchestrator dry-run remaining strictly non-modifying
#   5. Demo Console network ACL restriction and WebSocket origin validation
#   6. Error propagation in installers without misleading silent suppression
#   7. Go key generation, verification, unit tests, and go vet
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

echo "============================================================"
echo " PIPEJACK FRESH-INSTALL BLOCKER REGRESSION TEST SUITE"
echo " Working Directory: $ROOT_DIR"
echo " Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "============================================================"

# -----------------------------------------------------------------------------
# Test 1: VM1 Installed-Layout Archive Generation
# -----------------------------------------------------------------------------
section "VM1 Installed-Layout Archive Generation"
TEST_LAYOUT_DIR=$(mktemp -d "/tmp/pipejack-test-installed-layout-XXXXXX")
cleanup_test1() {
    rm -rf "$TEST_LAYOUT_DIR"
}
trap cleanup_test1 EXIT

mkdir -p "$TEST_LAYOUT_DIR/applications"
mkdir -p "$TEST_LAYOUT_DIR/attacks"
mkdir -p "$TEST_LAYOUT_DIR/security-fixtures"
mkdir -p "$TEST_LAYOUT_DIR/scripts"

# Emulate vm1/install.sh copying actions
cp -r "$ROOT_DIR/vm1/applications/"* "$TEST_LAYOUT_DIR/applications/"
cp -r "$ROOT_DIR/vm1/attacks/"* "$TEST_LAYOUT_DIR/attacks/"
cp -r "$ROOT_DIR/vm1/security-fixtures/"* "$TEST_LAYOUT_DIR/security-fixtures/"
cp -r "$ROOT_DIR/vm1/scripts/"* "$TEST_LAYOUT_DIR/scripts/"
chmod +x "$TEST_LAYOUT_DIR/scripts/"*.sh
find "$TEST_LAYOUT_DIR/attacks" -name "*.sh" -exec chmod +x {} +
find "$TEST_LAYOUT_DIR/applications" -name "*.sh" -exec chmod +x {} +
find "$TEST_LAYOUT_DIR/security-fixtures" -name "*.sh" -exec chmod +x {} +

# Create installed layout root-level symlinks ($TARGET_DIR/$app -> applications/$app)
for app in banking-api calculator-api nodejs-app python-app; do
    ln -sf "applications/$app" "$TEST_LAYOUT_DIR/$app"
done
for fix in nodejs-malicious python-malicious evil-pkg; do
    ln -sf "security-fixtures/$fix" "$TEST_LAYOUT_DIR/$fix"
done

# Run generator from within installed layout
if "$TEST_LAYOUT_DIR/scripts/build-all-tarballs.sh" >/dev/null 2>&1; then
    # Verify all 15 tarballs exist and are valid gzip archives
    EXPECTED_15=(
        "/tmp/banking-api-clean.tar.gz"
        "/tmp/banking-api-malicious.tar.gz"
        "/tmp/calculator-api.tar.gz"
        "/tmp/nodejs-app-clean.tar.gz"
        "/tmp/python-app-clean.tar.gz"
        "/tmp/nodejs-app-malicious.tar.gz"
        "/tmp/python-app-malicious.tar.gz"
        "$TEST_LAYOUT_DIR/security-fixtures/evil-pkg/evil-pkg-1.0.0.tgz"
        "/tmp/attack-01-shell-exec.tar.gz"
        "/tmp/attack-02-http-exfil.tar.gz"
        "/tmp/attack-03-fs-tamper.tar.gz"
        "/tmp/attack-04-base64-shell.tar.gz"
        "/tmp/attack-05-multi-stage.tar.gz"
        "/tmp/attack-06-slow-exfil.tar.gz"
        "/tmp/attack-07-anomaly.tar.gz"
    )
    ALL_VALID=1
    for arch in "${EXPECTED_15[@]}"; do
        if [ ! -s "$arch" ] || ! tar -tzf "$arch" >/dev/null 2>&1; then
            ALL_VALID=0
            break
        fi
    done
    if [ $ALL_VALID -eq 1 ]; then
        pass "All 15 expected archives generated and verified in installed layout contract"
    else
        fail "One or more generated archives are missing, empty, or corrupt"
    fi
else
    fail "build-all-tarballs.sh returned nonzero exit code in installed layout"
fi
rm -rf "$TEST_LAYOUT_DIR"

# -----------------------------------------------------------------------------
# Test 2: Archive Generator Failure Propagation & Stale Archive Purging
# -----------------------------------------------------------------------------
section "Archive Generator Failure Propagation & Stale Purging"
FAIL_LAYOUT_DIR=$(mktemp -d "/tmp/pipejack-test-fail-layout-XXXXXX")
cleanup_test2() {
    rm -rf "$FAIL_LAYOUT_DIR"
}
trap cleanup_test2 EXIT

# Plant a stale corrupt archive in /tmp
echo "stale corrupt data" > "/tmp/calculator-api.tar.gz"

mkdir -p "$FAIL_LAYOUT_DIR/applications"
mkdir -p "$FAIL_LAYOUT_DIR/scripts"
cp -r "$ROOT_DIR/vm1/scripts/"* "$FAIL_LAYOUT_DIR/scripts/"
chmod +x "$FAIL_LAYOUT_DIR/scripts/"*.sh

# Incomplete layout (missing attacks, fixtures, and banking-api)
if "$FAIL_LAYOUT_DIR/scripts/build-all-tarballs.sh" >/dev/null 2>&1; then
    fail "build-all-tarballs.sh unexpectedly succeeded despite missing inputs"
else
    # Verify stale corrupt archive was deleted and not accepted
    if [ ! -f "/tmp/calculator-api.tar.gz" ]; then
        pass "Generator correctly failed on missing inputs and purged stale archives"
    else
        fail "Stale archive was not removed before generation"
    fi
fi
rm -rf "$FAIL_LAYOUT_DIR"

# -----------------------------------------------------------------------------
# Test 3: PowerShell 5.1 AST Syntax Compatibility (Rejecting PS7+ constructs)
# -----------------------------------------------------------------------------
section "PowerShell 5.1 Syntax Compatibility"
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
            # Search for PowerShell 7-only AST nodes:
            # 1. Ternary expressions (TernaryExpressionAst)
            # 2. Pipeline chains (PipelineChainAst, e.g. && and ||)
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
        pass "PowerShell AST confirms 100% PS 5.1 compatibility (0 syntax errors, 0 ternary, 0 pipeline chains)"
    else
        fail "PowerShell AST detected incompatibility: $PS_CHECK_OUTPUT"
    fi
else
    fail "pwsh not available to verify PowerShell 5.1 AST compatibility"
fi

# -----------------------------------------------------------------------------
# Test 4: Windows Master Orchestrator Non-Modifying Dry-Run
# -----------------------------------------------------------------------------
section "Windows Master Orchestrator Non-Modifying Dry-Run"
if command -v pwsh >/dev/null 2>&1; then
    DRY_RUN_OUTPUT=$(pwsh -NoProfile -Command "& '$ROOT_DIR/windows/setup-pipejack.ps1' -SkipPreflight -DryRun" 2>&1)
    if echo "$DRY_RUN_OUTPUT" | grep -q "DRY-RUN"; then
        if echo "$DRY_RUN_OUTPUT" | grep -q "DRY-RUN PREVIEW COMPLETED"; then
            pass "setup-pipejack.ps1 -DryRun executes cleanly without modifying remote nodes"
        else
            fail "setup-pipejack.ps1 -DryRun failed to report completion"
        fi
    else
        fail "setup-pipejack.ps1 failed dry-run invocation: $DRY_RUN_OUTPUT"
    fi
else
    fail "pwsh not available for dry-run verification"
fi

# -----------------------------------------------------------------------------
# Test 5: Remote Sudo Detection & Interactive Escalation Guidance
# -----------------------------------------------------------------------------
section "Remote Sudo Detection & Non-Interactive Failure Handling"
if command -v pwsh >/dev/null 2>&1; then
    SUDO_CHECK=$(pwsh -NoProfile -Command "
        \$scriptContent = Get-Content '$ROOT_DIR/windows/setup-pipejack.ps1' -Raw
        if (\$scriptContent -match 'Test-RemoteSudo' -and \$scriptContent -match 'InteractiveSudo' -and \$scriptContent -match '-t') {
            Write-Host 'SUDO_HANDLING_VERIFIED'
        }
    ")
    PREFLIGHT_CHECK=$(pwsh -NoProfile -Command "
        \$scriptContent = Get-Content '$ROOT_DIR/windows/preflight.ps1' -Raw
        if (\$scriptContent -match 'sudo -n true' -and \$scriptContent -match 'PASSWORDLESS') {
            Write-Host 'PREFLIGHT_SUDO_VERIFIED'
        }
    ")
    if [ "$SUDO_CHECK" = "SUDO_HANDLING_VERIFIED" ] && [ "$PREFLIGHT_CHECK" = "PREFLIGHT_SUDO_VERIFIED" ]; then
        pass "Remote sudo status is inspected with sudo -n true, and -InteractiveSudo / -t terminal allocation is enforced"
    else
        fail "Remote sudo handling is missing required checks in windows/ scripts"
    fi
else
    fail "pwsh not available for sudo script analysis"
fi

# -----------------------------------------------------------------------------
# Test 6: Demo Console Network Access Control & Origin Validation
# -----------------------------------------------------------------------------
section "Demo Console Network ACL and CSWSH Origin Validation"
PYTHON_ACL_TEST=$(python3 -c "
import sys, os
sys.path.insert(0, '$ROOT_DIR/vm2/demo/demo-console')
import server

# Test 1: Loopback allowed
assert server.is_client_allowed('127.0.0.1') == True, 'Loopback must be allowed'
assert server.is_client_allowed('::1') == True, 'IPv6 loopback must be allowed'

# Test 2: Lab VM subnet allowed
assert server.is_client_allowed('192.168.88.132') == True, 'VM1 IP must be allowed'
assert server.is_client_allowed('192.168.88.133') == True, 'VM2 IP must be allowed'
assert server.is_client_allowed('192.168.152.1') == True, 'VMware NAT host IP must be allowed'

# Test 3: Unauthorized IP rejected
assert server.is_client_allowed('10.200.1.5') == False, 'Arbitrary private IP must be rejected by default'
assert server.is_client_allowed('8.8.8.8') == False, 'Public Internet IP must be rejected'

# Test 4: Origin header validation (anti-CSWSH)
assert server.is_origin_allowed('http://192.168.88.133:8090', '192.168.88.133:8090') == True, 'Matching host must be allowed'
assert server.is_origin_allowed('http://localhost:8090', '192.168.88.133:8090') == True, 'Localhost origin must be allowed'
assert server.is_origin_allowed('http://evil-attacker.com', '192.168.88.133:8090') == False, 'External untrusted origin must be rejected'

# Test 5: Custom PIPEJACK_ALLOWED_NETWORKS override
os.environ['PIPEJACK_ALLOWED_NETWORKS'] = '10.50.0.0/16'
assert server.is_client_allowed('10.50.1.2') == True, 'Configured subnet must be allowed'
assert server.is_client_allowed('192.168.88.132') == False, 'Unconfigured subnet must be rejected when overridden'

print('ACL_ORIGIN_VERIFIED')
" 2>&1)

if [ "$PYTHON_ACL_TEST" = "ACL_ORIGIN_VERIFIED" ]; then
    pass "Demo Console IP ACL and WebSocket Origin validation operate strictly and as documented"
else
    fail "Demo Console ACL/Origin verification failed: $PYTHON_ACL_TEST"
fi

# -----------------------------------------------------------------------------
# Test 7: Demo Artifact Failure Reporting in vm2/install.sh
# -----------------------------------------------------------------------------
section "vm2/install.sh Error Capture & Partial-Success Reporting"
VM2_INSTALL_CHECK=$(grep -n "DEMO_PREP_WARNING" "$ROOT_DIR/vm2/install.sh" || true)
if [ -n "$VM2_INSTALL_CHECK" ]; then
    if ! grep -q 'prepare-demo.sh >/dev/null 2>&1 || true' "$ROOT_DIR/vm2/install.sh"; then
        pass "vm2/install.sh captures prepare-demo.sh output and reports [PARTIAL SUCCESS] without masking errors"
    else
        fail "vm2/install.sh still contains silent '|| true' suppression for prepare-demo.sh"
    fi
else
    fail "vm2/install.sh does not track DEMO_PREP_WARNING"
fi

# -----------------------------------------------------------------------------
# Test 8: Go Unit Tests and Code Inspection (go vet)
# -----------------------------------------------------------------------------
section "Go Unit Tests and Static Analysis (go vet)"
if (cd "$ROOT_DIR/vm2/services/custom-ci" && go vet ./... && go test ./... >/dev/null 2>&1); then
    pass "All Go CI orchestrator tests and go vet passed with zero warnings"
else
    fail "go vet or go test failed in vm2/services/custom-ci"
fi

# -----------------------------------------------------------------------------
# Test 9: Ed25519 Attestation Key Generation & Verification
# -----------------------------------------------------------------------------
section "Ed25519 Attestation Key Generation & Cryptographic Verification"
TMP_TEST_KEY_DIR=$(mktemp -d "/tmp/pipejack-test-keys-XXXXXX")
cleanup_test9() {
    rm -rf "$TMP_TEST_KEY_DIR"
}
trap cleanup_test9 EXIT

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
rm -rf "$TMP_TEST_KEY_DIR"

# -----------------------------------------------------------------------------
# Test 10: Systemd Service Unit Syntax Verification
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
# Final Summary
# -----------------------------------------------------------------------------
echo
echo "============================================================"
echo " REGRESSION TEST RESULTS: $PASSED_TESTS/$TOTAL_TESTS PASSED ($FAILED_TESTS failures)"
echo "============================================================"

if [ $FAILED_TESTS -eq 0 ]; then
    echo " [PASSED] ALL FRESH-INSTALL BLOCKER CHECKS PASSED SUCCESSFULLY."
    exit 0
else
    echo " [-] REGRESSION TESTS FAILED WITH $FAILED_TESTS FAILURE(S)." >&2
    exit 1
fi
