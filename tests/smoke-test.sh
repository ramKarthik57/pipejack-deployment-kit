#!/usr/bin/env bash
# PipeJack Deployment Kit — Smoke Integration Test Suite
# Runs Go unit tests, code analysis, service health probes, and active pipeline validation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo " PIPEJACK DEPLOYMENT KIT — SMOKE INTEGRATION TEST"
echo "============================================================"

FAILURES=0

# 1. Custom-CI Go Unit Tests
echo
echo "[+] 1/5 Running Unit Tests in vm2/services/custom-ci..."
if (cd "$ROOT_DIR/vm2/services/custom-ci" && go test -v ./...); then
    echo "  [OK] Custom-CI tests passed successfully."
else
    echo "  [-] Custom-CI unit tests failed!"
    FAILURES=$((FAILURES + 1))
fi

# 2. Core Go Unit Tests
echo
echo "[+] 2/5 Running Unit Tests in vm2/core/pipejack..."
if (cd "$ROOT_DIR/vm2/core/pipejack" && go test -v ./...); then
    echo "  [OK] Core security tests passed successfully."
else
    echo "  [-] Core security unit tests failed!"
    FAILURES=$((FAILURES + 1))
fi

# 3. Go Vet Analysis
echo
echo "[+] 3/5 Running 'go vet' on Services..."
if (cd "$ROOT_DIR/vm2/services/custom-ci" && go vet ./...); then
    echo "  [OK] 'go vet' completed with 0 warnings."
else
    echo "  [-] 'go vet' reported issues!"
    FAILURES=$((FAILURES + 1))
fi

# 4. Service Health Checks (Active VM2 Environment)
echo
echo "[+] 4/5 Probing Live VM2 Services..."
if [ -f "$ROOT_DIR/vm2/scripts/health-check.sh" ]; then
    if "$ROOT_DIR/vm2/scripts/health-check.sh"; then
        echo "  [OK] All active services (:8888, :8090, :5000) are healthy."
    else
        echo "  [-] Service health check failed!"
        FAILURES=$((FAILURES + 1))
    fi
fi

# 5. Live Pipeline Upload Test (Non-destructive clean workload test)
echo
echo "[+] 5/5 Executing Live Pipeline Verification (Upload & Ledger Attestation Test)..."
TMP_DIR=$(mktemp -d)
cat << 'EOF' > "$TMP_DIR/package.json"
{
  "name": "smoke-test-app",
  "version": "1.0.0",
  "scripts": {
    "build": "echo 'smoke test build'",
    "test": "echo 'smoke test run'"
  },
  "main": "index.js"
}
EOF
cat << 'EOF' > "$TMP_DIR/index.js"
console.log("Smoke test workload active");
EOF

TARBALL="/tmp/pipejack-smoke-test-$$.tar.gz"
tar -czf "$TARBALL" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"

echo "  Created temporary smoke workload: $TARBALL"
UPLOAD_SCRIPT="$ROOT_DIR/vm1/scripts/pipejack-upload.sh"

if [ -x "$UPLOAD_SCRIPT" ]; then
    # Record baseline attestation count from Demo Console
    INITIAL_COUNT=$(curl -s -m 3 http://127.0.0.1:8090/api/status 2>/dev/null | jq -r '.attestation_count // 0' || echo "0")
    echo "  Baseline attestation count: $INITIAL_COUNT"

    UPLOAD_LOG="/tmp/smoke-upload-$$.log"
    if "$UPLOAD_SCRIPT" --endpoint "http://127.0.0.1:8888/upload" "$TARBALL" > "$UPLOAD_LOG" 2>&1; then
        echo "  [OK] Upload script executed with exit code 0."
        cat "$UPLOAD_LOG" | tail -10

        # Query Demo Console status and verify attestation recorded
        sleep 2
        STATUS_JSON=$(curl -s -m 3 http://127.0.0.1:8090/api/status 2>/dev/null || echo "{}")
        NEW_COUNT=$(echo "$STATUS_JSON" | jq -r '.attestation_count // 0' 2>/dev/null || echo "0")
        LATEST_VERDICT=$(echo "$STATUS_JSON" | jq -r '.latest_attestation.verdict // empty' 2>/dev/null || echo "")
        LATEST_BUILD_ID=$(echo "$STATUS_JSON" | jq -r '.latest_attestation.build_id // empty' 2>/dev/null || echo "")

        if [ "$NEW_COUNT" -ge "$((INITIAL_COUNT + 1))" ] && [ "$LATEST_VERDICT" = "ALLOW" ] && [ -n "$LATEST_BUILD_ID" ]; then
            ATTEST_FILE="/home/ubuntu/pipejack-attestations/${LATEST_BUILD_ID}.json"
            if [ -f "$ATTEST_FILE" ]; then
                SIG=$(jq -r '.signature // empty' "$ATTEST_FILE" 2>/dev/null || echo "")
                HASH=$(jq -r '.self_hash // empty' "$ATTEST_FILE" 2>/dev/null || echo "")
                if [ -n "$SIG" ] && [ -n "$HASH" ]; then
                    echo "  [OK] Clean workload attestation verified in VM2 ledger:"
                    echo "       Build ID:  $LATEST_BUILD_ID"
                    echo "       Verdict:   $LATEST_VERDICT"
                    echo "       Self-Hash: $HASH"
                    echo "       Signature: ${SIG:0:32}..."
                    echo "       Ledger:    $NEW_COUNT records (incremented from $INITIAL_COUNT)"
                else
                    echo "  [-] FAIL: Attestation file $ATTEST_FILE missing cryptographic signature or self_hash!"
                    FAILURES=$((FAILURES + 1))
                fi
            else
                echo "  [-] FAIL: Expected attestation ledger file $ATTEST_FILE not found on disk!"
                FAILURES=$((FAILURES + 1))
            fi
        else
            echo "  [-] FAIL: Attestation ledger not updated with ALLOW verdict! Count: $NEW_COUNT (was $INITIAL_COUNT), Verdict: '$LATEST_VERDICT'"
            FAILURES=$((FAILURES + 1))
        fi
    else
        UPLOAD_RC=$?
        echo "  [-] FAIL: Upload script exited with non-zero code ($UPLOAD_RC)!"
        cat "$UPLOAD_LOG" | tail -15
        FAILURES=$((FAILURES + 1))
    fi
    rm -f "$UPLOAD_LOG"
else
    echo "  [-] FAIL: Upload script $UPLOAD_SCRIPT not executable!"
    FAILURES=$((FAILURES + 1))
fi
rm -f "$TARBALL"

echo
echo "============================================================"
if [ $FAILURES -eq 0 ]; then
    echo " [PASSED] ALL SMOKE INTEGRATION TESTS PASSED (5/5)."
    echo "============================================================"
    exit 0
else
    echo " [FAILED] Smoke integration test suite encountered $FAILURES failure(s)."
    echo "============================================================"
    exit 1
fi
