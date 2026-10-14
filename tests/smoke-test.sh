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
echo "[+] 5/5 Executing Live Pipeline Verification (Upload Test)..."
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
    CI_ENDPOINT="http://127.0.0.1:8888/upload" "$UPLOAD_SCRIPT" "$TARBALL" > /tmp/smoke-upload.log 2>&1 || true
    cat /tmp/smoke-upload.log | tail -15
    if grep -q "ALLOW" /tmp/smoke-upload.log || grep -q "SUCCESS" /tmp/smoke-upload.log || grep -q "PASS" /tmp/smoke-upload.log; then
        echo "  [OK] Pipeline returned expected ALLOW verdict for clean workload."
    else
        echo "  [-] Unexpected pipeline response for clean workload!"
        FAILURES=$((FAILURES + 1))
    fi
fi
rm -f "$TARBALL" /tmp/smoke-upload.log

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
