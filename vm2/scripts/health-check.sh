#!/usr/bin/env bash
# PipeJack VM2 — Health Verification Script
# Checks status of CI orchestrator (:8888), Demo Console (:8090), and Local Registry (:5000).

set -euo pipefail

CI_PORT="${PIPEJACK_PORT:-8888}"
CONSOLE_PORT="8090"
REGISTRY_PORT="5000"

echo "============================================================"
echo " PIPEJACK VM2 — SYSTEM SERVICE HEALTH VERIFICATION"
echo " Host: $(hostname) ($(whoami))"
echo "============================================================"

FAILURES=0

# 1. CI Orchestrator Check (:8888)
echo
echo "[+] 1/4 Checking PipeJack CI Server (port $CI_PORT)..."
CI_RESP=""
if CI_RESP=$(curl -s -f -m 3 "http://127.0.0.1:${CI_PORT}/health" 2>/dev/null); then
    CI_STATUS=$(echo "$CI_RESP" | jq -r '.status // empty' 2>/dev/null || true)
    CI_SERVICE=$(echo "$CI_RESP" | jq -r '.service // empty' 2>/dev/null || true)
    if [ "$CI_STATUS" = "ok" ] && [ "$CI_SERVICE" = "pipejack-ci" ]; then
        echo "  [OK] CI Server is HEALTHY (service: $CI_SERVICE, status: $CI_STATUS)"
        echo "       Response: $CI_RESP"
    else
        echo "  [FAIL] CI Server returned invalid JSON payload: $CI_RESP"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "  [FAIL] CI Server unreachable or returned non-200 on http://127.0.0.1:${CI_PORT}/health"
    FAILURES=$((FAILURES + 1))
fi

# 2. Demo Console Check (:8090)
echo
echo "[+] 2/4 Checking PipeJack Demo Console (port $CONSOLE_PORT)..."
CONSOLE_RESP=""
if CONSOLE_RESP=$(curl -s -f -m 3 "http://127.0.0.1:${CONSOLE_PORT}/api/status" 2>/dev/null); then
    CI_HEALTHY=$(echo "$CONSOLE_RESP" | jq -r '.ci_healthy // empty' 2>/dev/null || true)
    ATTEST_COUNT=$(echo "$CONSOLE_RESP" | jq -r '.attestation_count // 0' 2>/dev/null || true)
    ENFORCEMENT=$(echo "$CONSOLE_RESP" | jq -r '.enforcement_mode // "unknown"' 2>/dev/null || true)

    if [ "$CI_HEALTHY" = "true" ]; then
        echo "  [OK] Demo Console is HEALTHY and connected to CI"
        echo "       Attestation Records: $ATTEST_COUNT"
        echo "       Enforcement Mode:    $ENFORCEMENT"
    else
        echo "  [FAIL] Demo Console reported ci_healthy != true: $CONSOLE_RESP"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "  [FAIL] Demo Console unreachable or returned non-200 on http://127.0.0.1:${CONSOLE_PORT}/api/status"
    FAILURES=$((FAILURES + 1))
fi

# 3. Docker Registry Check (:5000)
echo
echo "[+] 3/4 Checking Local Docker Registry (port $REGISTRY_PORT)..."
REG_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "http://127.0.0.1:${REGISTRY_PORT}/v2/" || echo "000")
if [ "$REG_STATUS" = "200" ]; then
    echo "  [OK] Docker Registry is HEALTHY (Docker Distribution API v2 operational, HTTP 200)"
else
    echo "  [FAIL] Docker Registry returned HTTP status $REG_STATUS on http://127.0.0.1:${REGISTRY_PORT}/v2/"
    FAILURES=$((FAILURES + 1))
fi

# 4. Systemd Units Status
echo
echo "[+] 4/4 Checking Systemd Service Unit States..."
if systemctl is-active --quiet pipejack-ci.service; then
    echo "  [OK] pipejack-ci.service:           ACTIVE (running)"
else
    echo "  [FAIL] pipejack-ci.service:         INACTIVE or FAILED"
    FAILURES=$((FAILURES + 1))
fi

if systemctl is-active --quiet pipejack-demo-console.service; then
    echo "  [OK] pipejack-demo-console.service: ACTIVE (running)"
else
    echo "  [FAIL] pipejack-demo-console.service: INACTIVE or FAILED"
    FAILURES=$((FAILURES + 1))
fi

echo
echo "============================================================"
if [ $FAILURES -eq 0 ]; then
    echo " ALL VM2 SERVICES ARE HEALTHY AND OPERATIONAL"
    echo " CI Endpoint:     http://192.168.88.133:8888/upload"
    echo " Demo Console:    http://192.168.88.133:8090"
    echo " Local Registry:  http://192.168.88.133:5000"
    echo "============================================================"
    exit 0
else
    echo " [!] HEALTH CHECK COMPLETED WITH $FAILURES FAILURE(S)"
    echo " Check service logs with: journalctl -u pipejack-ci -n 50"
    echo "============================================================"
    exit 1
fi
