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
echo "[+] 1/3 Checking PipeJack CI Server (port $CI_PORT)..."
if curl -s -f -m 3 "http://127.0.0.1:${CI_PORT}/health" > /tmp/ci_health.json 2>/dev/null; then
    echo "  [OK] CI Server is HEALTHY"
    echo "       Response: $(cat /tmp/ci_health.json)"
else
    echo "  [FAIL] CI Server unreachable or returned non-200 on http://127.0.0.1:${CI_PORT}/health"
    FAILURES=$((FAILURES + 1))
fi

# 2. Demo Console Check (:8090)
echo
echo "[+] 2/3 Checking PipeJack Demo Console (port $CONSOLE_PORT)..."
if curl -s -f -m 3 "http://127.0.0.1:${CONSOLE_PORT}/api/status" > /tmp/console_status.json 2>/dev/null; then
    echo "  [OK] Demo Console is HEALTHY"
    CI_HEALTHY=$(jq -r '.ci_healthy' /tmp/console_status.json 2>/dev/null || echo "unknown")
    ATTEST_COUNT=$(jq -r '.attestation_count' /tmp/console_status.json 2>/dev/null || echo "0")
    echo "       CI Healthy in Console: $CI_HEALTHY"
    echo "       Attestation Records:   $ATTEST_COUNT"
else
    echo "  [FAIL] Demo Console unreachable or returned non-200 on http://127.0.0.1:${CONSOLE_PORT}/api/status"
    FAILURES=$((FAILURES + 1))
fi

# 3. Docker Registry Check (:5000)
echo
echo "[+] 3/3 Checking Local Docker Registry (port $REGISTRY_PORT)..."
if curl -s -f -m 3 "http://127.0.0.1:${REGISTRY_PORT}/v2/" > /dev/null 2>&1; then
    echo "  [OK] Docker Registry is HEALTHY (Docker Distribution API v2 operational)"
else
    echo "  [FAIL] Docker Registry unreachable on http://127.0.0.1:${REGISTRY_PORT}/v2/"
    FAILURES=$((FAILURES + 1))
fi

# 4. Systemd Units Status
echo
echo "[+] Systemd Service Unit States:"
systemctl is-active pipejack-ci.service >/dev/null 2>&1 && echo "  * pipejack-ci.service:           ACTIVE (running)" || echo "  * pipejack-ci.service:           INACTIVE / FAILED"
systemctl is-active pipejack-demo-console.service >/dev/null 2>&1 && echo "  * pipejack-demo-console.service: ACTIVE (running)" || echo "  * pipejack-demo-console.service: INACTIVE / FAILED"

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
