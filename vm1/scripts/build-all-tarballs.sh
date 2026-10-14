#!/usr/bin/env bash
# PipeJack VM1 — Dynamic Workload and Attack Tarball Generator
# Builds all clean and malicious tarballs dynamically without committing archives to git.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo " PIPEJACK VM1 — DYNAMIC ARCHIVE GENERATION"
echo " Base Directory: $BASE_DIR"
echo "============================================================"

# 1. Applications
echo
echo "[+] 1/3 Building Application Packages..."
if [ -d "$BASE_DIR/applications/banking-api" ]; then
    echo "  -> banking-api (clean & malicious)..."
    (cd "$BASE_DIR/applications/banking-api" && ./build-tarballs.sh >/dev/null 2>&1 || true)
fi

if [ -d "$BASE_DIR/applications/calculator-api" ]; then
    echo "  -> calculator-api..."
    (cd "$BASE_DIR/applications/calculator-api" && ./build-tarball.sh >/dev/null 2>&1 || true)
fi

if [ -d "$BASE_DIR/applications/nodejs-app" ]; then
    echo "  -> nodejs-app..."
    (cd "$BASE_DIR/applications/nodejs-app" && ./build-tarball.sh >/dev/null 2>&1 || true)
fi

if [ -d "$BASE_DIR/applications/python-app" ]; then
    echo "  -> python-app..."
    (cd "$BASE_DIR/applications/python-app" && ./build-tarball.sh >/dev/null 2>&1 || true)
fi

# 2. Security Fixtures
echo
echo "[+] 2/3 Building Security Fixture Packages..."
if [ -d "$BASE_DIR/security-fixtures/nodejs-malicious" ]; then
    echo "  -> nodejs-malicious..."
    (cd "$BASE_DIR/security-fixtures/nodejs-malicious" && ./build-tarball.sh >/dev/null 2>&1 || true)
fi

if [ -d "$BASE_DIR/security-fixtures/python-malicious" ]; then
    echo "  -> python-malicious..."
    (cd "$BASE_DIR/security-fixtures/python-malicious" && ./build-tarball.sh >/dev/null 2>&1 || true)
fi

if [ -d "$BASE_DIR/security-fixtures/evil-pkg" ]; then
    echo "  -> evil-pkg..."
    (cd "$BASE_DIR/security-fixtures/evil-pkg" && ./build.sh >/dev/null 2>&1 || true)
fi

# 3. Attacks
echo
echo "[+] 3/3 Building Adversarial Attack Scenarios (01 to 07)..."
for scenario_dir in "$BASE_DIR"/attacks/[0-9]*/; do
    if [ -d "$scenario_dir" ] && [ -f "$scenario_dir/build.sh" ]; then
        sname=$(basename "$scenario_dir")
        echo "  -> scenario $sname..."
        (cd "$scenario_dir" && ./build.sh >/dev/null 2>&1 || true)
    fi
done

echo
echo "============================================================"
echo " GENERATION SUMMARY — ARTIFACTS CREATED IN /tmp:"
echo "============================================================"
ls -lh /tmp/*.tar.gz 2>/dev/null || echo "  (No tarballs found in /tmp)"
echo "============================================================"
