#!/bin/bash
# PipeJack CI Server — idempotent installer
# Run on VM-2 as user ubuntu (uses sudo for system paths)
set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="/tmp/custom-ci"
BIN_DST="/usr/local/bin/pipejack-ci"

echo "=== PipeJack CI deployment ==="
echo "  repo:    $REPO_DIR"
echo "  binary:  $BIN_SRC -> $BIN_DST"
echo

# 1. Build if source has changed (or /tmp/custom-ci missing)
if [ ! -f "$BIN_SRC" ] || [ "$REPO_DIR/main.go" -nt "$BIN_SRC" ]; then
    echo "[1/4] building CI server..."
    (cd "$REPO_DIR" && go build -o "$BIN_SRC" .)
    echo "      built: $BIN_SRC"
else
    echo "[1/4] binary up to date, skipping build"
fi

# 2. Copy binary to system path
echo "[2/4] installing binary..."
sudo install -m 755 "$BIN_SRC" "$BIN_DST"
echo "      installed: $BIN_DST"

# 3. Reload systemd (in case unit file changed)
echo "[3/4] reloading systemd..."
sudo systemctl daemon-reload

# 4. Restart service
echo "[4/4] restarting pipejack-ci.service..."
sudo systemctl restart pipejack-ci.service
sleep 2

# Verify
if systemctl is-active --quiet pipejack-ci.service; then
    echo
    echo "=== deploy OK ==="
    systemctl status pipejack-ci.service --no-pager | head -5
    echo
    echo "Listening on:"
    ss -ltnp 2>/dev/null | grep ":${PIPEJACK_PORT:-8888}" || echo "  (port not detected)"
else
    echo
    echo "=== deploy FAILED ==="
    systemctl status pipejack-ci.service --no-pager | head -20
    echo
    echo "Recent log:"
    sudo tail -20 /var/log/pipejack-ci.log
    exit 1
fi
