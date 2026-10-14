#!/usr/bin/env bash
# PipeJack VM2 Role Installer
# Installs and configures the PipeJack CI orchestrator, local Docker registry,
# security policies, attestation ledger, and the Web Demo Console.

set -euo pipefail

# Defaults
DRY_RUN=0
CHECK_MODE=0
SKIP_BUILD=0
NO_RESTART=0
CI_PORT=8888
CONSOLE_PORT=8090
REGISTRY_PORT=5000
CI_WORKDIR="/home/ubuntu/custom-ci"
CONSOLE_DIR="/home/ubuntu/pipejack-demo-console"
ATTEST_DIR="/home/ubuntu/pipejack-attestations"
KEY_DIR="/home/ubuntu/.pipejack"

show_help() {
    cat << EOF
PipeJack VM2 Role Installer

Usage:
  ./install.sh [options]

Options:
  -h, --help                Show this help message and exit
  -c, --check, --dry-run    Run preflight verification only without modifying system
  --skip-build              Skip compiling Go binaries from source
  --no-restart              Do not restart active systemd services
  --ci-port <PORT>          Port for CI orchestrator (default: 8888)
  --console-port <PORT>     Port for Demo Console (default: 8090)
  --workdir <DIR>           CI working directory (default: /home/ubuntu/custom-ci)
  --console-dir <DIR>       Demo console directory (default: /home/ubuntu/pipejack-demo-console)

Examples:
  ./install.sh --dry-run
  ./install.sh
EOF
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--check|--dry-run)
            DRY_RUN=1
            CHECK_MODE=1
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --no-restart)
            NO_RESTART=1
            shift
            ;;
        --ci-port)
            CI_PORT="$2"
            shift 2
            ;;
        --console-port)
            CONSOLE_PORT="$2"
            shift 2
            ;;
        --workdir)
            CI_WORKDIR="$2"
            shift 2
            ;;
        --console-dir)
            CONSOLE_DIR="$2"
            shift 2
            ;;
        *)
            echo "[-] ERROR: Unknown option '$1'. Use --help for usage." >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo " PIPEJACK VM2 ROLE INSTALLER"
echo " Host: $(hostname) ($(whoami))"
echo " CI Port:          $CI_PORT"
echo " Console Port:     $CONSOLE_PORT"
echo " Registry Port:    $REGISTRY_PORT"
echo " CI Working Dir:   $CI_WORKDIR"
echo " Console Dir:      $CONSOLE_DIR"
echo " Mode:             $([ $DRY_RUN -eq 1 ] && echo 'DRY-RUN / PREFLIGHT' || echo 'LIVE INSTALLATION')"
echo "============================================================"

# --- 1. System & Preflight Validation ---
echo
echo "[+] Step 1: Preflight Environment Validation..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "  Operating System: $NAME $VERSION_ID ($VERSION_CODENAME)"
else
    echo "  [!] WARNING: /etc/os-release not found." >&2
fi

ARCH=$(uname -m)
echo "  CPU Architecture: $ARCH"
if [ "$ARCH" != "x86_64" ]; then
    echo "  [!] WARNING: Architecture '$ARCH' may require cross-compilation for eBPF components." >&2
fi

FREE_DISK_KB=$(df -P "/home" 2>/dev/null | tail -1 | awk '{print $4}' || df -P "/" | tail -1 | awk '{print $4}')
FREE_DISK_GB=$((FREE_DISK_KB / 1024 / 1024))
echo "  Available Disk:   ${FREE_DISK_GB} GB"
if [ "$FREE_DISK_GB" -lt 5 ]; then
    echo "  [-] ERROR: Insufficient disk space for Docker containers and builds (minimum 5 GB required)." >&2
    exit 1
fi

SUDO=""
TARGET_USER="$(whoami)"
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "  [-] ERROR: sudo access required to configure VM2 services and systemd." >&2
        exit 1
    fi
fi

if [ $DRY_RUN -eq 1 ]; then
    echo
    echo "============================================================"
    echo " [PREFLIGHT OK] All VM2 prerequisites validated successfully."
    echo " System is ready for VM2 installation."
    echo "============================================================"
    exit 0
fi

# --- 2. Toolchain & Dependencies Installation ---
echo
echo "[+] Step 2: Installing Dependencies (Docker, Go, Python 3, Build Tools)..."
$SUDO apt-get update -y
$SUDO apt-get install -y --no-install-recommends \
    docker.io \
    golang-go \
    python3 \
    python3-pip \
    build-essential \
    curl \
    jq \
    iproute2 \
    psmisc \
    ca-certificates

echo "  Installed docker:  $(docker --version 2>/dev/null || echo 'not active')"
echo "  Installed go:      $(go version 2>/dev/null || echo 'not active')"
echo "  Installed python3: $(python3 --version 2>/dev/null || echo 'not active')"

# --- 3. Docker Service & Registry Setup ---
echo
echo "[+] Step 3: Configuring Docker Daemon and Local Registry..."
$SUDO systemctl enable --now docker

# Add user to docker group if needed
if ! id -nG "$TARGET_USER" | grep -qw "docker"; then
    echo "  Adding $TARGET_USER to docker group..."
    $SUDO usermod -aG docker "$TARGET_USER" || true
fi

# Ensure registry:2 container is running on 0.0.0.0:5000
if ! $SUDO docker ps --format '{{.Names}}' | grep -qw "registry"; then
    if $SUDO docker ps -a --format '{{.Names}}' | grep -qw "registry"; then
        echo "  Starting existing registry container..."
        $SUDO docker start registry
    else
        echo "  Deploying local docker registry on port 5000..."
        $SUDO docker run -d -p 5000:5000 --restart=always --name registry registry:2 || true
    fi
else
    echo "  Local docker registry container is already running."
fi

# --- 4. CI Service Compilation & Installation ---
echo
echo "[+] Step 4: Compiling and Installing PipeJack CI Service..."
mkdir -p "$CI_WORKDIR"

BIN_DST="/usr/local/bin/pipejack-ci"
if [ $SKIP_BUILD -eq 0 ] || [ ! -f "$BIN_DST" ]; then
    echo "  Compiling pipejack-ci binary from $SCRIPT_DIR/services/custom-ci..."
    TMP_BUILD_BIN="/tmp/pipejack-ci-build"
    (cd "$SCRIPT_DIR/services/custom-ci" && go build -o "$TMP_BUILD_BIN" .)
    $SUDO install -m 755 "$TMP_BUILD_BIN" "$BIN_DST"
    rm -f "$TMP_BUILD_BIN"
    echo "  Binary installed to $BIN_DST"
else
    echo "  Skipping compilation (--skip-build requested or binary exists)."
fi

# Copy Dockerfiles and Policies to CI working directory
if [ -d "$SCRIPT_DIR/deployment/docker" ]; then
    echo "  Installing application Dockerfiles to $CI_WORKDIR..."
    cp "$SCRIPT_DIR/deployment/docker/"* "$CI_WORKDIR/"
fi

if [ -d "$SCRIPT_DIR/deployment/policies" ]; then
    echo "  Installing security policies to $CI_WORKDIR..."
    cp "$SCRIPT_DIR/deployment/policies/"* "$CI_WORKDIR/"
fi

# Ensure /etc/pipejack directory exists and install ci.env
$SUDO mkdir -p /etc/pipejack
$SUDO mkdir -p /var/log
if [ -f "$SCRIPT_DIR/deployment/systemd/ci.env" ]; then
    $SUDO cp "$SCRIPT_DIR/deployment/systemd/ci.env" /etc/pipejack/ci.env
elif [ -f "$SCRIPT_DIR/config/ci.env.example" ]; then
    $SUDO cp "$SCRIPT_DIR/config/ci.env.example" /etc/pipejack/ci.env
fi

# --- 5. Cryptographic Keys and Attestation Ledger ---
echo
echo "[+] Step 5: Validating Cryptographic Keys and Attestation Ledger..."
mkdir -p "$KEY_DIR"
mkdir -p "$ATTEST_DIR"
chmod 700 "$KEY_DIR"

if [ ! -f "$KEY_DIR/attest-key" ]; then
    echo "  Generating fresh local Ed25519 signing key for CI attestation ledger..."
    python3 -c "
import os
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    with open('$KEY_DIR/attest-key', 'wb') as f:
        f.write(raw)
    with open('$KEY_DIR/attest-key.pub', 'w') as f:
        f.write(pub.hex())
except Exception:
    # Fallback to 32-byte secure random seed if cryptography not installed
    seed = os.urandom(32)
    with open('$KEY_DIR/attest-key', 'wb') as f:
        f.write(seed)
    with open('$KEY_DIR/attest-key.pub', 'w') as f:
        f.write(seed.hex())
"
    chmod 600 "$KEY_DIR/attest-key"
    chmod 644 "$KEY_DIR/attest-key.pub" 2>/dev/null || true
    echo "  Generated new key: $KEY_DIR/attest-key"
else
    echo "  Preserving existing signing key at $KEY_DIR/attest-key (idempotent preservation)."
fi

# --- 6. Demo Console Installation ---
echo
echo "[+] Step 6: Deploying Demo Console to $CONSOLE_DIR..."
mkdir -p "$CONSOLE_DIR"
if [ -d "$SCRIPT_DIR/demo/demo-console" ]; then
    cp -r "$SCRIPT_DIR/demo/demo-console/"* "$CONSOLE_DIR/"
fi

# Ensure prepare-demo.sh is executable and execute it to generate artifacts
if [ -f "$CONSOLE_DIR/prepare-demo.sh" ]; then
    chmod +x "$CONSOLE_DIR/prepare-demo.sh"
    echo "  Generating demo scenario artifacts..."
    (cd "$CONSOLE_DIR" && ./prepare-demo.sh >/dev/null 2>&1 || true)
fi

# --- 7. Systemd Service Deployment & Activation ---
echo
echo "[+] Step 7: Configuring Systemd Service Units..."
if [ -f "$SCRIPT_DIR/deployment/systemd/pipejack-ci.service" ]; then
    $SUDO cp "$SCRIPT_DIR/deployment/systemd/pipejack-ci.service" /etc/systemd/system/pipejack-ci.service
fi

if [ -f "$SCRIPT_DIR/demo/demo-console/pipejack-demo-console.service" ]; then
    $SUDO cp "$SCRIPT_DIR/demo/demo-console/pipejack-demo-console.service" /etc/systemd/system/pipejack-demo-console.service
elif [ -f "/etc/systemd/system/pipejack-demo-console.service" ]; then
    echo "  Preserving existing /etc/systemd/system/pipejack-demo-console.service"
fi

$SUDO systemctl daemon-reload

if [ $NO_RESTART -eq 0 ]; then
    echo "  Enabling and starting systemd services..."
    $SUDO systemctl enable pipejack-ci.service
    $SUDO systemctl restart pipejack-ci.service

    $SUDO systemctl enable pipejack-demo-console.service
    $SUDO systemctl restart pipejack-demo-console.service

    echo "  Waiting 2 seconds for services to initialize..."
    sleep 2
fi

# --- 8. Health Verification ---
echo
echo "[+] Step 8: Verifying Service Health..."
if [ -f "$SCRIPT_DIR/scripts/health-check.sh" ]; then
    chmod +x "$SCRIPT_DIR/scripts/health-check.sh"
    "$SCRIPT_DIR/scripts/health-check.sh" || echo "  [!] Initial health check returned warnings; check logs."
fi

echo
echo "============================================================"
echo " PIPEJACK VM2 INSTALLATION COMPLETE"
echo "============================================================"
echo " Lead Orchestrator Node Ready:"
echo "   CI Upload Endpoint:  http://192.168.88.133:${CI_PORT}/upload"
echo "   Web Demo Console:    http://192.168.88.133:${CONSOLE_PORT}"
echo "   Local Registry:      http://192.168.88.133:${REGISTRY_PORT}"
echo "   Attestation Ledger:  $ATTEST_DIR"
echo
echo " Diagnostic Commands:"
echo "   * Systemd status:   sudo systemctl status pipejack-ci"
echo "   * CI Service Log:   sudo tail -f /var/log/pipejack-ci.log"
echo "   * Console Log:      tail -f $CONSOLE_DIR/console.log"
echo "============================================================"
exit 0
