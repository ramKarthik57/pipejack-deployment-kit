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

# Canonical service unit check
if [ ! -f "$SCRIPT_DIR/deployment/systemd/pipejack-ci.service" ]; then
    echo "  [-] ERROR: Missing packaged systemd unit: $SCRIPT_DIR/deployment/systemd/pipejack-ci.service" >&2
    exit 1
fi
if [ ! -f "$SCRIPT_DIR/deployment/systemd/pipejack-demo-console.service" ]; then
    echo "  [-] ERROR: Missing packaged systemd unit: $SCRIPT_DIR/deployment/systemd/pipejack-demo-console.service" >&2
    exit 1
fi

if [ $DRY_RUN -eq 1 ]; then
    echo
    echo "============================================================"
    echo " [PREFLIGHT OK] All VM2 prerequisites validated successfully."
    echo " Package units verified:"
    echo "   * $SCRIPT_DIR/deployment/systemd/pipejack-ci.service"
    echo "   * $SCRIPT_DIR/deployment/systemd/pipejack-demo-console.service"
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
    python3 \
    python3-pip \
    build-essential \
    curl \
    jq \
    iproute2 \
    psmisc \
    ca-certificates

# Verify Go toolchain (requires Go 1.23+; Go 1.25.0 is the canonical reference version)
export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"

check_go_installed() {
    if command -v go >/dev/null 2>&1; then
        local raw_ver
        raw_ver=$(go version | awk '{print $3}' | sed 's/go//')
        local major minor
        major=$(echo "$raw_ver" | cut -d. -f1)
        minor=$(echo "$raw_ver" | cut -d. -f2)
        if [ "$major" -eq 1 ] && [ "$minor" -ge 23 ]; then
            return 0
        fi
    fi
    return 1
}

if ! check_go_installed; then
    echo "  Go 1.23+ not found in PATH. Checking /usr/local/go/bin/go..."
    if [ -x "/usr/local/go/bin/go" ]; then
        $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/go
    else
        echo "  Installing Go 1.25.0 from official archive..."
        GO_TAR="go1.25.0.linux-amd64.tar.gz"
        if [ -f "/home/ubuntu/$GO_TAR" ]; then
            $SUDO tar -C /usr/local -xzf "/home/ubuntu/$GO_TAR"
        else
            TMP_GO=$(mktemp -d)
            curl -sSL "https://go.dev/dl/$GO_TAR" -o "$TMP_GO/$GO_TAR"
            $SUDO tar -C /usr/local -xzf "$TMP_GO/$GO_TAR"
            rm -rf "$TMP_GO"
        fi
        $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/go
    fi
fi

# Ensure profile.d configuration exists
if [ ! -f /etc/profile.d/pipejack-go.sh ]; then
    echo 'export PATH=$PATH:/usr/local/go/bin' | $SUDO tee /etc/profile.d/pipejack-go.sh >/dev/null
fi

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
echo "[+] Step 5: Initializing and Cryptographically Verifying Attestation Key..."
mkdir -p "$KEY_DIR"
mkdir -p "$ATTEST_DIR"
chmod 700 "$KEY_DIR"

# Initialize and verify Ed25519 signing key using the actual Go implementation
if [ -x "$BIN_DST" ]; then
    $BIN_DST --init-key
    $BIN_DST --verify-key
else
    (cd "$SCRIPT_DIR/services/custom-ci" && go run . --init-key && go run . --verify-key)
fi

chmod 600 "$KEY_DIR/attest-key"
chmod 644 "$KEY_DIR/attest-key.pub" 2>/dev/null || true
echo "  Key pair verified at $KEY_DIR/attest-key (mode 0600) and $KEY_DIR/attest-key.pub (mode 0644)."

# --- 6. Demo Console Installation ---
echo
echo "[+] Step 6: Deploying Demo Console to $CONSOLE_DIR..."
mkdir -p "$CONSOLE_DIR"
if [ -d "$SCRIPT_DIR/demo/demo-console" ]; then
    cp -r "$SCRIPT_DIR/demo/demo-console/"* "$CONSOLE_DIR/"
fi

# Ensure prepare-demo.sh is executable and execute it to generate artifacts
DEMO_PREP_WARNING=0
if [ -f "$CONSOLE_DIR/prepare-demo.sh" ]; then
    chmod +x "$CONSOLE_DIR/prepare-demo.sh"
    echo "  Generating demo scenario artifacts..."
    DEMO_LOG=$(mktemp)
    if (cd "$CONSOLE_DIR" && ./prepare-demo.sh > "$DEMO_LOG" 2>&1); then
        echo "  [OK] Demo scenario artifacts generated successfully."
        rm -f "$DEMO_LOG"
    else
        echo "  [WARNING] [PARTIAL SUCCESS] Demo scenario artifact generation failed." >&2
        echo "  prepare-demo.sh output:" >&2
        sed 's/^/       | /' "$DEMO_LOG" >&2
        rm -f "$DEMO_LOG"
        echo "  Continuing core installation (demo scenarios are optional for core CI daemon)." >&2
        DEMO_PREP_WARNING=1
    fi
fi

# --- 7. Systemd Service Deployment & Activation ---
echo
echo "[+] Step 7: Configuring Systemd Service Units from Canonical Packaging..."
CI_UNIT_SRC="$SCRIPT_DIR/deployment/systemd/pipejack-ci.service"
CONSOLE_UNIT_SRC="$SCRIPT_DIR/deployment/systemd/pipejack-demo-console.service"

$SUDO cp "$CI_UNIT_SRC" /etc/systemd/system/pipejack-ci.service
$SUDO cp "$CONSOLE_UNIT_SRC" /etc/systemd/system/pipejack-demo-console.service

# Verify unit files with systemd-analyze if available
if command -v systemd-analyze >/dev/null 2>&1; then
    echo "  Validating unit syntax with systemd-analyze verify..."
    systemd-analyze verify /etc/systemd/system/pipejack-ci.service
    systemd-analyze verify /etc/systemd/system/pipejack-demo-console.service
    echo "  [OK] Both systemd service units passed verification."
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

    # Verify service activation status
    if ! systemctl is-active --quiet pipejack-ci.service; then
        echo "  [-] ERROR: pipejack-ci.service failed to activate!" >&2
        $SUDO journalctl -u pipejack-ci -n 25 --no-pager >&2 || true
        exit 1
    fi
    echo "  [OK] pipejack-ci.service is active and running."

    if ! systemctl is-active --quiet pipejack-demo-console.service; then
        echo "  [-] ERROR: pipejack-demo-console.service failed to activate!" >&2
        $SUDO journalctl -u pipejack-demo-console -n 25 --no-pager >&2 || true
        exit 1
    fi
    echo "  [OK] pipejack-demo-console.service is active and running."
fi

# --- 8. Health Verification ---
echo
echo "[+] Step 8: Verifying Service Health..."
if [ -f "$SCRIPT_DIR/scripts/health-check.sh" ]; then
    chmod +x "$SCRIPT_DIR/scripts/health-check.sh"
    if ! "$SCRIPT_DIR/scripts/health-check.sh"; then
        echo "  [-] ERROR: Health check probes failed after installation!" >&2
        exit 1
    fi
fi

echo
echo "============================================================"
if [ "$DEMO_PREP_WARNING" -ne 0 ]; then
    echo " [PARTIAL SUCCESS] PIPEJACK VM2 INSTALLATION COMPLETE WITH WARNINGS"
    echo "============================================================"
    echo " Core services are fully active, but demo scenario artifacts"
    echo " failed to generate. Regenerate them at any time with:"
    echo "   cd $CONSOLE_DIR && ./prepare-demo.sh"
else
    echo " PIPEJACK VM2 INSTALLATION COMPLETE"
fi
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
