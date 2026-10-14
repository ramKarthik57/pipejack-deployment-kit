#!/usr/bin/env bash
# PipeJack VM1 Role Installer
# Installs workload applications, attack scenarios, security fixtures, and upload utilities.
# VM1 is a lightweight developer/workload client. Docker, Java, and Maven are NOT installed here.

set -euo pipefail

# Default configuration
DRY_RUN=0
CHECK_MODE=0
SKIP_BUILD=0
CI_ENDPOINT="http://192.168.88.133:8888/upload"
TARGET_DIR="${HOME}"

SKIP_DEPS=0

show_help() {
    cat << EOF
PipeJack VM1 Role Installer

Usage:
  ./install.sh [options]

Options:
  -h, --help                Show this help message and exit
  -c, --check, --dry-run    Run preflight verification only without modifying system
  --ci-endpoint <URL>       Set the PipeJack CI upload URL (default: http://192.168.88.133:8888/upload)
  --target-dir <DIR>        Destination directory for workloads (default: \$HOME)
  --skip-deps, --no-deps    Skip apt-get package installation (for non-root or test runs)
  --skip-build              Skip initial generation of workload tarballs in /tmp

Examples:
  ./install.sh --dry-run
  ./install.sh --ci-endpoint http://192.168.88.133:8888/upload
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
        --ci-endpoint)
            CI_ENDPOINT="$2"
            shift 2
            ;;
        --target-dir)
            TARGET_DIR="$2"
            shift 2
            ;;
        --skip-deps|--no-deps)
            SKIP_DEPS=1
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        *)
            echo "[-] ERROR: Unknown option '$1'. Use --help for usage." >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo " PIPEJACK VM1 ROLE INSTALLER"
echo " Host: $(hostname) ($(whoami))"
echo " Target Directory: $TARGET_DIR"
echo " CI Endpoint:      $CI_ENDPOINT"
echo " Mode:             $([ $DRY_RUN -eq 1 ] && echo 'DRY-RUN / PREFLIGHT' || echo 'LIVE INSTALLATION')"
echo "============================================================"

# --- 1. System & Preflight Validation ---
echo
echo "[+] Step 1: Preflight Environment Validation..."

# OS Check
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "  Operating System: $NAME $VERSION_ID ($VERSION_CODENAME)"
    if [[ "$ID" != "ubuntu" && "$ID_LIKE" != *"debian"* ]]; then
        echo "  [!] WARNING: Expected Ubuntu/Debian; detected '$ID'. Proceeding with caution." >&2
    fi
else
    echo "  [!] WARNING: /etc/os-release not found. Unable to verify OS distribution." >&2
fi

# Architecture Check
ARCH=$(uname -m)
echo "  CPU Architecture: $ARCH"
if [ "$ARCH" != "x86_64" ]; then
    echo "  [!] WARNING: PipeJack eBPF/container profiles are calibrated for x86_64." >&2
fi

# Disk Space Check
FREE_DISK_KB=$(df -P "$TARGET_DIR" | tail -1 | awk '{print $4}')
FREE_DISK_GB=$((FREE_DISK_KB / 1024 / 1024))
MIN_DISK_GB="${PIPEJACK_MIN_DISK_GB:-1}"
echo "  Available Disk:   ${FREE_DISK_GB} GB in $TARGET_DIR"
if [ "$FREE_DISK_GB" -lt "$MIN_DISK_GB" ]; then
    echo "  [-] ERROR: Insufficient disk space (minimum ${MIN_DISK_GB} GB required, found ${FREE_DISK_GB} GB)." >&2
    exit 1
fi

# Network Connectivity Check to CI Endpoint (non-fatal warning if VM2 offline during preflight)
CI_HOST=$(echo "$CI_ENDPOINT" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:.*$||')
echo "  Target CI Host:   $CI_HOST"
if ping -c 1 -W 2 "$CI_HOST" >/dev/null 2>&1; then
    echo "  Network Reach:    CI Host $CI_HOST is REACHABLE via ICMP ping."
else
    echo "  [!] Network Note: CI Host $CI_HOST did not respond to ICMP ping (may be offline or firewalled)."
fi

if [ $DRY_RUN -eq 1 ]; then
    echo
    echo "============================================================"
    echo " [PREFLIGHT OK] All VM1 prerequisites validated successfully."
    echo " System is ready for VM1 installation."
    echo "============================================================"
    exit 0
fi

# --- 2. Toolchain & Dependencies Installation ---
echo
echo "[+] Step 2: Installing Client Dependencies (git, curl, tar, jq, nodejs, npm, python3)..."
echo "  Note: Docker, Java, and Maven are deliberately NOT installed on VM1 (VM1 is client-only)."

if [ $SKIP_DEPS -eq 1 ]; then
    echo "  Skipping system package installation (--skip-deps requested)."
else
    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            echo "  [-] ERROR: sudo access required to install system dependencies." >&2
            exit 1
        fi
    fi

    $SUDO apt-get update -y
    $SUDO apt-get install -y --no-install-recommends \
        git \
        curl \
        tar \
        jq \
        nodejs \
        npm \
        python3 \
        iproute2 \
        ca-certificates
fi

# Verify installed versions
echo "  Installed git:     $(git --version)"
echo "  Installed curl:    $(curl --version | head -1)"
echo "  Installed tar:     $(tar --version | head -1)"
echo "  Installed jq:      $(jq --version)"
echo "  Installed node:    $(node -v 2>/dev/null || echo 'not found')"
echo "  Installed npm:     $(npm -v 2>/dev/null || echo 'not found')"
echo "  Installed python3: $(python3 --version)"

# --- 3. Directory Layout & File Deployment ---
echo
echo "[+] Step 3: Deploying Workloads, Attacks, Fixtures, and Scripts to $TARGET_DIR..."
mkdir -p "$TARGET_DIR"

# Applications
mkdir -p "$TARGET_DIR/applications"
for app in banking-api calculator-api nodejs-app python-app; do
    if [ -d "$SCRIPT_DIR/applications/$app" ]; then
        echo "  Deploying applications/$app -> $TARGET_DIR/applications/$app and $TARGET_DIR/$app..."
        mkdir -p "$TARGET_DIR/applications/$app"
        cp -r "$SCRIPT_DIR/applications/$app/"* "$TARGET_DIR/applications/$app/"
        if [ ! -e "$TARGET_DIR/$app" ]; then
            ln -s "$TARGET_DIR/applications/$app" "$TARGET_DIR/$app"
        fi
    fi
done

# Legacy compatibility symlink for spring-calc -> calculator-api
if [ ! -e "$TARGET_DIR/spring-calc" ]; then
    if [ -d "$TARGET_DIR/applications/calculator-api" ]; then
        ln -s "$TARGET_DIR/applications/calculator-api" "$TARGET_DIR/spring-calc"
        echo "  Created legacy compatibility symlink: $TARGET_DIR/spring-calc -> applications/calculator-api"
    elif [ -d "$TARGET_DIR/calculator-api" ]; then
        ln -s "$TARGET_DIR/calculator-api" "$TARGET_DIR/spring-calc"
        echo "  Created legacy compatibility symlink: $TARGET_DIR/spring-calc -> calculator-api"
    fi
fi

# Attacks
if [ -d "$SCRIPT_DIR/attacks" ]; then
    echo "  Deploying attacks suite -> $TARGET_DIR/attacks..."
    mkdir -p "$TARGET_DIR/attacks"
    cp -r "$SCRIPT_DIR/attacks/"* "$TARGET_DIR/attacks/"
fi

# Security Fixtures
mkdir -p "$TARGET_DIR/security-fixtures"
for fix in evil-pkg nodejs-malicious python-malicious vuln-app; do
    if [ -d "$SCRIPT_DIR/security-fixtures/$fix" ]; then
        echo "  Deploying security-fixtures/$fix -> $TARGET_DIR/security-fixtures/$fix and $TARGET_DIR/$fix..."
        mkdir -p "$TARGET_DIR/security-fixtures/$fix"
        cp -r "$SCRIPT_DIR/security-fixtures/$fix/"* "$TARGET_DIR/security-fixtures/$fix/"
        if [ ! -e "$TARGET_DIR/$fix" ]; then
            ln -s "$TARGET_DIR/security-fixtures/$fix" "$TARGET_DIR/$fix"
        fi
    fi
done

# Scripts (deployed to both $TARGET_DIR/scripts and $TARGET_DIR/ for workflow convenience)
mkdir -p "$TARGET_DIR/scripts"
if [ -f "$SCRIPT_DIR/scripts/pipejack-upload.sh" ]; then
    echo "  Deploying pipejack-upload.sh -> $TARGET_DIR/pipejack-upload.sh and $TARGET_DIR/scripts/..."
    cp "$SCRIPT_DIR/scripts/pipejack-upload.sh" "$TARGET_DIR/scripts/pipejack-upload.sh"
    chmod +x "$TARGET_DIR/scripts/pipejack-upload.sh"
    cp "$SCRIPT_DIR/scripts/pipejack-upload.sh" "$TARGET_DIR/pipejack-upload.sh"
    chmod +x "$TARGET_DIR/pipejack-upload.sh"
fi

# Tarball Generator
if [ -f "$SCRIPT_DIR/scripts/build-all-tarballs.sh" ]; then
    echo "  Deploying build-all-tarballs.sh -> $TARGET_DIR/build-all-tarballs.sh and $TARGET_DIR/scripts/..."
    cp "$SCRIPT_DIR/scripts/build-all-tarballs.sh" "$TARGET_DIR/scripts/build-all-tarballs.sh"
    chmod +x "$TARGET_DIR/scripts/build-all-tarballs.sh"
    cp "$SCRIPT_DIR/scripts/build-all-tarballs.sh" "$TARGET_DIR/build-all-tarballs.sh"
    chmod +x "$TARGET_DIR/build-all-tarballs.sh"
fi

# --- 4. Permissions Hardening ---
echo
echo "[+] Step 4: Configuring Executable Permissions on Scripts..."
find "$TARGET_DIR/attacks" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/applications" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/security-fixtures" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/banking-api" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/calculator-api" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/nodejs-app" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/python-app" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/nodejs-malicious" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/python-malicious" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
find "$TARGET_DIR/evil-pkg" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true

# --- 5. Environment & Shell Setup ---
echo
echo "[+] Step 5: Configuring Shell Environment & Upload Aliases..."
BASHRC="${BASHRC:-$HOME/.bashrc}"
if [ -f "$BASHRC" ]; then
    if ! grep -q "CI_ENDPOINT" "$BASHRC"; then
        echo "  Adding PipeJack environment variables to $BASHRC..."
        cat << EOF >> "$BASHRC"

# PipeJack VM1 Environment
export CI_ENDPOINT="${CI_ENDPOINT}"
export VM2="${CI_HOST}"
alias upload="${TARGET_DIR}/pipejack-upload.sh"
alias pipejack-upload="${TARGET_DIR}/pipejack-upload.sh"
EOF
    else
        echo "  PipeJack configuration already present in $BASHRC; updating CI_ENDPOINT..."
        sed -i "s|export CI_ENDPOINT=.*|export CI_ENDPOINT=\"${CI_ENDPOINT}\"|" "$BASHRC"
        sed -i "s|export VM2=.*|export VM2=\"${CI_HOST}\"|" "$BASHRC"
    fi
fi

# --- 6. Initial Archive Generation ---
if [ $SKIP_BUILD -eq 0 ]; then
    echo
    echo "[+] Step 6: Generating Initial Workload and Attack Tarballs in ${PIPEJACK_OUTPUT_DIR:-/tmp}..."
    if [ -f "$TARGET_DIR/build-all-tarballs.sh" ]; then
        if [ -n "${PIPEJACK_OUTPUT_DIR:-}" ]; then
            "$TARGET_DIR/build-all-tarballs.sh" --output-dir "$PIPEJACK_OUTPUT_DIR"
        else
            "$TARGET_DIR/build-all-tarballs.sh"
        fi
    fi
else
    echo
    echo "[+] Step 6: Skipping archive generation (--skip-build requested)."
fi

echo
echo "============================================================"
echo " PIPEJACK VM1 INSTALLATION COMPLETE"
echo "============================================================"
echo " Client Node Ready:"
echo "   Target Directory: $TARGET_DIR"
echo "   CI Upload Target: $CI_ENDPOINT"
echo "   Uploader Tool:    $TARGET_DIR/pipejack-upload.sh"
echo
echo " Quick Verification Commands:"
echo "   1. Source environment:  source ~/.bashrc"
echo "   2. Upload clean app:    upload /tmp/banking-api-clean.tar.gz"
echo "   3. Run all attacks:     cd ~/attacks && ./run-all.sh"
echo "============================================================"
exit 0
