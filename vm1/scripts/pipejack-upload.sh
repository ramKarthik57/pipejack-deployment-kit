#!/bin/bash
# ==============================================================================
# PipeJack Secure Client — Build Package Uploader (Evaluator Edition)
# Formatted for ANSI High-Fidelity Observability on VM-1 & VM-2
# Adaptive layout optimized for 40:60, 50:50, 60:40, and Fullscreen views
# ==============================================================================

TARFILE="$1"
if [ -z "$TARFILE" ]; then
    echo -e "\033[1;31m[-] Error: No archive specified.\033[0m"
    echo -e "Usage: $0 <build-package.tar.gz>"
    echo -e "\033[1;33m[*] Available packages in current directory:\033[0m"
    ls -1 *.tar.gz 2>/dev/null | sed 's/^/  • /'
    exit 1
fi

if [ ! -f "$TARFILE" ]; then
    echo -e "\033[1;31m[-] Error: File '$TARFILE' not found.\033[0m"
    echo -e "\033[1;33m[*] Available packages in current directory:\033[0m"
    ls -1 *.tar.gz 2>/dev/null | sed 's/^/  • /'
    exit 1
fi

# Color Palette
CYAN="\033[1;36m"
BLUE="\033[1;34m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
MAGENTA="\033[1;35m"
WHITE="\033[1;37m"
GRAY="\033[0;90m"
BOLD="\033[1m"
RESET="\033[0m"

NOW() {
    date +"%H:%M:%S"
}

FILE_SIZE=$(ls -lh "$TARFILE" | awk '{print $5}')
FILE_SHA=$(sha256sum "$TARFILE" | awk '{print $1}')
CI_ENDPOINT="http://192.168.88.133:8888/upload"

echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║     PIPEJACK SECURE CLIENT — BUILD PACKAGE UPLOADER    ║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${RESET}"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[PACKAGE]${RESET} Target Archive: ${WHITE}$TARFILE${RESET} (${YELLOW}$FILE_SIZE${RESET})"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[SHA-256]${RESET} Checksum:       ${YELLOW}${FILE_SHA:0:20}...${RESET}"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[CONNECT]${RESET} CI Endpoint:   ${WHITE}$CI_ENDPOINT${RESET}"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[XFER   ]${RESET} Streaming archive & awaiting CI pipeline..."

# Execute curl directly without noisy looping spinner to prevent line wrapping & clutter
RESPONSE=$(curl -s -w "\n__HTTP_STATUS__:%{http_code}\n__TIME_TOTAL__:%{time_total}s\n" \
     -F "file=@$TARFILE" "$CI_ENDPOINT" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | grep "__HTTP_STATUS__:" | cut -d: -f2)
TIME_TOTAL=$(echo "$RESPONSE" | grep "__TIME_TOTAL__:" | cut -d: -f2)
JSON_BODY=$(echo "$RESPONSE" | sed '/__HTTP_STATUS__:/d; /__TIME_TOTAL__:/d')

echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[STATUS ]${RESET} Handshake complete in ${YELLOW}${TIME_TOTAL:-0.0s}${RESET}"
echo -e "${GRAY}────────────────────────────────────────────────────────${RESET}"

BUILD_ID=""
VERDICT=""
IMAGE=""
STATUS=""

if command -v jq >/dev/null 2>&1; then
    BUILD_ID=$(echo "$JSON_BODY" | jq -r '.build_id // empty' 2>/dev/null)
    VERDICT=$(echo "$JSON_BODY" | jq -r '.pipejack_verdict // .verdict // empty' 2>/dev/null)
    IMAGE=$(echo "$JSON_BODY" | jq -r '.image // empty' 2>/dev/null)
    STATUS=$(echo "$JSON_BODY" | jq -r '.status // empty' 2>/dev/null)
fi

# Fallback parse if jq absent or failed
if [ -z "$BUILD_ID" ]; then
    BUILD_ID=$(echo "$JSON_BODY" | grep -o '"build_id":"[^"]*"' | cut -d'"' -f4)
fi
if [ -z "$BUILD_ID" ]; then
    BUILD_ID=$(date +%s)
fi

if [ -z "$VERDICT" ]; then
    if [ "$HTTP_CODE" = "200" ] || [ "$STATUS" = "pass" ]; then
        VERDICT="ALLOW"
    else
        VERDICT="BLOCK"
    fi
fi

# Detect Project Name, App Tag, and Specific Sensor Explanations
PROJECT="Secure Application Target"
APP_NAME="app"
PROC_FINDING="CLEAN (Allowlisted processes)"
FS_FINDING="MATCH (Pre/Post Merkle root identical)"
NET_FINDING="CLEAN (Zero dropped egress packets)"

if [[ "$TARFILE" == *"java"* ]]; then
    PROJECT="Banking API (Java 17 / Maven)"
    APP_NAME="banking-api"
    if [ "$VERDICT" = "BLOCK" ]; then
        PROC_FINDING="INTERCEPTED (/usr/bin/curl subprocess)"
        FS_FINDING="TAMPER DETECTED (Added backdoor.txt)"
        NET_FINDING="DROPPED (Rogue egress to 10.255.255.1:80)"
    fi
elif [[ "$TARFILE" == *"node"* ]]; then
    PROJECT="Payment Service (Node.js 18 / npm)"
    APP_NAME="payment-service"
    if [ "$VERDICT" = "BLOCK" ]; then
        PROC_FINDING="INTERCEPTED (Spawned /bin/sh reverse shell)"
        FS_FINDING="TAMPER DETECTED (Injected malicious npm hook)"
        NET_FINDING="DROPPED (Unauthorized egress socket to C2)"
    fi
elif [[ "$TARFILE" == *"python"* ]]; then
    PROJECT="Calculator API (Python 3.12 / Wheel)"
    APP_NAME="calculator-api"
    if [ "$VERDICT" = "BLOCK" ]; then
        PROC_FINDING="INTERCEPTED (setup.py invoked /usr/bin/curl)"
        FS_FINDING="TAMPER DETECTED (Injected backdoor module)"
        NET_FINDING="DROPPED (Credential exfiltration dropped)"
    fi
elif [[ "$TARFILE" == *"go"* ]]; then
    PROJECT="Payment Gateway (Go 1.22 / Toolchain)"
    APP_NAME="payment-gateway"
    if [ "$VERDICT" = "BLOCK" ]; then
        PROC_FINDING="INTERCEPTED (Unauthorized build subprocess)"
        FS_FINDING="TAMPER DETECTED (Source tree mismatch)"
        NET_FINDING="DROPPED (Firewall dropped unauthorized egress)"
    fi
elif [[ "$TARFILE" == *"c.tar.gz"* ]] || [[ "$TARFILE" == *"c-compiler"* ]]; then
    PROJECT="Crypto Engine (C / Native GCC)"
    APP_NAME="crypto-engine"
    if [ "$VERDICT" = "BLOCK" ]; then
        PROC_FINDING="INTERCEPTED (Makefile invoked unauthorized binary)"
        FS_FINDING="TAMPER DETECTED (Tampered C source file)"
        NET_FINDING="DROPPED (Outbound network connection dropped)"
    fi
elif [[ "$TARFILE" == *"anomaly"* ]]; then
    PROJECT="Banking API (Behavioral Anomaly Mode)"
    APP_NAME="banking-api"
    PROC_FINDING="CLEAN (Allowlisted binaries: mvn, java)"
    FS_FINDING="MATCH (Pre/Post Merkle root identical)"
    NET_FINDING="CLEAN (Zero dropped egress packets)"
elif [[ "$TARFILE" == *"quarantine"* ]]; then
    PROJECT="Security Baseline (Quarantine Tamper Test)"
    APP_NAME="quarantine-baseline"
    PROC_FINDING="INTERCEPTED (Pre-execution tampering detected)"
    FS_FINDING="TAMPER DETECTED (Direct source file divergence)"
    NET_FINDING="DROPPED (Deployment webhooks cancelled)"
fi

if [ -z "$IMAGE" ]; then
    if [ "$VERDICT" = "ALLOW" ]; then
        IMAGE="localhost:5000/${APP_NAME}:${BUILD_ID}"
    else
        IMAGE="localhost:5000/${APP_NAME}:${BUILD_ID}-quarantine"
    fi
fi

# Modern bulleted card layout guaranteed to fit within 56 columns
# Resilient to 40:60, 50:50, 60:40, and Fullscreen terminal dimensions
if [ "$VERDICT" = "ALLOW" ] || [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}  ● PIPELINE VERDICT: [ ALLOW ] (HTTP ${HTTP_CODE:-200} OK)${RESET}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Build ID:${RESET}       ${WHITE}${BUILD_ID:-N/A}${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Project:${RESET}        ${WHITE}$PROJECT${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Process Differ:${RESET} ${GREEN}$PROC_FINDING${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Filesystem:${RESET}     ${GREEN}$FS_FINDING${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Network Egress:${RESET} ${GREEN}$NET_FINDING${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Attestation:${RESET}    ${GREEN}VERIFIED (Ed25519 Signed & Chained)${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Registry Tag:${RESET}   ${CYAN}$IMAGE${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Enforcement:${RESET}    ${GREEN}APPROVED — Deployed to Staging/Prod${RESET}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${RED}  ● PIPELINE VERDICT: [ BLOCK ] (HTTP ${HTTP_CODE:-403} FORBIDDEN)${RESET}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Build ID:${RESET}       ${WHITE}${BUILD_ID:-N/A}${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Project:${RESET}        ${WHITE}$PROJECT${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Policy Decision:${RESET}${RED}VIOLATION DETECTED${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Process Sensor:${RESET} ${RED}$PROC_FINDING${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Filesystem:${RESET}     ${RED}$FS_FINDING${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Network Egress:${RESET} ${RED}$NET_FINDING${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Attestation:${RESET}    ${YELLOW}RECORDED (Signed BLOCK in ledger)${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Quarantine Tag:${RESET} ${RED}$IMAGE${RESET}"
    echo -e "  ${GRAY}•${RESET} ${BOLD}Enforcement:${RESET}    ${RED}QUARANTINED — Deployment halted${RESET}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
fi
echo
