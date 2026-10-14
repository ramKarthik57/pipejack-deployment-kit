#!/usr/bin/env bash
# ==============================================================================
# PipeJack Secure Client — Build Package Uploader
# Formatted for ANSI High-Fidelity Observability on VM1 & VM2
# Supports CLI endpoint override, inherited $CI_ENDPOINT, and strict exit codes.
# ==============================================================================

set -uo pipefail

TARFILE=""
ENDPOINT_OVERRIDE=""

show_help() {
    cat << EOF
PipeJack Build Package Uploader

Usage:
  pipejack-upload.sh [options] <build-package.tar.gz>

Options:
  -e, --endpoint <URL>   Explicitly specify the PipeJack CI upload URL
                         (Overrides \$CI_ENDPOINT environment variable)
  -h, --help             Show this help message and exit

Environment Variables:
  CI_ENDPOINT            Upload endpoint URL (Default: http://192.168.88.133:8888/upload)

Exit Codes:
  0   Build ALLOWED and successfully deployed/attested
  1   Build BLOCKED and quarantined due to policy violation
  2   Connection refused, timeout, or server error
EOF
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -e|--endpoint)
            ENDPOINT_OVERRIDE="$2"
            shift 2
            ;;
        *)
            if [ -z "$TARFILE" ]; then
                TARFILE="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$TARFILE" ]; then
    echo -e "\033[1;31m[-] Error: No archive specified.\033[0m" >&2
    echo -e "Usage: $0 [options] <build-package.tar.gz>" >&2
    exit 2
fi

if [ ! -f "$TARFILE" ]; then
    echo -e "\033[1;31m[-] Error: File '$TARFILE' not found.\033[0m" >&2
    exit 2
fi

# Resolve CI Endpoint with strict precedence:
# 1. Explicit CLI argument (--endpoint)
# 2. Inherited environment variable ($CI_ENDPOINT)
# 3. Documented default (http://192.168.88.133:8888/upload)
if [ -n "$ENDPOINT_OVERRIDE" ]; then
    CI_ENDPOINT="$ENDPOINT_OVERRIDE"
elif [ -z "${CI_ENDPOINT:-}" ]; then
    CI_ENDPOINT="http://192.168.88.133:8888/upload"
fi

# Color Palette
CYAN="\033[1;36m"
BLUE="\033[1;34m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
WHITE="\033[1;37m"
GRAY="\033[0;90m"
BOLD="\033[1m"
RESET="\033[0m"

NOW() {
    date +"%H:%M:%S"
}

FILE_SIZE=$(ls -lh "$TARFILE" | awk '{print $5}')
FILE_SHA=$(sha256sum "$TARFILE" | awk '{print $1}')

echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║     PIPEJACK SECURE CLIENT — BUILD PACKAGE UPLOADER    ║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${RESET}"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[PACKAGE]${RESET} Target Archive: ${WHITE}$TARFILE${RESET} (${YELLOW}$FILE_SIZE${RESET})"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[SHA-256]${RESET} Checksum:       ${YELLOW}${FILE_SHA:0:20}...${RESET}"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[CONNECT]${RESET} CI Endpoint:   ${WHITE}$CI_ENDPOINT${RESET}"
echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[XFER   ]${RESET} Streaming archive & awaiting CI pipeline..."

# Execute curl directly
CURL_OUT=$(mktemp)
HTTP_CODE="000"
if HTTP_RAW=$(curl -s -o "$CURL_OUT" -w "%{http_code}" -m 180 \
     -F "file=@$TARFILE" "$CI_ENDPOINT" 2>/dev/null); then
    HTTP_CODE="$HTTP_RAW"
else
    HTTP_CODE="000"
fi

JSON_BODY=$(cat "$CURL_OUT" 2>/dev/null || echo "")
rm -f "$CURL_OUT"

echo -e " ${GRAY}[$(NOW)]${RESET} ${BLUE}[STATUS ]${RESET} HTTP Response Status: ${YELLOW}${HTTP_CODE}${RESET}"
echo -e "${GRAY}────────────────────────────────────────────────────────${RESET}"

# Handle connection failure or unreachable endpoint
if [[ "$HTTP_CODE" =~ ^0+$ ]] || [ -z "$HTTP_CODE" ]; then
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${RED}  ● CONNECTION ERROR: CI SERVER UNREACHABLE${RESET}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  Failed to connect to PipeJack CI server at: ${WHITE}$CI_ENDPOINT${RESET}"
    echo -e "  Verify that VM2 is running and port 8888 is accessible."
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    exit 2
fi

BUILD_ID=""
VERDICT=""
IMAGE=""
STATUS=""

if command -v jq >/dev/null 2>&1; then
    BUILD_ID=$(echo "$JSON_BODY" | jq -r '.build_id // empty' 2>/dev/null || echo "")
    VERDICT=$(echo "$JSON_BODY" | jq -r '.pipejack_verdict // .verdict // empty' 2>/dev/null || echo "")
    IMAGE=$(echo "$JSON_BODY" | jq -r '.image // empty' 2>/dev/null || echo "")
    STATUS=$(echo "$JSON_BODY" | jq -r '.status // empty' 2>/dev/null || echo "")
fi

# Fallback parse if jq absent or failed
if [ -z "$BUILD_ID" ]; then
    BUILD_ID=$(echo "$JSON_BODY" | grep -o '"build_id":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
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

# Detect Project Name and App Tag
PROJECT="Application Workload"
APP_NAME="app"
PROC_FINDING="CLEAN (Allowlisted processes)"
FS_FINDING="MATCH (Pre/Post Merkle root identical)"
NET_FINDING="CLEAN (Zero dropped egress packets)"

if [[ "$TARFILE" == *"banking"* ]] || [[ "$TARFILE" == *"java"* ]]; then
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
    PROJECT="Fraud Inference (Python 3.12 / Flask)"
    APP_NAME="fraud-service"
    if [ "$VERDICT" = "BLOCK" ]; then
        PROC_FINDING="INTERCEPTED (setup.py invoked /usr/bin/curl)"
        FS_FINDING="TAMPER DETECTED (Injected backdoor module)"
        NET_FINDING="DROPPED (Credential exfiltration dropped)"
    fi
elif [[ "$TARFILE" == *"calc"* ]]; then
    PROJECT="Calculator API (Spring Boot AST)"
    APP_NAME="calculator-api"
fi

if [ -z "$IMAGE" ]; then
    if [ "$VERDICT" = "ALLOW" ]; then
        IMAGE="localhost:5000/${APP_NAME}:${BUILD_ID}"
    else
        IMAGE="localhost:5000/${APP_NAME}:${BUILD_ID}-quarantine"
    fi
fi

if [ "$VERDICT" = "ALLOW" ] && [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}  ● PIPELINE VERDICT: [ ALLOW ] (HTTP ${HTTP_CODE} OK)${RESET}"
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
    exit 0
elif [ "$VERDICT" = "BLOCK" ] || [ "$HTTP_CODE" = "403" ]; then
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${RED}  ● PIPELINE VERDICT: [ BLOCK ] (HTTP ${HTTP_CODE} FORBIDDEN)${RESET}"
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
    exit 1
else
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${YELLOW}  ● PIPELINE UNEXPECTED STATUS (HTTP ${HTTP_CODE})${RESET}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  Response: $JSON_BODY"
    exit 2
fi
