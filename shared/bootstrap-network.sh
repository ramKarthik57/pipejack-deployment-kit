#!/usr/bin/env bash
# PipeJack Guest Network Bootstrap Utility
# Configures private inter-VM static IP and NAT outbound connectivity on a fresh Ubuntu VM.
# Supports VM1 (192.168.88.132) and VM2 (192.168.88.133) in the 192.168.88.0/24 private lab topology.

set -euo pipefail

# Default configuration
ROLE=""
PRIVATE_IP=""
SUBNET_CIDR="24"
PRIVATE_SUBNET="192.168.88.0/24"
PRIVATE_IFACE=""
NAT_IFACE=""
DRY_RUN=0
FORCE=0
SKIP_APPLY=0
SYS_CLASS_NET="${PIPEJACK_SYS_CLASS_NET:-/sys/class/net}"
NETPLAN_DIR="${PIPEJACK_NETPLAN_DIR:-/etc/netplan}"
NETPLAN_FILE="$NETPLAN_DIR/01-pipejack-netcfg.yaml"
BACKUP_DIR=""

show_help() {
    cat << 'EOF'
PipeJack Guest Network Bootstrap Utility

Usage:
  sudo ./bootstrap-network.sh --role <vm1|vm2> [options]

Required Options:
  -r, --role <vm1|vm2>      Target VM role:
                              vm1 -> Static IP: 192.168.88.132/24 (Client)
                              vm2 -> Static IP: 192.168.88.133/24 (Server Orchestrator)

Optional Settings:
  --private-ip <IP>         Override default private static IP for role
  --private-iface <IFACE>   Manually specify private lab interface (e.g. ens33, ens34)
  --nat-iface <IFACE>       Manually specify NAT / internet interface (e.g. ens37, ens38)
  --netplan-dir <DIR>       Override default netplan directory (default: /etc/netplan)
  -d, --dry-run             Preview generated Netplan configuration without applying
  -f, --force               Bypass interactive confirmation prompt
  --skip-apply              Write Netplan configuration file but do not execute apply
  -h, --help                Show this help message and exit

Examples:
  # On VM2 (Server Orchestrator):
  sudo ./bootstrap-network.sh --role vm2

  # On VM1 (Workload Client):
  sudo ./bootstrap-network.sh --role vm1

  # With manual interface specification:
  sudo ./bootstrap-network.sh --role vm2 --private-iface ens33 --nat-iface ens37

  # Dry-run preview:
  ./bootstrap-network.sh --role vm2 --dry-run
EOF
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--role)
            ROLE="${2:-}"
            shift 2
            ;;
        --private-ip)
            PRIVATE_IP="${2:-}"
            shift 2
            ;;
        --private-iface)
            PRIVATE_IFACE="${2:-}"
            shift 2
            ;;
        --nat-iface)
            NAT_IFACE="${2:-}"
            shift 2
            ;;
        --netplan-dir)
            NETPLAN_DIR="${2:-}"
            NETPLAN_FILE="$NETPLAN_DIR/01-pipejack-netcfg.yaml"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -f|--force)
            FORCE=1
            shift
            ;;
        --skip-apply)
            SKIP_APPLY=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "[-] ERROR: Unknown option '$1'. Use --help for usage." >&2
            exit 1
            ;;
    esac
done

echo "============================================================"
echo " PIPEJACK GUEST NETWORK BOOTSTRAP UTILITY"
echo " Host: $(hostname) ($(whoami))"
echo " Mode: $([ "$DRY_RUN" -eq 1 ] && echo 'DRY-RUN / PREVIEW' || echo 'LIVE APPLICATION')"
echo "============================================================"

# 1. Validate role
if [ -z "$ROLE" ]; then
    echo "[-] ERROR: Missing required option --role <vm1|vm2>." >&2
    echo "    Specify '--role vm1' for the Workload Client or '--role vm2' for the Server Orchestrator." >&2
    exit 1
fi

case "$ROLE" in
    vm1)
        TARGET_ROLE_DESC="VM1 (Workload Client)"
        [ -z "$PRIVATE_IP" ] && PRIVATE_IP="192.168.88.132"
        ;;
    vm2)
        TARGET_ROLE_DESC="VM2 (Server Orchestrator)"
        [ -z "$PRIVATE_IP" ] && PRIVATE_IP="192.168.88.133"
        ;;
    *)
        echo "[-] ERROR: Invalid role '$ROLE'. Must be 'vm1' or 'vm2'." >&2
        exit 1
        ;;
esac

# Validate IPv4 format
validate_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done
    return 0
}

if ! validate_ipv4 "$PRIVATE_IP"; then
    echo "[-] ERROR: Invalid private IPv4 address format: '$PRIVATE_IP'." >&2
    exit 1
fi

echo "[+] Target Role: $TARGET_ROLE_DESC"
echo "[+] Configured Private IP: $PRIVATE_IP/$SUBNET_CIDR"

# Validate root privileges for live modification (bypassed if PIPEJACK_NETPLAN_DIR is set for isolated testing)
if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ] && [ -z "$PIPEJACK_NETPLAN_DIR" ]; then
    echo "[-] ERROR: Root privileges required to configure networking. Run with sudo:" >&2
    echo "    sudo $0 --role $ROLE" >&2
    exit 1
fi

# 2. Interface Discovery & Ambiguity Checks
echo
echo "[+] Step 1: Discovering Network Interfaces..."

DISCOVERED_IFACES=()
if [ -d "$SYS_CLASS_NET" ]; then
    for iface_path in "$SYS_CLASS_NET"/*; do
        [ -e "$iface_path" ] || continue
        iface="$(basename "$iface_path")"
        case "$iface" in
            lo|docker*|veth*|br-*|virbr*)
                continue
                ;;
            *)
                DISCOVERED_IFACES+=("$iface")
                ;;
        esac
    done
fi

if [ ${#DISCOVERED_IFACES[@]} -eq 0 ]; then
    echo "[-] ERROR: No physical or virtual ethernet interfaces found in $SYS_CLASS_NET." >&2
    echo "    Ensure network adapters are connected to this virtual machine in VMware." >&2
    exit 1
fi

echo "  Discovered ethernet interfaces: ${DISCOVERED_IFACES[*]}"

# Determine NAT interface
DETECTED_NAT=""
if command -v ip >/dev/null 2>&1; then
    DETECTED_NAT="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || echo "")"
fi

if [ -n "$NAT_IFACE" ]; then
    echo "  NAT / Internet interface explicitly specified: $NAT_IFACE"
    if [ ! -d "$SYS_CLASS_NET/$NAT_IFACE" ]; then
        echo "[-] ERROR: Specified NAT interface '$NAT_IFACE' does not exist in $SYS_CLASS_NET." >&2
        exit 1
    fi
elif [ -n "$DETECTED_NAT" ] && [[ " ${DISCOVERED_IFACES[*]} " =~ " ${DETECTED_NAT} " ]]; then
    NAT_IFACE="$DETECTED_NAT"
    echo "  Auto-detected NAT / Internet interface via default route: $NAT_IFACE"
else
    # Ambiguous NAT: No default route found
    if [ ${#DISCOVERED_IFACES[@]} -eq 1 ]; then
        NAT_IFACE="${DISCOVERED_IFACES[0]}"
        echo "  [!] Notice: Only 1 interface discovered. Defaulted NAT interface to: $NAT_IFACE"
    else
        echo "[-] ERROR: Ambiguous network configuration: Multiple interfaces detected (${DISCOVERED_IFACES[*]}) but no default route exists." >&2
        echo "    Cannot reliably determine which interface connects to NAT/Internet." >&2
        echo "    Remediation: Specify --nat-iface <interface> and --private-iface <interface> explicitly." >&2
        exit 1
    fi
fi

# Determine Private interface
if [ -n "$PRIVATE_IFACE" ]; then
    echo "  Private lab interface explicitly specified: $PRIVATE_IFACE"
    if [ ! -d "$SYS_CLASS_NET/$PRIVATE_IFACE" ]; then
        echo "[-] ERROR: Specified private interface '$PRIVATE_IFACE' does not exist in $SYS_CLASS_NET." >&2
        exit 1
    fi
else
    # Find candidate non-NAT interfaces
    PRIVATE_CANDIDATES=()
    for candidate in "${DISCOVERED_IFACES[@]}"; do
        if [ "$candidate" != "$NAT_IFACE" ]; then
            PRIVATE_CANDIDATES+=("$candidate")
        fi
    done

    if [ ${#PRIVATE_CANDIDATES[@]} -eq 1 ]; then
        PRIVATE_IFACE="${PRIVATE_CANDIDATES[0]}"
        echo "  Auto-detected Private Lab interface: $PRIVATE_IFACE"
    elif [ ${#PRIVATE_CANDIDATES[@]} -eq 0 ]; then
        echo "[-] ERROR: No candidate private lab interface found." >&2
        echo "    PipeJack requires two distinct network adapters: one Host-Only (private) and one NAT." >&2
        echo "    Verify in VMware settings that a secondary network adapter is connected." >&2
        exit 1
    else
        echo "[-] ERROR: Ambiguous private interface discovery: Multiple candidate non-NAT interfaces found: ${PRIVATE_CANDIDATES[*]}." >&2
        echo "    Remediation: Specify --private-iface <interface> explicitly." >&2
        exit 1
    fi
fi

if [ "$PRIVATE_IFACE" = "$NAT_IFACE" ]; then
    echo "[-] ERROR: Private interface ($PRIVATE_IFACE) cannot be the same as NAT interface ($NAT_IFACE)." >&2
    echo "    PipeJack requires two distinct network adapters for proper isolation." >&2
    exit 1
fi

ipv4_to_int() {
    local ip="$1"
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

cidr_to_netmask() {
    local prefix="$1"
    if [ "$prefix" -eq 0 ]; then
        echo 0
    else
        echo $(( ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF) ))
    fi
}

check_cidr_overlap() {
    local ip1="$1" prefix1="$2"
    local ip2="$3" prefix2="$4"

    local int1 int2 mask1 min_prefix min_mask
    int1=$(ipv4_to_int "$ip1")
    int2=$(ipv4_to_int "$ip2")

    if [ "$prefix1" -le "$prefix2" ]; then
        min_prefix="$prefix1"
    else
        min_prefix="$prefix2"
    fi
    min_mask=$(cidr_to_netmask "$min_prefix")

    if [ $(( (int1 & min_mask) == (int2 & min_mask) )) -eq 1 ]; then
        return 0 # Overlap detected
    else
        return 1 # No overlap
    fi
}

# 3. Check for Subnet Conflicts
echo
echo "[+] Step 2: Validating Subnet Topology and Conflict Avoidance..."

if command -v ip >/dev/null 2>&1; then
    NAT_CURRENT_ADDR="$(ip -4 addr show "$NAT_IFACE" 2>/dev/null | awk '/inet / {print $2; exit}' || echo "")"
    if [ -n "$NAT_CURRENT_ADDR" ]; then
        NAT_CURRENT_IP="${NAT_CURRENT_ADDR%/*}"
        NAT_CURRENT_CIDR="${NAT_CURRENT_ADDR#*/}"
        [ "$NAT_CURRENT_CIDR" = "$NAT_CURRENT_ADDR" ] && NAT_CURRENT_CIDR="24"
        echo "  Current NAT interface address: $NAT_CURRENT_ADDR"
        if check_cidr_overlap "$PRIVATE_IP" "$SUBNET_CIDR" "$NAT_CURRENT_IP" "$NAT_CURRENT_CIDR"; then
            echo "[-] ERROR: Subnet conflict detected!" >&2
            echo "    NAT interface '$NAT_IFACE' ($NAT_CURRENT_ADDR) overlaps with private lab subnet ($PRIVATE_IP/$SUBNET_CIDR)." >&2
            echo "    The private inter-VM lab requires exclusive use of $PRIVATE_IP/$SUBNET_CIDR without route overlap." >&2
            echo "    Remediation: In VMware Virtual Network Editor, change your NAT subnet to 192.168.152.0/24 or another non-conflicting range." >&2
            exit 1
        fi
    fi
fi
echo "  [OK] Private subnet ($PRIVATE_IP/$SUBNET_CIDR) is distinct from external/NAT routes."

# 4. Generate Clean Netplan Configuration
echo
echo "[+] Step 3: Generating Netplan Configuration..."

NETPLAN_CONTENT="# PipeJack Automated Network Configuration
# Generated by bootstrap-network.sh for $TARGET_ROLE_DESC
# Security Rule: Private lab interface has static IP with NO default gateway.
# Outbound traffic routes via NAT interface with higher route priority (metric 101).
network:
  version: 2
  renderer: networkd
  ethernets:
    $PRIVATE_IFACE:
      dhcp4: no
      addresses:
        - $PRIVATE_IP/$SUBNET_CIDR
    $NAT_IFACE:
      dhcp4: yes
      dhcp4-overrides:
        route-metric: 101
"

echo "------------------------------------------------------------"
echo "$NETPLAN_CONTENT"
echo "------------------------------------------------------------"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[OK] DRY-RUN PREVIEW COMPLETE. No files were modified."
    exit 0
fi

# 5. Interactive Confirmation (without --force)
if [ "$FORCE" -eq 0 ]; then
    if [ "${PIPEJACK_TEST_TRY:-0}" -eq 1 ]; then
        echo "  [TEST] Bypassing confirmation prompt for netplan try testing (PIPEJACK_TEST_TRY=1)."
    elif [ -t 0 ]; then
        echo
        read -r -p "Apply these network changes to this virtual machine? [y/N]: " CONFIRM_APPLY
        if [[ ! "$CONFIRM_APPLY" =~ ^[Yy]$ ]]; then
            echo "[-] Network configuration cancelled by user. No files were modified."
            exit 0
        fi
    else
        echo "[-] ERROR: Non-interactive execution requires --force to confirm network changes." >&2
        echo "    Run with '--force' to proceed non-interactively." >&2
        exit 1
    fi
fi

# 6. Safe Backup Creation
echo
echo "[+] Step 4: Backing Up Existing Netplan Files..."

mkdir -p "$NETPLAN_DIR"
BACKUP_DIR=$(mktemp -d -p "$NETPLAN_DIR" "pipejack-backup-$(date +%Y%m%d%H%M%S)-XXXXXX" 2>/dev/null || true)
if [ -z "$BACKUP_DIR" ] || [ ! -d "$BACKUP_DIR" ]; then
    BACKUP_DIR="$NETPLAN_DIR/pipejack-backup-$(date +%Y%m%d%H%M%S%N)-$$"
    mkdir -p -m 0700 "$BACKUP_DIR"
fi
chmod 0700 "$BACKUP_DIR"
ORIGINAL_RECORD="$BACKUP_DIR/original_files.txt"
RENAMED_RECORD="$BACKUP_DIR/renamed_by_this_run.txt"
touch "$ORIGINAL_RECORD" "$RENAMED_RECORD"

# Snapshot existing yaml files (including pre-existing 01-pipejack-netcfg.yaml)
PRE_EXISTING_NETPLAN_FILE=0
if [ -f "$NETPLAN_FILE" ]; then
    PRE_EXISTING_NETPLAN_FILE=1
    cp -p "$NETPLAN_FILE" "$BACKUP_DIR/01-pipejack-netcfg.yaml.prerun"
    echo "$NETPLAN_FILE" >> "$ORIGINAL_RECORD"
    echo "  Backed up pre-existing PipeJack configuration: $NETPLAN_FILE"
fi

shopt -s nullglob
EXISTING_YAMLS=("$NETPLAN_DIR"/*.yaml)
shopt -u nullglob

for yf in "${EXISTING_YAMLS[@]}"; do
    [ -f "$yf" ] || continue
    if [ "$yf" != "$NETPLAN_FILE" ]; then
        cp -p "$yf" "$BACKUP_DIR/$(basename "$yf")"
        echo "$yf" >> "$ORIGINAL_RECORD"
        echo "  Backed up: $yf -> $BACKUP_DIR/$(basename "$yf")"
    fi
done

echo "  [OK] Netplan backup preserved in: $BACKUP_DIR"

# Restoration function for failure rollback
restore_network_state() {
    local rollback_failed=0
    echo
    echo "[-] FAILURE DETECTED: Initiating full network configuration rollback..." >&2

    # 1. Restore or remove NETPLAN_FILE
    if [ "$PRE_EXISTING_NETPLAN_FILE" -eq 1 ] && [ -f "$BACKUP_DIR/01-pipejack-netcfg.yaml.prerun" ]; then
        echo "  Restoring pre-existing PipeJack configuration: $NETPLAN_FILE" >&2
        cp -p "$BACKUP_DIR/01-pipejack-netcfg.yaml.prerun" "$NETPLAN_FILE" || rollback_failed=1
    else
        rm -f "$NETPLAN_FILE"
    fi

    # 2. Restore files renamed to .disabled by THIS execution ONLY
    if [ -f "$RENAMED_RECORD" ]; then
        while IFS= read -r dis_file; do
            [ -n "$dis_file" ] || continue
            orig_file="${dis_file%.disabled}"
            base_name="$(basename "$orig_file")"
            if [ -f "$dis_file" ]; then
                if [ -f "$BACKUP_DIR/$base_name" ]; then
                    cp -p "$BACKUP_DIR/$base_name" "$orig_file" || rollback_failed=1
                    rm -f "$dis_file"
                    echo "  Restored: $orig_file" >&2
                else
                    mv "$dis_file" "$orig_file" || rollback_failed=1
                    echo "  Re-enabled: $orig_file" >&2
                fi
            fi
        done < "$RENAMED_RECORD"
    fi

    # 3. Explicitly re-apply runtime network state with netplan if available
    if command -v netplan >/dev/null 2>&1; then
        echo "  Re-applying original network state with netplan..." >&2
        if ! netplan generate 2>&1; then
            echo "[-] WARNING: netplan generate failed during rollback." >&2
            rollback_failed=1
        elif ! netplan apply 2>&1; then
            echo "[-] WARNING: netplan apply failed during rollback." >&2
            rollback_failed=1
        fi
    fi

    if [ "$rollback_failed" -eq 0 ]; then
        echo "[-] Network rollback completed. Previous configuration restored." >&2
    else
        echo "[-] ERROR: Network rollback encountered errors during restoration. Runtime recovery could not be fully guaranteed." >&2
    fi
    echo "[-] Manual recovery directory available at: $BACKUP_DIR" >&2
}

# 7. Write and Validate New Configuration
echo
echo "[+] Step 5: Writing and Validating New Netplan Configuration..."

# Deactivate previous third-party yaml files to avoid duplicate static routes
for yf in "${EXISTING_YAMLS[@]}"; do
    [ -f "$yf" ] || continue
    if [ "$yf" != "$NETPLAN_FILE" ]; then
        echo "  Deactivating previous configuration: $yf -> ${yf}.disabled"
        mv "$yf" "${yf}.disabled"
        echo "${yf}.disabled" >> "$RENAMED_RECORD"
    fi
done

# Write new configuration
printf "%s\n" "$NETPLAN_CONTENT" > "$NETPLAN_FILE"
chmod 0600 "$NETPLAN_FILE"

# Validate syntax with netplan generate if available
if command -v netplan >/dev/null 2>&1; then
    echo "  Running 'netplan generate' syntax check..."
    if ! netplan generate 2>&1; then
        echo "[-] ERROR: 'netplan generate' failed on generated configuration." >&2
        restore_network_state
        exit 1
    fi
    echo "  [OK] Netplan syntax validated successfully."

    # 8. Apply or Try Configuration
    if [ "$SKIP_APPLY" -eq 0 ]; then
        echo
        # Use netplan try when interactive on the console without --force (or in automated testing)
        if { [ -t 0 ] || [ "${PIPEJACK_TEST_TRY:-0}" -eq 1 ]; } && [ "$FORCE" -eq 0 ]; then
            echo "[+] Step 6: Testing Network Configuration with automatic rollback (netplan try)..."
            echo "    Press ENTER within 30 seconds to confirm and keep the new settings."
            if ! netplan try --timeout 30; then
                echo "[-] Configuration not accepted or timed out during 'netplan try'." >&2
                restore_network_state
                exit 1
            fi
            echo "  [OK] 'netplan try' confirmed and accepted by operator."
        else
            echo "[+] Step 6: Applying Netplan Configuration (netplan apply)..."
            if ! netplan apply 2>&1; then
                echo "[-] ERROR: 'netplan apply' failed." >&2
                restore_network_state
                exit 1
            fi
            echo "  [OK] 'netplan apply' executed successfully."
        fi
    else
        echo
        echo "[!] Notice: --skip-apply specified. Run 'sudo netplan apply' to activate."
    fi
else
    echo "  [!] Notice: 'netplan' binary not found. Configuration written to $NETPLAN_FILE."
fi

# 9. Verification Summary
echo
echo "============================================================"
echo " PIPEJACK NETWORK BOOTSTRAP COMPLETE"
echo " Role:                 $TARGET_ROLE_DESC"
echo " Private Interface:    $PRIVATE_IFACE ($PRIVATE_IP/$SUBNET_CIDR)"
echo " NAT Interface:        $NAT_IFACE (DHCP, metric 101)"
echo " Netplan Config File:  $NETPLAN_FILE"
echo " Backup Directory:     $BACKUP_DIR"
echo "============================================================"
echo
echo "To verify connectivity, run:"
if [ "$ROLE" = "vm1" ]; then
    echo "  ping -c 2 192.168.88.133   # Ping VM2 (Orchestrator)"
else
    echo "  ping -c 2 192.168.88.132   # Ping VM1 (Client)"
fi
echo "  ping -c 2 8.8.8.8          # Verify outbound internet access"
echo
exit 0
