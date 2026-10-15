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
NETPLAN_FILE="/etc/netplan/01-pipejack-netcfg.yaml"

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
  -d, --dry-run             Preview generated Netplan configuration without applying
  -f, --force               Bypass interactive confirmation prompt
  --skip-apply              Write Netplan configuration file but do not execute 'netplan apply'
  -h, --help                Show this help message and exit

Examples:
  # On VM2 (Server Orchestrator):
  sudo ./bootstrap-network.sh --role vm2

  # On VM1 (Workload Client):
  sudo ./bootstrap-network.sh --role vm1

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

# Validate role
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

echo "[+] Target Role: $TARGET_ROLE_DESC"
echo "[+] Configured Private IP: $PRIVATE_IP/$SUBNET_CIDR"

# Validate root privileges for live modification
if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "[-] ERROR: Root privileges required to configure networking. Run with sudo:" >&2
    echo "    sudo $0 --role $ROLE" >&2
    exit 1
fi

# 1. Interface Auto-Discovery
echo
echo "[+] Step 1: Discovering Network Interfaces..."

# Get all physical / virtual ethernet interfaces (excluding lo, docker, veth, br)
DISCOVERED_IFACES=()
for iface_path in /sys/class/net/*; do
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

if [ ${#DISCOVERED_IFACES[@]} -eq 0 ]; then
    echo "[-] ERROR: No ethernet network interfaces found in /sys/class/net/." >&2
    exit 1
fi

echo "  Discovered active interfaces: ${DISCOVERED_IFACES[*]}"

# Determine NAT interface (default gateway interface)
DETECTED_NAT=""
if command -v ip >/dev/null 2>&1; then
    DETECTED_NAT="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || echo "")"
fi

if [ -n "$NAT_IFACE" ]; then
    echo "  NAT / Internet interface explicitly set: $NAT_IFACE"
elif [ -n "$DETECTED_NAT" ] && [[ " ${DISCOVERED_IFACES[*]} " =~ " ${DETECTED_NAT} " ]]; then
    NAT_IFACE="$DETECTED_NAT"
    echo "  Auto-detected NAT / Internet interface (default route): $NAT_IFACE"
else
    # If no default route, check if we have at least 2 interfaces
    if [ ${#DISCOVERED_IFACES[@]} -ge 2 ]; then
        NAT_IFACE="${DISCOVERED_IFACES[1]}"
        echo "  Defaulted NAT interface to second discovered interface: $NAT_IFACE"
    elif [ ${#DISCOVERED_IFACES[@]} -eq 1 ]; then
        NAT_IFACE="${DISCOVERED_IFACES[0]}"
        echo "  [!] Notice: Only 1 interface discovered. Using $NAT_IFACE for NAT."
    fi
fi

# Determine Private interface
if [ -n "$PRIVATE_IFACE" ]; then
    echo "  Private lab interface explicitly set: $PRIVATE_IFACE"
else
    # Choose an interface from DISCOVERED_IFACES that is not NAT_IFACE
    for candidate in "${DISCOVERED_IFACES[@]}"; do
        if [ "$candidate" != "$NAT_IFACE" ]; then
            PRIVATE_IFACE="$candidate"
            break
        fi
    done
fi

if [ -z "$PRIVATE_IFACE" ]; then
    echo "[-] ERROR: Could not determine private lab interface." >&2
    echo "    PipeJack requires two network adapters: one Host-Only (private) and one NAT." >&2
    echo "    Please verify in VMware that two network adapters are connected to this VM." >&2
    echo "    You can also specify interfaces manually with --private-iface and --nat-iface." >&2
    exit 1
fi

echo "  Auto-detected Private Lab interface: $PRIVATE_IFACE"

if [ "$PRIVATE_IFACE" = "$NAT_IFACE" ]; then
    echo "[-] ERROR: Private interface ($PRIVATE_IFACE) cannot be the same as NAT interface ($NAT_IFACE)." >&2
    echo "    PipeJack requires two distinct network adapters for proper isolation." >&2
    exit 1
fi

# Validate interfaces exist
for iface in "$PRIVATE_IFACE" "$NAT_IFACE"; do
    if [ ! -d "/sys/class/net/$iface" ]; then
        echo "[-] ERROR: Interface '$iface' does not exist." >&2
        exit 1
    fi
done

# 2. Check for Subnet Conflicts
echo
echo "[+] Step 2: Validating Subnet Topology and Conflict Avoidance..."

# Check if NAT interface IP overlaps with private subnet 192.168.88.0/24
if command -v ip >/dev/null 2>&1; then
    NAT_CURRENT_IP="$(ip -4 addr show "$NAT_IFACE" 2>/dev/null | awk '/inet / {print $2; exit}' || echo "")"
    if [ -n "$NAT_CURRENT_IP" ]; then
        echo "  Current NAT interface IP: $NAT_CURRENT_IP"
        if [[ "$NAT_CURRENT_IP" == 192.168.88.* ]]; then
            echo "[-] ERROR: Subnet conflict detected!" >&2
            echo "    NAT interface '$NAT_IFACE' is on the 192.168.88.0/24 subnet ($NAT_CURRENT_IP)." >&2
            echo "    The private inter-VM lab requires exclusive use of 192.168.88.0/24." >&2
            echo "    Remediation: In VMware Virtual Network Editor, change your NAT subnet to 192.168.152.0/24 or another non-conflicting range." >&2
            exit 1
        fi
    fi
fi
echo "  [OK] Private subnet ($PRIVATE_SUBNET) is distinct from external/NAT routes."

# 3. Generate Clean Netplan Configuration
echo
echo "[+] Step 3: Generating Netplan Configuration..."

# Format Netplan YAML
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

# 4. Backup Existing Netplan Configurations
echo
echo "[+] Step 4: Backing Up Existing Netplan Files..."
BACKUP_DIR="/etc/netplan/pipejack-backup-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

if ls /etc/netplan/*.yaml >/dev/null 2>&1; then
    for f in /etc/netplan/*.yaml; do
        [ -f "$f" ] || continue
        # Do not backup our own previous output into the archive if re-running
        if [ "$f" != "$NETPLAN_FILE" ]; then
            cp -p "$f" "$BACKUP_DIR/"
            echo "  Backed up: $f -> $BACKUP_DIR/$(basename "$f")"
        fi
    done
fi
echo "  [OK] Netplan backup preserved in: $BACKUP_DIR"

# 5. Write and Validate New Configuration
echo
echo "[+] Step 5: Writing and Validating New Netplan Configuration..."

# Disable conflicting old static or dhcp configs by renaming them with .disabled extension
if ls /etc/netplan/*.yaml >/dev/null 2>&1; then
    for f in /etc/netplan/*.yaml; do
        [ -f "$f" ] || continue
        if [ "$f" != "$NETPLAN_FILE" ]; then
            echo "  Deactivating previous configuration: $f -> ${f}.disabled"
            mv "$f" "${f}.disabled"
        fi
    done
fi

printf "%s\n" "$NETPLAN_CONTENT" > "$NETPLAN_FILE"
chmod 0600 "$NETPLAN_FILE"

# Validate with netplan generate if command is available
if command -v netplan >/dev/null 2>&1; then
    echo "  Running 'netplan generate' syntax check..."
    if ! netplan generate 2>&1; then
        echo "[-] ERROR: 'netplan generate' failed on generated configuration." >&2
        echo "    Restoring backup from $BACKUP_DIR..." >&2
        rm -f "$NETPLAN_FILE"
        for bf in "$BACKUP_DIR"/*; do
            [ -f "$bf" ] || continue
            cp -p "$bf" "/etc/netplan/$(basename "$bf")"
        done
        for df in /etc/netplan/*.yaml.disabled; do
            [ -f "$df" ] || continue
            mv "$df" "${df%.disabled}"
        done
        exit 1
    fi
    echo "  [OK] Netplan syntax validated successfully."

    # 6. Apply Netplan
    if [ "$SKIP_APPLY" -eq 0 ]; then
        echo
        echo "[+] Step 6: Applying Netplan Configuration..."
        netplan apply
        echo "  [OK] 'netplan apply' executed successfully."
    else
        echo
        echo "[!] Notice: --skip-apply specified. Run 'sudo netplan apply' to activate."
    fi
else
    echo "  [!] WARNING: 'netplan' command not found. Configuration written to $NETPLAN_FILE."
fi

# 7. Verification Summary
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
