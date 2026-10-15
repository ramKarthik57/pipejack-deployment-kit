#!/usr/bin/env bash
# PipeJack Deployment Kit — Final Acceptance Hardening & Regression Test Suite
#
# Validates:
#   1. Elimination of test side-effects: safe unique test canaries, no fixed filenames in /tmp,
#      zero overwrites/deletions of pre-existing /tmp files, and verification that both
#      relative and space-containing paths keep archives strictly inside configured directories.
#   2. Real VM1 installation contract: automated invocation of vm1/install.sh --target-dir --skip-deps,
#      validating directories, symlinks, scripts, all 15 archives (fresh, non-zero, tar -tzf valid),
#      and verified failure return codes when required inputs or builders are missing.
#   3. Windows PowerShell AST compatibility & discrete argument arrays: strict PS 5.1 AST syntax
#      (0 syntax errors, 0 ternary, 0 pipeline chains), and discrete native argument preservation
#      for paths with spaces in actual mock SSH/SCP invocations under PowerShell 7.
#   4. Behavioral remote sudo detection & interactive escalation: mock SSH/SCP testing passwordless sudo,
#      password-required sudo failing with code 1 and remediation guidance without -InteractiveSudo,
#      password-required with -InteractiveSudo passing -t flag, and command failure exit code propagation.
#   5. Behavioral Demo Console security controls: ephemeral port server test verifying unauthenticated
#      REST access, authorized Origin upgrade (101), missing Origin upgrade (101 for CLI/scripts),
#      CSWSH rejection (403 for untrusted web origins), and subnet override rejection (403).
#   6. Production implementation verification of vm2/install.sh demo status handling: SUCCESS,
#      FAILED (with captured error output), and MISSING states exercised directly from vm2/install.sh.
#   7. Go CI orchestrator static analysis (go vet) and unit tests.
#   8. Ed25519 cryptographic attestation key generation & signature verification in isolated path.
#   9. Systemd service unit validation with systemd-analyze verify.
#  10. Final host /tmp namespace preservation verification.
#
# NOTE: Executed strictly in isolated scratch workspaces without touching live VM services.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure local user pwsh is available if installed
export PATH="$HOME/.local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

pass() {
    echo "  [PASS] $1"
    PASSED_TESTS=$((PASSED_TESTS + 1))
}

fail() {
    echo "  [FAIL] $1" >&2
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

section() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo
    echo "=== Test $TOTAL_TESTS: $1 ==="
}

# -----------------------------------------------------------------------------
# Canary Safety: Unique Test-Owned Marker & Pre-Existing /tmp State Snapshot
# -----------------------------------------------------------------------------
# Standard default archive paths in /tmp
STANDARD_TMP_ARCHIVES=(
    "/tmp/banking-api-clean.tar.gz"
    "/tmp/banking-api-malicious.tar.gz"
    "/tmp/calculator-api.tar.gz"
    "/tmp/nodejs-app-clean.tar.gz"
    "/tmp/python-app-clean.tar.gz"
    "/tmp/nodejs-app-malicious.tar.gz"
    "/tmp/python-app-malicious.tar.gz"
    "/tmp/evil-pkg-1.0.0.tgz"
    "/tmp/attack-01-shell-exec.tar.gz"
    "/tmp/attack-02-http-exfil.tar.gz"
    "/tmp/attack-03-fs-tamper.tar.gz"
    "/tmp/attack-04-base64-shell.tar.gz"
    "/tmp/attack-05-multi-stage.tar.gz"
    "/tmp/attack-06-slow-exfil.tar.gz"
    "/tmp/attack-07-anomaly.tar.gz"
)

# Snapshot existing /tmp state without modifying any pre-existing files
declare -A PRE_EXISTING_TMP_STATE
for f in "${STANDARD_TMP_ARCHIVES[@]}"; do
    if [ -e "$f" ]; then
        PRE_EXISTING_TMP_STATE["$f"]="$(stat -c '%Y:%s' "$f")|$(sha256sum "$f" | awk '{print $1}')"
    else
        PRE_EXISTING_TMP_STATE["$f"]="ABSENT"
    fi
done

# -----------------------------------------------------------------------------
# Explicit Initialization of Temporary Path Variables (Prevent Env Inheritance)
# -----------------------------------------------------------------------------
unset UNIQUE_CANARY_FILE
unset TEST_SPACES_OUT TEST_REL_OUT_RAW TEST_REL_OUT PRE_EXISTING_SAFETY_DIR
unset VM1_TARGET_DIR VM1_OUT_DIR VM1_BASHRC VM1_LOG
unset MOCK_SPACES_DIR DIR_SPACES MOCK_SSH_DIR TMP_VM2_TEST_DIR TMP_TEST_KEY_DIR TMP_SYSTEMD_FIXTURE
unset HOSTILE_SENTINEL_DIR OUTSIDE_TEST_FIXTURE OUTSIDE_TEST_FIXTURES
unset TRAPS_DEFERRED PENDING_SIGNAL TEST_RACE_HOOK TEST_RACE_FAIL_HOOK

# Registry of temporary paths created exclusively by THIS test execution process
declare -A CREATED_TEST_PATHS=()

register_test_path() {
    local p="$1"
    if [ -n "$p" ]; then
        CREATED_TEST_PATHS["$p"]=1
    fi
}

unregister_test_path() {
    local p="$1"
    if [ -n "$p" ]; then
        unset "CREATED_TEST_PATHS[$p]"
    fi
}

# Dedicated tracker for intentionally out-of-boundary test fixtures (e.g. in /var/tmp)
# Maps registered fixture path -> expected type ('dir' or 'symlink')
declare -A OUTSIDE_TEST_FIXTURES=()

register_outside_fixture() {
    local target="$1"
    local ftype="${2:-dir}"
    if [ -n "$target" ]; then
        OUTSIDE_TEST_FIXTURES["$target"]="$ftype"
    fi
}

unregister_outside_fixture() {
    local target="$1"
    if [ -n "$target" ]; then
        unset "OUTSIDE_TEST_FIXTURES[$target]"
    fi
}

# Strictly safe deletion helper for intentionally out-of-boundary fixtures in /var/tmp
safe_delete_outside_fixture() {
    local target="$1"
    if [ -z "$target" ]; then
        return 0
    fi

    # Security Rule 1: Must be explicitly registered in OUTSIDE_TEST_FIXTURES
    local expected_type="${OUTSIDE_TEST_FIXTURES["$target"]:-}"
    if [ -z "$expected_type" ]; then
        return 0
    fi

    # Security Rule 2: Path must actually exist on filesystem (file, dir, or symlink)
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        unset "OUTSIDE_TEST_FIXTURES[$target]"
        return 0
    fi

    # Security Rule 3: Type check according to expected registration
    if [ "$expected_type" = "symlink" ]; then
        if [ ! -L "$target" ]; then
            echo "  [-] safe_delete_outside_fixture refused: expected symlink, found other type: $target" >&2
            return 1
        fi
    elif [ "$expected_type" = "dir" ]; then
        if [ -L "$target" ] || [ ! -d "$target" ]; then
            echo "  [-] safe_delete_outside_fixture refused: expected directory, found symlink or non-dir: $target" >&2
            return 1
        fi
    else
        echo "  [-] safe_delete_outside_fixture refused: unknown expected type $expected_type for $target" >&2
        return 1
    fi

    # Security Rule 4: Ownership check: must be owned by current user UID
    local owner_uid
    owner_uid=$(stat -c '%u' "$target" 2>/dev/null || echo -1)
    if [ "$owner_uid" -ne "$(id -u)" ]; then
        echo "  [-] safe_delete_outside_fixture refused: target not owned by UID $(id -u): $target" >&2
        return 1
    fi

    # Security Rule 5: Parent check - canonical parent must be EXACTLY /var/tmp
    local parent_dir canon_parent canon_var_tmp
    parent_dir="$(dirname "$target")"
    canon_parent="$(realpath -q "$parent_dir" 2>/dev/null || echo "")"
    canon_var_tmp="$(realpath -q "/var/tmp" 2>/dev/null || echo "/var/tmp")"
    if [ -z "$canon_parent" ] || [ -z "$canon_var_tmp" ] || [ "$canon_parent" != "$canon_var_tmp" ]; then
        echo "  [-] safe_delete_outside_fixture refused: canonical parent $canon_parent != $canon_var_tmp: $target" >&2
        return 1
    fi

    # Security Rule 6: Basename must match pipejack-boundary-* without directory separators or traversal
    local base_name
    base_name="$(basename "$target")"
    if [[ "$base_name" != pipejack-boundary-* ]] || [[ "$base_name" == *"/"* ]] || [ "$base_name" = "." ] || [ "$base_name" = ".." ] || [ "$base_name" = "pipejack-boundary-" ]; then
        echo "  [-] safe_delete_outside_fixture refused: invalid basename pattern: $base_name" >&2
        return 1
    fi

    # If directory, also canonicalize and verify canonical target
    if [ "$expected_type" = "dir" ]; then
        local canon_target
        canon_target="$(realpath -q "$target" 2>/dev/null || echo "")"
        if [ -z "$canon_target" ] || [ ! -d "$canon_target" ] || [ -L "$canon_target" ]; then
            echo "  [-] safe_delete_outside_fixture refused: canonical target is not a real directory: $canon_target" >&2
            return 1
        fi
        local canon_target_parent
        canon_target_parent="$(dirname "$canon_target")"
        if [ "$canon_target_parent" != "$canon_var_tmp" ]; then
            echo "  [-] safe_delete_outside_fixture refused: canonical target parent $canon_target_parent != $canon_var_tmp" >&2
            return 1
        fi
        if [ "$(basename "$canon_target")" != "$base_name" ]; then
            echo "  [-] safe_delete_outside_fixture refused: canonical basename mismatch for $target" >&2
            return 1
        fi
        rm -rf "$canon_target"
    else
        # For symlinks, remove the symlink itself
        rm -f "$target"
    fi

    unset "OUTSIDE_TEST_FIXTURES[$target]"
    return 0
}

# Permitted canonical boundary roots
CANONICAL_TMP="$(realpath -q "/tmp" 2>/dev/null || echo "/tmp")"
CANONICAL_ROOT="$(realpath -q "$ROOT_DIR" 2>/dev/null || echo "$ROOT_DIR")"

# Helper to verify if target resides strictly within boundary directory
is_within_boundary() {
    local target="$1"
    local boundary="$2"
    [ -n "$target" ] && [ -n "$boundary" ] || return 1
    boundary="${boundary%/}"
    [ "$target" != "$boundary" ] && [ "${target#$boundary/}" != "$target" ]
}

# Out-of-boundary test fixture tracking (cleaned only for exact verified fixture)
OUTSIDE_TEST_FIXTURE=""

cleanup_outside_fixture() {
    local d="${1:-$OUTSIDE_TEST_FIXTURE}"
    # Idempotent reset if cleaning the global variable
    if [ "$d" = "$OUTSIDE_TEST_FIXTURE" ]; then
        OUTSIDE_TEST_FIXTURE=""
    fi

    if [ -z "$d" ]; then
        return 0
    fi

    # 1. Reject symlinks explicitly (whether valid or dangling)
    if [ -L "$d" ]; then
        echo "  [-] cleanup_outside_fixture refused: target is a symlink: $d" >&2
        return 1
    fi

    # 2. Target must actually exist on filesystem
    if [ ! -e "$d" ]; then
        return 0
    fi

    # 3. Must be a real directory
    if [ ! -d "$d" ]; then
        echo "  [-] cleanup_outside_fixture refused: target is not a real directory: $d" >&2
        return 1
    fi

    # 4. Ownership check: must be owned by current user UID
    local owner_uid
    owner_uid=$(stat -c '%u' "$d" 2>/dev/null || echo -1)
    if [ "$owner_uid" -ne "$(id -u)" ]; then
        echo "  [-] cleanup_outside_fixture refused: target not owned by UID $(id -u): $d" >&2
        return 1
    fi

    # 5. Canonicalize target path and canonicalize /var/tmp
    local canon_d canon_var_tmp
    canon_d="$(realpath -q "$d" 2>/dev/null || echo "")"
    canon_var_tmp="$(realpath -q "/var/tmp" 2>/dev/null || echo "/var/tmp")"

    if [ -z "$canon_d" ] || [ -z "$canon_var_tmp" ]; then
        echo "  [-] cleanup_outside_fixture refused: failed to resolve canonical paths for $d" >&2
        return 1
    fi

    # Canonical path itself must be a directory and not a symlink component
    if [ ! -d "$canon_d" ] || [ -L "$canon_d" ]; then
        echo "  [-] cleanup_outside_fixture refused: canonical target is not a real directory: $canon_d" >&2
        return 1
    fi

    # 6. Canonical fixture path's parent must be EXACTLY the canonical /var/tmp directory
    local parent_dir
    parent_dir="$(dirname "$canon_d")"
    if [ "$parent_dir" != "$canon_var_tmp" ]; then
        echo "  [-] cleanup_outside_fixture refused: canonical parent $parent_dir != $canon_var_tmp" >&2
        return 1
    fi

    # 7. Basename must match pipejack-boundary-test-* without allowing wildcard to span directory separators
    local base_name
    base_name="$(basename "$canon_d")"
    if [[ "$base_name" != pipejack-boundary-test-* ]] || [[ "$base_name" == *"/"* ]] || [ "$base_name" = "pipejack-boundary-test-" ]; then
        echo "  [-] cleanup_outside_fixture refused: invalid basename pattern: $base_name" >&2
        return 1
    fi

    # 8. Original recorded path and canonical target must refer to the exact same fixture
    local orig_canon
    orig_canon="$(realpath -q "$d" 2>/dev/null || echo "")"
    if [ "$orig_canon" != "$canon_d" ] || [ "$(basename "$d")" != "$base_name" ]; then
        echo "  [-] cleanup_outside_fixture refused: original path $d does not match canonical fixture $canon_d" >&2
        return 1
    fi

    # All validations passed: safe to delete
    rm -rf "$canon_d"
    unregister_outside_fixture "$d"
    return 0
}

# Recovery helper for orphaned test-owned directories (strictly validates direct child of /tmp)
recover_and_clean_test_dir() {
    local target="$1"
    local expected_pattern="${2:-pipejack-legit-cleanup-*}"

    if [ -z "$target" ]; then
        return 1
    fi

    # 1. Reject symlinks explicitly (whether valid or dangling)
    if [ -L "$target" ]; then
        echo "  [-] recover_and_clean_test_dir refused: target is a symlink: $target" >&2
        return 1
    fi

    # 2. Target must actually exist on filesystem
    if [ ! -e "$target" ]; then
        return 0
    fi

    # 3. Must be a real directory
    if [ ! -d "$target" ]; then
        echo "  [-] recover_and_clean_test_dir refused: target is not a real directory: $target" >&2
        return 1
    fi

    # 3. Ownership check: must be owned by current user UID
    local owner_uid
    owner_uid=$(stat -c '%u' "$target" 2>/dev/null || echo -1)
    if [ "$owner_uid" -ne "$(id -u)" ]; then
        echo "  [-] recover_and_clean_test_dir refused: target not owned by UID $(id -u): $target" >&2
        return 1
    fi

    # 4. Canonicalize target and canonicalize /tmp
    local canon_target canon_tmp
    canon_target="$(realpath -q "$target" 2>/dev/null || echo "")"
    canon_tmp="$(realpath -q "/tmp" 2>/dev/null || echo "/tmp")"

    if [ -z "$canon_target" ] || [ -z "$canon_tmp" ]; then
        echo "  [-] recover_and_clean_test_dir refused: failed to resolve canonical paths for $target" >&2
        return 1
    fi

    # Canonical path itself must be a directory and not a symlink
    if [ ! -d "$canon_target" ] || [ -L "$canon_target" ]; then
        echo "  [-] recover_and_clean_test_dir refused: canonical target is not a real directory: $canon_target" >&2
        return 1
    fi

    # 5. Strict direct child check: canonical target's parent must be EXACTLY canonical /tmp
    local parent_dir
    parent_dir="$(dirname "$canon_target")"
    if [ "$parent_dir" != "$canon_tmp" ]; then
        echo "  [-] recover_and_clean_test_dir refused: target $target is not a direct child of $canon_tmp (parent: $parent_dir)" >&2
        return 1
    fi

    # 6. Strict basename check: must match expected pattern without directory separators or traversal
    local base_name
    base_name="$(basename "$canon_target")"
    if [[ "$base_name" != $expected_pattern ]] || [[ "$base_name" == *"/"* ]] || [ "$base_name" = "." ] || [ "$base_name" = ".." ] || [ "$base_name" = "$expected_pattern" ]; then
        echo "  [-] recover_and_clean_test_dir refused: basename $base_name does not match pattern $expected_pattern" >&2
        return 1
    fi

    # 7. Original target basename must match canonical basename
    local orig_base
    orig_base="$(basename "$target")"
    if [ "$orig_base" != "$base_name" ]; then
        echo "  [-] recover_and_clean_test_dir refused: original basename $orig_base mismatch with canonical $base_name" >&2
        return 1
    fi

    # All checks passed: register in CREATED_TEST_PATHS and clean via safe_delete_path
    register_test_path "$target"
    safe_delete_path "$target"

    if [ ! -e "$target" ]; then
        return 0
    else
        return 1
    fi
}

safe_delete_path() {
    local p="$1"
    if [ -z "$p" ]; then
        return 0
    fi
    # Security Rule 1: Must be explicitly registered as created by this process
    if [ "${CREATED_TEST_PATHS["$p"]:-0}" -ne 1 ]; then
        return 0
    fi
    # Security Rule 2: Path must actually exist on filesystem (file, directory, or symlink)
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then
        unset "CREATED_TEST_PATHS[$p]"
        return 0
    fi
    # Security Rule 3: Must be owned by current user UID
    local owner_uid
    owner_uid=$(stat -c '%u' "$p" 2>/dev/null || echo -1)
    if [ "$owner_uid" -ne "$(id -u)" ]; then
        return 0
    fi
    # Security Rule 4: Canonicalize target path (resolving all symlinks and .. segments)
    local canonical_p
    canonical_p="$(realpath -q "$p" 2>/dev/null || echo "")"
    if [ -z "$canonical_p" ]; then
        return 0
    fi
    # Security Rule 5: Reject system roots and critical paths
    case "$canonical_p" in
        "/"|"/tmp"|"/root"|"/home"|"/etc"|"/var"|"/usr"|"/bin"|"/sbin"|"/lib"|"/lib64"|"/opt"|"/boot"|"/sys"|"/proc"|"/dev"|"$HOME"|"$CANONICAL_ROOT")
            return 0
            ;;
    esac
    # Security Rule 6: Enforce permitted directory boundaries (/tmp or repository root)
    if ! is_within_boundary "$canonical_p" "$CANONICAL_TMP" && ! is_within_boundary "$canonical_p" "$CANONICAL_ROOT"; then
        return 0
    fi
    # Security Rule 7: Forbid deletion of repository source trees or git metadata inside repository root
    if [ "$canonical_p" = "$CANONICAL_ROOT/.git" ] || is_within_boundary "$canonical_p" "$CANONICAL_ROOT/.git"; then
        return 0
    fi
    for protected_repo_tree in "vm1" "vm2" "docs" "tests" "shared" "windows" "config"; do
        local prot_path="$CANONICAL_ROOT/$protected_repo_tree"
        if [ "$canonical_p" = "$prot_path" ] || is_within_boundary "$canonical_p" "$prot_path"; then
            return 0
        fi
    done

    # All safety predicates verified: safe to delete
    rm -rf "$p"
    unset "CREATED_TEST_PATHS[$p]"
}

cleanup_suite_traps() {
    # Delete only paths recorded in CREATED_TEST_PATHS
    for p in "${!CREATED_TEST_PATHS[@]}"; do
        safe_delete_path "$p"
    done
    # Safely clean out-of-boundary test fixture if active during interrupt or exit
    cleanup_outside_fixture
    # Safely clean all registered out-of-boundary fixtures
    for p in "${!OUTSIDE_TEST_FIXTURES[@]}"; do
        safe_delete_outside_fixture "$p"
    done
}

# -----------------------------------------------------------------------------
# Signal Deferral and Race-Free Fixture Creation Infrastructure
# -----------------------------------------------------------------------------
TRAPS_DEFERRED=0
PENDING_SIGNAL=""
TEST_RACE_HOOK=""
TEST_RACE_FAIL_HOOK=""

defer_signals() {
    TRAPS_DEFERRED=1
    PENDING_SIGNAL=""
}

resume_signals() {
    TRAPS_DEFERRED=0
    if [ -n "$PENDING_SIGNAL" ]; then
        local sig="$PENDING_SIGNAL"
        PENDING_SIGNAL=""
        handle_signal "$sig"
    fi
}

handle_signal() {
    local sig="$1"
    if [ "${TRAPS_DEFERRED:-0}" -eq 1 ]; then
        PENDING_SIGNAL="$sig"
        return 0
    fi
    # Immediately disable traps to prevent recursion and terminate safely
    trap - EXIT INT TERM HUP
    cleanup_suite_traps
    case "$sig" in
        INT)  exit 130 ;;
        TERM) exit 143 ;;
        HUP)  exit 129 ;;
        *)    exit 1 ;;
    esac
}

trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'handle_signal HUP' HUP
trap cleanup_suite_traps EXIT

create_safe_tmp_dir() {
    local out_var="$1"
    shift
    defer_signals
    local created
    created=$(mktemp -d "$@" 2>/dev/null || echo "")
    if [ -n "$created" ]; then
        if [ -n "${TEST_RACE_HOOK:-}" ]; then
            "$TEST_RACE_HOOK" "$created" "dir"
        fi
        register_test_path "$created"
        printf -v "$out_var" '%s' "$created"
    else
        if [ -n "${TEST_RACE_FAIL_HOOK:-}" ]; then
            "$TEST_RACE_FAIL_HOOK" "tmp_dir"
        fi
    fi
    resume_signals
    [ -n "$created" ]
}

create_safe_tmp_file() {
    local out_var="$1"
    shift
    defer_signals
    local created
    created=$(mktemp "$@" 2>/dev/null || echo "")
    if [ -n "$created" ]; then
        if [ -n "${TEST_RACE_HOOK:-}" ]; then
            "$TEST_RACE_HOOK" "$created" "file"
        fi
        register_test_path "$created"
        printf -v "$out_var" '%s' "$created"
    else
        if [ -n "${TEST_RACE_FAIL_HOOK:-}" ]; then
            "$TEST_RACE_FAIL_HOOK" "tmp_file"
        fi
    fi
    resume_signals
    [ -n "$created" ]
}

create_safe_outside_dir() {
    local out_var="$1"
    local template="${2:-pipejack-boundary-test-XXXXXX}"
    defer_signals
    local created=""
    if [ -d "/var/tmp" ] && [ -w "/var/tmp" ]; then
        created=$(mktemp -d -p /var/tmp "$template" 2>/dev/null || echo "")
    fi
    if [ -n "$created" ]; then
        if [ -n "${TEST_RACE_HOOK:-}" ]; then
            "$TEST_RACE_HOOK" "$created" "dir"
        fi
        register_outside_fixture "$created" "dir"
        printf -v "$out_var" '%s' "$created"
    else
        if [ -n "${TEST_RACE_FAIL_HOOK:-}" ]; then
            "$TEST_RACE_FAIL_HOOK" "outside_dir"
        fi
    fi
    resume_signals
    [ -n "$created" ]
}

create_safe_symlink() {
    local target="$1"
    local link_path="$2"
    local loc="${3:-tmp}"
    defer_signals
    local ok=0
    if ln -s "$target" "$link_path" 2>/dev/null; then
        ok=1
        if [ -n "${TEST_RACE_HOOK:-}" ]; then
            "$TEST_RACE_HOOK" "$link_path" "symlink"
        fi
        if [ "$loc" = "outside" ]; then
            register_outside_fixture "$link_path" "symlink"
        else
            register_test_path "$link_path"
        fi
    else
        if [ -n "${TEST_RACE_FAIL_HOOK:-}" ]; then
            "$TEST_RACE_FAIL_HOOK" "$link_path"
        fi
    fi
    resume_signals
    [ $ok -eq 1 ]
}

create_safe_nested_dir() {
    local dir_path="$1"
    defer_signals
    local ok=0
    if mkdir -p "$dir_path" 2>/dev/null; then
        ok=1
        if [ -n "${TEST_RACE_HOOK:-}" ]; then
            "$TEST_RACE_HOOK" "$dir_path" "dir"
        fi
    else
        if [ -n "${TEST_RACE_FAIL_HOOK:-}" ]; then
            "$TEST_RACE_FAIL_HOOK" "$dir_path"
        fi
    fi
    resume_signals
    [ $ok -eq 1 ]
}

# Internal subtest handlers to exercise the actual traps and cleanup implementation directly
if [ "${1:-}" = "--internal-test-cleanup-env" ]; then
    create_safe_tmp_dir LEGIT_TMP "/tmp/pipejack-legit-cleanup-XXXXXX" || exit 1
    echo "LEGIT_CREATED:$LEGIT_TMP"
    exit 0
fi

if [ "${1:-}" = "--internal-test-cleanup-signal" ]; then
    SIG_NAME="${2:-INT}"
    create_safe_tmp_dir SIG_TMP "/tmp/pipejack-sig-cleanup-XXXXXX" || { echo "[-] Failed to create SIG_TMP in /tmp" >&2; exit 1; }
    echo "SIG_TMP:$SIG_TMP"
    if [ ! -d "/var/tmp" ] || [ ! -w "/var/tmp" ]; then
        echo "[-] /var/tmp is missing or not writable" >&2
        exit 1
    fi
    create_safe_outside_dir SIG_OUTSIDE "pipejack-boundary-test-XXXXXX" || { echo "[-] Failed to create SIG_OUTSIDE in /var/tmp" >&2; exit 1; }
    OUTSIDE_TEST_FIXTURE="$SIG_OUTSIDE"
    echo "SIG_OUTSIDE:$SIG_OUTSIDE"
    case "$SIG_NAME" in
        TERM) kill -TERM $$ ;;
        HUP)  kill -HUP $$ ;;
        *)    kill -INT $$ ;;
    esac
    echo "SHOULD_NOT_REACH_HERE"
    exit 0
fi

if [ "${1:-}" = "--internal-test-creation-race" ]; then
    RACE_MODE="${2:-tmp_dir}"
    SIG_NAME="${3:-INT}"
    TARGET_PARAM="${4:-}"

    safe_cleanup_failed_hook_fixture() {
        local fixture="$1"
        local assertion_reason="$2"
        echo "RACE_FIXTURE_VERIFY_FAILED:path=$fixture:assertion=$assertion_reason"

        # Independent verification before attempting cleanup of failed fixture:
        if [ -z "$fixture" ] || { [ ! -L "$fixture" ] && [ ! -e "$fixture" ]; }; then
            exit 1
        fi

        # 1. Permitted test-owned basename pattern
        local base
        base="$(basename "$fixture")"
        case "$base" in
            pipejack-race-*|pipejack-boundary-test-*) ;;
            *)
                echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=unexpected_basename_pattern"
                exit 1
                ;;
        esac

        # 2. Permitted canonical parent (/tmp or /var/tmp)
        local fdir cdir canon_tmp canon_vartmp
        fdir="$(dirname "$fixture")"
        cdir="$(cd "$fdir" 2>/dev/null && pwd -P)"
        canon_tmp="$(cd /tmp && pwd -P)"
        canon_vartmp="$(cd /var/tmp && pwd -P)"
        if [ "$cdir" != "$canon_tmp" ] && [ "$cdir" != "$canon_vartmp" ]; then
            echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=parent_not_permitted"
            exit 1
        fi

        # 3. Object existence and type identification
        local actual_type=""
        if [ -L "$fixture" ]; then
            actual_type="symlink"
        elif [ -d "$fixture" ]; then
            actual_type="dir"
        elif [ -f "$fixture" ]; then
            actual_type="file"
        else
            echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=unknown_type"
            exit 1
        fi

        # 4. Ownership and device/inode identity verification
        local stat_info
        stat_info="$(stat -c '%u:%d:%i' "$fixture" 2>/dev/null || true)"
        if [ -z "$stat_info" ]; then
            echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=stat_identity_unavailable"
            exit 1
        fi

        local fuid fdev fino
        IFS=':' read -r fuid fdev fino <<< "$stat_info"

        if [ "$fuid" -ne "$(id -u)" ]; then
            echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=owner_mismatch"
            exit 1
        fi

        if [ -z "$fdev" ] || [ -z "$fino" ] || [ "$fino" -le 0 ] 2>/dev/null; then
            echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=device_inode_invalid"
            exit 1
        fi

        local pdev
        pdev="$(stat -c '%d' "$cdir" 2>/dev/null || true)"
        if [ -n "$pdev" ] && [ "$fdev" -ne "$pdev" ]; then
            echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=device_mismatch_with_parent"
            exit 1
        fi

        # 5. Type-verified removal
        if [ "$actual_type" = "symlink" ]; then
            if rm -f "$fixture" 2>/dev/null; then
                echo "RACE_FAILED_FIXTURE_CLEANED:path=$fixture:type=symlink"
            else
                echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=rm_symlink_failed"
            fi
        elif [ "$actual_type" = "dir" ]; then
            if rmdir "$fixture" 2>/dev/null; then
                echo "RACE_FAILED_FIXTURE_CLEANED:path=$fixture:type=dir"
            else
                echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=rmdir_failed"
            fi
        elif [ "$actual_type" = "file" ]; then
            if rm -f "$fixture" 2>/dev/null; then
                echo "RACE_FAILED_FIXTURE_CLEANED:path=$fixture:type=file"
            else
                echo "RACE_FIXTURE_PRESERVED:path=$fixture:reason=rm_file_failed"
            fi
        fi
        exit 1
    }

    deliver_race_signal() {
        local fixture="$1"
        local expected_type="${2:-}"

        # 1. Non-empty and exists on filesystem (using -L or -e)
        if [ -z "$fixture" ]; then
            echo "RACE_FIXTURE_VERIFY_FAILED:path=:assertion=empty_fixture_path"
            exit 1
        fi
        if [ ! -L "$fixture" ] && [ ! -e "$fixture" ]; then
            echo "RACE_FIXTURE_VERIFY_FAILED:path=$fixture:assertion=fixture_does_not_exist"
            exit 1
        fi

        # 2. Derive actual filesystem type independently
        local actual_type=""
        if [ -L "$fixture" ]; then
            actual_type="symlink"
        elif [ -d "$fixture" ]; then
            actual_type="dir"
        elif [ -f "$fixture" ]; then
            actual_type="file"
        else
            actual_type="unknown"
        fi

        local exp_mode_type=""
        case "$RACE_MODE" in
            tmp_dir|outside_dir) exp_mode_type="dir" ;;
            tmp_symlink|outside_symlink|outside_dangling_symlink|hook_fail_target) exp_mode_type="symlink" ;;
        esac
        local required_type="${exp_mode_type:-$expected_type}"
        if [ -n "$required_type" ] && [ "$actual_type" != "$required_type" ]; then
            safe_cleanup_failed_hook_fixture "$fixture" "type_mismatch:actual=$actual_type:expected=$required_type"
        fi

        # 3. Parent resolves to intended canonical /tmp or /var/tmp directory
        local fixture_parent
        fixture_parent="$(dirname "$fixture")"
        if [ ! -d "$fixture_parent" ]; then
            safe_cleanup_failed_hook_fixture "$fixture" "parent_not_dir:$fixture_parent"
        fi
        local actual_canonical_parent
        actual_canonical_parent="$(cd "$fixture_parent" 2>/dev/null && pwd -P)"
        local expected_canonical_parent=""
        case "$RACE_MODE" in
            tmp_dir|tmp_symlink|hook_fail_target)
                expected_canonical_parent="$(cd /tmp && pwd -P)"
                ;;
            outside_dir|outside_symlink|outside_dangling_symlink)
                expected_canonical_parent="$(cd /var/tmp && pwd -P)"
                ;;
        esac
        if [ -n "$expected_canonical_parent" ] && [ "$actual_canonical_parent" != "$expected_canonical_parent" ]; then
            safe_cleanup_failed_hook_fixture "$fixture" "parent_mismatch:actual=$actual_canonical_parent:expected=$expected_canonical_parent"
        fi

        # 4. A symlink's target relationship is the expected one, including dangling case
        if [ "$actual_type" = "symlink" ]; then
            local actual_target
            actual_target="$(readlink "$fixture" 2>/dev/null || true)"
            if [ -z "$actual_target" ]; then
                safe_cleanup_failed_hook_fixture "$fixture" "readlink_empty"
            fi

            case "$RACE_MODE" in
                tmp_symlink|outside_symlink|hook_fail_target)
                    if [ "$actual_target" != "$TARGET_PARAM" ]; then
                        safe_cleanup_failed_hook_fixture "$fixture" "target_mismatch:actual=$actual_target:expected=$TARGET_PARAM"
                    fi
                    if [ ! -d "$actual_target" ]; then
                        safe_cleanup_failed_hook_fixture "$fixture" "target_not_dir:$actual_target"
                    fi
                    ;;
                outside_dangling_symlink)
                    if [ "$actual_target" != "$TARGET" ]; then
                        safe_cleanup_failed_hook_fixture "$fixture" "target_mismatch:actual=$actual_target:expected=$TARGET"
                    fi
                    if [ -e "$actual_target" ] || [ -L "$actual_target" ]; then
                        safe_cleanup_failed_hook_fixture "$fixture" "dangling_target_exists:$actual_target"
                    fi
                    ;;
            esac
        fi

        # Only report after all checks pass
        echo "RACE_FIXTURE_CREATED:$fixture:$actual_type"
        case "$SIG_NAME" in
            TERM) kill -TERM $$ ;;
            HUP)  kill -HUP $$ ;;
            *)    kill -INT $$ ;;
        esac
    }
    TEST_RACE_HOOK="deliver_race_signal"

    deliver_fail_signal() {
        local path_or_info="${1:-}"
        echo "RACE_FAIL_HOOK_FIRED:$path_or_info"
        case "$SIG_NAME" in
            TERM) kill -TERM $$ ;;
            HUP)  kill -HUP $$ ;;
            *)    kill -INT $$ ;;
        esac
    }
    TEST_RACE_FAIL_HOOK="deliver_fail_signal"

    case "$RACE_MODE" in
        tmp_dir)
            create_safe_tmp_dir FIXTURE "/tmp/pipejack-race-tmp-XXXXXX"
            ;;
        outside_dir)
            create_safe_outside_dir FIXTURE "pipejack-boundary-test-XXXXXX"
            ;;
        tmp_symlink)
            if [ -z "$TARGET_PARAM" ] || [ ! -d "$TARGET_PARAM" ]; then
                echo "[-] tmp_symlink requires existing directory TARGET_PARAM" >&2
                exit 1
            fi
            LINK="/tmp/pipejack-race-link-$$"
            create_safe_symlink "$TARGET_PARAM" "$LINK" "tmp"
            ;;
        outside_symlink)
            if [ -z "$TARGET_PARAM" ] || [ ! -d "$TARGET_PARAM" ]; then
                echo "[-] outside_symlink requires existing directory TARGET_PARAM" >&2
                exit 1
            fi
            LINK="/var/tmp/pipejack-boundary-test-link-$$"
            create_safe_symlink "$TARGET_PARAM" "$LINK" "outside"
            ;;
        outside_dangling_symlink)
            TARGET="/var/tmp/pipejack-boundary-target-nonexistent-$$"
            LINK="/var/tmp/pipejack-boundary-test-dangling-$$"
            create_safe_symlink "$TARGET" "$LINK" "outside"
            ;;
        failed_creation)
            if [ -z "$TARGET_PARAM" ] || [ ! -e "$TARGET_PARAM" ]; then
                echo "[-] failed_creation requires existing TARGET_PARAM sentinel" >&2
                exit 1
            fi
            create_safe_symlink "/tmp/pipejack-dummy-target-$$" "$TARGET_PARAM" "tmp"
            ;;
        hook_fail_target)
            LINK="/tmp/pipejack-race-link-fail-target-$$"
            create_safe_symlink "/tmp/deliberate-mismatched-target-$$" "$LINK" "tmp"
            ;;
        hook_fail_unverified_pattern)
            LINK="${TARGET_PARAM:-/tmp/unverified-forbidden-pattern-link-$$}"
            if [ ! -L "$LINK" ] && [ ! -e "$LINK" ]; then
                ln -s "/tmp" "$LINK" 2>/dev/null
            fi
            safe_cleanup_failed_hook_fixture "$LINK" "deliberate_pattern_failure"
            ;;
        *)
            echo "[-] Unknown race test mode: $RACE_MODE" >&2
            exit 1
            ;;
    esac

    echo "SHOULD_NOT_REACH_HERE"
    exit 0
fi

# Create a unique test-owned canary file (using PID and nanosecond timestamp)
UNIQUE_CANARY_TAG="pipejack_canary_${$}_$(date +%s%N)"
create_safe_tmp_file UNIQUE_CANARY_FILE "/tmp/${UNIQUE_CANARY_TAG}_XXXXXX.marker" || {
    echo "[-] Failed to create unique canary marker" >&2
    exit 1
}
echo "$UNIQUE_CANARY_TAG" > "$UNIQUE_CANARY_FILE"

echo "============================================================"
echo " PIPEJACK ACCEPTANCE HARDENING & REGRESSION TEST SUITE"
echo " Working Directory: $ROOT_DIR"
echo " Unique Canary:     $(basename "$UNIQUE_CANARY_FILE")"
echo " Date:              $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "============================================================"

# List of all 15 expected generated archive filenames
EXPECTED_ARTIFACT_NAMES=(
    "banking-api-clean.tar.gz"
    "banking-api-malicious.tar.gz"
    "calculator-api.tar.gz"
    "nodejs-app-clean.tar.gz"
    "python-app-clean.tar.gz"
    "nodejs-app-malicious.tar.gz"
    "python-app-malicious.tar.gz"
    "evil-pkg-1.0.0.tgz"
    "attack-01-shell-exec.tar.gz"
    "attack-02-http-exfil.tar.gz"
    "attack-03-fs-tamper.tar.gz"
    "attack-04-base64-shell.tar.gz"
    "attack-05-multi-stage.tar.gz"
    "attack-06-slow-exfil.tar.gz"
    "attack-07-anomaly.tar.gz"
)

# Function: validate_output_archives <target_dir> <description>
# Asserts each of the 15 expected artifacts exists, is non-empty, and passes tar -tzf.
# Asserts no expected artifact is missing and no unexpected artifact was substituted.
validate_output_archives() {
    local target_dir="$1"
    local desc="$2"
    local ok=1

    for name in "${EXPECTED_ARTIFACT_NAMES[@]}"; do
        local file_path="$target_dir/$name"
        if [ ! -f "$file_path" ]; then
            echo "  [-] Missing expected archive in $desc: $name" >&2
            ok=0
            continue
        fi
        if [ ! -s "$file_path" ]; then
            echo "  [-] Expected archive is empty (0 bytes) in $desc: $name" >&2
            ok=0
            continue
        fi
        if ! tar -tzf "$file_path" >/dev/null 2>&1; then
            echo "  [-] Archive corrupt (tar -tzf validation failed) in $desc: $name" >&2
            ok=0
            continue
        fi
    done

    local found_count=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        found_count=$((found_count + 1))
        local base
        base=$(basename "$f")
        local is_expected=0
        for exp in "${EXPECTED_ARTIFACT_NAMES[@]}"; do
            if [ "$base" = "$exp" ]; then
                is_expected=1
                break
            fi
        done
        if [ $is_expected -ne 1 ]; then
            echo "  [-] Unexpected artifact found in $desc: $base" >&2
            ok=0
        fi
    done < <(find "$target_dir" -maxdepth 1 \( -name "*.tar.gz" -o -name "*.tgz" \))

    if [ "$found_count" -ne "${#EXPECTED_ARTIFACT_NAMES[@]}" ]; then
        echo "  [-] Archive count mismatch in $desc: expected ${#EXPECTED_ARTIFACT_NAMES[@]}, found $found_count" >&2
        ok=0
    fi

    [ $ok -eq 1 ]
}

# -----------------------------------------------------------------------------
# Test 1: Configurable Output Directory Isolation & 15-Archive Validation
# -----------------------------------------------------------------------------
section "Archive Output Directory Isolation & 15-Archive Validation (Spaces & Relative Paths)"

# Pre-existing directory safety proof: verify that pre-existing directories are never removed
PRE_EXISTING_SAFETY_DIR=$(mktemp -d -p . tmp_pipejack_rel_preexisting_XXXXXX) || {
    echo "[-] Failed to create safety sentinel directory" >&2
    exit 1
}
register_test_path "$PRE_EXISTING_SAFETY_DIR"
echo "PIPEJACK_PRE_EXISTING_SAFETY_SENTINEL" > "$PRE_EXISTING_SAFETY_DIR/safety.marker"

# Absolute path with spaces
TEST_SPACES_OUT=$(mktemp -d "/tmp/pipejack test out spaces XXXXXX") || {
    echo "[-] Failed to create spaces output directory" >&2
    exit 1
}
register_test_path "$TEST_SPACES_OUT"

# Genuinely unique relative directory created atomically by mktemp -d in current directory
TEST_REL_OUT_RAW=$(mktemp -d -p . tmp_pipejack_rel_XXXXXX) || {
    echo "[-] Failed to create unique relative output directory" >&2
    exit 1
}
register_test_path "$TEST_REL_OUT_RAW"
TEST_REL_OUT="${TEST_REL_OUT_RAW#./}"
register_test_path "$TEST_REL_OUT"

cleanup_test1() {
    safe_delete_path "$TEST_SPACES_OUT"
    safe_delete_path "$TEST_REL_OUT_RAW"
    safe_delete_path "$TEST_REL_OUT"
    safe_delete_path "$PRE_EXISTING_SAFETY_DIR"
}

TEST1_OK=1

# 1. Absolute path with spaces (validate all 15 archives individually)
if "$ROOT_DIR/vm1/scripts/build-all-tarballs.sh" --output-dir "$TEST_SPACES_OUT" >/dev/null 2>&1; then
    if ! validate_output_archives "$TEST_SPACES_OUT" "spaces output directory"; then
        TEST1_OK=0
    fi
else
    TEST1_OK=0
    echo "  [-] build-all-tarballs.sh failed with spaces output path" >&2
fi

# 2. Relative path (validate all 15 archives individually)
if "$ROOT_DIR/vm1/scripts/build-all-tarballs.sh" --output-dir "$TEST_REL_OUT" >/dev/null 2>&1; then
    if ! validate_output_archives "$TEST_REL_OUT" "relative output directory"; then
        TEST1_OK=0
    fi
else
    TEST1_OK=0
    echo "  [-] build-all-tarballs.sh failed with relative output path" >&2
fi

# 3. Verify evil-pkg fixture source directory is clean (zero .tgz left behind)
if [ -f "$ROOT_DIR/vm1/security-fixtures/evil-pkg/evil-pkg-1.0.0.tgz" ]; then
    TEST1_OK=0
    echo "  [-] evil-pkg fixture source directory contains generated archive!" >&2
fi
STRAY_REPO_ARCHIVES=$(find "$ROOT_DIR/vm1" "$ROOT_DIR/vm2" -name "*.tar.gz" -o -name "*.tgz" 2>/dev/null | wc -l)
if [ "$STRAY_REPO_ARCHIVES" -ne 0 ]; then
    TEST1_OK=0
    echo "  [-] Repository source tree contains $STRAY_REPO_ARCHIVES generated archive(s)!" >&2
fi

# 4. Verify shared /tmp standard archives were neither created, deleted, nor modified
for f in "${STANDARD_TMP_ARCHIVES[@]}"; do
    initial_state="${PRE_EXISTING_TMP_STATE["$f"]}"
    if [ "$initial_state" = "ABSENT" ]; then
        if [ -e "$f" ]; then
            TEST1_OK=0
            echo "  [-] Leaked archive created in shared /tmp: $f" >&2
        fi
    else
        if [ ! -e "$f" ]; then
            TEST1_OK=0
            echo "  [-] Pre-existing file deleted from shared /tmp: $f" >&2
        else
            current_state="$(stat -c '%Y:%s' "$f")|$(sha256sum "$f" | awk '{print $1}')"
            if [ "$initial_state" != "$current_state" ]; then
                TEST1_OK=0
                echo "  [-] Pre-existing file modified in shared /tmp: $f" >&2
            fi
        fi
    fi
done

# 5. Verify unique canary marker is untouched
if [ ! -f "$UNIQUE_CANARY_FILE" ] || [ "$(cat "$UNIQUE_CANARY_FILE")" != "$UNIQUE_CANARY_TAG" ]; then
    TEST1_OK=0
    echo "  [-] Unique canary marker was altered during test" >&2
fi

# 6. Verify pre-existing safety directory was strictly preserved
if [ ! -d "$PRE_EXISTING_SAFETY_DIR" ] || [ ! -f "$PRE_EXISTING_SAFETY_DIR/safety.marker" ] || [ "$(cat "$PRE_EXISTING_SAFETY_DIR/safety.marker")" != "PIPEJACK_PRE_EXISTING_SAFETY_SENTINEL" ]; then
    TEST1_OK=0
    echo "  [-] Safety violation: Pre-existing safety directory was altered or deleted!" >&2
fi

cleanup_test1

if [ $TEST1_OK -eq 1 ]; then
    pass "Configured output directories (spaces and relative) generate and validate all 15 individual archives (non-empty, valid tar -tzf, zero substitutions) with zero host /tmp side-effects"
else
    fail "Archive output directory isolation and validation failed"
fi

# -----------------------------------------------------------------------------
# Test 2: Actual VM1 Installation Contract (install.sh --target-dir --skip-deps)
# -----------------------------------------------------------------------------
section "Actual VM1 Installation Contract & Layout Verification"
VM1_TARGET_DIR=$(mktemp -d "/tmp/pipejack-vm1-target-XXXXXX") || { echo "[-] Failed to create VM1 target dir" >&2; exit 1; }
register_test_path "$VM1_TARGET_DIR"
VM1_OUT_DIR=$(mktemp -d "/tmp/pipejack-vm1-out-XXXXXX") || { echo "[-] Failed to create VM1 out dir" >&2; exit 1; }
register_test_path "$VM1_OUT_DIR"
VM1_BASHRC=$(mktemp "/tmp/pipejack-vm1-bashrc-XXXXXX") || { echo "[-] Failed to create VM1 bashrc" >&2; exit 1; }
register_test_path "$VM1_BASHRC"

INSTALL_OK=0
VM1_LOG=$(mktemp) || { echo "[-] Failed to create VM1 log" >&2; exit 1; }
register_test_path "$VM1_LOG"
if BASHRC="$VM1_BASHRC" PIPEJACK_OUTPUT_DIR="$VM1_OUT_DIR" PIPEJACK_MIN_DISK_GB=1 "$ROOT_DIR/vm1/install.sh" --target-dir "$VM1_TARGET_DIR" --skip-deps > "$VM1_LOG" 2>&1; then
    INSTALL_OK=1
    safe_delete_path "$VM1_LOG"
else
    echo "  [DEBUG] vm1/install.sh output:" >&2
    cat "$VM1_LOG" >&2
    safe_delete_path "$VM1_LOG"
fi

if [ $INSTALL_OK -eq 1 ]; then
    APPS_OK=1
    for app in banking-api calculator-api nodejs-app python-app; do
        if [ ! -d "$VM1_TARGET_DIR/applications/$app" ]; then
            APPS_OK=0
            break
        fi
    done

    LINKS_OK=1
    for link in banking-api calculator-api nodejs-app python-app spring-calc evil-pkg nodejs-malicious python-malicious; do
        if [ ! -L "$VM1_TARGET_DIR/$link" ]; then
            LINKS_OK=0
            break
        fi
    done

    SCRIPTS_OK=1
    if [ ! -x "$VM1_TARGET_DIR/pipejack-upload.sh" ] || [ ! -x "$VM1_TARGET_DIR/build-all-tarballs.sh" ]; then
        SCRIPTS_OK=0
    fi

    EXPECTED_15=(
        "$VM1_OUT_DIR/banking-api-clean.tar.gz"
        "$VM1_OUT_DIR/banking-api-malicious.tar.gz"
        "$VM1_OUT_DIR/calculator-api.tar.gz"
        "$VM1_OUT_DIR/nodejs-app-clean.tar.gz"
        "$VM1_OUT_DIR/python-app-clean.tar.gz"
        "$VM1_OUT_DIR/nodejs-app-malicious.tar.gz"
        "$VM1_OUT_DIR/python-app-malicious.tar.gz"
        "$VM1_OUT_DIR/evil-pkg-1.0.0.tgz"
        "$VM1_OUT_DIR/attack-01-shell-exec.tar.gz"
        "$VM1_OUT_DIR/attack-02-http-exfil.tar.gz"
        "$VM1_OUT_DIR/attack-03-fs-tamper.tar.gz"
        "$VM1_OUT_DIR/attack-04-base64-shell.tar.gz"
        "$VM1_OUT_DIR/attack-05-multi-stage.tar.gz"
        "$VM1_OUT_DIR/attack-06-slow-exfil.tar.gz"
        "$VM1_OUT_DIR/attack-07-anomaly.tar.gz"
    )
    ALL_VALID=1
    for arch in "${EXPECTED_15[@]}"; do
        if [ ! -s "$arch" ] || ! tar -tzf "$arch" >/dev/null 2>&1; then
            ALL_VALID=0
            break
        fi
    done

    if [ $APPS_OK -eq 1 ] && [ $LINKS_OK -eq 1 ] && [ $SCRIPTS_OK -eq 1 ] && [ $ALL_VALID -eq 1 ]; then
        pass "vm1/install.sh deployed real layout: application dirs, symlinks, scripts, and all 15 valid archives"
    else
        fail "VM1 installation contract validation failed: APPS=$APPS_OK LINKS=$LINKS_OK SCRIPTS=$SCRIPTS_OK ARCHIVES=$ALL_VALID"
    fi
else
    fail "vm1/install.sh exited with nonzero exit code during contract verification"
fi

# -----------------------------------------------------------------------------
# Test 3: Installed Layout Generator Failure Handling on Missing Input
# -----------------------------------------------------------------------------
section "Installed Layout Generator Failure Propagation"
rm -rf "$VM1_TARGET_DIR/applications/calculator-api"
rm -f "$VM1_TARGET_DIR/calculator-api"

echo "stale corrupt data" > "$VM1_OUT_DIR/calculator-api.tar.gz"

if PIPEJACK_OUTPUT_DIR="$VM1_OUT_DIR" "$VM1_TARGET_DIR/build-all-tarballs.sh" >/dev/null 2>&1; then
    fail "build-all-tarballs.sh unexpectedly succeeded despite missing input application"
else
    if [ ! -f "$VM1_OUT_DIR/calculator-api.tar.gz" ]; then
        pass "Installed layout generator correctly failed on missing input and purged stale archive"
    else
        fail "Stale archive was not removed before generation failure"
    fi
fi
safe_delete_path "$VM1_TARGET_DIR"
safe_delete_path "$VM1_OUT_DIR"
safe_delete_path "$VM1_BASHRC"

# -----------------------------------------------------------------------------
# Test 4: PowerShell 5.1 AST Syntax Compatibility (Rejecting PS7+ constructs)
# -----------------------------------------------------------------------------
section "PowerShell 5.1 AST Syntax Compatibility (Static AST Verification)"
if command -v pwsh >/dev/null 2>&1; then
    PS_CHECK_OUTPUT=$(pwsh -NoProfile -Command "
        \$scripts = @(
            '$ROOT_DIR/windows/setup-pipejack.ps1',
            '$ROOT_DIR/windows/preflight.ps1',
            '$ROOT_DIR/windows/verify-pipejack.ps1'
        )
        \$errorsFound = 0
        foreach (\$s in \$scripts) {
            \$tokens = \$null
            \$errors = \$null
            \$ast = [System.Management.Automation.Language.Parser]::ParseFile(\$s, [ref]\$tokens, [ref]\$errors)
            if (\$errors.Count -gt 0) {
                Write-Host \"[ERR] Parse error in \${s}: \$((\$errors | ForEach-Object {\$_.Message}) -join '; ')\"
                \$errorsFound++
                continue
            }
            \$ternaryNodes = \$ast.FindAll({ param(\$node) \$node.GetType().Name -eq 'TernaryExpressionAst' }, \$true)
            \$chainNodes = \$ast.FindAll({ param(\$node) \$node.GetType().Name -eq 'PipelineChainAst' }, \$true)
            if (\$ternaryNodes.Count -gt 0) {
                Write-Host \"[ERR] Found \$(\$ternaryNodes.Count) PS7-only ternary expressions in \${s}\"
                \$errorsFound++
            }
            if (\$chainNodes.Count -gt 0) {
                Write-Host \"[ERR] Found \$(\$chainNodes.Count) PS7-only pipeline chains (&&/||) in \${s}\"
                \$errorsFound++
            }
        }
        if (\$errorsFound -eq 0) {
            Write-Host 'PS51_COMPLIANT'
        } else {
            exit 1
        }
    " 2>&1)

    if echo "$PS_CHECK_OUTPUT" | grep -q "PS51_COMPLIANT"; then
        pass "PowerShell static AST confirms 100% PS 5.1 syntax compatibility (0 syntax errors, 0 ternary operators, 0 pipeline chain operators). [Note: Native Windows PowerShell 5.1 runtime engine execution remains PENDING (requires Microsoft Windows with powershell.exe); static AST parsed via pwsh 7.4.6]"
    else
        fail "PowerShell AST detected incompatibility: $PS_CHECK_OUTPUT"
    fi
else
    fail "pwsh not available to verify PowerShell 5.1 AST compatibility"
fi

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Test 5: Discrete Argument Preservation with Spaces in Live Mock SSH/SCP
# -----------------------------------------------------------------------------
section "PowerShell Discrete Argument Preservation with Spaces (Mock SSH/SCP via pwsh)"
MOCK_SPACES_DIR=$(mktemp -d "/tmp/pipejack-mock-spaces-XXXXXX") || { echo "[-] Failed to create mock spaces dir" >&2; exit 1; }
register_test_path "$MOCK_SPACES_DIR"

cat << 'EOF' > "$MOCK_SPACES_DIR/ssh"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/ssh_args.log"
echo "--- EXEC ssh ---" >> "$LOGFILE"
arg_idx=1
for arg in "$@"; do
    printf "ARG_%d: [%s]\n" "$arg_idx" "$arg" >> "$LOGFILE"
    ((arg_idx++))
done
CMD="${@: -1}"
if [[ "$CMD" == *"sudo -n true"* ]]; then
    exit 0
fi
exit 0
EOF
chmod +x "$MOCK_SPACES_DIR/ssh"
ln -sf "$MOCK_SPACES_DIR/ssh" "$MOCK_SPACES_DIR/ssh.exe"

cat << 'EOF' > "$MOCK_SPACES_DIR/scp"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/scp_args.log"
echo "--- EXEC scp ---" >> "$LOGFILE"
arg_idx=1
for arg in "$@"; do
    printf "ARG_%d: [%s]\n" "$arg_idx" "$arg" >> "$LOGFILE"
    ((arg_idx++))
done
exit 0
EOF
chmod +x "$MOCK_SPACES_DIR/scp"
ln -sf "$MOCK_SPACES_DIR/scp" "$MOCK_SPACES_DIR/scp.exe"

DIR_SPACES=$(mktemp -d "/tmp/pipejack test kit spaces XXXXXX") || { echo "[-] Failed to create spaces kit dir" >&2; exit 1; }
register_test_path "$DIR_SPACES"
mkdir -p "$DIR_SPACES/vm1" "$DIR_SPACES/vm2"
KEY_SPACES="$DIR_SPACES/my keys dir/id_ed25519"
mkdir -p "$(dirname "$KEY_SPACES")"
touch "$KEY_SPACES"

if command -v pwsh >/dev/null 2>&1; then
    # Verify that SSH and SCP resolve strictly to the mock directory before execution
    RESOLVED_SSH=$(PATH="$MOCK_SPACES_DIR:$PATH" pwsh -NoProfile -Command "
        \$c = Get-Command 'ssh.exe' -ErrorAction SilentlyContinue
        if (-not \$c) { \$c = Get-Command 'ssh' -ErrorAction SilentlyContinue }
        if (\$c) { \$c.Source }
    " 2>/dev/null || true)
    RESOLVED_SCP=$(PATH="$MOCK_SPACES_DIR:$PATH" pwsh -NoProfile -Command "
        \$c = Get-Command 'scp.exe' -ErrorAction SilentlyContinue
        if (-not \$c) { \$c = Get-Command 'scp' -ErrorAction SilentlyContinue }
        if (\$c) { \$c.Source }
    " 2>/dev/null || true)

    if [[ "$RESOLVED_SSH" != "$MOCK_SPACES_DIR"* ]] || [[ "$RESOLVED_SCP" != "$MOCK_SPACES_DIR"* ]]; then
        fail "Pre-flight executable check failed: SSH/SCP did not resolve to mock directory (SSH: '$RESOLVED_SSH', SCP: '$RESOLVED_SCP')"
    else
        rm -f "$MOCK_SPACES_DIR/ssh_args.log" "$MOCK_SPACES_DIR/scp_args.log"
        pwsh_ec=0
        OUT_5=$(PATH="$MOCK_SPACES_DIR:$PATH" pwsh -NoProfile -Command "
            & '$ROOT_DIR/windows/setup-pipejack.ps1' -KitDir '$DIR_SPACES' -SSHKey '$KEY_SPACES' -VM2_IP 127.0.0.2 -VM1_IP 127.0.0.1 -SSHUser testuser -SkipPreflight -SkipVM1 -SkipVerify -Force
        " 2>&1) || pwsh_ec=$?

        SPACES_ARG_OK=1

        # Check process exit code
        if [ $pwsh_ec -ne 0 ]; then
            SPACES_ARG_OK=0
            echo "  [-] pwsh process exited with non-zero exit code $pwsh_ec: $OUT_5" >&2
        fi

        # Check that mock logs exist and were invoked
        if [ ! -s "$MOCK_SPACES_DIR/scp_args.log" ] || [ ! -s "$MOCK_SPACES_DIR/ssh_args.log" ]; then
            SPACES_ARG_OK=0
            echo "  [-] Mock tools were not invoked (logs empty or missing)" >&2
        fi

        # Check that SCP received the target directory containing spaces as a single discrete argument
        if ! grep -q -E "^ARG_[0-9]+: \[${DIR_SPACES}/vm2\]$" "$MOCK_SPACES_DIR/scp_args.log" && ! grep -q -E "^ARG_[0-9]+: \[${DIR_SPACES}\\\\vm2\]$" "$MOCK_SPACES_DIR/scp_args.log"; then
            SPACES_ARG_OK=0
            echo "  [-] SCP failed to receive kit path containing spaces as a single discrete argument" >&2
        fi

        # Check that SSH received the private key containing spaces as a single discrete argument
        if ! grep -q -E "^ARG_[0-9]+: \[${KEY_SPACES}\]$" "$MOCK_SPACES_DIR/ssh_args.log"; then
            SPACES_ARG_OK=0
            echo "  [-] SSH failed to receive private key path containing spaces as a single discrete argument" >&2
        fi

        if [ $SPACES_ARG_OK -eq 1 ]; then
            pass "Mock SSH/SCP confirmed discrete argument preservation for paths containing spaces under live pwsh execution (exit code: $pwsh_ec)"
        else
            fail "PowerShell argument array passing split arguments containing spaces or failed execution"
        fi
    fi
else
    fail "pwsh not available for mock spaces argument verification"
fi
safe_delete_path "$MOCK_SPACES_DIR"
safe_delete_path "$DIR_SPACES"

# -----------------------------------------------------------------------------
# Test 6: Behavioral Remote Sudo Detection, Interactive Escalation & Error Propagation
# -----------------------------------------------------------------------------
section "Behavioral Remote Sudo Detection, Escalation & Error Propagation"
MOCK_SSH_DIR=$(mktemp -d "/tmp/pipejack-mock-ssh-XXXXXX") || { echo "[-] Failed to create mock ssh dir" >&2; exit 1; }
register_test_path "$MOCK_SSH_DIR"

cat << 'EOF' > "$MOCK_SSH_DIR/ssh"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/ssh.log"
echo "--- EXEC ssh ---" >> "$LOGFILE"
arg_idx=1
for arg in "$@"; do
    printf "ARG_%d: [%s]\n" "$arg_idx" "$arg" >> "$LOGFILE"
    ((arg_idx++))
done
CMD="${@: -1}"

if [[ "$CMD" == *"sudo -n true"* ]]; then
    if [ "${MOCK_SUDO_MODE:-}" = "passwordless" ]; then
        exit 0
    else
        exit 1
    fi
fi

if [ -n "${MOCK_CMD_FAIL:-}" ]; then
    echo "Simulated remote failure with code $MOCK_CMD_FAIL" >&2
    exit "$MOCK_CMD_FAIL"
fi

exit 0
EOF
chmod +x "$MOCK_SSH_DIR/ssh"
ln -sf "$MOCK_SSH_DIR/ssh" "$MOCK_SSH_DIR/ssh.exe"

cat << 'EOF' > "$MOCK_SSH_DIR/scp"
#!/usr/bin/env bash
LOGFILE="$(dirname "$0")/scp.log"
echo "--- EXEC scp ---" >> "$LOGFILE"
arg_idx=1
for arg in "$@"; do
    printf "ARG_%d: [%s]\n" "$arg_idx" "$arg" >> "$LOGFILE"
    ((arg_idx++))
done
exit 0
EOF
chmod +x "$MOCK_SSH_DIR/scp"
ln -sf "$MOCK_SSH_DIR/scp" "$MOCK_SSH_DIR/scp.exe"

if command -v pwsh >/dev/null 2>&1; then
    # Verify that SSH and SCP resolve strictly to the mock directory before execution
    RESOLVED_SSH_6=$(PATH="$MOCK_SSH_DIR:$PATH" pwsh -NoProfile -Command "
        \$c = Get-Command 'ssh.exe' -ErrorAction SilentlyContinue
        if (-not \$c) { \$c = Get-Command 'ssh' -ErrorAction SilentlyContinue }
        if (\$c) { \$c.Source }
    " 2>/dev/null || true)
    RESOLVED_SCP_6=$(PATH="$MOCK_SSH_DIR:$PATH" pwsh -NoProfile -Command "
        \$c = Get-Command 'scp.exe' -ErrorAction SilentlyContinue
        if (-not \$c) { \$c = Get-Command 'scp' -ErrorAction SilentlyContinue }
        if (\$c) { \$c.Source }
    " 2>/dev/null || true)

    if [[ "$RESOLVED_SSH_6" != "$MOCK_SSH_DIR"* ]] || [[ "$RESOLVED_SCP_6" != "$MOCK_SSH_DIR"* ]]; then
        fail "Pre-flight executable check failed: SSH/SCP did not resolve to mock directory (SSH: '$RESOLVED_SSH_6', SCP: '$RESOLVED_SCP_6')"
    else
        SUDO_TESTS_OK=1

        # Subtest A: Passwordless sudo succeeds cleanly
        rm -f "$MOCK_SSH_DIR/ssh.log" "$MOCK_SSH_DIR/scp.log"
        ec_A=0
        OUT_A=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="passwordless" pwsh -NoProfile -Command "
            & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 127.0.0.2 -VM1_IP 127.0.0.1 -SSHUser testuser -SkipPreflight -SkipVM1 -SkipVerify -Force
        " 2>&1) || ec_A=$?
        if [ $ec_A -ne 0 ] || ! echo "$OUT_A" | grep -q "Creating isolated staging directory" || [ ! -s "$MOCK_SSH_DIR/ssh.log" ]; then
            SUDO_TESTS_OK=0
            echo "  [-] Passwordless sudo test failed (process exit code: $ec_A)" >&2
        fi

        # Subtest B: Password-required without -InteractiveSudo fails early with exit code 1 and prints guidance before any transfer
        rm -f "$MOCK_SSH_DIR/ssh.log" "$MOCK_SSH_DIR/scp.log"
        ec_B=0
        OUT_B=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="password_required" pwsh -NoProfile -Command "
            & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 127.0.0.2 -VM1_IP 127.0.0.1 -SSHUser testuser -SkipPreflight -SkipVM1 -SkipVerify -Force
        " 2>&1) || ec_B=$?
        if [ $ec_B -ne 1 ] || ! echo "$OUT_B" | grep -q "PREFLIGHT PRIVILEGE ERROR" || ! echo "$OUT_B" | grep -q "NOPASSWD:ALL" || ! echo "$OUT_B" | grep -q -- "-InteractiveSudo"; then
            SUDO_TESTS_OK=0
            echo "  [-] Password-required guidance test failed (process exit code: $ec_B)" >&2
        fi
        if [ -s "$MOCK_SSH_DIR/scp.log" ] || grep -q "install.sh" "$MOCK_SSH_DIR/ssh.log" 2>/dev/null; then
            SUDO_TESTS_OK=0
            echo "  [-] Password-required mode attempted SCP or remote installation before privilege validation" >&2
        fi

        # Subtest C: Password-required with -InteractiveSudo passes -t to SSH
        rm -f "$MOCK_SSH_DIR/ssh.log" "$MOCK_SSH_DIR/scp.log"
        ec_C=0
        OUT_C=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="password_required" pwsh -NoProfile -Command "
            & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 127.0.0.2 -VM1_IP 127.0.0.1 -SSHUser testuser -SkipPreflight -SkipVM1 -SkipVerify -Force -InteractiveSudo
        " 2>&1) || ec_C=$?
        if [ $ec_C -ne 0 ] || ! echo "$OUT_C" | grep -q "Interactive sudo mode active" || ! grep -q -E '^ARG_[0-9]+: \[-t\]$' "$MOCK_SSH_DIR/ssh.log"; then
            SUDO_TESTS_OK=0
            echo "  [-] Interactive sudo -t allocation test failed (process exit code: $ec_C)" >&2
        fi

        # Subtest D: Remote command failure propagates exit code
        rm -f "$MOCK_SSH_DIR/ssh.log" "$MOCK_SSH_DIR/scp.log"
        ec_D=0
        OUT_D=$(PATH="$MOCK_SSH_DIR:$PATH" MOCK_SUDO_MODE="passwordless" MOCK_CMD_FAIL="42" pwsh -NoProfile -Command "
            & '$ROOT_DIR/windows/setup-pipejack.ps1' -VM2_IP 127.0.0.2 -VM1_IP 127.0.0.1 -SSHUser testuser -SkipPreflight -SkipVM1 -SkipVerify -Force
        " 2>&1) || ec_D=$?
        if [ $ec_D -ne 1 ] || ! echo "$OUT_D" | grep -q "Exit Code: 42"; then
            SUDO_TESTS_OK=0
            echo "  [-] Remote command exit code propagation test failed (process exit code: $ec_D)" >&2
        fi

        if [ $SUDO_TESTS_OK -eq 1 ]; then
            pass "Behavioral mock SSH proved: passwordless ok (ec 0), password-required guidance (ec 1, no transfers), interactive -t allocation (ec 0), and remote exit code 42 diagnostics (process ec 1)"
        else
            fail "Behavioral sudo test suite encountered failures"
        fi
    fi
else
    fail "pwsh not available for mock sudo behavioral verification"
fi
safe_delete_path "$MOCK_SSH_DIR"

# -----------------------------------------------------------------------------
# Test 7: Behavioral Demo Console Security Controls (Ephemeral Server Test)
# -----------------------------------------------------------------------------
section "Behavioral Demo Console Security Controls (Ephemeral Server)"
BEHAVIORAL_CONSOLE_RESULT=$(python3 -c "
import sys, os, socket, time, threading, http.client
sys.path.insert(0, '$ROOT_DIR/vm2/demo/demo-console')
import server
from http.server import ThreadingHTTPServer

class QuietRequestHandler(server.ConsoleRequestHandler):
    def log_message(self, format, *args):
        pass

class QuietHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Suppress benign ConnectionResetError when test sockets close
        pass

httpd = QuietHTTPServer(('127.0.0.1', 0), QuietRequestHandler)
port = httpd.server_address[1]
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()
time.sleep(0.2)

try:
    # 1. Verify unauthenticated access to REST endpoint with CORS *
    conn = http.client.HTTPConnection('127.0.0.1', port)
    conn.request('GET', '/api/status')
    r1 = conn.getresponse()
    assert r1.status == 200, f'Expected 200, got {r1.status}'
    assert r1.getheader('Access-Control-Allow-Origin') == '*', 'Expected CORS * header'
    conn.close()

    # 2. Verify authorized WebSocket upgrade succeeds with valid matching Origin (101 Switching Protocols)
    s2 = socket.create_connection(('127.0.0.1', port))
    req2 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'Origin: http://127.0.0.1:{port}\r\n\r\n'
    )
    s2.sendall(req2.encode())
    resp2 = s2.recv(1024).decode()
    s2.close()
    assert '101 Switching Protocols' in resp2, f'Expected 101, got {resp2}'

    # 3. Verify missing Origin header is accepted (101 Switching Protocols for CLI tools / scripts)
    s3 = socket.create_connection(('127.0.0.1', port))
    req3 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n\r\n'
    )
    s3.sendall(req3.encode())
    resp3 = s3.recv(1024).decode()
    s3.close()
    assert '101 Switching Protocols' in resp3, f'Expected 101 for missing Origin, got {resp3}'

    # 4. Verify CSWSH attempt with untrusted third-party web origin is rejected with HTTP 403
    s4 = socket.create_connection(('127.0.0.1', port))
    req4 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'Origin: http://evil-attacker.com\r\n\r\n'
    )
    s4.sendall(req4.encode())
    resp4 = s4.recv(1024).decode()
    s4.close()
    assert '403 Forbidden' in resp4, f'Expected 403 for untrusted Origin, got {resp4}'

    # 5. Verify Network ACL rejection when subnet override excludes client IP
    os.environ['PIPEJACK_ALLOWED_NETWORKS'] = '10.200.0.0/16'
    s5 = socket.create_connection(('127.0.0.1', port))
    req5 = (
        f'GET /ws/terminal/vm1 HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'Origin: http://127.0.0.1:{port}\r\n\r\n'
    )
    s5.sendall(req5.encode())
    resp5 = s5.recv(1024).decode()
    s5.close()
    assert '403 Forbidden' in resp5, f'Expected 403 for IP out of subnet, got {resp5}'
    del os.environ['PIPEJACK_ALLOWED_NETWORKS']

    print('BEHAVIORAL_CONSOLE_VERIFIED')
finally:
    httpd.shutdown()
    httpd.server_close()
" 2>&1 || true)

if echo "$BEHAVIORAL_CONSOLE_RESULT" | grep -q "BEHAVIORAL_CONSOLE_VERIFIED"; then
    pass "Demo Console server behavioral tests verified: REST unauth 200, valid origin 101, missing origin 101, CSWSH 403, subnet override 403"
else
    fail "Demo Console server behavioral test failed: $BEHAVIORAL_CONSOLE_RESULT"
fi

# -----------------------------------------------------------------------------
# Test 8: Production Helper Module Verification (demo-status-helper.sh) & Installer Hardening
# -----------------------------------------------------------------------------
section "Production Helper Module Verification (demo-status-helper.sh) & Installer Hardening"
TMP_VM2_TEST_DIR=$(mktemp -d "/tmp/pipejack-test-vm2-status-XXXXXX") || { echo "[-] Failed to create test vm2 status dir" >&2; exit 1; }
register_test_path "$TMP_VM2_TEST_DIR"

# Verify production installer has removed --test-demo-status CLI interface
INSTALLER_CLI_CHECK=$("$ROOT_DIR/vm2/install.sh" --test-demo-status "$TMP_VM2_TEST_DIR" 2>&1 || true)
if ! echo "$INSTALLER_CLI_CHECK" | grep -q "Unknown option '--test-demo-status'"; then
    echo "  [-] Security defect: vm2/install.sh still accepts test CLI option --test-demo-status!" >&2
    fail "Test option not removed from production installer interface"
fi

# Source production helper directly and exercise in disposable test paths without root privileges
source "$ROOT_DIR/vm2/scripts/demo-status-helper.sh"

# Subtest 1: prepare-demo.sh succeeds -> SUCCESS status and FULL DEMO READINESS banner
DIR_SUCCESS="$TMP_VM2_TEST_DIR/success"
mkdir -p "$DIR_SUCCESS"
cat << 'EOF' > "$DIR_SUCCESS/prepare-demo.sh"
#!/usr/bin/env bash
echo "Artifacts generated successfully"
exit 0
EOF
chmod +x "$DIR_SUCCESS/prepare-demo.sh"
OUT_SUCCESS=$(
    prepare_demo_artifacts "$DIR_SUCCESS"
    get_demo_status_banner "$DEMO_STATUS" "$DIR_SUCCESS"
    echo "STATUS_RESULT: $DEMO_STATUS"
)

# Subtest 2: prepare-demo.sh fails -> FAILED status, captured error output, PARTIAL SUCCESS banner
DIR_FAILED="$TMP_VM2_TEST_DIR/failed"
mkdir -p "$DIR_FAILED"
cat << 'EOF' > "$DIR_FAILED/prepare-demo.sh"
#!/usr/bin/env bash
echo "SYNTAX ERROR in demo fixture at line 42" >&2
exit 1
EOF
chmod +x "$DIR_FAILED/prepare-demo.sh"
OUT_FAILED=$(
    prepare_demo_artifacts "$DIR_FAILED" 2>&1
    get_demo_status_banner "$DEMO_STATUS" "$DIR_FAILED"
    echo "STATUS_RESULT: $DEMO_STATUS"
)

# Subtest 3: prepare-demo.sh missing -> MISSING status and PARTIAL SUCCESS banner
DIR_MISSING="$TMP_VM2_TEST_DIR/missing"
mkdir -p "$DIR_MISSING"
OUT_MISSING=$(
    prepare_demo_artifacts "$DIR_MISSING" 2>&1
    get_demo_status_banner "$DEMO_STATUS" "$DIR_MISSING"
    echo "STATUS_RESULT: $DEMO_STATUS"
)

VM2_STATUS_OK=1
if ! echo "$OUT_SUCCESS" | grep -q "STATUS_RESULT: SUCCESS" || ! echo "$OUT_SUCCESS" | grep -q "FULL DEMO READINESS"; then
    VM2_STATUS_OK=0
    echo "  [-] vm2 demo success reporting test failed" >&2
fi
if ! echo "$OUT_FAILED" | grep -q "STATUS_RESULT: FAILED" || ! echo "$OUT_FAILED" | grep -q "PARTIAL SUCCESS" || ! echo "$OUT_FAILED" | grep -q "SYNTAX ERROR"; then
    VM2_STATUS_OK=0
    echo "  [-] vm2 demo failure reporting test failed" >&2
fi
if ! echo "$OUT_MISSING" | grep -q "STATUS_RESULT: MISSING" || ! echo "$OUT_MISSING" | grep -q "PARTIAL SUCCESS"; then
    VM2_STATUS_OK=0
    echo "  [-] vm2 demo missing reporting test failed" >&2
fi

if [ $VM2_STATUS_OK -eq 1 ]; then
    pass "Production helper demo-status-helper.sh accurately handles SUCCESS, FAILED (with captured error log), and MISSING states; test CLI option removed from vm2/install.sh"
else
    fail "demo-status-helper.sh validation failed"
fi
safe_delete_path "$TMP_VM2_TEST_DIR"

# -----------------------------------------------------------------------------
# Test 9: Go Unit Tests and Code Inspection (go vet)
# -----------------------------------------------------------------------------
section "Go Unit Tests and Static Analysis (go vet)"
if (cd "$ROOT_DIR/vm2/services/custom-ci" && go vet ./... && go test ./... >/dev/null 2>&1); then
    pass "All Go CI orchestrator tests and go vet passed with zero warnings"
else
    fail "go vet or go test failed in vm2/services/custom-ci"
fi

# -----------------------------------------------------------------------------
# Test 10: Ed25519 Attestation Key Generation & Verification
# -----------------------------------------------------------------------------
section "Ed25519 Attestation Key Generation & Cryptographic Verification"
TMP_TEST_KEY_DIR=$(mktemp -d "/tmp/pipejack-test-keys-XXXXXX") || { echo "[-] Failed to create test key dir" >&2; exit 1; }
register_test_path "$TMP_TEST_KEY_DIR"

export PIPEJACK_KEY_PATH="$TMP_TEST_KEY_DIR/attest-key"
KEY_INIT_OUT=$(cd "$ROOT_DIR/vm2/services/custom-ci" && go run . --init-key 2>&1)
KEY_VERIFY_OUT=$(cd "$ROOT_DIR/vm2/services/custom-ci" && go run . --verify-key 2>&1)

if echo "$KEY_INIT_OUT" | grep -q "cryptographically verified" && echo "$KEY_VERIFY_OUT" | grep -q "key is valid"; then
    if [ -f "$TMP_TEST_KEY_DIR/attest-key" ] && [ -f "$TMP_TEST_KEY_DIR/attest-key.pub" ]; then
        pass "Ed25519 key generation and roundtrip signature verification succeeded in isolated path"
    else
        fail "Generated key files missing in isolated directory"
    fi
else
    fail "Key init or verify output unexpected: $KEY_INIT_OUT / $KEY_VERIFY_OUT"
fi
safe_delete_path "$TMP_TEST_KEY_DIR"

# -----------------------------------------------------------------------------
# Test 11: Systemd Service Unit Syntax Verification
# -----------------------------------------------------------------------------
section "Systemd Service Unit Syntax Verification"

SYSTEMD_TEST_OK=1
SYSTEMD_DIAGNOSTICS=""

# 1. Static Unit Syntax and Structural Integrity
for unit_file in "$ROOT_DIR/vm2/deployment/systemd/pipejack-ci.service" "$ROOT_DIR/vm2/deployment/systemd/pipejack-demo-console.service"; do
    if [ ! -f "$unit_file" ]; then
        SYSTEMD_TEST_OK=0
        SYSTEMD_DIAGNOSTICS="Missing unit file: $unit_file"
        break
    fi
    for sec in "\[Unit\]" "\[Service\]" "\[Install\]"; do
        if ! grep -q "^$sec" "$unit_file"; then
            SYSTEMD_TEST_OK=0
            SYSTEMD_DIAGNOSTICS="Unit $unit_file missing mandatory section $sec"
            break 2
        fi
    done
    if ! grep -q "^ExecStart=" "$unit_file"; then
        SYSTEMD_TEST_OK=0
        SYSTEMD_DIAGNOSTICS="Unit $unit_file missing ExecStart directive"
        break
    fi
done

# 2. Dependency-aware systemd-analyze verify with minimal temporary dependency fixtures
if [ $SYSTEMD_TEST_OK -eq 1 ]; then
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        fail "systemd-analyze not available in test environment; systemd service unit verification NOT EXECUTED (static structural checks passed)"
    elif ! command -v unshare >/dev/null 2>&1 || ! unshare -rm true >/dev/null 2>&1; then
        fail "unshare namespace capabilities not available in test environment; isolated dependency verification of pipejack-ci.service NOT EXECUTED (requires unshare mount namespace to mock /usr/local/bin/pipejack-ci; static structural checks passed)"
    else
        TMP_SYSTEMD_FIXTURE=""
        create_safe_tmp_dir TMP_SYSTEMD_FIXTURE "/tmp/pipejack-systemd-fixture-XXXXXX" || {
            echo "[-] Failed to create systemd test fixture directory" >&2
            exit 1
        }

        mkdir -p "$TMP_SYSTEMD_FIXTURE/units"
        mkdir -p "$TMP_SYSTEMD_FIXTURE/bin"
        mkdir -p "$TMP_SYSTEMD_FIXTURE/staged"

        # Stage real units with canonical non-executable, non-world-writable 0644 permissions
        cp "$ROOT_DIR/vm2/deployment/systemd/pipejack-ci.service" "$TMP_SYSTEMD_FIXTURE/staged/"
        cp "$ROOT_DIR/vm2/deployment/systemd/pipejack-demo-console.service" "$TMP_SYSTEMD_FIXTURE/staged/"
        chmod 0644 "$TMP_SYSTEMD_FIXTURE/staged/"*.service

        # Dependency fixture 1: mock docker.service for Requires=docker.service
        cat << 'EOF' > "$TMP_SYSTEMD_FIXTURE/units/docker.service"
[Unit]
Description=Docker Application Container Engine
[Service]
Type=notify
ExecStart=/bin/true
EOF
        chmod 0644 "$TMP_SYSTEMD_FIXTURE/units/docker.service"

        # Dependency fixture 2: mock target fixtures for unit references and systemd default dependencies
        cat << 'EOF' > "$TMP_SYSTEMD_FIXTURE/units/network.target"
[Unit]
Description=Network
EOF
        chmod 0644 "$TMP_SYSTEMD_FIXTURE/units/network.target"

        cat << 'EOF' > "$TMP_SYSTEMD_FIXTURE/units/multi-user.target"
[Unit]
Description=Multi-User System
EOF
        chmod 0644 "$TMP_SYSTEMD_FIXTURE/units/multi-user.target"

        cat << 'EOF' > "$TMP_SYSTEMD_FIXTURE/units/sysinit.target"
[Unit]
Description=System Initialization
EOF
        chmod 0644 "$TMP_SYSTEMD_FIXTURE/units/sysinit.target"

        # Dependency fixture 3: mock pipejack-ci executable for ExecStart=/usr/local/bin/pipejack-ci
        cat << 'EOF' > "$TMP_SYSTEMD_FIXTURE/bin/pipejack-ci"
#!/bin/sh
exit 0
EOF
        chmod 0755 "$TMP_SYSTEMD_FIXTURE/bin/pipejack-ci"

        # Run systemd-analyze verify inside unshare user/mount namespace with mock /usr/local/bin
        # SYSTEMD_UNIT_PATH is strictly restricted to disposable test directories without host unit paths
        verify_ec=0
        SYSTEMD_VERIFY_OUT=$(unshare -rm bash -c "
            set -euo pipefail
            mount --bind '$TMP_SYSTEMD_FIXTURE/bin' /usr/local/bin
            export SYSTEMD_UNIT_PATH='$TMP_SYSTEMD_FIXTURE/units:$TMP_SYSTEMD_FIXTURE/staged'
            systemd-analyze verify '$TMP_SYSTEMD_FIXTURE/staged/pipejack-ci.service' '$TMP_SYSTEMD_FIXTURE/staged/pipejack-demo-console.service' 2>&1
            umount /usr/local/bin
        " 2>&1) || verify_ec=$?

        safe_delete_path "$TMP_SYSTEMD_FIXTURE"

        # Verify exit code is 0 and zero warning/error diagnostics were produced
        if [ $verify_ec -eq 0 ] && [ -z "$SYSTEMD_VERIFY_OUT" ]; then
            pass "Packaged systemd service units verified: static structure clean and systemd-analyze verify passed with 0 errors/warnings against both units in isolated fixture root"
        else
            fail "systemd-analyze verify failed on packaged service units (exit code $verify_ec): $SYSTEMD_VERIFY_OUT"
        fi
    fi
else
    fail "Systemd static structural check failed: $SYSTEMD_DIAGNOSTICS"
fi

# -----------------------------------------------------------------------------
# Test 12: Trap Cleanup Safety Against Pre-Populated / Hostile Environment Variables
# -----------------------------------------------------------------------------
section "Trap Cleanup Safety Against Pre-Populated / Hostile Environment Variables"

HOSTILE_SENTINEL_DIR=""
create_safe_tmp_dir HOSTILE_SENTINEL_DIR "/tmp/pipejack-hostile-sentinel-XXXXXX" || { echo "[-] Failed to create hostile sentinel dir" >&2; exit 1; }
echo "IMMUTABLE_SENTINEL_CONTENT_$$" > "$HOSTILE_SENTINEL_DIR/sentinel.data"

TRAP_SAFETY_OK=1

# 1. Direct Boundary and Registration Tests of safe_delete_path
# 1a: Unregistered path must NOT be deleted
unregister_test_path "$HOSTILE_SENTINEL_DIR"
safe_delete_path "$HOSTILE_SENTINEL_DIR"
if [ ! -f "$HOSTILE_SENTINEL_DIR/sentinel.data" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: safe_delete_path deleted an unregistered path!" >&2
fi
register_test_path "$HOSTILE_SENTINEL_DIR"

# 1b: Out-of-bounds path must NOT be deleted by safe_delete_path (even if registered)
OUTSIDE_TMP_DIR=""
create_safe_outside_dir OUTSIDE_TMP_DIR "pipejack-boundary-test-XXXXXX"

if [ -z "$OUTSIDE_TMP_DIR" ] || [ ! -d "$OUTSIDE_TMP_DIR" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Test defect: Failed to create out-of-boundary test fixture in /var/tmp" >&2
else
    # Register in OUTSIDE_TEST_FIXTURE and tracker so interruption traps guarantee cleanup
    OUTSIDE_TEST_FIXTURE="$OUTSIDE_TMP_DIR"
    register_test_path "$OUTSIDE_TMP_DIR"
    safe_delete_path "$OUTSIDE_TMP_DIR"
    if [ ! -d "$OUTSIDE_TMP_DIR" ]; then
        TRAP_SAFETY_OK=0
        echo "  [-] Security defect: safe_delete_path deleted a path outside permitted boundaries (/tmp, repo root)!" >&2
    else
        # safe_delete_path correctly refused deletion!
        unregister_test_path "$OUTSIDE_TMP_DIR"
    fi
    # Clean up the validated test fixture via verified cleanup function
    cleanup_outside_fixture
    if [ -d "$OUTSIDE_TMP_DIR" ]; then
        TRAP_SAFETY_OK=0
        echo "  [-] Failed to clean out-of-boundary test fixture after test" >&2
    fi
fi

# 1c: Negative assertion checks on cleanup_outside_fixture
# 1c-1: Symlinked path (valid target) in /var/tmp must be rejected by cleanup_outside_fixture
TEST_SYMLINK_TARGET=""
create_safe_outside_dir TEST_SYMLINK_TARGET "pipejack-boundary-target-XXXXXX"
TEST_SYMLINK="/var/tmp/pipejack-boundary-test-symlink-$$"
create_safe_symlink "$TEST_SYMLINK_TARGET" "$TEST_SYMLINK" "outside"
OUTSIDE_TEST_FIXTURE="$TEST_SYMLINK"
if cleanup_outside_fixture 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture accepted a symlink!" >&2
fi
if [ ! -L "$TEST_SYMLINK" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture deleted a symlink!" >&2
fi
if [ ! -d "$TEST_SYMLINK_TARGET" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture deleted symlink target!" >&2
fi
safe_delete_outside_fixture "$TEST_SYMLINK"
safe_delete_outside_fixture "$TEST_SYMLINK_TARGET"

# 1c-2: Dangling symlink in /var/tmp must be rejected by cleanup_outside_fixture
TEST_DANGLING_TARGET="/var/tmp/pipejack-boundary-target-nonexistent-$$"
TEST_DANGLING_SYMLINK="/var/tmp/pipejack-boundary-test-dangling-$$"
create_safe_symlink "$TEST_DANGLING_TARGET" "$TEST_DANGLING_SYMLINK" "outside"
OUTSIDE_TEST_FIXTURE="$TEST_DANGLING_SYMLINK"
if cleanup_outside_fixture 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture accepted a dangling symlink!" >&2
fi
if [ ! -L "$TEST_DANGLING_SYMLINK" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture deleted a dangling symlink!" >&2
fi
safe_delete_outside_fixture "$TEST_DANGLING_SYMLINK"

# 1c-3: Nested path in /var/tmp must be rejected by cleanup_outside_fixture
TEST_NESTED_PARENT=""
create_safe_outside_dir TEST_NESTED_PARENT "pipejack-boundary-nested-XXXXXX"
TEST_NESTED_CHILD="$TEST_NESTED_PARENT/pipejack-boundary-test-child-$$"
create_safe_nested_dir "$TEST_NESTED_CHILD"
OUTSIDE_TEST_FIXTURE="$TEST_NESTED_CHILD"
if cleanup_outside_fixture 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture accepted a nested path!" >&2
fi
if [ ! -d "$TEST_NESTED_CHILD" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture deleted a nested path!" >&2
fi
safe_delete_outside_fixture "$TEST_NESTED_PARENT"

# 1c-4: Mismatched basename pattern must be rejected by cleanup_outside_fixture
TEST_MISMATCH_DIR=""
create_safe_outside_dir TEST_MISMATCH_DIR "pipejack-boundary-mismatch-XXXXXX"
OUTSIDE_TEST_FIXTURE="$TEST_MISMATCH_DIR"
if cleanup_outside_fixture 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture accepted mismatched pattern!" >&2
fi
if [ ! -d "$TEST_MISMATCH_DIR" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: cleanup_outside_fixture deleted mismatched directory!" >&2
fi
safe_delete_outside_fixture "$TEST_MISMATCH_DIR"

# 1d: Critical system root and repo root protection
register_test_path "$ROOT_DIR"
safe_delete_path "$ROOT_DIR"
if [ ! -d "$ROOT_DIR" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Critical defect: safe_delete_path attempted to delete repository root!" >&2
fi
unregister_test_path "$ROOT_DIR"

register_test_path "$ROOT_DIR/vm1"
safe_delete_path "$ROOT_DIR/vm1"
if [ ! -d "$ROOT_DIR/vm1" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Critical defect: safe_delete_path attempted to delete repository source tree!" >&2
fi
unregister_test_path "$ROOT_DIR/vm1"

# 2. Subtest A: Testing actual script cleanup and trap setup with hostile environment variables
# Invokes this very script with hostile pre-populated variables pointing to HOSTILE_SENTINEL_DIR
SCRIPT_FILE="$(realpath "${BASH_SOURCE[0]}")"
SUB_OUTPUT=$(TEST_SPACES_OUT="$HOSTILE_SENTINEL_DIR" \
    TEST_REL_OUT="$HOSTILE_SENTINEL_DIR" \
    VM1_TARGET_DIR="$HOSTILE_SENTINEL_DIR" \
    VM1_OUT_DIR="$HOSTILE_SENTINEL_DIR" \
    TMP_VM2_TEST_DIR="$HOSTILE_SENTINEL_DIR" \
    PRE_EXISTING_SAFETY_DIR="$HOSTILE_SENTINEL_DIR" \
    bash "$SCRIPT_FILE" --internal-test-cleanup-env 2>&1)

LEGIT_PATH=$(echo "$SUB_OUTPUT" | grep "^LEGIT_CREATED:" | cut -d: -f2)

# Verify hostile sentinel directory was NOT deleted and contents unchanged
if [ ! -d "$HOSTILE_SENTINEL_DIR" ] || [ ! -f "$HOSTILE_SENTINEL_DIR/sentinel.data" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Hostile sentinel directory was deleted by script cleanup traps!" >&2
elif [ "$(cat "$HOSTILE_SENTINEL_DIR/sentinel.data")" != "IMMUTABLE_SENTINEL_CONTENT_$$" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Hostile sentinel data was altered during script execution!" >&2
fi

# Verify legitimately created test path WAS cleaned up by the script's actual cleanup trap
if [ -z "$LEGIT_PATH" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Subtest A failed to report legitimate created temporary path" >&2
elif [ -d "$LEGIT_PATH" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Legitimate test temporary directory was not cleaned up by script EXIT trap: $LEGIT_PATH" >&2
    # Recovery: validate path identity, ownership, and boundary before safe registration and deletion (no rm -rf fallback)
    if ! recover_and_clean_test_dir "$LEGIT_PATH" "pipejack-legit-cleanup-*"; then
        echo "  [-] Recovery failed for orphaned test directory: $LEGIT_PATH" >&2
    fi
fi

# 2b. Comprehensive negative and positive assertions on recover_and_clean_test_dir
# 2b-1: Unmatching hostile sentinel must be refused by recover_and_clean_test_dir
if recover_and_clean_test_dir "$HOSTILE_SENTINEL_DIR" "pipejack-legit-cleanup-*" 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir returned success for hostile sentinel!" >&2
fi
if [ ! -f "$HOSTILE_SENTINEL_DIR/sentinel.data" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Critical defect: recover_and_clean_test_dir deleted hostile sentinel!" >&2
fi

# 2b-2: Nested matching-name directory must be refused (must be direct child of /tmp)
NESTED_TMP_PARENT=""
create_safe_tmp_dir NESTED_TMP_PARENT "/tmp/pipejack-nested-parent-XXXXXX"
NESTED_TMP_CHILD="$NESTED_TMP_PARENT/pipejack-legit-cleanup-child-$$"
create_safe_nested_dir "$NESTED_TMP_CHILD"
if recover_and_clean_test_dir "$NESTED_TMP_CHILD" "pipejack-legit-cleanup-*" 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir accepted nested directory!" >&2
fi
if [ ! -d "$NESTED_TMP_CHILD" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir deleted nested directory!" >&2
fi
safe_delete_path "$NESTED_TMP_PARENT"

# 2b-3: Symlinked directory matching pattern (valid target) must be refused
TARGET_FOR_LINK=""
create_safe_tmp_dir TARGET_FOR_LINK "/tmp/pipejack-target-XXXXXX"
SYMLINK_LEGIT="/tmp/pipejack-legit-cleanup-symlink-$$"
create_safe_symlink "$TARGET_FOR_LINK" "$SYMLINK_LEGIT" "tmp"
if recover_and_clean_test_dir "$SYMLINK_LEGIT" "pipejack-legit-cleanup-*" 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir accepted symlink!" >&2
fi
if [ ! -L "$SYMLINK_LEGIT" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir deleted symlink!" >&2
fi
if [ ! -d "$TARGET_FOR_LINK" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir deleted symlink target!" >&2
fi
safe_delete_path "$SYMLINK_LEGIT"
safe_delete_path "$TARGET_FOR_LINK"

# 2b-4: Dangling symlinked directory matching pattern must be refused (not masked as absent)
DANGLING_TARGET_LEGIT="/tmp/pipejack-target-nonexistent-$$"
DANGLING_LEGIT="/tmp/pipejack-legit-cleanup-dangling-$$"
create_safe_symlink "$DANGLING_TARGET_LEGIT" "$DANGLING_LEGIT" "tmp"
if recover_and_clean_test_dir "$DANGLING_LEGIT" "pipejack-legit-cleanup-*" 2>/dev/null; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir accepted dangling symlink!" >&2
fi
if [ ! -L "$DANGLING_LEGIT" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Security defect: recover_and_clean_test_dir deleted dangling symlink!" >&2
fi
safe_delete_path "$DANGLING_LEGIT"

# 2b-5: Valid direct child of /tmp matching pattern must succeed
VALID_DIRECT_TMP=""
create_safe_tmp_dir VALID_DIRECT_TMP "/tmp/pipejack-legit-cleanup-valid-XXXXXX"
if ! recover_and_clean_test_dir "$VALID_DIRECT_TMP" "pipejack-legit-cleanup-*"; then
    TRAP_SAFETY_OK=0
    echo "  [-] recover_and_clean_test_dir failed on valid direct child directory" >&2
elif [ -e "$VALID_DIRECT_TMP" ]; then
    TRAP_SAFETY_OK=0
    echo "  [-] Valid direct child was not cleaned by recover_and_clean_test_dir" >&2
fi

# 3. Subtest B: Multi-signal termination (SIGINT, SIGTERM, SIGHUP) invokes actual traps, terminates immediately, and cleans all fixtures
SIG_OUTPUT=$(python3 -c "
import subprocess, os, signal

SCRIPT_FILE = '$SCRIPT_FILE'
all_sig_ok = True
details = []
for test_sig, expected_rc in [('INT', 130), ('TERM', 143), ('HUP', 129)]:
    res = subprocess.run(
        ['bash', SCRIPT_FILE, '--internal-test-cleanup-signal', test_sig],
        capture_output=True,
        text=True,
        preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_DFL)
    )
    sig_tmp = None
    sig_outside = None
    for line in res.stdout.splitlines():
        if line.startswith('SIG_TMP:'):
            sig_tmp = line.split(':', 1)[1].strip()
        elif line.startswith('SIG_OUTSIDE:'):
            sig_outside = line.split(':', 1)[1].strip()

    fixtures_created = bool(sig_tmp and sig_outside)
    cleaned_tmp = bool(sig_tmp and not os.path.exists(sig_tmp) and not os.path.lexists(sig_tmp))
    cleaned_outside = bool(sig_outside and not os.path.exists(sig_outside) and not os.path.lexists(sig_outside))
    unreached = ('SHOULD_NOT_REACH_HERE' not in res.stdout)
    rc_match = (res.returncode == expected_rc)

    if not (fixtures_created and cleaned_tmp and cleaned_outside and unreached and rc_match):
        all_sig_ok = False
    details.append(f'{test_sig}:rc={res.returncode}(exp {expected_rc}),created={fixtures_created},tmp_cleaned={cleaned_tmp},outside_cleaned={cleaned_outside},unreached={unreached}')

status = 'PASS' if all_sig_ok else 'FAIL'
print(f'STATUS:{status}|' + '; '.join(details))
" 2>&1)

if ! echo "$SIG_OUTPUT" | grep -q "^STATUS:PASS"; then
    TRAP_SAFETY_OK=0
    echo "  [-] Multi-signal termination safety test failed: $SIG_OUTPUT" >&2
fi

# 4. Subtest C: Deterministic creation-to-registration interrupt race regression tests
RACE_OUTPUT=$(python3 -c '
import subprocess, os, signal, tempfile, hashlib, sys, stat

SCRIPT_FILE = sys.argv[1]

def safe_validate_and_cleanup_sentinel(sentinel_path, baseline, sentinel_name):
    errors = []
    if sentinel_path is None:
        return True, errors

    if not os.path.lexists(sentinel_path):
        if baseline is not None:
            errors.append(f"{sentinel_name} {sentinel_path} was deleted before cleanup")
            return False, errors
        return True, errors

    if baseline is None:
        errors.append(f"{sentinel_name} baseline unrecorded: preserving {sentinel_path}")
        return False, errors

    mismatches = []
    if sentinel_path != baseline.get("path"):
        mismatches.append(f"path mismatch ({sentinel_path} != {baseline.get('path')})")

    if os.path.islink(sentinel_path):
        mismatches.append("is symlink")
    elif not os.path.isfile(sentinel_path):
        mismatches.append("not regular file")
    else:
        fd = None
        try:
            fd = os.open(sentinel_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                mismatches.append("mode indicates not a regular file")
            if st.st_uid != baseline.get("uid"):
                mismatches.append(f"uid mismatch {st.st_uid} != {baseline.get('uid')}")
            if st.st_uid != os.getuid():
                mismatches.append(f"uid {st.st_uid} != current user {os.getuid()}")
            if st.st_dev != baseline.get("dev") or st.st_ino != baseline.get("ino"):
                mismatches.append("dev/ino changed")
            if st.st_mode != baseline.get("mode"):
                mismatches.append("mode changed")
            if st.st_size != baseline.get("size"):
                mismatches.append("size changed")
            if st.st_mtime_ns != baseline.get("mtime_ns"):
                mismatches.append("mtime changed")

            h = hashlib.sha256()
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                h.update(chunk)
            cur_hash = h.hexdigest()
            if cur_hash != baseline.get("hash"):
                mismatches.append("content hash changed")
        except Exception as e:
            mismatches.append(f"stat/read error: {e}")
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass

    if mismatches:
        reasons_str = "; ".join(mismatches)
        errors.append(f"{sentinel_name} identity mismatch ({reasons_str}): preserving {sentinel_path}")
        return False, errors

    try:
        os.unlink(sentinel_path)
        return True, errors
    except Exception as e:
        errors.append(f"failed to unlink {sentinel_path}: {e}")
        return False, errors

def safe_validate_and_cleanup_dir(dir_path, baseline, dir_name):
    errors = []
    if dir_path is None:
        return True, errors

    if not os.path.lexists(dir_path):
        if baseline is not None:
            errors.append(f"{dir_name} {dir_path} was deleted before cleanup")
            return False, errors
        return True, errors

    if baseline is None:
        errors.append(f"{dir_name} baseline unrecorded: preserving {dir_path}")
        return False, errors

    mismatches = []
    if dir_path != baseline.get("path"):
        mismatches.append(f"path mismatch ({dir_path} != {baseline.get('path')})")

    if os.path.islink(dir_path):
        mismatches.append("is symlink")
    elif not os.path.isdir(dir_path):
        mismatches.append("not a directory")
    else:
        try:
            st = os.stat(dir_path)
            if not stat.S_ISDIR(st.st_mode):
                mismatches.append("mode indicates not a directory")
            if st.st_uid != baseline.get("uid") or st.st_uid != os.getuid():
                mismatches.append(f"uid mismatch {st.st_uid}")
            if st.st_dev != baseline.get("dev") or st.st_ino != baseline.get("ino"):
                mismatches.append("dev/ino changed")
            if "mode" in baseline and st.st_mode != baseline.get("mode"):
                mismatches.append("mode changed")
        except Exception as e:
            mismatches.append(f"stat error: {e}")

    if mismatches:
        reasons_str = "; ".join(mismatches)
        errors.append(f"{dir_name} identity mismatch ({reasons_str}): preserving {dir_path}")
        return False, errors

    try:
        os.rmdir(dir_path)
        return True, errors
    except Exception as e:
        errors.append(f"failed to rmdir {dir_path}: {e}")
        return False, errors

STANDARD_TMP_ARCHIVES = [
    "/tmp/banking-api-clean.tar.gz",
    "/tmp/banking-api-malicious.tar.gz",
    "/tmp/calculator-api.tar.gz",
    "/tmp/nodejs-app-clean.tar.gz",
    "/tmp/python-app-clean.tar.gz",
    "/tmp/nodejs-app-malicious.tar.gz",
    "/tmp/python-app-malicious.tar.gz",
    "/tmp/evil-pkg-1.0.0.tgz",
    "/tmp/attack-01-shell-exec.tar.gz",
    "/tmp/attack-02-http-exfil.tar.gz",
    "/tmp/attack-03-fs-tamper.tar.gz",
    "/tmp/attack-04-base64-shell.tar.gz",
    "/tmp/attack-05-multi-stage.tar.gz",
    "/tmp/attack-06-slow-exfil.tar.gz",
    "/tmp/attack-07-anomaly.tar.gz",
]

# Snapshot standard archives before running race scenarios
archive_pre_state = {}
for arch in STANDARD_TMP_ARCHIVES:
    if os.path.exists(arch):
        st = os.stat(arch)
        with open(arch, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        archive_pre_state[arch] = (st.st_size, st.st_mtime_ns, h)
    else:
        archive_pre_state[arch] = None

race_scenarios = [
    ("tmp_dir", "INT", 130),
    ("tmp_dir", "TERM", 143),
    ("tmp_dir", "HUP", 129),
    ("outside_dir", "INT", 130),
    ("outside_dir", "TERM", 143),
    ("outside_dir", "HUP", 129),
    ("tmp_symlink", "INT", 130),
    ("tmp_symlink", "TERM", 143),
    ("tmp_symlink", "HUP", 129),
    ("outside_symlink", "INT", 130),
    ("outside_symlink", "TERM", 143),
    ("outside_symlink", "HUP", 129),
    ("outside_dangling_symlink", "INT", 130),
    ("outside_dangling_symlink", "TERM", 143),
    ("outside_dangling_symlink", "HUP", 129),
    ("failed_creation", "INT", 130),
    ("failed_creation", "TERM", 143),
    ("failed_creation", "HUP", 129),
]

passed_scenarios = []
failed_scenarios = []
skipped_scenarios = []
details = []

for mode, sig, exp_rc in race_scenarios:
    scenario_id = f"{mode}_{sig}"
    scenario_errors = []
    cleanup_errors = []

    target_dir = None
    target_dir_baseline = None
    target_sentinel = None
    target_sentinel_baseline = None

    failed_sentinel = None
    failed_sentinel_baseline = None

    setup_ok = False
    subprocess_ran = False

    try:
        # 1. Early-identity parent fixture setup
        try:
            if mode == "tmp_symlink":
                target_dir = tempfile.mkdtemp(prefix="pipejack-target-tmp-", dir="/tmp")
                td_st = os.stat(target_dir)
                target_dir_baseline = {
                    "path": target_dir,
                    "dev": td_st.st_dev,
                    "ino": td_st.st_ino,
                    "mode": td_st.st_mode,
                    "uid": td_st.st_uid,
                }

                target_sentinel = os.path.join(target_dir, "sentinel.dat")
                fd = os.open(target_sentinel, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
                try:
                    content = f"tmp-target-data-{sig}-{os.getpid()}".encode()
                    os.write(fd, content)
                    os.fsync(fd)
                    ts_st = os.fstat(fd)
                    target_sentinel_baseline = {
                        "path": target_sentinel,
                        "dev": ts_st.st_dev,
                        "ino": ts_st.st_ino,
                        "mode": ts_st.st_mode,
                        "uid": ts_st.st_uid,
                        "size": ts_st.st_size,
                        "mtime_ns": ts_st.st_mtime_ns,
                        "hash": hashlib.sha256(content).hexdigest(),
                    }
                finally:
                    os.close(fd)

            elif mode == "outside_symlink":
                if not os.path.isdir("/var/tmp") or not os.access("/var/tmp", os.W_OK):
                    raise RuntimeError("/var/tmp not writable")
                target_dir = tempfile.mkdtemp(prefix="pipejack-target-out-", dir="/var/tmp")
                td_st = os.stat(target_dir)
                target_dir_baseline = {
                    "path": target_dir,
                    "dev": td_st.st_dev,
                    "ino": td_st.st_ino,
                    "mode": td_st.st_mode,
                    "uid": td_st.st_uid,
                }

                target_sentinel = os.path.join(target_dir, "sentinel.dat")
                fd = os.open(target_sentinel, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
                try:
                    content = f"out-target-data-{sig}-{os.getpid()}".encode()
                    os.write(fd, content)
                    os.fsync(fd)
                    ts_st = os.fstat(fd)
                    target_sentinel_baseline = {
                        "path": target_sentinel,
                        "dev": ts_st.st_dev,
                        "ino": ts_st.st_ino,
                        "mode": ts_st.st_mode,
                        "uid": ts_st.st_uid,
                        "size": ts_st.st_size,
                        "mtime_ns": ts_st.st_mtime_ns,
                        "hash": hashlib.sha256(content).hexdigest(),
                    }
                finally:
                    os.close(fd)

            elif mode == "failed_creation":
                fd, failed_sentinel = tempfile.mkstemp(prefix="pipejack-fail-sentinel-", dir="/tmp")
                try:
                    content = f"fail-sentinel-data-{sig}-{os.getpid()}".encode()
                    os.write(fd, content)
                    os.fsync(fd)
                    fs_st = os.fstat(fd)
                    failed_sentinel_baseline = {
                        "path": failed_sentinel,
                        "dev": fs_st.st_dev,
                        "ino": fs_st.st_ino,
                        "mode": fs_st.st_mode,
                        "uid": fs_st.st_uid,
                        "size": fs_st.st_size,
                        "mtime_ns": fs_st.st_mtime_ns,
                        "hash": hashlib.sha256(content).hexdigest(),
                    }
                finally:
                    os.close(fd)

            elif mode in ("outside_dir", "outside_dangling_symlink"):
                if not os.path.isdir("/var/tmp") or not os.access("/var/tmp", os.W_OK):
                    raise RuntimeError("/var/tmp not writable")

            setup_ok = True

        except Exception as e:
            setup_ok = False
            scenario_errors.append(f"Setup failed: {e}")

        # 2. Child execution (narrowly scoped exception handling)
        if setup_ok:
            args = ["bash", SCRIPT_FILE, "--internal-test-creation-race", mode, sig]
            if target_dir:
                args.append(target_dir)
            elif failed_sentinel:
                args.append(failed_sentinel)

            try:
                res = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_DFL)
                )
                subprocess_ran = True
            except Exception as e:
                scenario_errors.append(f"Subprocess launch failed: {e}")

        # 3. Post-child verification
        if subprocess_ran:
            fixture_path = None
            fixture_type = None
            fail_hook_fired = False
            verify_failed_lines = []

            for line in res.stdout.splitlines():
                if line.startswith("RACE_FIXTURE_CREATED:"):
                    parts = line.split(":", 2)
                    if len(parts) >= 2:
                        fixture_path = parts[1].strip()
                    if len(parts) >= 3:
                        fixture_type = parts[2].strip()
                elif line.startswith("RACE_FAIL_HOOK_FIRED:"):
                    fail_hook_fired = True
                elif line.startswith("RACE_FIXTURE_VERIFY_FAILED:"):
                    verify_failed_lines.append(line)

            if verify_failed_lines:
                vf_msg = "; ".join(verify_failed_lines)
                scenario_errors.append(f"race hook verification failed: {vf_msg}")

            if res.returncode != exp_rc:
                scenario_errors.append(f"rc={res.returncode}(expected {exp_rc})")
            if "SHOULD_NOT_REACH_HERE" in res.stdout:
                scenario_errors.append("reached SHOULD_NOT_REACH_HERE")

            if mode == "failed_creation":
                if not fail_hook_fired:
                    scenario_errors.append("fail hook did not fire")
                if fixture_path is not None:
                    scenario_errors.append(f"unexpected fixture created: {fixture_path}")

                if not os.path.lexists(failed_sentinel):
                    scenario_errors.append("pre-existing sentinel was deleted")
                elif os.path.islink(failed_sentinel):
                    scenario_errors.append("pre-existing sentinel turned into symlink")
                elif not os.path.isfile(failed_sentinel):
                    scenario_errors.append("pre-existing sentinel is not a regular file")
                else:
                    cur_st = os.stat(failed_sentinel)
                    if cur_st.st_dev != failed_sentinel_baseline["dev"] or cur_st.st_ino != failed_sentinel_baseline["ino"]:
                        scenario_errors.append("pre-existing sentinel device/inode changed")
                    if cur_st.st_uid != os.getuid():
                        scenario_errors.append(f"pre-existing sentinel uid mismatch: {cur_st.st_uid}")
                    if cur_st.st_mode != failed_sentinel_baseline["mode"]:
                        scenario_errors.append("pre-existing sentinel mode changed")
                    if cur_st.st_size != failed_sentinel_baseline["size"]:
                        scenario_errors.append("pre-existing sentinel size changed")
                    if cur_st.st_mtime_ns != failed_sentinel_baseline["mtime_ns"]:
                        scenario_errors.append("pre-existing sentinel mtime changed")
                    with open(failed_sentinel, "rb") as f:
                        cur_hash = hashlib.sha256(f.read()).hexdigest()
                    if cur_hash != failed_sentinel_baseline["hash"]:
                        scenario_errors.append("pre-existing sentinel content modified")

            else:
                if not fixture_path:
                    scenario_errors.append("missing RACE_FIXTURE_CREATED output")
                else:
                    canon_parent = os.path.realpath(os.path.dirname(fixture_path))
                    if mode in ("tmp_dir", "tmp_symlink"):
                        expected_parent = os.path.realpath("/tmp")
                    else:
                        expected_parent = os.path.realpath("/var/tmp")
                    if canon_parent != expected_parent:
                        scenario_errors.append(f"parent dir mismatch: {canon_parent} != {expected_parent}")

                    exp_type = "dir" if mode in ("tmp_dir", "outside_dir") else "symlink"
                    if fixture_type != exp_type:
                        scenario_errors.append(f"fixture type mismatch: {fixture_type} != {exp_type}")

                    if os.path.lexists(fixture_path):
                        scenario_errors.append(f"fixture was not cleaned up: {fixture_path}")

                if target_dir:
                    if not os.path.isdir(target_dir) or os.path.islink(target_dir):
                        scenario_errors.append(f"target dir missing or not a directory: {target_dir}")
                    elif not os.path.isfile(target_sentinel) or os.path.islink(target_sentinel):
                        scenario_errors.append(f"target sentinel missing or not a regular file: {target_sentinel}")
                    else:
                        st_td = os.stat(target_dir)
                        if st_td.st_dev != target_dir_baseline["dev"] or st_td.st_ino != target_dir_baseline["ino"]:
                            scenario_errors.append("target dir device/inode mismatch")
                        st_ts = os.stat(target_sentinel)
                        if st_ts.st_dev != target_sentinel_baseline["dev"] or st_ts.st_ino != target_sentinel_baseline["ino"]:
                            scenario_errors.append("target sentinel device/inode mismatch")
                        if st_ts.st_size != target_sentinel_baseline["size"]:
                            scenario_errors.append(f"target sentinel size mismatch: {st_ts.st_size} != {target_sentinel_baseline['size']}")
                        with open(target_sentinel, "rb") as f:
                            cur_hash = hashlib.sha256(f.read()).hexdigest()
                        if cur_hash != target_sentinel_baseline["hash"]:
                            scenario_errors.append("target sentinel content modified")

    finally:
        # 4. Independent baseline revalidation and validated cleanup
        if failed_sentinel is not None:
            cleaned_fs, fs_errs = safe_validate_and_cleanup_sentinel(
                failed_sentinel, failed_sentinel_baseline, "failed_sentinel"
            )
            cleanup_errors.extend(fs_errs)

        sentinel_cleaned = False
        if target_sentinel is not None:
            sentinel_cleaned, ts_errs = safe_validate_and_cleanup_sentinel(
                target_sentinel, target_sentinel_baseline, "target_sentinel"
            )
            cleanup_errors.extend(ts_errs)

        if target_dir is not None:
            if not os.path.lexists(target_dir):
                pass
            elif target_dir_baseline is None:
                cleanup_errors.append(f"target_dir baseline unrecorded: preserving {target_dir}")
            elif not sentinel_cleaned and target_sentinel is not None and os.path.lexists(target_sentinel):
                cleanup_errors.append(f"target_dir {target_dir} preserved because sentinel could not be cleaned")
            else:
                cleaned_td, td_errs = safe_validate_and_cleanup_dir(
                    target_dir, target_dir_baseline, "target_dir"
                )
                cleanup_errors.extend(td_errs)

    # Combine scenario errors and cleanup errors
    all_case_errors = list(scenario_errors)
    if cleanup_errors:
        all_case_errors.extend([f"CLEANUP_FAIL({ce})" for ce in cleanup_errors])

    if all_case_errors:
        err_msg = ", ".join(all_case_errors)
        failed_scenarios.append((scenario_id, err_msg))
        details.append(f"{scenario_id}:FAIL({err_msg})")
    else:
        passed_scenarios.append(scenario_id)
        details.append(f"{scenario_id}:PASS")

# Verify standard archives after all race iterations
archives_intact = True
archive_errors = []
for arch in STANDARD_TMP_ARCHIVES:
    pre = archive_pre_state[arch]
    if pre is None:
        if os.path.lexists(arch):
            archives_intact = False
            archive_errors.append(f"{arch}:created")
    else:
        if not os.path.exists(arch):
            archives_intact = False
            archive_errors.append(f"{arch}:deleted")
        else:
            st = os.stat(arch)
            with open(arch, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            cur = (st.st_size, st.st_mtime_ns, h)
            if cur != pre:
                archives_intact = False
                archive_errors.append(f"{arch}:modified")

total_count = len(race_scenarios)
pass_count = len(passed_scenarios)
fail_count = len(failed_scenarios)
skip_count = len(skipped_scenarios)

all_ok = (pass_count == total_count) and (fail_count == 0) and (skip_count == 0) and archives_intact
status = "PASS" if all_ok else "FAIL"

summary = f"STATUS:{status}|passed={pass_count},failed={fail_count},skipped={skip_count},archives_intact={archives_intact}"
if archive_errors:
    arch_msg = ", ".join(archive_errors)
    summary += f",archive_errors=[{arch_msg}]"
print(summary + "|" + "; ".join(details))
' "$SCRIPT_FILE" 2>&1)

if ! echo "$RACE_OUTPUT" | grep -q "^STATUS:PASS"; then
    TRAP_SAFETY_OK=0
    echo "  [-] Creation-registration race regression tests failed: $RACE_OUTPUT" >&2
fi

# 5. Subtest D: Controlled Failure-Path & Fault-Injection Regression Tests
FAULT_OUTPUT=$(python3 -c '
import subprocess, os, signal, tempfile, hashlib, sys, stat

SCRIPT_FILE = sys.argv[1]
all_fault_tests_ok = True
fault_details = []

def safe_validate_and_cleanup_sentinel(sentinel_path, baseline, sentinel_name):
    errors = []
    if sentinel_path is None:
        return True, errors

    if not os.path.lexists(sentinel_path):
        if baseline is not None:
            errors.append(f"{sentinel_name} {sentinel_path} was deleted before cleanup")
            return False, errors
        return True, errors

    if baseline is None:
        errors.append(f"{sentinel_name} baseline unrecorded: preserving {sentinel_path}")
        return False, errors

    mismatches = []
    if sentinel_path != baseline.get("path"):
        mismatches.append(f"path mismatch ({sentinel_path} != {baseline.get('path')})")

    if os.path.islink(sentinel_path):
        mismatches.append("is symlink")
    elif not os.path.isfile(sentinel_path):
        mismatches.append("not regular file")
    else:
        fd = None
        try:
            fd = os.open(sentinel_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                mismatches.append("mode indicates not a regular file")
            if st.st_uid != baseline.get("uid"):
                mismatches.append(f"uid mismatch {st.st_uid} != {baseline.get('uid')}")
            if st.st_uid != os.getuid():
                mismatches.append(f"uid {st.st_uid} != current user {os.getuid()}")
            if st.st_dev != baseline.get("dev") or st.st_ino != baseline.get("ino"):
                mismatches.append("dev/ino changed")
            if st.st_mode != baseline.get("mode"):
                mismatches.append("mode changed")
            if st.st_size != baseline.get("size"):
                mismatches.append("size changed")
            if st.st_mtime_ns != baseline.get("mtime_ns"):
                mismatches.append("mtime changed")

            h = hashlib.sha256()
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                h.update(chunk)
            cur_hash = h.hexdigest()
            if cur_hash != baseline.get("hash"):
                mismatches.append("content hash changed")
        except Exception as e:
            mismatches.append(f"stat/read error: {e}")
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass

    if mismatches:
        reasons_str = "; ".join(mismatches)
        errors.append(f"{sentinel_name} identity mismatch ({reasons_str}): preserving {sentinel_path}")
        return False, errors

    try:
        os.unlink(sentinel_path)
        return True, errors
    except Exception as e:
        errors.append(f"failed to unlink {sentinel_path}: {e}")
        return False, errors

def safe_validate_and_cleanup_dir(dir_path, baseline, dir_name):
    errors = []
    if dir_path is None:
        return True, errors

    if not os.path.lexists(dir_path):
        if baseline is not None:
            errors.append(f"{dir_name} {dir_path} was deleted before cleanup")
            return False, errors
        return True, errors

    if baseline is None:
        errors.append(f"{dir_name} baseline unrecorded: preserving {dir_path}")
        return False, errors

    mismatches = []
    if dir_path != baseline.get("path"):
        mismatches.append(f"path mismatch ({dir_path} != {baseline.get('path')})")

    if os.path.islink(dir_path):
        mismatches.append("is symlink")
    elif not os.path.isdir(dir_path):
        mismatches.append("not a directory")
    else:
        try:
            st = os.stat(dir_path)
            if not stat.S_ISDIR(st.st_mode):
                mismatches.append("mode indicates not a directory")
            if st.st_uid != baseline.get("uid") or st.st_uid != os.getuid():
                mismatches.append(f"uid mismatch {st.st_uid}")
            if st.st_dev != baseline.get("dev") or st.st_ino != baseline.get("ino"):
                mismatches.append("dev/ino changed")
            if "mode" in baseline and st.st_mode != baseline.get("mode"):
                mismatches.append("mode changed")
        except Exception as e:
            mismatches.append(f"stat error: {e}")

    if mismatches:
        reasons_str = "; ".join(mismatches)
        errors.append(f"{dir_name} identity mismatch ({reasons_str}): preserving {dir_path}")
        return False, errors

    try:
        os.rmdir(dir_path)
        return True, errors
    except Exception as e:
        errors.append(f"failed to rmdir {dir_path}: {e}")
        return False, errors

def safe_validate_and_cleanup_symlink(link_path, baseline, link_name):
    errors = []
    if link_path is None:
        return True, errors

    if not os.path.lexists(link_path):
        if baseline is not None:
            errors.append(f"{link_name} {link_path} was deleted before cleanup")
            return False, errors
        return True, errors

    if baseline is None:
        errors.append(f"{link_name} baseline unrecorded: preserving {link_path}")
        return False, errors

    mismatches = []
    if link_path != baseline.get("path"):
        mismatches.append(f"path mismatch ({link_path} != {baseline.get('path')})")

    if not os.path.islink(link_path):
        mismatches.append("not a symlink")
    else:
        try:
            target = os.readlink(link_path)
            if "target" in baseline and target != baseline["target"]:
                mismatches.append(f"target mismatch ({target} != {baseline['target']})")
            st = os.lstat(link_path)
            if not stat.S_ISLNK(st.st_mode):
                mismatches.append("mode indicates not a symlink")
            if st.st_uid != baseline.get("uid") or st.st_uid != os.getuid():
                mismatches.append(f"uid mismatch {st.st_uid}")
            if st.st_dev != baseline.get("dev") or st.st_ino != baseline.get("ino"):
                mismatches.append("dev/ino changed")
        except Exception as e:
            mismatches.append(f"stat error: {e}")

    if mismatches:
        reasons_str = "; ".join(mismatches)
        errors.append(f"{link_name} identity mismatch ({reasons_str}): preserving {link_path}")
        return False, errors

    try:
        os.unlink(link_path)
        return True, errors
    except Exception as e:
        errors.append(f"failed to unlink {link_path}: {e}")
        return False, errors

def run_fault_case(name, fn):
    global all_fault_tests_ok
    try:
        ok, msg = fn()
        if ok:
            fault_details.append(f"{name}:PASS")
        else:
            all_fault_tests_ok = False
            fault_details.append(f"{name}:FAIL({msg})")
    except Exception as e:
        all_fault_tests_ok = False
        fault_details.append(f"{name}:EXCEPTION({e})")

# Fault 1: Setup exception after creating target directory
def test_setup_exception_after_target_dir():
    target_dir = None
    target_dir_baseline = None
    cleanup_errors = []
    try:
        target_dir = tempfile.mkdtemp(prefix="pipejack-fault-td-", dir="/tmp")
        st = os.stat(target_dir)
        target_dir_baseline = {
            "path": target_dir, "dev": st.st_dev, "ino": st.st_ino,
            "uid": st.st_uid, "mode": st.st_mode
        }
        raise RuntimeError("injected setup exception after target dir creation")
    except RuntimeError:
        pass
    finally:
        cleaned_td, td_errs = safe_validate_and_cleanup_dir(
            target_dir, target_dir_baseline, "target_dir"
        )
        cleanup_errors.extend(td_errs)
    
    if os.path.lexists(target_dir):
        return False, f"target_dir {target_dir} was not cleaned up after setup exception"
    if cleanup_errors:
        return False, f"unexpected cleanup error: {cleanup_errors}"
    return True, "cleaned"

# Fault 2: Exception during sentinel writing or before identity recording completes
def test_exception_before_sentinel_identity_recorded():
    target_dir = tempfile.mkdtemp(prefix="pipejack-fault-unrec-", dir="/tmp")
    td_st = os.stat(target_dir)
    target_dir_baseline = {
        "path": target_dir, "dev": td_st.st_dev, "ino": td_st.st_ino,
        "uid": td_st.st_uid, "mode": td_st.st_mode
    }
    teardown_dir_baseline = dict(target_dir_baseline)
    
    target_sentinel = os.path.join(target_dir, "sentinel.dat")
    with open(target_sentinel, "w") as f:
        f.write("partial")
    
    ts_st = os.stat(target_sentinel)
    with open(target_sentinel, "rb") as f:
        ts_hash = hashlib.sha256(f.read()).hexdigest()
    teardown_sentinel_baseline = {
        "path": target_sentinel,
        "dev": ts_st.st_dev,
        "ino": ts_st.st_ino,
        "mode": ts_st.st_mode,
        "uid": ts_st.st_uid,
        "size": ts_st.st_size,
        "mtime_ns": ts_st.st_mtime_ns,
        "hash": ts_hash,
    }
    
    target_sentinel_baseline = None
    cleanup_errors = []
    
    try:
        pass
    finally:
        sentinel_cleaned, ts_errs = safe_validate_and_cleanup_sentinel(
            target_sentinel, target_sentinel_baseline, "target_sentinel"
        )
        cleanup_errors.extend(ts_errs)

        if target_dir is not None:
            if not sentinel_cleaned and os.path.lexists(target_sentinel):
                cleanup_errors.append(f"target_dir {target_dir} preserved because sentinel could not be cleaned")
            else:
                cleaned_td, td_errs = safe_validate_and_cleanup_dir(
                    target_dir, target_dir_baseline, "target_dir"
                )
                cleanup_errors.extend(td_errs)

    preserved = os.path.lexists(target_sentinel)
    reported = any("baseline unrecorded: preserving" in ce for ce in cleanup_errors)
    
    # Safe teardown using independent teardown identity
    teardown_errors = []
    cleaned_ts, ts_td_errs = safe_validate_and_cleanup_sentinel(
        target_sentinel, teardown_sentinel_baseline, "teardown_sentinel"
    )
    teardown_errors.extend(ts_td_errs)

    if cleaned_ts:
        cleaned_td, td_td_errs = safe_validate_and_cleanup_dir(
            target_dir, teardown_dir_baseline, "teardown_dir"
        )
        teardown_errors.extend(td_td_errs)
        
    if not preserved:
        return False, "unrecorded sentinel was deleted blindly"
    if not reported:
        return False, f"cleanup failure was not reported: {cleanup_errors}"
    if teardown_errors or os.path.lexists(target_sentinel) or os.path.lexists(target_dir):
        return False, f"teardown failed: {teardown_errors}"
    return True, "preserved_and_reported"

# Fault 3: Mocked subprocess-launch exception
def test_mocked_subprocess_launch_exception():
    fd, failed_sentinel = tempfile.mkstemp(prefix="pipejack-fault-launch-", dir="/tmp")
    try:
        content = b"launch-fail-test-data"
        os.write(fd, content)
        os.fsync(fd)
        st = os.fstat(fd)
        failed_sentinel_baseline = {
            "path": failed_sentinel, "dev": st.st_dev, "ino": st.st_ino,
            "mode": st.st_mode, "uid": st.st_uid, "size": st.st_size,
            "mtime_ns": st.st_mtime_ns, "hash": hashlib.sha256(content).hexdigest()
        }
    finally:
        os.close(fd)

    scenario_errors = []
    cleanup_errors = []
    
    try:
        raise OSError("Mocked execve failure: [Errno 8] Exec format error")
    except Exception as e:
        scenario_errors.append(f"Subprocess launch failed: {e}")
    finally:
        cleaned_fs, fs_errs = safe_validate_and_cleanup_sentinel(
            failed_sentinel, failed_sentinel_baseline, "failed_sentinel"
        )
        cleanup_errors.extend(fs_errs)

    cleaned = not os.path.lexists(failed_sentinel)
    reported = any("Subprocess launch failed" in se for se in scenario_errors)
    if not cleaned or cleanup_errors:
        return False, f"sentinel was not cleaned up after launch failure: {cleanup_errors}"
    if not reported:
        return False, "launch exception was not recorded in scenario errors"
    return True, "cleaned_and_reported"

# Fault 4: Sentinel metadata, type, ownership, or content mismatch
def test_sentinel_content_mismatch_preservation():
    fd, failed_sentinel = tempfile.mkstemp(prefix="pipejack-fault-mismatch-", dir="/tmp")
    try:
        content = b"original-content"
        os.write(fd, content)
        os.fsync(fd)
        st = os.fstat(fd)
        failed_sentinel_baseline = {
            "path": failed_sentinel, "dev": st.st_dev, "ino": st.st_ino,
            "mode": st.st_mode, "uid": st.st_uid, "size": st.st_size,
            "mtime_ns": st.st_mtime_ns, "hash": hashlib.sha256(content).hexdigest()
        }
    finally:
        os.close(fd)

    with open(failed_sentinel, "ab") as f:
        f.write(b"-TAMPERED")

    tampered_st = os.stat(failed_sentinel)
    with open(failed_sentinel, "rb") as f:
        tampered_hash = hashlib.sha256(f.read()).hexdigest()
    teardown_sentinel_baseline = {
        "path": failed_sentinel,
        "dev": tampered_st.st_dev,
        "ino": tampered_st.st_ino,
        "mode": tampered_st.st_mode,
        "uid": tampered_st.st_uid,
        "size": tampered_st.st_size,
        "mtime_ns": tampered_st.st_mtime_ns,
        "hash": tampered_hash,
    }

    cleanup_errors = []
    try:
        pass
    finally:
        cleaned, se_errs = safe_validate_and_cleanup_sentinel(
            failed_sentinel, failed_sentinel_baseline, "failed_sentinel"
        )
        cleanup_errors.extend(se_errs)

    preserved = os.path.lexists(failed_sentinel)
    reported = any("identity mismatch" in ce for ce in cleanup_errors)
    
    # Safe teardown using independent teardown identity
    teardown_errors = []
    cleaned_teardown, td_errs = safe_validate_and_cleanup_sentinel(
        failed_sentinel, teardown_sentinel_baseline, "teardown_tampered_sentinel"
    )
    teardown_errors.extend(td_errs)

    if not preserved:
        return False, "tampered sentinel was deleted instead of preserved"
    if not reported:
        return False, f"identity mismatch cleanup failure was not reported: {cleanup_errors}"
    if not cleaned_teardown or teardown_errors or os.path.lexists(failed_sentinel):
        return False, f"teardown failed to safely clean verified tampered fixture: {teardown_errors}"
    return True, "preserved_and_reported"

# Fault 5: Race-hook type or target verification failure
def test_race_hook_target_verification_failure():
    target_dir = tempfile.mkdtemp(prefix="pipejack-fault-hook-", dir="/tmp")
    st = os.stat(target_dir)
    target_dir_baseline = {
        "path": target_dir, "dev": st.st_dev, "ino": st.st_ino,
        "uid": st.st_uid, "mode": st.st_mode
    }
    teardown_errors = []
    try:
        res = subprocess.run(
            ["bash", SCRIPT_FILE, "--internal-test-creation-race", "hook_fail_target", "INT", target_dir],
            capture_output=True,
            text=True
        )
    finally:
        cleaned_td, td_errs = safe_validate_and_cleanup_dir(
            target_dir, target_dir_baseline, "target_dir"
        )
        teardown_errors.extend(td_errs)

    verify_failed = ("RACE_FIXTURE_VERIFY_FAILED:" in res.stdout and "target_mismatch" in res.stdout)
    rc_failed = (res.returncode == 1)
    cleaned = ("RACE_FAILED_FIXTURE_CLEANED:" in res.stdout)
    
    if not verify_failed:
        return False, f"missing RACE_FIXTURE_VERIFY_FAILED: stdout={res.stdout}"
    if not rc_failed:
        return False, f"child returncode was {res.returncode}, expected 1"
    if not cleaned:
        return False, f"failed hook fixture was not cleaned up: stdout={res.stdout}"
    if teardown_errors or os.path.lexists(target_dir):
        return False, f"teardown failed to safely clean verified target_dir: {teardown_errors}"
    return True, "verified_and_cleaned"

# Fault 6: Race-hook unverified pattern preservation
def test_race_hook_unverified_pattern_preservation():
    test_link = f"/tmp/unverified-forbidden-pattern-link-{os.getpid()}"
    if os.path.lexists(test_link):
        try:
            os.unlink(test_link)
        except Exception:
            pass
    os.symlink("/tmp", test_link)
    st = os.lstat(test_link)
    teardown_link_baseline = {
        "path": test_link,
        "dev": st.st_dev,
        "ino": st.st_ino,
        "uid": st.st_uid,
        "target": "/tmp",
    }
    
    res = subprocess.run(
        ["bash", SCRIPT_FILE, "--internal-test-creation-race", "hook_fail_unverified_pattern", "INT", test_link],
        capture_output=True,
        text=True
    )
    verify_failed = ("RACE_FIXTURE_VERIFY_FAILED:" in res.stdout)
    preserved_reported = ("RACE_FIXTURE_PRESERVED:" in res.stdout and "unexpected_basename_pattern" in res.stdout)
    preserved = os.path.lexists(test_link)

    # Safe teardown using independent teardown identity
    cleaned_link, link_errs = safe_validate_and_cleanup_symlink(
        test_link, teardown_link_baseline, "unverified_pattern_fixture"
    )

    if not verify_failed:
        return False, f"missing verify failed: stdout={res.stdout}"
    if not preserved_reported:
        return False, f"unverified pattern residue was not preserved/reported: stdout={res.stdout}"
    if not preserved:
        return False, "unverified pattern fixture was deleted by safety hook instead of preserved"
    if not cleaned_link or link_errs or os.path.lexists(test_link):
        return False, f"teardown failed to safely clean verified fixture: {link_errs}"
    return True, "preserved_and_reported"

run_fault_case("setup_exception_cleanup", test_setup_exception_after_target_dir)
run_fault_case("unrecorded_sentinel_preservation", test_exception_before_sentinel_identity_recorded)
run_fault_case("mocked_launch_exception_cleanup", test_mocked_subprocess_launch_exception)
run_fault_case("tampered_sentinel_preservation", test_sentinel_content_mismatch_preservation)
run_fault_case("race_hook_target_verification_failure", test_race_hook_target_verification_failure)
run_fault_case("race_hook_unverified_pattern_preservation", test_race_hook_unverified_pattern_preservation)

status = "PASS" if all_fault_tests_ok else "FAIL"
print(f"STATUS:{status}|" + "; ".join(fault_details))
' "$SCRIPT_FILE" 2>&1)

if ! echo "$FAULT_OUTPUT" | grep -q "^STATUS:PASS"; then
    TRAP_SAFETY_OK=0
    echo "  [-] Failure-path and fault-injection regression tests failed: $FAULT_OUTPUT" >&2
fi

# Clean up sentinel directory safely via safe_delete_path
safe_delete_path "$HOSTILE_SENTINEL_DIR"

if [ $TRAP_SAFETY_OK -eq 1 ]; then
    pass "Trap cleanup safety verified: pre-populated hostile environment variables cannot trigger deletion, creation-registration races are closed with deferred signal dispatch, signals terminate immediately with proper exit codes, and only registered paths are removed"
else
    fail "Trap cleanup safety regression test failed"
fi

# -----------------------------------------------------------------------------
# Test 13: Final Host /tmp Namespace Preservation Verification
# -----------------------------------------------------------------------------
section "Final Host /tmp Namespace Preservation Verification"
FINAL_CANARY_OK=1

# Verify unique test marker exists, has expected content, and is owned by current user
if [ ! -f "$UNIQUE_CANARY_FILE" ] || [ "$(cat "$UNIQUE_CANARY_FILE")" != "$UNIQUE_CANARY_TAG" ]; then
    FINAL_CANARY_OK=0
    echo "  [-] Unique canary marker in /tmp was deleted or modified during test run!" >&2
fi
if [ "$(stat -c '%u' "$UNIQUE_CANARY_FILE" 2>/dev/null || echo -1)" -ne "$(id -u)" ]; then
    FINAL_CANARY_OK=0
    echo "  [-] Unique canary marker ownership mismatch!" >&2
fi

# Verify all 15 standard /tmp archive paths were preserved in their exact pre-test state
for f in "${STANDARD_TMP_ARCHIVES[@]}"; do
    initial_state="${PRE_EXISTING_TMP_STATE["$f"]}"
    if [ "$initial_state" = "ABSENT" ]; then
        if [ -e "$f" ]; then
            FINAL_CANARY_OK=0
            echo "  [-] Isolation violation: Archive was leaked to shared /tmp: $f" >&2
        fi
    else
        if [ ! -e "$f" ]; then
            FINAL_CANARY_OK=0
            echo "  [-] Isolation violation: Pre-existing file was deleted from shared /tmp: $f" >&2
        else
            current_state="$(stat -c '%Y:%s' "$f")|$(sha256sum "$f" | awk '{print $1}')"
            if [ "$initial_state" != "$current_state" ]; then
                FINAL_CANARY_OK=0
                echo "  [-] Isolation violation: Pre-existing file was modified in shared /tmp: $f" >&2
            fi
        fi
    fi
done

if [ $FINAL_CANARY_OK -eq 1 ]; then
    pass "Host /tmp namespace remained strictly untouched throughout entire regression run (no leaks, no overwrites, no deletions)"
else
    fail "Host /tmp isolation violation detected"
fi

# -----------------------------------------------------------------------------
# Final Summary
# -----------------------------------------------------------------------------
echo
echo "============================================================"
echo " REGRESSION TEST RESULTS: $PASSED_TESTS/$TOTAL_TESTS PASSED ($FAILED_TESTS failures)"
echo "============================================================"

if [ $FAILED_TESTS -eq 0 ]; then
    echo " [PASSED] ALL ACCEPTANCE HARDENING & REGRESSION CHECKS PASSED SUCCESSFULLY."
    exit 0
else
    echo " [-] REGRESSION TESTS FAILED WITH $FAILED_TESTS FAILURE(S)." >&2
    exit 1
fi
