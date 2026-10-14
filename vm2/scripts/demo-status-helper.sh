#!/usr/bin/env bash
# PipeJack VM2 — Demo Console Status and Scenario Artifact Helper
# Shared production helper module used by vm2/install.sh and verification test suites.

# Function: prepare_demo_artifacts <target_console_dir>
# Executes prepare-demo.sh in target directory and exports DEMO_STATUS ("SUCCESS", "FAILED", "MISSING")
prepare_demo_artifacts() {
    local target_dir="$1"
    DEMO_STATUS="MISSING"
    if [ -f "$target_dir/prepare-demo.sh" ]; then
        chmod +x "$target_dir/prepare-demo.sh" 2>/dev/null || true
        echo "  Generating demo scenario artifacts..."
        local demo_log
        demo_log=$(mktemp)
        if (cd "$target_dir" && ./prepare-demo.sh > "$demo_log" 2>&1); then
            echo "  [OK] Demo scenario artifacts generated successfully."
            DEMO_STATUS="SUCCESS"
            rm -f "$demo_log"
        else
            echo "  [WARNING] [PARTIAL SUCCESS] Demo scenario artifact generation failed!" >&2
            echo "  prepare-demo.sh output:" >&2
            sed 's/^/       | /' "$demo_log" >&2
            rm -f "$demo_log"
            echo "  Continuing core installation (demo scenarios are optional for core CI daemon)." >&2
            DEMO_STATUS="FAILED"
        fi
    else
        echo "  [WARNING] [PARTIAL SUCCESS] prepare-demo.sh not found in $target_dir; skipping demo scenario artifact generation." >&2
        DEMO_STATUS="MISSING"
    fi
    export DEMO_STATUS
}

# Function: get_demo_status_banner <demo_status> [console_dir]
# Renders user-facing status banner reflecting full readiness vs partial success
get_demo_status_banner() {
    local status="$1"
    local console_dir="${2:-/home/ubuntu/pipejack-demo-console}"
    if [ "$status" = "FAILED" ]; then
        echo " [PARTIAL SUCCESS] PIPEJACK VM2 INSTALLATION COMPLETE WITH WARNINGS"
        echo "============================================================"
        echo " Core services are active, but demo scenario artifacts failed to generate."
        echo " The Demo Console is running, but UI demo scenarios require artifacts."
        echo " To generate them manually, run:"
        echo "   cd $console_dir && ./prepare-demo.sh"
    elif [ "$status" = "MISSING" ]; then
        echo " [PARTIAL SUCCESS] PIPEJACK VM2 INSTALLATION COMPLETE WITH WARNINGS"
        echo "============================================================"
        echo " Core services are active, but prepare-demo.sh was not found."
        echo " Demo scenario artifacts were not generated for the Demo Console."
    else
        echo " PIPEJACK VM2 INSTALLATION COMPLETE (FULL DEMO READINESS)"
    fi
}
