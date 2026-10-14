#!/bin/bash
# Builds evil-pkg-1.0.0.tgz fixture from package.json directly into configured output directory
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${PIPEJACK_OUTPUT_DIR:-/tmp}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

# Stage fixture in isolated temporary directory to ensure source checkout is never modified
STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT

cp "$DIR/package.json" "$STAGE_DIR/"
if [ -f "$DIR/README.md" ]; then
    cp "$DIR/README.md" "$STAGE_DIR/"
fi

# Generate directly in OUT_DIR using --pack-destination
npm pack "$STAGE_DIR" --pack-destination "$OUT_DIR" >/dev/null

echo "Built $OUT_DIR/evil-pkg-1.0.0.tgz"
