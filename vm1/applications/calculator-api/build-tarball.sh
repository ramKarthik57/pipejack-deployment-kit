#!/bin/bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${PIPEJACK_OUTPUT_DIR:-/tmp}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
OUT="$OUT_DIR/calculator-api.tar.gz"

STAGE=$(mktemp -d)
cp -r "$DIR/src" "$STAGE/"
cp "$DIR/pom.xml" "$STAGE/"
tar -czf "$OUT" -C "$STAGE" .
rm -rf "$STAGE"

echo "built $OUT"
ls -la "$OUT"
