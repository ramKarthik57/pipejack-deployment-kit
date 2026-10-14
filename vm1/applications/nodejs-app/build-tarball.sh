#!/bin/bash
set -e
SRC="$(dirname "$(realpath "$0")")"
OUT_DIR="${PIPEJACK_OUTPUT_DIR:-/tmp}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
OUT="$OUT_DIR/nodejs-app-clean.tar.gz"
STAGE=$(mktemp -d)
cp "$SRC/package.json" "$STAGE/"
cp "$SRC/app.js"       "$STAGE/"
cp "$SRC/Dockerfile"   "$STAGE/"
tar -czf "$OUT" -C "$STAGE" .
echo "built $OUT"
ls -la "$OUT"
echo
echo "contents:"
tar -tzf "$OUT"
rm -rf "$STAGE"
