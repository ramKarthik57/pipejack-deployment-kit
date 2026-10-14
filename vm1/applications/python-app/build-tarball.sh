#!/bin/bash
set -e
SRC="$(dirname "$(realpath "$0")")"
OUT_DIR="${PIPEJACK_OUTPUT_DIR:-/tmp}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/python-app-clean.tar.gz"
STAGE=$(mktemp -d)
cp "$SRC/requirements.txt" "$STAGE/"
cp "$SRC/app.py"           "$STAGE/"
cp "$SRC/Dockerfile"       "$STAGE/"
tar -czf "$OUT" -C "$STAGE" .
echo "built $OUT"
ls -la "$OUT"
rm -rf "$STAGE"
