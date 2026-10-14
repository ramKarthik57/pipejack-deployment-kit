#!/bin/bash
set -e
SRC="$(dirname "$(realpath "$0")")"
OUT_DIR="${PIPEJACK_OUTPUT_DIR:-/tmp}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
OUT="$OUT_DIR/python-app-malicious.tar.gz"
STAGE=$(mktemp -d)
cp "$SRC/requirements.txt" "$STAGE/"
cp "$SRC/setup.py"         "$STAGE/"
cp "$SRC/pyproject.toml"   "$STAGE/"
cp "$SRC/app.py"           "$STAGE/"
cp "$SRC/Dockerfile"       "$STAGE/"
tar -czf "$OUT" -C "$STAGE" .
echo "built $OUT"
tar -tzf "$OUT"
rm -rf "$STAGE"
