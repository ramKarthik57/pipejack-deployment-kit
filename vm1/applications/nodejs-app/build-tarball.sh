#!/bin/bash
set -e
SRC="$(dirname "$(realpath "$0")")"
OUT=/tmp/nodejs-app-clean.tar.gz
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
