#!/bin/bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT=/tmp/calculator-api.tar.gz

STAGE=$(mktemp -d)
cp -r "$DIR/src" "$STAGE/"
cp "$DIR/pom.xml" "$STAGE/"
tar -czf "$OUT" -C "$STAGE" .
rm -rf "$STAGE"

echo "built $OUT"
ls -la "$OUT"
