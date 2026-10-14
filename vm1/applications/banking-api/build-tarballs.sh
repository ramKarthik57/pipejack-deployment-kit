#!/bin/bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Clean tarball
STAGE_CLEAN=$(mktemp -d)
cp -r "$DIR/src" "$STAGE_CLEAN/"
cp "$DIR/pom.xml" "$STAGE_CLEAN/pom.xml"
tar -czf /tmp/banking-api-clean.tar.gz -C "$STAGE_CLEAN" .
rm -rf "$STAGE_CLEAN"
echo "built /tmp/banking-api-clean.tar.gz"

# Malicious tarball
STAGE_MAL=$(mktemp -d)
cp -r "$DIR/src" "$STAGE_MAL/"
cp "$DIR/pom-malicious.xml" "$STAGE_MAL/pom.xml"
cp "$DIR/malicious.sh" "$STAGE_MAL/malicious.sh"
tar -czf /tmp/banking-api-malicious.tar.gz -C "$STAGE_MAL" .
rm -rf "$STAGE_MAL"
echo "built /tmp/banking-api-malicious.tar.gz"
