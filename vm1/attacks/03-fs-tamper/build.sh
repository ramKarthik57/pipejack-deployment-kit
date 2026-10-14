#!/bin/bash
set -e
SRC="$(dirname "$(realpath "$0")")"
if [ -z "$BANKING" ]; then
    if [ -d "$SRC/../../applications/banking-api" ]; then
        BANKING="$(realpath "$SRC/../../applications/banking-api")"
    else
        BANKING=~/banking-api
    fi
fi
OUT=/tmp/attack-03-fs-tamper.tar.gz

[ -d "$BANKING/src" ] || { echo "ERROR: $BANKING/src missing" >&2; exit 1; }

STAGE=$(mktemp -d)
mkdir -p "$STAGE/src"
cp -r "$BANKING/src/." "$STAGE/src/"
cp "$SRC/pom.xml"    "$STAGE/pom.xml"
cp "$SRC/attack.sh"  "$STAGE/attack.sh"

tar -czf "$OUT" -C "$STAGE" .
echo "built $OUT"
ls -la "$OUT"
rm -rf "$STAGE"
