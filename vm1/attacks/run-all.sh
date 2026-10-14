#!/bin/bash
# Build + upload all scenarios, print verdict summary.
VM2=${VM2:-192.168.88.133}
HOST="http://$VM2:8888/upload"

declare -A RESULTS
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_DIRS=("$SCRIPT_DIR"/[0-9]*/)
if [ ! -d "${ATTACK_DIRS[0]}" ]; then
    ATTACK_DIRS=(~/attacks/[0-9]*/)
fi

for dir in "${ATTACK_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    echo
    echo "==========================================="
    echo "  $name"
    echo "==========================================="

    # Build
    (cd "$dir" && ./build.sh >/dev/null 2>&1)
    tarball=$(ls /tmp/attack-*.tar.gz 2>/dev/null | grep "$name" | head -1)
    if [ -z "$tarball" ]; then
        echo "  BUILD FAIL"
        RESULTS[$name]="build-fail"
        continue
    fi

    # Upload (Maven build can take ~1-2 minutes)
    resp=$(curl -s -m 180 -F "file=@$tarball" "$HOST")
    verdict=$(echo "$resp" | grep -o '"verdict":"[A-Z]*"' | head -1)
    if [ -z "$verdict" ] && echo "$resp" | grep -q '"status":"pass"'; then
        verdict='"verdict":"ALLOW"'
    fi
    echo "  $verdict"
    RESULTS[$name]="$verdict"
done

echo
echo "==========================================="
echo "  SUMMARY"
echo "==========================================="
for k in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
    printf "  %-25s  %s\n" "$k" "${RESULTS[$k]}"
done
