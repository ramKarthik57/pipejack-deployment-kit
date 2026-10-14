# PipeJack Attack Library

Six attack scenarios, each demonstrating a different detection path.
All run against the same Banking API source, uploaded to VM-2's CI on port 8888.

## Quick run

    for d in ~/attacks/[0-9]*/; do
        (cd "$d" && ./build.sh)
    done
    # Then upload each /tmp/attack-*.tar.gz to VM-2

## Scenarios

### 01 — Shell exec
Spawns `/bin/sh -c 'curl ...'`. Detection: process tree sees curl and sh.
Expected: BLOCK via process + network.

### 02 — HTTP exfiltration
Reads `~/.npmrc`, POSTs contents to `10.255.255.1:8443`.
Detection: process + network on port 8443.
Expected: BLOCK.

### 03 — Filesystem tamper only
Modifies, deletes, and adds source files during the build.
Detection: filesystem Merkle root changes.
Expected: BLOCK via filesystem only (no process, no network).

### 04 — Base64-obfuscated shell
Payload is base64-encoded; decoded and executed at runtime.
Detection: process tree sees the decoded binaries (curl).
Expected: BLOCK. Demonstrates that static source scanning alone would miss it.

### 05 — Multi-stage chain
Recon (curl) + tamper (source edit) + exfil (POST) in one build.
Detection: all three sensors fire.
Expected: BLOCK. The central demo for the viva.

### 06 — Slow exfiltration
Long-lived connection to `10.255.255.1:8080` for 8 seconds.
Detection: network poller catches the sustained connection.
Expected: BLOCK. Proves the poller does not require short bursts.

## Expected verdicts

All six scenarios produce `verdict: BLOCK`. None produce false negatives.

## Modes

Fast testing uses three environment variables on the CI server:

    PIPEJACK_ENFORCE=1 PIPEJACK_FAST=1 PIPEJACK_DEV=1

- PIPEJACK_ENFORCE=1  enable policy enforcement
- PIPEJACK_FAST=1     skip Docker build, push, deploy
- PIPEJACK_DEV=1      skip Maven, run attack.sh directly

For the final viva demo, drop FAST and DEV to run the full pipeline:
`PIPEJACK_ENFORCE=1` only.

## Building a tarball

Each scenario's `build.sh` assembles:

    pom.xml       (exec plugin bound to attack.sh)
    attack.sh     (the payload)
    src/...       (Banking API source from ~/banking-api)

Output: `/tmp/attack-NN-<name>.tar.gz`
