# PipeJack

Build-time compromise detection and enforcement for CI/CD pipelines.

PipeJack runs as a security sidecar alongside the build container. It shares the build's PID and network namespaces, monitors what the build actually does, and reports violations against a YAML policy.

## Sensors

| Sensor | What it watches | Detection method |
|---|---|---|
| Process Tree Differ | Executed binaries | `/proc` scan filtered by build cgroup |
| Filesystem Baseline | File changes | SHA-256 Merkle root of workspace before and after |
| Network Egress | Outbound connections | `/proc/net/{tcp,udp}` and socket inode to PID mapping |

## Policy Decision Engine

Every build is evaluated against a YAML policy that defines allowed binaries, blocked binaries, allowed filesystem changes, allowed egress endpoints, and response actions. The verdict is one of `ALLOW`, `BLOCK`, or `QUARANTINE`.

## Enforcement

- **Detection-only mode** (`PIPEJACK_ENFORCE` unset): sensors report, build always succeeds.
- **Enforcement mode** (`PIPEJACK_ENFORCE=1`): BLOCK fails the build with HTTP 403, no artifact is pushed, and the image may be quarantined in the local registry.
- **Network enforcement** (`enforce_network: true` in policy): an isolated iptables chain named `PIPEJACK_EGRESS` drops unauthorized egress inside the sidecar's shared network namespace.

## Attestation

Every build produces a signed JSON attestation containing:

- `pre_merkle` and `post_merkle` — filesystem integrity roots
- `process_violations` — unauthorized binaries observed
- `fs_changes` — modified, added, or deleted files
- `network_violations` — unauthorized egress attempts
- `verdict` — ALLOW or BLOCK
- `prev_hash`, `self_hash`, `signature` — Ed25519-signed hash chain

The chain is tamper-evident. Modifying any past attestation breaks verification at the modified entry and every subsequent one.

## Architecture

See [PIPEJACK_ARCHITECTURE.md](../../docs/architecture/PIPEJACK_ARCHITECTURE.md).

## Implementation status

See [VALIDATION_REPORT.md](../../docs/testing/VALIDATION_REPORT.md).

## Build

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o pipejackd-static ./cmd/pipejackd/

The `CGO_ENABLED=0` flag is required. The sidecar ships on Alpine with musl, and a glibc-linked binary will not run there.

## Test

    go test ./...
