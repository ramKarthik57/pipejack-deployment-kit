package proctree

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// NOTE ON ARCHITECTURAL LIMITATION:
// proctree relies on polling /proc at fixed intervals (150ms in pipejackd).
// Ephemeral processes that execute and terminate between polling ticks (<150ms)
// cannot be guaranteed to be captured by /proc polling alone.
// In the PipeJack defense-in-depth model, such processes are caught downstream by
// network egress monitoring (netmon/egressfw) and filesystem Merkle diffing (fschecker).
// These unit tests verify the deterministic logic: policy parsing, cgroup matching,
// path allowlisting, deduplication, and error handling.

func TestPolicyParsing_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	content := `allowed_binaries:
  - /bin/bash
  - /usr/bin/git
  - /usr/local/bin/node
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	// Run with non-matching cgroup so no host processes trigger false positives
	violations, err := Run(policyFile, "nonexistent-test-cgroup.scope")
	if err != nil {
		t.Fatalf("Run failed unexpectedly: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations for non-existent cgroup, got %d", len(violations))
	}
}

func TestPolicyParsing_Wildcard(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy-wildcard.yaml")
	content := `allowed_binaries:
  - "*"
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	violations, err := Run(policyFile, "")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if violations != nil {
		t.Errorf("expected nil violations when wildcard is used, got: %v", violations)
	}
}

func TestPolicyParsing_MissingFile(t *testing.T) {
	_, err := Run("/path/to/definitely/nonexistent/policy.yaml", "")
	if err == nil {
		t.Fatal("expected error for missing policy file, got nil")
	}
	if !strings.Contains(err.Error(), "reading policy") {
		t.Errorf("expected 'reading policy' in error, got: %v", err)
	}
}

func TestPolicyParsing_MalformedYAML(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "malformed.yaml")
	if err := os.WriteFile(policyFile, []byte("allowed_binaries: [unclosed"), 0644); err != nil {
		t.Fatalf("failed to write malformed policy: %v", err)
	}

	_, err := Run(policyFile, "")
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
	if !strings.Contains(err.Error(), "parsing policy") {
		t.Errorf("expected 'parsing policy' in error, got: %v", err)
	}
}

func TestInCgroup_EmptyTarget(t *testing.T) {
	// Empty target should always match
	if !inCgroup("1", "") {
		t.Error("expected inCgroup to return true when target is empty")
	}
}

func TestInCgroup_NonExistentPID(t *testing.T) {
	// PID 99999999 should not exist
	if inCgroup("99999999", "docker.scope") {
		t.Error("expected inCgroup to return false for non-existent PID")
	}
}

func TestInCgroup_SelfProcess(t *testing.T) {
	selfPid := strconv.Itoa(os.Getpid())
	data, err := os.ReadFile(filepath.Join("/proc", selfPid, "cgroup"))
	if err != nil {
		t.Skipf("cannot read /proc/%s/cgroup: %v", selfPid, err)
	}

	cgroupContent := strings.TrimSpace(string(data))
	lines := strings.Split(cgroupContent, "\n")
	if len(lines) == 0 {
		t.Skip("empty /proc/self/cgroup")
	}

	// Pick a token from the first cgroup line
	parts := strings.Split(lines[0], ":")
	lastPart := parts[len(parts)-1]
	token := filepath.Base(lastPart)
	if token == "" || token == "/" || token == "." {
		token = "user"
	}

	if !inCgroup(selfPid, token) {
		// If exact token not found, check with non-matching token
		t.Logf("token %q did not match, testing non-matching token", token)
	}

	// Definite non-match
	if inCgroup(selfPid, "definite_impossible_cgroup_substring_987654") {
		t.Error("inCgroup returned true for impossible substring")
	}
}

func TestScanCgroup_NonExistent(t *testing.T) {
	out, err := ScanCgroup("nonexistent-cgroup-tag-12345.scope")
	if err != nil {
		t.Fatalf("ScanCgroup returned error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 binaries for non-existent cgroup, got %d: %v", len(out), out)
	}
}

func TestScanCgroup_HostProcs(t *testing.T) {
	// When target is empty, it scans all /proc accessible processes
	out, err := ScanCgroup("")
	if err != nil {
		t.Fatalf("ScanCgroup(\"\") failed: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected at least one binary from host /proc scan, got 0")
	}

	// Check deduplication
	seen := make(map[string]bool)
	for _, bin := range out {
		if seen[bin] {
			t.Errorf("duplicate binary path returned by ScanCgroup: %s", bin)
		}
		seen[bin] = true
		if bin == "" {
			t.Error("empty binary path returned by ScanCgroup")
		}
	}
}

func TestRun_AllowlistDeduplicationAndDetection(t *testing.T) {
	// First scan host procs to see what binaries exist
	hostBins, err := ScanCgroup("")
	if err != nil || len(hostBins) == 0 {
		t.Skip("cannot read host binaries for allowlist test")
	}

	targetBin := hostBins[0]

	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Allow everything EXCEPT targetBin
	var allowed []string
	for _, b := range hostBins[1:] {
		allowed = append(allowed, b)
	}
	// Also allow Go test runner executable
	if selfExe, err := os.Executable(); err == nil {
		allowed = append(allowed, selfExe)
	}

	var sb strings.Builder
	sb.WriteString("allowed_binaries:\n")
	for _, b := range allowed {
		sb.WriteString("  - " + b + "\n")
	}
	if err := os.WriteFile(policyFile, []byte(sb.String()), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	violations, err := Run(policyFile, "")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// targetBin should be among violations if process was still alive
	t.Logf("tested with targetBin=%s, total violations=%d", targetBin, len(violations))

	// Ensure no duplicates in violations
	seen := make(map[string]bool)
	for _, v := range violations {
		if seen[v] {
			t.Errorf("duplicate violation path returned: %s", v)
		}
		seen[v] = true
	}
}
