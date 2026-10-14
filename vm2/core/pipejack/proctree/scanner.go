package proctree

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	AllowedBinaries []string `yaml:"allowed_binaries"`
}

// Run scans /proc for processes in the given cgroup and returns a unique list
// of executable paths that are NOT in the policy's allowed_binaries.
// If allowed_binaries contains "*", no process checks are performed and nil is returned.
func Run(policyPath, cgroupPath string) ([]string, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	allowed := make(map[string]bool)
	for _, bin := range policy.AllowedBinaries {
		allowed[bin] = true
	}
	if allowed["*"] {
		return nil, nil
	}

	// Extract the cgroup basename for matching, e.g. "docker-abc123.scope"
	target := filepath.Base(cgroupPath)

	seen := make(map[string]bool)
	var violations []string

	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}

		// Filter by cgroup: only monitor processes in the build's cgroup.
		if !inCgroup(p.Name(), target) {
			continue
		}

		exe, err := os.Readlink(filepath.Join("/proc", p.Name(), "exe"))
		if err != nil {
			continue
		}
		if allowed[exe] {
			continue
		}
		if seen[exe] {
			continue
		}
		seen[exe] = true
		violations = append(violations, exe)
	}
	return violations, nil
}

// inCgroup returns true if /proc/<pid>/cgroup contains the target substring.
func inCgroup(pid, target string) bool {
	if target == "" {
		return true
	}
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), target)
}

// ScanCgroup returns every distinct executable path visible in the given
// cgroup, regardless of policy. Used by the anomaly detector to build a
// baseline of "normal" build binaries.
// Empty cgroupPath means no cgroup filter.
func ScanCgroup(cgroupPath string) ([]string, error) {
	target := filepath.Base(cgroupPath)

	seen := make(map[string]bool)
	var out []string

	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		if target != "" && !inCgroup(p.Name(), target) {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", p.Name(), "exe"))
		if err != nil {
			continue
		}
		if !seen[exe] {
			seen[exe] = true
			out = append(out, exe)
		}
	}
	return out, nil
}
