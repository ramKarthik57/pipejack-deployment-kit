package pdp

import (
	"fmt"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

type Decision string

const (
	ALLOW      Decision = "ALLOW"
	BLOCK      Decision = "BLOCK"
	QUARANTINE Decision = "QUARANTINE"
)

type Policy struct {
	AllowedBinaries          []string `yaml:"allowed_binaries"`
	BlockedBinaries          []string `yaml:"blocked_binaries"`
	AllowedFilesystemChanges []struct {
		Pattern string `yaml:"pattern"`
		Action  string `yaml:"action"`
	} `yaml:"allowed_filesystem_changes"`
	SeverityThresholds map[string]int `yaml:"severity_thresholds"`
	ActionsOnViolation struct {
		Block      bool `yaml:"block"`
		Quarantine bool `yaml:"quarantine"`
		Alert      bool `yaml:"alert"`
	} `yaml:"actions_on_violation"`
}

type Result struct {
	Decision Decision
	Reasons  []string
}

func Evaluate(policyPath string, processViolations, fsViolations, networkViolations []string) (Result, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return Result{}, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Result{}, fmt.Errorf("parse policy: %w", err)
	}

	res := Result{Decision: ALLOW}

	blocked := make(map[string]bool)
	for _, b := range p.BlockedBinaries {
		blocked[b] = true
	}

	for _, v := range processViolations {
		res.Decision = BLOCK
		if blocked[v] {
			res.Reasons = append(res.Reasons, fmt.Sprintf("blocked binary executed: %s", v))
		} else {
			res.Reasons = append(res.Reasons, fmt.Sprintf("unauthorized binary executed: %s", v))
		}
	}

	for _, v := range fsViolations {
		allowed := false
		for _, a := range p.AllowedFilesystemChanges {
			if a.Action == "ignore" && matchPattern(a.Pattern, v) {
				allowed = true
				break
			}
		}
		if !allowed {
			res.Decision = BLOCK
			res.Reasons = append(res.Reasons, fmt.Sprintf("unexpected filesystem change: %s", v))
		}
	}

	for _, v := range networkViolations {
		res.Decision = BLOCK
		res.Reasons = append(res.Reasons, fmt.Sprintf("network violation: %s", v))
	}

	if len(res.Reasons) == 0 {
		res.Reasons = append(res.Reasons, "no violations")
	}
	return res, nil
}

// matchPattern supports three cases:
//   - "exact/path.txt"          literal match
//   - "dir/**"                  matches anything under dir/ (recursively)
//   - "*.ext" or "prefix*"      glob match on the basename
//
// Wildcards only work in the basename segment or in the /** prefix.
func matchPattern(pattern, filePath string) bool {
	if pattern == filePath {
		return true
	}

	// Case 1: trailing /** — match dir or anything under dir/
	if len(pattern) > 3 && pattern[len(pattern)-3:] == "/**" {
		prefix := pattern[:len(pattern)-3]

		// Wildcards in the prefix segment (e.g. "*.egg-info/**")
		if strings.Contains(prefix, "*") || strings.Contains(prefix, "?") {
			// Extract the first segment of filePath and match it
			firstSeg := filePath
			if i := strings.Index(filePath, "/"); i != -1 {
				firstSeg = filePath[:i]
			}
			if ok, _ := path.Match(prefix, firstSeg); ok {
				return true
			}
			// Also try matching against the whole prefix literally
			if ok, _ := path.Match(prefix, filePath); ok {
				return true
			}
			return false
		}

		// Literal prefix: match the prefix itself or anything under it
		return filePath == prefix || strings.HasPrefix(filePath, prefix+"/")
	}

	// Case 2: glob against the full filePath (no /**)
	if ok, _ := path.Match(pattern, filePath); ok {
		return true
	}

	// Case 3: pattern has no slash — try matching basename
	if !strings.Contains(pattern, "/") {
		if ok, _ := path.Match(pattern, path.Base(filePath)); ok {
			return true
		}
	}

	return false
}
