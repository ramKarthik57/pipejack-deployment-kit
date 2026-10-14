// Package anomaly performs statistical deviation detection on build metrics.
// It compares the current build's behavior to a rolling baseline of previous
// builds for the same project and flags metrics that deviate significantly.
package anomaly

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BaselineDir is where per-project baselines are stored.
// Declared as a variable (not const) so tests can override it.
var BaselineDir = "/home/ubuntu/pipejack-baseline"

const (
	DefaultMaxBuilds   = 20
	DefaultThreshold   = 3.0
	DefaultMinBaseline = 5
	knownBinaryRatio   = 0.8 // binary appears in >=80% of baseline builds
)

// BuildMetrics is one build's observable behavior fingerprint.
type BuildMetrics struct {
	Timestamp       string   `json:"timestamp"`
	ProcessCount    int      `json:"process_count"`
	FileChangeCount int      `json:"file_change_count"`
	NetworkCount    int      `json:"network_count"`
	DurationMs      int64    `json:"duration_ms"`
	Binaries        []string `json:"binaries"`
}

// BaselineStore holds the rolling window of recent builds for a project.
type BaselineStore struct {
	Project string         `json:"project"`
	Builds  []BuildMetrics `json:"builds"`
}

// Config controls how strict the anomaly check is.
type Config struct {
	Enabled     bool
	Threshold   float64 // z-score threshold for numeric metrics
	MinBaseline int     // builds required before detection activates
	MaxBuilds   int     // rolling window size
	Block       bool    // if true, anomalies force BLOCK (advisory if false)
}

// Finding is one detected anomaly.
type Finding struct {
	Metric   string  `json:"metric"`
	Value    float64 `json:"value"`
	Mean     float64 `json:"mean"`
	Stddev   float64 `json:"stddev"`
	Z        float64 `json:"z"`
	Severity string  `json:"severity"` // "high" or "medium"
	Message  string  `json:"message"`
}

// Result is the outcome of evaluating one build.
type Result struct {
	Findings     []Finding `json:"findings"`
	WarmingUp    bool      `json:"warming_up"`
	BaselineSize int       `json:"baseline_size"`
	MinBaseline  int       `json:"min_baseline"`
}

// Evaluate compares current against the project's baseline, updates the
// baseline with the current build, and returns findings.
func Evaluate(project string, current BuildMetrics, cfg Config) (Result, error) {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultThreshold
	}
	if cfg.MinBaseline <= 0 {
		cfg.MinBaseline = DefaultMinBaseline
	}
	if cfg.MaxBuilds <= 0 {
		cfg.MaxBuilds = DefaultMaxBuilds
	}

	store, err := load(project)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		BaselineSize: len(store.Builds),
		MinBaseline:  cfg.MinBaseline,
	}

	if len(store.Builds) >= cfg.MinBaseline {
		result.Findings = computeFindings(store.Builds, current, cfg.Threshold)
	} else {
		result.WarmingUp = true
	}

	// Update baseline with current build, keeping only the last N.
	store.Builds = append(store.Builds, current)
	if len(store.Builds) > cfg.MaxBuilds {
		store.Builds = store.Builds[len(store.Builds)-cfg.MaxBuilds:]
	}

	if err := save(project, store); err != nil {
		return result, err
	}
	return result, nil
}

// computeFindings compares current against the rolling window.
func computeFindings(builds []BuildMetrics, current BuildMetrics, threshold float64) []Finding {
	var findings []Finding

	type spec struct {
		name string
		get  func(BuildMetrics) float64
		cur  float64
	}
	specs := []spec{
		{"process_count", func(b BuildMetrics) float64 { return float64(b.ProcessCount) }, float64(current.ProcessCount)},
		{"file_change_count", func(b BuildMetrics) float64 { return float64(b.FileChangeCount) }, float64(current.FileChangeCount)},
		{"network_count", func(b BuildMetrics) float64 { return float64(b.NetworkCount) }, float64(current.NetworkCount)},
		{"duration_ms", func(b BuildMetrics) float64 { return float64(b.DurationMs) }, float64(current.DurationMs)},
	}

	for _, s := range specs {
		vals := make([]float64, len(builds))
		for i, b := range builds {
			vals[i] = s.get(b)
		}
		mean, stddev := meanStddev(vals)

		var z float64
		var severity, message string

		if stddev < 0.001 {
			// Baseline is flat. Any nonzero deviation is a strong anomaly.
			if math.Abs(s.cur-mean) > 0.5 {
				severity = "high"
				z = 99.9
				message = fmt.Sprintf("%s=%.0f, baseline flat at %.0f", s.name, s.cur, mean)
			}
		} else {
			z = (s.cur - mean) / stddev
			if math.Abs(z) > threshold {
				severity = "medium"
				if math.Abs(z) > 2*threshold {
					severity = "high"
				}
				message = fmt.Sprintf("%s=%.0f (mean %.1f, sigma %.1f, z=%.2f)",
					s.name, s.cur, mean, stddev, z)
			}
		}

		if severity != "" {
			findings = append(findings, Finding{
				Metric: s.name, Value: s.cur, Mean: mean, Stddev: stddev,
				Z: z, Severity: severity, Message: message,
			})
		}
	}

	// Binary set: flag binaries not present in the baseline's known set.
	known := knownBinaries(builds, knownBinaryRatio)
	knownSet := make(map[string]bool, len(known))
	for _, b := range known {
		knownSet[b] = true
	}
	for _, bin := range current.Binaries {
		if !knownSet[bin] {
			findings = append(findings, Finding{
				Metric:   "binary",
				Severity: "high",
				Message:  fmt.Sprintf("new binary not in baseline: %s", bin),
			})
		}
	}

	return findings
}

// meanStddev returns the sample mean and sample standard deviation.
func meanStddev(vals []float64) (float64, float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	if len(vals) < 2 {
		return mean, 0
	}
	var sq float64
	for _, v := range vals {
		sq += (v - mean) * (v - mean)
	}
	return mean, math.Sqrt(sq / float64(len(vals)-1))
}

// knownBinaries returns binaries that appear in at least `ratio` fraction of builds.
func knownBinaries(builds []BuildMetrics, ratio float64) []string {
	counts := make(map[string]int)
	for _, b := range builds {
		seen := make(map[string]bool)
		for _, bin := range b.Binaries {
			if !seen[bin] {
				counts[bin]++
				seen[bin] = true
			}
		}
	}
	threshold := int(math.Ceil(ratio * float64(len(builds))))
	var known []string
	for bin, c := range counts {
		if c >= threshold {
			known = append(known, bin)
		}
	}
	sort.Strings(known)
	return known
}

// load reads the baseline store for a project. Returns an empty store if
// the file is missing or corrupt rather than failing.
func load(project string) (*BaselineStore, error) {
	if err := os.MkdirAll(BaselineDir, 0755); err != nil {
		return nil, err
	}
	path := filepath.Join(BaselineDir, sanitize(project)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &BaselineStore{Project: project}, nil
		}
		return nil, err
	}
	var s BaselineStore
	if err := json.Unmarshal(data, &s); err != nil {
		return &BaselineStore{Project: project}, nil
	}
	if s.Project == "" {
		s.Project = project
	}
	return &s, nil
}

func save(project string, s *BaselineStore) error {
	if err := os.MkdirAll(BaselineDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(BaselineDir, sanitize(project)+".json")
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}
