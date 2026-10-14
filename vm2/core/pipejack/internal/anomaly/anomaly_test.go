package anomaly

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

// helper: run each test in its own temp baseline dir
func withTempBaseline(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old := BaselineDir
	BaselineDir = dir
	t.Cleanup(func() { BaselineDir = old })
}

func TestMeanStddevBasic(t *testing.T) {
	mean, sd := meanStddev([]float64{1, 2, 3, 4, 5})
	if math.Abs(mean-3.0) > 0.001 {
		t.Errorf("mean=%v want 3", mean)
	}
	if math.Abs(sd-1.5811) > 0.001 {
		t.Errorf("stddev=%v want 1.5811", sd)
	}
}

func TestMeanStddevSingleValue(t *testing.T) {
	mean, sd := meanStddev([]float64{42})
	if mean != 42 || sd != 0 {
		t.Errorf("got (%v,%v) want (42,0)", mean, sd)
	}
}

func TestKnownBinariesThreshold(t *testing.T) {
	builds := []BuildMetrics{
		{Binaries: []string{"/bin/sh", "/usr/bin/java"}},
		{Binaries: []string{"/bin/sh", "/usr/bin/java"}},
		{Binaries: []string{"/bin/sh", "/usr/bin/java"}},
		{Binaries: []string{"/bin/sh", "/usr/bin/java", "/usr/bin/curl"}},
		{Binaries: []string{"/bin/sh", "/usr/bin/java"}},
	}
	// 80% of 5 = 4; curl appears once, should not be known
	known := knownBinaries(builds, 0.8)
	want := map[string]bool{"/bin/sh": true, "/usr/bin/java": true}
	if len(known) != len(want) {
		t.Fatalf("got %v, want %v", known, want)
	}
	for _, k := range known {
		if !want[k] {
			t.Errorf("unexpected known binary %q", k)
		}
	}
}

func TestComputeFindingsFlatBaseline(t *testing.T) {
	// Baseline of 5 clean builds: all counts are 0
	builds := []BuildMetrics{}
	for i := 0; i < 5; i++ {
		builds = append(builds, BuildMetrics{})
	}
	// Current build has 3 process violations → z should be "high" (flat baseline)
	current := BuildMetrics{ProcessCount: 3}
	findings := computeFindings(builds, current, 3.0)

	found := false
	for _, f := range findings {
		if f.Metric == "process_count" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected high-severity process_count finding, got %+v", findings)
	}
}

func TestComputeFindingsZScore(t *testing.T) {
	// Baseline durations: 1000, 1100, 900, 1050, 950 → mean 1000, sd ~79
	builds := []BuildMetrics{
		{DurationMs: 1000}, {DurationMs: 1100}, {DurationMs: 900},
		{DurationMs: 1050}, {DurationMs: 950},
	}
	// Current duration 3000 → z = 2000/79 ≈ 25 → far above 3
	current := BuildMetrics{DurationMs: 3000}
	findings := computeFindings(builds, current, 3.0)

	found := false
	for _, f := range findings {
		if f.Metric == "duration_ms" && math.Abs(f.Z) > 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duration_ms anomaly, got %+v", findings)
	}
}

func TestNewBinaryFinding(t *testing.T) {
	builds := []BuildMetrics{}
	for i := 0; i < 5; i++ {
		builds = append(builds, BuildMetrics{Binaries: []string{"/usr/bin/java"}})
	}
	current := BuildMetrics{Binaries: []string{"/usr/bin/unzip"}}
	findings := computeFindings(builds, current, 3.0)

	found := false
	for _, f := range findings {
		if f.Metric == "binary" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected binary anomaly, got %+v", findings)
	}
}

func TestEvaluateWarmingUp(t *testing.T) {
	withTempBaseline(t)
	cfg := Config{Enabled: true, Threshold: 3.0, MinBaseline: 5, MaxBuilds: 20}

	// First 5 builds should all be "warming up" (need 5 PRIOR builds
	// before detection activates)
	for i := 0; i < 5; i++ {
		res, err := Evaluate("test-proj", BuildMetrics{ProcessCount: i}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !res.WarmingUp {
			t.Errorf("build %d: expected WarmingUp=true, got %+v", i+1, res)
		}
		if len(res.Findings) != 0 {
			t.Errorf("build %d: expected 0 findings during warm-up, got %d", i+1, len(res.Findings))
		}
	}

	// 6th build activates detection (5 prior builds now exist)
	res, err := Evaluate("test-proj", BuildMetrics{ProcessCount: 4}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.WarmingUp {
		t.Errorf("build 6: expected WarmingUp=false, got %+v", res)
	}
}

func TestEvaluateFullCycle(t *testing.T) {
	withTempBaseline(t)
	cfg := Config{Enabled: true, Threshold: 3.0, MinBaseline: 5, MaxBuilds: 20}

	// Seed 5 clean builds
	for i := 0; i < 5; i++ {
		_, err := Evaluate("banking", BuildMetrics{DurationMs: 1000, ProcessCount: 0}, cfg)
		if err != nil {
			t.Fatal(err)
		}
	}

	// 6th build has 3 process violations on a flat baseline
	res, err := Evaluate("banking", BuildMetrics{DurationMs: 1000, ProcessCount: 3}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.WarmingUp {
		t.Errorf("should not be warming up at build 6")
	}
	if len(res.Findings) == 0 {
		t.Errorf("expected anomaly findings, got none")
	}
}

func TestLoadCorruptFile(t *testing.T) {
	withTempBaseline(t)
	path := filepath.Join(BaselineDir, "corrupt.json")
	os.WriteFile(path, []byte("{not-valid-json"), 0644)

	// Should not error — should return empty store
	store, err := load("corrupt")
	if err != nil {
		t.Fatalf("expected no error for corrupt file, got %v", err)
	}
	if len(store.Builds) != 0 {
		t.Errorf("expected empty store, got %d builds", len(store.Builds))
	}
}
