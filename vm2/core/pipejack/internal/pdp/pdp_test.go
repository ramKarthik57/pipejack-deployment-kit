package pdp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluateClean(t *testing.T) {
	dir := t.TempDir()
	policy := `
blocked_binaries:
  - /usr/bin/curl
allowed_filesystem_changes:
  - pattern: "target/**"
    action: ignore
`
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	res, err := Evaluate(path, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != ALLOW {
		t.Errorf("expected ALLOW, got %s", res.Decision)
	}
}

func TestEvaluateProcessViolation(t *testing.T) {
	dir := t.TempDir()
	policy := `
blocked_binaries:
  - /usr/bin/curl
`
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	res, err := Evaluate(path, []string{"/usr/bin/curl"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != BLOCK {
		t.Errorf("expected BLOCK, got %s", res.Decision)
	}
}

func TestEvaluateFilesystemViolation(t *testing.T) {
	dir := t.TempDir()
	policy := `
allowed_filesystem_changes:
  - pattern: "target/**"
    action: ignore
`
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	res, err := Evaluate(path, nil, []string{"src/main/java/AccountController.java"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != BLOCK {
		t.Errorf("expected BLOCK, got %s", res.Decision)
	}
}

func TestEvaluateMissingPolicy(t *testing.T) {
	_, err := Evaluate("/nonexistent/policy.yaml", nil, nil, nil)
	if err == nil {
		t.Error("expected error for missing policy")
	}
}

func TestEvaluateUnauthorizedProcess(t *testing.T) {
	dir := t.TempDir()
	policy := `
allowed_binaries:
  - /usr/bin/java
blocked_binaries:
  - /usr/bin/curl
`
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	res, err := Evaluate(path, []string{"/usr/bin/nc"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != BLOCK {
		t.Errorf("expected BLOCK, got %s", res.Decision)
	}
}

func TestMatchPatternGlob(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"target/**", "target/a", true},
		{"target/**", "target/a/b/c", true},
		{"target/**", "src/target/a", false},
		{"target/**", "target", true},
		{"*.pyc", "foo.pyc", true},
		{"*.pyc", "dir/foo.pyc", true},
		{"*.pyc", "foo.txt", false},
		{"*.egg-info/**", "python_malicious.egg-info/PKG-INFO", true},
		{"*.egg-info/**", "python_malicious.egg-info/SOURCES.txt", true},
		{"*.egg-info/**", "src/foo.txt", false},
		{"*.class", "Foo.class", true},
		{"*.class", "src/Foo.class", true},
		{"exact.txt", "exact.txt", true},
		{"exact.txt", "other.txt", false},
	}
	for _, c := range cases {
		got := matchPattern(c.pattern, c.path)
		if got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}
