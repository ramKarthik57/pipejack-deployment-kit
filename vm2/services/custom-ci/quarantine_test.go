package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantine_BlockedWithQuarantineSuccess(t *testing.T) {
	origExecHost := execHost
	defer func() { execHost = origExecHost }()

	execHost = func(name string, args ...string) (string, error) {
		return "mock success", nil
	}

	tmpDir := t.TempDir()
	workspace := filepath.Join(tmpDir, "workspace")
	os.MkdirAll(workspace, 0755)
	dockerfile := filepath.Join(tmpDir, "Dockerfile.mock")
	os.WriteFile(dockerfile, []byte("FROM alpine\n"), 0644)

	rec := httptest.NewRecorder()
	processArtifactManagement(
		rec,
		"test-build-1",
		"Test Project",
		false,
		false,
		workspace,
		dockerfile,
		"BLOCK",
		true, // enforcementEnabled
		true, // quarantineEnabled
		"build-container-1",
		"VIOLATION DETECTED",
		"CLEAN",
		"mock log",
		nil,
	)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden, got %d", rec.Code)
	}

	var resp struct {
		Status  string `json:"status"`
		BuildID string `json:"build_id"`
		Verdict string `json:"verdict"`
		Tag     string `json:"tag"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nBody: %s", err, rec.Body.String())
	}

	if resp.Status != "quarantined" {
		t.Errorf("expected status 'quarantined', got %q", resp.Status)
	}
	if resp.Verdict != "BLOCK" {
		t.Errorf("expected verdict 'BLOCK', got %q", resp.Verdict)
	}
	if resp.Tag == "" {
		t.Errorf("expected quarantine tag in response, got empty")
	}
}

func TestQuarantine_BlockedWithQuarantineBuildFailure(t *testing.T) {
	origExecHost := execHost
	defer func() { execHost = origExecHost }()

	// Simulate Docker build failure (e.g. source file deleted by attack)
	execHost = func(name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "build" {
			return "compilation error: AccountService.java not found", errors.New("exit status 1")
		}
		return "ok", nil
	}

	tmpDir := t.TempDir()
	workspace := filepath.Join(tmpDir, "workspace")
	os.MkdirAll(workspace, 0755)
	dockerfile := filepath.Join(tmpDir, "Dockerfile.mock")
	os.WriteFile(dockerfile, []byte("FROM alpine\n"), 0644)

	rec := httptest.NewRecorder()
	processArtifactManagement(
		rec,
		"test-build-2",
		"Test Banking API",
		true,
		true,
		workspace,
		dockerfile,
		"BLOCK",
		true, // enforcementEnabled
		true, // quarantineEnabled
		"build-container-2",
		"VIOLATION DETECTED",
		"VIOLATION DETECTED",
		"mock log",
		nil,
	)

	// MANDATORY INVARIANT: Must remain HTTP 403 Forbidden and verdict BLOCK
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden on quarantine build failure, got %d", rec.Code)
	}

	var resp struct {
		Status     string `json:"status"`
		BuildID    string `json:"build_id"`
		Verdict    string `json:"verdict"`
		Quarantine string `json:"quarantine"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nBody: %s", err, rec.Body.String())
	}

	if resp.Verdict != "BLOCK" {
		t.Errorf("CRITICAL DEFECT: expected verdict 'BLOCK', got %q", resp.Verdict)
	}
	if resp.Status != "blocked" {
		t.Errorf("expected status 'blocked', got %q", resp.Status)
	}
	if resp.Quarantine != "failed" {
		t.Errorf("expected quarantine 'failed', got %q", resp.Quarantine)
	}
	if resp.Error == "" {
		t.Errorf("expected explicit error message in JSON, got empty")
	}
}

func TestQuarantine_BlockedWithMissingDockerfile(t *testing.T) {
	origExecHost := execHost
	defer func() { execHost = origExecHost }()

	execHost = func(name string, args ...string) (string, error) {
		return "ok", nil
	}

	tmpDir := t.TempDir()
	workspace := filepath.Join(tmpDir, "workspace")
	os.MkdirAll(workspace, 0755)
	missingDockerfile := filepath.Join(tmpDir, "nonexistent-Dockerfile")

	rec := httptest.NewRecorder()
	processArtifactManagement(
		rec,
		"test-build-3",
		"Test Project",
		false,
		false,
		workspace,
		missingDockerfile,
		"BLOCK",
		true, // enforcementEnabled
		true, // quarantineEnabled
		"build-container-3",
		"VIOLATION DETECTED",
		"CLEAN",
		"mock log",
		nil,
	)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden on missing Dockerfile, got %d", rec.Code)
	}

	var resp struct {
		Status     string `json:"status"`
		Verdict    string `json:"verdict"`
		Quarantine string `json:"quarantine"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nBody: %s", err, rec.Body.String())
	}

	if resp.Verdict != "BLOCK" {
		t.Errorf("CRITICAL DEFECT: expected verdict 'BLOCK', got %q", resp.Verdict)
	}
	if resp.Status != "blocked" {
		t.Errorf("expected status 'blocked', got %q", resp.Status)
	}
	if resp.Quarantine != "failed" {
		t.Errorf("expected quarantine 'failed', got %q", resp.Quarantine)
	}
}

func TestBuild_CleanSuccessRemainsAllow(t *testing.T) {
	origExecHost := execHost
	defer func() { execHost = origExecHost }()

	execHost = func(name string, args ...string) (string, error) {
		return "mock success", nil
	}

	tmpDir := t.TempDir()
	workspace := filepath.Join(tmpDir, "workspace")
	os.MkdirAll(workspace, 0755)
	dockerfile := filepath.Join(tmpDir, "Dockerfile.mock")
	os.WriteFile(dockerfile, []byte("FROM alpine\n"), 0644)

	rec := httptest.NewRecorder()
	processArtifactManagement(
		rec,
		"test-build-4",
		"Clean Project",
		false,
		false,
		workspace,
		dockerfile,
		"ALLOW",
		true, // enforcementEnabled
		true, // quarantineEnabled
		"build-container-4",
		"CLEAN",
		"CLEAN",
		"clean build log",
		nil,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK for clean build, got %d", rec.Code)
	}

	var resp BuildResult
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nBody: %s", err, rec.Body.String())
	}

	if resp.Status != "pass" {
		t.Errorf("expected status 'pass', got %q", resp.Status)
	}
	if resp.BuildID != "test-build-4" {
		t.Errorf("expected build_id 'test-build-4', got %q", resp.BuildID)
	}
}

func TestBuild_CleanBuildFailureReturnsError(t *testing.T) {
	origExecHost := execHost
	defer func() { execHost = origExecHost }()

	execHost = func(name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "build" {
			return "build error", errors.New("build failed")
		}
		return "ok", nil
	}

	tmpDir := t.TempDir()
	workspace := filepath.Join(tmpDir, "workspace")
	os.MkdirAll(workspace, 0755)
	dockerfile := filepath.Join(tmpDir, "Dockerfile.mock")
	os.WriteFile(dockerfile, []byte("FROM alpine\n"), 0644)

	rec := httptest.NewRecorder()
	processArtifactManagement(
		rec,
		"test-build-5",
		"Clean Project",
		false,
		false,
		workspace,
		dockerfile,
		"ALLOW",
		true, // enforcementEnabled
		true, // quarantineEnabled
		"build-container-5",
		"CLEAN",
		"CLEAN",
		"clean build log",
		nil,
	)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 InternalServerError for failed clean build, got %d", rec.Code)
	}

	var resp struct {
		Status  string `json:"status"`
		Verdict string `json:"verdict"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nBody: %s", err, rec.Body.String())
	}

	if resp.Status != "error" {
		t.Errorf("expected status 'error', got %q", resp.Status)
	}
	if resp.Verdict != "ALLOW" {
		t.Errorf("expected verdict 'ALLOW', got %q", resp.Verdict)
	}
}
