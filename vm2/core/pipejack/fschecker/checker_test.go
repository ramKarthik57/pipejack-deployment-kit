package fschecker

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/ramKarthik57/pipejack-test/pipejack/internal/pdp"
)

func TestBuildMerkleTree_BaselineGeneration(t *testing.T) {
	dir := t.TempDir()

	// Create test file structure
	if err := os.MkdirAll(filepath.Join(dir, "src", "main"), 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	f1 := filepath.Join(dir, "src", "main", "App.java")
	if err := os.WriteFile(f1, []byte("public class App {}"), 0644); err != nil {
		t.Fatalf("write f1: %v", err)
	}
	f2 := filepath.Join(dir, "pom.xml")
	if err := os.WriteFile(f2, []byte("<project></project>"), 0644); err != nil {
		t.Fatalf("write f2: %v", err)
	}

	rootNode, fileMap, err := BuildMerkleTree(dir, nil)
	if err != nil {
		t.Fatalf("BuildMerkleTree failed: %v", err)
	}
	if rootNode == nil {
		t.Fatal("expected non-nil rootNode")
	}
	if len(rootNode.Hash) != 64 {
		t.Errorf("expected 64-char SHA256 hex hash, got %d chars: %s", len(rootNode.Hash), rootNode.Hash)
	}
	if len(fileMap) != 2 {
		t.Fatalf("expected 2 files in map, got %d", len(fileMap))
	}

	rel1 := filepath.Join("src", "main", "App.java")
	h1 := sha256.Sum256([]byte("public class App {}"))
	expectedH1 := hex.EncodeToString(h1[:])
	if fileMap[rel1] != expectedH1 {
		t.Errorf("expected hash %s for %s, got %s", expectedH1, rel1, fileMap[rel1])
	}
}

func TestBuildMerkleTree_DeterministicOutput(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Create identical contents in different order
	os.WriteFile(filepath.Join(dir1, "b.txt"), []byte("beta"), 0644)
	os.WriteFile(filepath.Join(dir1, "a.txt"), []byte("alpha"), 0644)

	os.WriteFile(filepath.Join(dir2, "a.txt"), []byte("alpha"), 0644)
	os.WriteFile(filepath.Join(dir2, "b.txt"), []byte("beta"), 0644)

	root1, map1, err1 := BuildMerkleTree(dir1, nil)
	if err1 != nil {
		t.Fatalf("dir1 build failed: %v", err1)
	}
	root2, map2, err2 := BuildMerkleTree(dir2, nil)
	if err2 != nil {
		t.Fatalf("dir2 build failed: %v", err2)
	}

	if root1.Hash != root2.Hash {
		t.Errorf("expected identical root hashes, got %s != %s", root1.Hash, root2.Hash)
	}
	for k, v := range map1 {
		if map2[k] != v {
			t.Errorf("hash mismatch for %s: %s != %s", k, v, map2[k])
		}
	}
}

func TestBuildMerkleTree_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	rootNode, fileMap, err := BuildMerkleTree(dir, nil)
	if err != nil {
		t.Fatalf("empty directory failed: %v", err)
	}
	if len(fileMap) != 0 {
		t.Errorf("expected 0 files in map for empty dir, got %d", len(fileMap))
	}
	// SHA-256 of empty string
	emptyHash := sha256.Sum256([]byte(""))
	expectedHash := hex.EncodeToString(emptyHash[:])
	if rootNode.Hash != expectedHash {
		t.Errorf("expected empty string hash %s, got %s", expectedHash, rootNode.Hash)
	}
}

func TestBuildMerkleTree_NonExistentPath(t *testing.T) {
	_, _, err := BuildMerkleTree("/path/to/nonexistent/directory/test1234", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestBuildMerkleTree_IgnorePrefixes(t *testing.T) {
	dir := t.TempDir()

	// Normal source file
	os.WriteFile(filepath.Join(dir, "index.js"), []byte("console.log('hi')"), 0644)

	// Ignored build directories: target, .git, node_modules
	os.MkdirAll(filepath.Join(dir, "target", "classes"), 0755)
	os.WriteFile(filepath.Join(dir, "target", "classes", "App.class"), []byte("bytecode"), 0644)

	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644)

	os.MkdirAll(filepath.Join(dir, "node_modules", "express"), 0755)
	os.WriteFile(filepath.Join(dir, "node_modules", "express", "index.js"), []byte("module.exports={}"), 0644)

	ignorePrefixes := []string{"target", ".git", "node_modules"}

	_, fileMap, err := BuildMerkleTree(dir, ignorePrefixes)
	if err != nil {
		t.Fatalf("BuildMerkleTree with ignores failed: %v", err)
	}

	if len(fileMap) != 1 {
		t.Fatalf("expected exactly 1 file (index.js), got %d files: %v", len(fileMap), fileMap)
	}
	if _, ok := fileMap["index.js"]; !ok {
		t.Errorf("expected index.js in file map, got keys: %v", fileMap)
	}
}

func TestCompareSnapshots_UnchangedFilesystem(t *testing.T) {
	pre := map[string]string{
		"src/main.rs": "hash1",
		"Cargo.toml":  "hash2",
	}
	post := map[string]string{
		"src/main.rs": "hash1",
		"Cargo.toml":  "hash2",
	}

	changes := CompareSnapshots(pre, post)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for identical maps, got %d: %v", len(changes), changes)
	}
}

func TestCompareSnapshots_ModifiedFile(t *testing.T) {
	pre := map[string]string{
		"src/App.java": "original_hash",
	}
	post := map[string]string{
		"src/App.java": "tampered_hash",
	}

	changes := CompareSnapshots(pre, post)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Path != "src/App.java" || changes[0].Type != "modified" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestCompareSnapshots_AddedFile(t *testing.T) {
	pre := map[string]string{
		"README.md": "hash1",
	}
	post := map[string]string{
		"README.md":     "hash1",
		"Backdoor.java": "backdoor_hash",
	}

	changes := CompareSnapshots(pre, post)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Path != "Backdoor.java" || changes[0].Type != "added" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestCompareSnapshots_DeletedFile(t *testing.T) {
	pre := map[string]string{
		"AccountService.java":    "orig_hash",
		"AccountController.java": "ctrl_hash",
	}
	post := map[string]string{
		"AccountController.java": "ctrl_hash",
	}

	changes := CompareSnapshots(pre, post)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Path != "AccountService.java" || changes[0].Type != "deleted" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestCompareSnapshots_MultiChange(t *testing.T) {
	pre := map[string]string{
		"file_to_modify": "hash_pre",
		"file_to_delete": "hash_del",
		"file_unchanged": "hash_same",
	}
	post := map[string]string{
		"file_to_modify": "hash_post",
		"file_to_add":    "hash_new",
		"file_unchanged": "hash_same",
	}

	changes := CompareSnapshots(pre, post)
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %d: %v", len(changes), changes)
	}

	changeMap := make(map[string]string)
	for _, ch := range changes {
		changeMap[ch.Path] = ch.Type
	}

	if changeMap["file_to_modify"] != "modified" {
		t.Errorf("expected modified for file_to_modify, got %s", changeMap["file_to_modify"])
	}
	if changeMap["file_to_delete"] != "deleted" {
		t.Errorf("expected deleted for file_to_delete, got %s", changeMap["file_to_delete"])
	}
	if changeMap["file_to_add"] != "added" {
		t.Errorf("expected added for file_to_add, got %s", changeMap["file_to_add"])
	}
}

// TestPolicyPatternCompatibility verifies that the changes produced by fschecker
// integrate with PDP policy evaluation:
// - "target/**" ignores changes under target directory
// - "*.pyc" ignores compiled Python files
// - "*.egg-info/**" ignores Python egg metadata
func TestPolicyPatternCompatibility(t *testing.T) {
	dir := t.TempDir()
	policyYAML := `allowed_filesystem_changes:
  - pattern: "target/**"
    action: ignore
  - pattern: "*.pyc"
    action: ignore
  - pattern: "*.egg-info/**"
    action: ignore
`
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	// 1. Changes that match allowed patterns should result in ALLOW
	allowedChanges := []string{
		"target/classes/com/pipejack/App.class",
		"target/banking-1.0.0.jar",
		"service/auth.pyc",
		"pipejack.egg-info/PKG-INFO",
	}
	res, err := pdp.Evaluate(policyPath, nil, allowedChanges, nil)
	if err != nil {
		t.Fatalf("pdp.Evaluate failed: %v", err)
	}
	if res.Decision != pdp.ALLOW {
		t.Errorf("expected ALLOW for allowed filesystem changes, got %s (reasons: %v)", res.Decision, res.Reasons)
	}

	// 2. Unexpected changes outside allowlist must trigger BLOCK
	violatingChanges := []string{
		"src/main/java/Backdoor.java",
		"setup.py",
	}
	resBlock, err := pdp.Evaluate(policyPath, nil, violatingChanges, nil)
	if err != nil {
		t.Fatalf("pdp.Evaluate failed: %v", err)
	}
	if resBlock.Decision != pdp.BLOCK {
		t.Errorf("expected BLOCK for unauthorized modifications, got %s", resBlock.Decision)
	}
}
