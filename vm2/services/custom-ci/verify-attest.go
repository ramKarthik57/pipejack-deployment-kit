//go:build ignore

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Attestation struct {
	BuildID           string   `json:"build_id"`
	Timestamp         string   `json:"timestamp"`
	Project           string   `json:"project"`
	PreMerkle         string   `json:"pre_merkle"`
	PostMerkle        string   `json:"post_merkle"`
	ProcessViolations []string `json:"process_violations"`
	FSChanges         []string `json:"fs_changes"`
	NetworkViolations []string `json:"network_violations"`
	Anomalies         []string `json:"anomalies,omitempty"`
	Verdict           string   `json:"verdict"`
	PrevHash          string   `json:"prev_hash"`
	SelfHash          string   `json:"self_hash"`
	Signature         string   `json:"signature"`
}

func main() {
	dir := "/home/ubuntu/pipejack-attestations"
	pubHex, err := os.ReadFile("/home/ubuntu/.pipejack/attest-key.pub")
	if err != nil {
		fmt.Println("cannot read pubkey:", err)
		os.Exit(1)
	}
	pub, _ := hex.DecodeString(string(pubHex))
	if len(pub) != ed25519.PublicKeySize {
		fmt.Println("bad pubkey size")
		os.Exit(1)
	}

	entries, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	var files []string
	for _, e := range entries {
		if filepath.Base(e) == "index.json" {
			continue
		}
		files = append(files, e)
	}
	byPrev := make(map[string]Attestation)
	fileMap := make(map[string]string)
	bad := 0

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("❌ %s: read error: %v\n", filepath.Base(f), err)
			bad++
			continue
		}
		var att Attestation
		if err := json.Unmarshal(data, &att); err != nil {
			fmt.Printf("❌ %s: parse error: %v\n", filepath.Base(f), err)
			bad++
			continue
		}
		byPrev[att.PrevHash] = att
		fileMap[att.SelfHash] = filepath.Base(f)
	}

	prevHash := ""
	visited := 0
	for {
		att, exists := byPrev[prevHash]
		if !exists {
			break
		}
		visited++
		fname := fileMap[att.SelfHash]

		// Recompute self_hash
		canon := att
		canon.SelfHash = ""
		canon.Signature = ""
		cb, _ := json.Marshal(canon)
		h := sha256.Sum256(cb)
		computedSelf := hex.EncodeToString(h[:])

		// Verify signature
		sig, _ := hex.DecodeString(att.Signature)
		sigOK := ed25519.Verify(ed25519.PublicKey(pub), []byte(att.SelfHash), sig)

		// Verify chain link
		linkOK := att.PrevHash == prevHash

		status := "✅"
		if computedSelf != att.SelfHash || !sigOK || !linkOK {
			status = "❌"
			bad++
		}

		fmt.Printf("%s %s  verdict=%s\n", status, fname, att.Verdict)
		fmt.Printf("   self_hash match: %v\n", computedSelf == att.SelfHash)
		fmt.Printf("   signature valid: %v\n", sigOK)
		fmt.Printf("   chain link:      %v\n", linkOK)

		prevHash = att.SelfHash
	}

	if visited != len(files) {
		fmt.Printf("❌ Chain broken: only %d of %d attestations linked\n", visited, len(files))
		bad += (len(files) - visited)
	}

	if bad > 0 {
		fmt.Printf("\n❌ CHAIN HAS %d INVALID ENTRY(IES)\n", bad)
		os.Exit(1)
	}
	fmt.Println("\n✅ CHAIN INTACT")
}
