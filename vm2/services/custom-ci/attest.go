package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
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

const (
	attestDir       = "/home/ubuntu/pipejack-attestations"
	attestKeyPath   = "/home/ubuntu/.pipejack/attest-key"
	attestIndexPath = "/home/ubuntu/pipejack-attestations/index.json"
)

func loadOrCreateKey() (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(attestKeyPath); err == nil {
		if len(data) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(data), nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(attestKeyPath), 0700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(attestKeyPath, priv, 0600); err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := os.WriteFile(attestKeyPath+".pub", []byte(hex.EncodeToString(pub)), 0644); err != nil {
		return nil, err
	}
	return priv, nil
}

func loadPrevHash() string {
	data, err := os.ReadFile(attestIndexPath)
	if err != nil {
		return ""
	}
	var idx struct {
		LastHash string `json:"last_hash"`
	}
	if err := json.Unmarshal(data, &idx); err != nil {
		return ""
	}
	return idx.LastHash
}

func saveIndex(hash string) error {
	if err := os.MkdirAll(attestDir, 0755); err != nil {
		return err
	}
	idx := map[string]string{"last_hash": hash}
	data, _ := json.MarshalIndent(idx, "", "  ")
	return os.WriteFile(attestIndexPath, data, 0644)
}

func writeAttestation(buildID, project, preMerkle, postMerkle string,
	processViolations, fsChanges, networkViolations, anomalies []string, verdict string) error {

	if err := os.MkdirAll(attestDir, 0755); err != nil {
		return err
	}
	priv, err := loadOrCreateKey()
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	att := Attestation{
		BuildID:           buildID,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Project:           project,
		PreMerkle:         preMerkle,
		PostMerkle:        postMerkle,
		ProcessViolations: processViolations,
		FSChanges:         fsChanges,
		NetworkViolations: networkViolations,
		Anomalies:         anomalies,
		Verdict:           verdict,
		PrevHash:          loadPrevHash(),
	}

	canon := att
	canon.SelfHash = ""
	canon.Signature = ""
	canonBytes, _ := json.Marshal(canon)
	h := sha256.Sum256(canonBytes)
	att.SelfHash = hex.EncodeToString(h[:])

	sig := ed25519.Sign(priv, []byte(att.SelfHash))
	att.Signature = hex.EncodeToString(sig)

	path := filepath.Join(attestDir, buildID+".json")
	data, err := json.MarshalIndent(att, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	return saveIndex(att.SelfHash)
}
