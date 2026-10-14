package netmon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseIPv4Hex(t *testing.T) {
	cases := map[string]string{
		"0100007F": "127.0.0.1",
		"0101A8C0": "192.168.1.1",
		"00000000": "0.0.0.0",
	}
	for in, want := range cases {
		if got := parseIPv4Hex(in); got != want {
			t.Errorf("parseIPv4Hex(%s)=%s want %s", in, got, want)
		}
	}
}

func TestParseIPv6HexLoopback(t *testing.T) {
	got := parseIPv6Hex("00000000000000000000000001000000")
	if got != "::1" {
		t.Errorf("got %s want ::1", got)
	}
}

func TestParseRulesValid(t *testing.T) {
	rules, err := parseRules([]string{"*:443", "127.0.0.1:*", "10.0.0.0/8:80", "8.8.8.8:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("want 4 rules, got %d", len(rules))
	}
}

func TestParseRulesInvalid(t *testing.T) {
	bad := []string{"not-a-rule", "*:notaport", "999.999.999.999:80"}
	for _, s := range bad {
		if _, err := parseRules([]string{s}); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}

func TestMatchesAny(t *testing.T) {
	rules, _ := parseRules([]string{"*:443", "127.0.0.1:*", "10.0.0.0/8:80"})
	cases := []struct {
		ip   string
		port int
		want bool
	}{
		{"1.2.3.4", 443, true},
		{"1.2.3.4", 80, false},
		{"127.0.0.1", 9999, true},
		{"10.1.2.3", 80, true},
		{"10.1.2.3", 443, true},
		{"11.1.2.3", 80, false},
	}
	for _, c := range cases {
		conn := Connection{RemoteIP: c.ip, RemotePort: c.port}
		if got := matchesAny(conn, rules); got != c.want {
			t.Errorf("matchesAny(%s:%d)=%v want %v", c.ip, c.port, got, c.want)
		}
	}
}

func TestEvaluateClean(t *testing.T) {
	dir := t.TempDir()
	policy := "allowed_egress:\n  - \"127.0.0.1:*\"\n  - \"*:443\"\n"
	path := filepath.Join(dir, "p.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	conns := []Connection{{RemoteIP: "1.2.3.4", RemotePort: 443}}
	v, err := Evaluate(path, conns)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations, got %d", len(v))
	}
}

func TestEvaluateViolation(t *testing.T) {
	dir := t.TempDir()
	policy := "allowed_egress:\n  - \"127.0.0.1:*\"\n"
	path := filepath.Join(dir, "p.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	conns := []Connection{{PID: 1, Process: "/usr/bin/curl", RemoteIP: "10.255.255.1", RemotePort: 80, Protocol: "tcp"}}
	v, err := Evaluate(path, conns)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 {
		t.Fatalf("want 1 violation, got %d", len(v))
	}
	if v[0].Rule != "UNAUTHORIZED_EGRESS" {
		t.Errorf("wrong rule: %s", v[0].Rule)
	}
}

func TestEvaluateWildcard(t *testing.T) {
	dir := t.TempDir()
	policy := "allowed_egress:\n  - \"*\"\n"
	path := filepath.Join(dir, "p.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	conns := []Connection{{RemoteIP: "1.2.3.4", RemotePort: 9999}}
	v, _ := Evaluate(path, conns)
	if len(v) != 0 {
		t.Errorf("wildcard should allow all")
	}
}

func TestEvaluateMissingField(t *testing.T) {
	dir := t.TempDir()
	policy := "allowed_binaries:\n  - /usr/bin/java\n"
	path := filepath.Join(dir, "p.yaml")
	os.WriteFile(path, []byte(policy), 0644)

	conns := []Connection{{RemoteIP: "1.2.3.4", RemotePort: 9999}}
	v, _ := Evaluate(path, conns)
	if len(v) != 0 {
		t.Errorf("missing allowed_egress should skip checks, got %d violations", len(v))
	}
}
