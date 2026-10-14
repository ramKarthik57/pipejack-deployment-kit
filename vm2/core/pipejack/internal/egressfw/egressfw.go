package egressfw

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const ChainName = "PIPEJACK_EGRESS"

type Policy struct {
	AllowedEgress  []string `yaml:"allowed_egress"`
	EnforceNetwork bool     `yaml:"enforce_network"`
}

func Apply(policyPath string) error {
	if !insideContainer() {
		return fmt.Errorf("refusing to apply iptables outside a container")
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	if !p.EnforceNetwork {
		return nil
	}
	for _, s := range p.AllowedEgress {
		if strings.TrimSpace(s) == "*" {
			return nil
		}
	}
	if len(p.AllowedEgress) == 0 {
		return nil
	}

	// Ensure clean state, then create the chain.
	_ = iptables("-D", "OUTPUT", "-j", ChainName)
	_ = iptables("-F", ChainName)
	_ = iptables("-X", ChainName)

	if err := iptables("-N", ChainName); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	for _, rule := range p.AllowedEgress {
		if err := addRule(rule); err != nil {
			_ = Cleanup()
			return fmt.Errorf("rule %q: %w", rule, err)
		}
	}

	if err := iptables("-A", ChainName, "-j", "DROP"); err != nil {
		_ = Cleanup()
		return fmt.Errorf("default drop: %w", err)
	}

	if err := iptables("-I", "OUTPUT", "1", "-j", ChainName); err != nil {
		_ = Cleanup()
		return fmt.Errorf("hook OUTPUT: %w", err)
	}

	return nil
}

func Cleanup() error {
	_ = iptables("-D", "OUTPUT", "-j", ChainName)
	_ = iptables("-F", ChainName)
	_ = iptables("-X", ChainName)
	return nil
}

func ListRules() string {
	out, _ := exec.Command("iptables", "-L", ChainName, "-n", "-v").CombinedOutput()
	return string(out)
}

// addRule converts "*:443", "127.0.0.1:*", "10.0.0.0/8:80" into iptables rules.
func addRule(spec string) error {
	ip, port, err := parseSpec(spec)
	if err != nil {
		return err
	}

	base := []string{"-A", ChainName}
	if ip != "" && ip != "*" {
		base = append(base, "-d", ip)
	}

	if port == "*" {
		// match any port: rule applies to any protocol
		args := append(base, "-j", "ACCEPT")
		return iptables(args...)
	}

	// add TCP rule
	tcpArgs := append(base, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
	if err := iptables(tcpArgs...); err != nil {
		return err
	}
	// add UDP rule (harmless if unused)
	udpArgs := append(base, "-p", "udp", "--dport", port, "-j", "ACCEPT")
	return iptables(udpArgs...)
}

func parseSpec(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return "", "", fmt.Errorf("missing port separator")
	}
	ipPart := strings.TrimSpace(s[:idx])
	portPart := strings.TrimSpace(s[idx+1:])

	switch {
	case ipPart == "*":
		// any IP
	case strings.Contains(ipPart, "/"):
		if _, _, err := net.ParseCIDR(ipPart); err != nil {
			return "", "", fmt.Errorf("bad CIDR %q", ipPart)
		}
	case net.ParseIP(ipPart) == nil:
		return "", "", fmt.Errorf("bad IP %q", ipPart)
	}

	if portPart != "*" {
		p, err := strconv.Atoi(portPart)
		if err != nil || p < 0 || p > 65535 {
			return "", "", fmt.Errorf("bad port %q", portPart)
		}
	}
	return ipPart, portPart, nil
}

func iptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v failed: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func insideContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Also accept if cgroup path mentions docker
	data, _ := os.ReadFile("/proc/1/cgroup")
	return strings.Contains(string(data), "docker")
}
