package netmon

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Connection struct {
	PID        int
	Process    string
	Protocol   string // "tcp", "tcp6", "udp", "udp6"
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      string
}

type Violation struct {
	Connection
	Rule string
}

type Policy struct {
	AllowedEgress []string `yaml:"allowed_egress"`
}

type egressRule struct {
	ipAny   bool
	ip      string
	cidr    string
	portAny bool
	port    int
}

// Snapshot reads /proc/net/{tcp,tcp6,udp,udp6}, maps socket inodes to PIDs,
// and returns outbound connections owned by processes in the given cgroup.
// Empty cgroupPath means no cgroup filter.
func Snapshot(cgroupPath string) ([]Connection, error) {
	inodeMap := buildInodeMap(cgroupPath)

	var conns []Connection
	for _, f := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	} {
		cs, err := parseNetFile(f.path, f.proto, inodeMap)
		if err != nil {
			continue
		}
		conns = append(conns, cs...)
	}
	return conns, nil
}

// Evaluate checks each connection against allowed_egress in the policy.
func Evaluate(policyPath string, conns []Connection) ([]Violation, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	// Wildcard "*" disables egress checks.
	for _, s := range p.AllowedEgress {
		if strings.TrimSpace(s) == "*" {
			return nil, nil
		}
	}
	// Missing allowed_egress field → back-compat, skip checks.
	if len(p.AllowedEgress) == 0 {
		return nil, nil
	}

	rules, err := parseRules(p.AllowedEgress)
	if err != nil {
		return nil, err
	}

	var violations []Violation
	for _, c := range conns {
		if !matchesAny(c, rules) {
			violations = append(violations, Violation{Connection: c, Rule: "UNAUTHORIZED_EGRESS"})
		}
	}
	return violations, nil
}

func parseRules(specs []string) ([]egressRule, error) {
	var rules []egressRule
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		idx := strings.LastIndex(s, ":")
		if idx == -1 {
			return nil, fmt.Errorf("bad egress rule (missing port): %s", s)
		}
		ipPart := s[:idx]
		portPart := s[idx+1:]

		var r egressRule
		switch {
		case ipPart == "*":
			r.ipAny = true
		case strings.Contains(ipPart, "/"):
			if _, _, err := net.ParseCIDR(ipPart); err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", ipPart, err)
			}
			r.cidr = ipPart
		default:
			if net.ParseIP(ipPart) == nil {
				return nil, fmt.Errorf("bad IP %q", ipPart)
			}
			r.ip = ipPart
		}

		if portPart == "*" {
			r.portAny = true
		} else {
			p, err := strconv.Atoi(portPart)
			if err != nil || p < 0 || p > 65535 {
				return nil, fmt.Errorf("bad port %q", portPart)
			}
			r.port = p
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func matchesAny(c Connection, rules []egressRule) bool {
	for _, r := range rules {
		if !r.portAny && r.port != c.RemotePort {
			continue
		}
		if r.ipAny {
			return true
		}
		if r.cidr != "" {
			_, cidr, err := net.ParseCIDR(r.cidr)
			if err == nil && cidr.Contains(net.ParseIP(c.RemoteIP)) {
				return true
			}
		}
		if r.ip != "" && r.ip == c.RemoteIP {
			return true
		}
	}
	return false
}

func parseNetFile(path, proto string, inodeMap map[uint64]int) ([]Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Connection
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		state := fields[3]
		if state == "0A" { // TCP_LISTEN
			continue
		}

		lip, lport, err := parseHexAddr(fields[1], proto)
		if err != nil {
			continue
		}
		rip, rport, err := parseHexAddr(fields[2], proto)
		if err != nil {
			continue
		}
		if rport == 0 {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		pid, ok := inodeMap[inode]
		if !ok {
			continue
		}

		exe, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
		out = append(out, Connection{
			PID:        pid,
			Process:    exe,
			Protocol:   proto,
			LocalIP:    lip,
			LocalPort:  lport,
			RemoteIP:   rip,
			RemotePort: rport,
			State:      state,
		})
	}
	return out, nil
}

func parseHexAddr(s, proto string) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad addr %q", s)
	}
	port64, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}
	port := int(port64)
	if proto == "tcp6" || proto == "udp6" {
		return parseIPv6Hex(parts[0]), port, nil
	}
	return parseIPv4Hex(parts[0]), port, nil
}

func parseIPv4Hex(s string) string {
	if len(s) != 8 {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

func parseIPv6Hex(s string) string {
	if len(s) != 32 {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return ""
	}
	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		out[i*4+0] = b[i*4+3]
		out[i*4+1] = b[i*4+2]
		out[i*4+2] = b[i*4+1]
		out[i*4+3] = b[i*4+0]
	}
	return net.IP(out).String()
}

func buildInodeMap(cgroupPath string) map[uint64]int {
	inodes := make(map[uint64]int)
	target := filepath.Base(cgroupPath)

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return inodes
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		if target != "" && !inCgroup(p.Name(), target) {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				ino, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
				if err == nil {
					inodes[ino] = pid
				}
			}
		}
	}
	return inodes
}

func inCgroup(pid, target string) bool {
	if target == "" {
		return true
	}
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), target)
}
