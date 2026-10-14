package main

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ramKarthik57/pipejack-test/pipejack/fschecker"
	"github.com/ramKarthik57/pipejack-test/pipejack/internal/egressfw"
	"github.com/ramKarthik57/pipejack-test/pipejack/internal/netmon"
	"github.com/ramKarthik57/pipejack-test/pipejack/internal/pdp"
	"github.com/ramKarthik57/pipejack-test/pipejack/proctree"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: pipejackd <workspace_dir> <policy_path> [cgroup_path]\n")
		os.Exit(1)
	}
	workspace := os.Args[1]
	policyPath := os.Args[2]
	cgroupPath := ""
	if len(os.Args) >= 4 {
		cgroupPath = os.Args[3]
	}

	ignore := []string{"node_modules/", ".git/", "package-lock.json", "target/"}
	preRoot, preFiles, err := fschecker.BuildMerkleTree(workspace, ignore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pre-snapshot error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Pre-build Merkle root: %s\n", preRoot.Hash)

	// Background network egress poller
	var netMu sync.Mutex
	seenNet := make(map[string]bool)
	var netViolationStrs []string
	netDone := make(chan struct{})

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-netDone:
				return
			case <-ticker.C:
				conns, err := netmon.Snapshot(cgroupPath)
				if err != nil {
					continue
				}
				vs, err := netmon.Evaluate(policyPath, conns)
				if err != nil {
					continue
				}
				netMu.Lock()
				for _, v := range vs {
					key := fmt.Sprintf("%s|%s|%d", v.Process, v.RemoteIP, v.RemotePort)
					if seenNet[key] {
						continue
					}
					seenNet[key] = true
					msg := fmt.Sprintf("NETWORK VIOLATION: PID %d (%s) -> %s:%d/%s UNAUTHORIZED_EGRESS",
						v.PID, v.Process, v.RemoteIP, v.RemotePort, v.Protocol)
					fmt.Println(msg)
					netViolationStrs = append(netViolationStrs, msg)
				}
				netMu.Unlock()
			}
		}
	}()

	// Background process tree poller (cgroup-filtered)
	var procMu sync.Mutex
	seenProc := make(map[string]bool)
	allBins := make(map[string]bool)
	var procViolationStrs []string
	var procViolationPaths []string
	procDone := make(chan struct{})

	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-procDone:
				return
			case <-ticker.C:
				vs, err := proctree.Run(policyPath, cgroupPath)
				if err != nil {
					continue
				}
				if all, err2 := proctree.ScanCgroup(cgroupPath); err2 == nil {
					procMu.Lock()
					for _, exe := range all {
						allBins[exe] = true
					}
					procMu.Unlock()
				}
				procMu.Lock()
				for _, exe := range vs {
					if seenProc[exe] {
						continue
					}
					seenProc[exe] = true
					msg := fmt.Sprintf("VIOLATION: unauthorized binary %s", exe)
					fmt.Println(msg)
					procViolationStrs = append(procViolationStrs, msg)
					procViolationPaths = append(procViolationPaths, exe)
				}
				procMu.Unlock()
			}
		}
	}()

	// Egress firewall enforcement (if policy enables it)
	if err := egressfw.Apply(policyPath); err != nil {
		fmt.Fprintf(os.Stderr, "Egress firewall error: %v\n", err)
	} else {
		fmt.Println("Egress firewall applied")
		fmt.Println(egressfw.ListRules())
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	fmt.Println("PipeJack daemon running... waiting for build completion signal (SIGTERM/INT).")
	<-sigCh

	close(netDone)
	close(procDone)
	time.Sleep(300 * time.Millisecond)

	// Pre-cleanup chain counters — proof that rules fired
	fmt.Println("=== Pre-cleanup chain counters ===")
	fmt.Println(egressfw.ListRules())
	fmt.Println("=== End pre-cleanup counters ===")

	// Remove egress firewall rules before shutdown
	if err := egressfw.Cleanup(); err != nil {
		fmt.Fprintf(os.Stderr, "Egress firewall cleanup error: %v\n", err)
	} else {
		fmt.Println("Egress firewall cleaned up")
	}

	// Post-build filesystem snapshot
	postRoot, postFiles, err := fschecker.BuildMerkleTree(workspace, ignore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Post-snapshot error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Post-build Merkle root: %s\n", postRoot.Hash)

	var fsViolationPaths []string
	if preRoot.Hash != postRoot.Hash {
		fmt.Println("Filesystem integrity violated!")
		changes := fschecker.CompareSnapshots(preFiles, postFiles)
		for _, ch := range changes {
			fmt.Printf("  [%s] %s\n", ch.Type, ch.Path)
			fsViolationPaths = append(fsViolationPaths, ch.Path)
		}
	}

	// Policy Decision Engine
	pdpResult, err := pdp.Evaluate(policyPath, procViolationPaths, fsViolationPaths, netViolationStrs)
	var pdpProcViolation, pdpFsViolation, pdpNetViolation bool
	if err != nil {
		fmt.Fprintf(os.Stderr, "PDP error: %v\n", err)
	} else {
		fmt.Printf("\n===== POLICY DECISION =====\n")
		fmt.Printf("Decision: %s\n", pdpResult.Decision)
		for _, r := range pdpResult.Reasons {
			fmt.Printf("Reason: %s\n", r)
			if strings.Contains(r, "binary executed:") {
				pdpProcViolation = true
			} else if strings.Contains(r, "filesystem change:") {
				pdpFsViolation = true
			} else if strings.Contains(r, "network violation:") {
				pdpNetViolation = true
			}
		}
		fmt.Println("===========================")
	}

	// Emit binary list for the CI anomaly baseline
	procMu.Lock()
	var binList []string
	for b := range allBins {
		binList = append(binList, b)
	}
	procMu.Unlock()
	sort.Strings(binList)
	fmt.Printf("PIPEJACK_BINARIES: %s\n", strings.Join(binList, ","))

	fmt.Println("\n===== PIPEJACK DETECTION SUMMARY =====")
	procMu.Lock()
	_ = procViolationStrs
	procMu.Unlock()
	if pdpProcViolation {
		fmt.Println("Process Tree: VIOLATION DETECTED")
	} else {
		fmt.Println("Process Tree: CLEAN")
	}
	if pdpFsViolation {
		fmt.Println("Filesystem:   VIOLATION DETECTED")
	} else {
		fmt.Println("Filesystem:   CLEAN")
	}
	netMu.Lock()
	_ = netViolationStrs
	netMu.Unlock()
	if pdpNetViolation {
		fmt.Println("Network:      VIOLATION DETECTED")
	} else {
		fmt.Println("Network:      CLEAN")
	}
	fmt.Println("Build:        SUCCESS")
	fmt.Println("Mode:         DETECTION ONLY")
	fmt.Println("======================================")

	os.Exit(0)
}
