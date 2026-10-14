package main

import (
	"archive/tar"
	"compress/gzip"
	"custom-ci/anomaly"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type BuildResult struct {
	Status  string `json:"status"`
	Log     string `json:"log"`
	BuildID string `json:"build_id"`
	Image   string `json:"image"`
}

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	cyan    = "\033[36m"
	magenta = "\033[35m"
)

func colorStatus(status string) string {
	switch status {
	case "CLEAN", "SUCCESS", "ALLOW":
		return green + status + reset
	case "VIOLATION DETECTED", "BLOCK", "FAIL":
		return red + status + reset
	case "DETECTION ONLY", "DISABLED":
		return yellow + status + reset
	default:
		return status
	}
}

func main() {
	os.MkdirAll("/home/ubuntu/code-repo", 0755)
	http.HandleFunc("/upload", handleUpload)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","service":"pipejack-ci","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
	})
	printBanner()
	err := http.ListenAndServe(":8888", nil)
	if err != nil {
		fmt.Println("Server error:", err)
	}
}

func printBanner() {
	fmt.Println(cyan + "╔══════════════════════════════════════════════╗" + reset)
	fmt.Printf("%s║   PIPEJACK UNIFIED CI/CD ENGINE  |  :8888    ║%s\n", cyan, reset)
	fmt.Printf("%s║   Endpoint: POST /upload                     ║%s\n", cyan, reset)
	fmt.Println(cyan + "╚══════════════════════════════════════════════╝" + reset)
}

func printSection(title string) {
	fmt.Println()
	fmt.Println(cyan + "────────────────────────────────────────────────" + reset)
	fmt.Printf("%s%s%s\n", bold+cyan, title, reset)
	fmt.Println(cyan + "────────────────────────────────────────────────" + reset)
}

func extractProcessViolations(output string) []string {
	var violations []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		t := strings.TrimSpace(line)
		// Only true proctree lines — exclude "NETWORK VIOLATION:"
		if strings.HasPrefix(t, "VIOLATION: PID") || strings.HasPrefix(t, "VIOLATION: unauthorized binary") {
			if !seen[t] {
				seen[t] = true
				violations = append(violations, t)
			}
		}
	}
	return violations
}

func extractFileChanges(output string) []string {
	var changes []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[modified]") || strings.HasPrefix(trimmed, "[added]") ||
			strings.HasPrefix(trimmed, "[deleted]") {
			changes = append(changes, trimmed)
		}
	}
	return changes
}

func extractMerkleRoots(output string) (string, string) {
	pre, post := "N/A", "N/A"
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "Merkle root:") {
			continue
		}
		idx := strings.Index(trimmed, "Merkle root:")
		val := strings.TrimSpace(trimmed[idx+len("Merkle root:"):])
		// Unicode-safe: check prefix using ToLower
		low := strings.ToLower(trimmed)
		if strings.HasPrefix(low, "pre") {
			pre = val
		} else if strings.HasPrefix(low, "post") {
			post = val
		}
	}
	return pre, post
}

func filterSpringBuild(out string) string {
	keywords := []string{"Building", "Tests run:", "BUILD SUCCESS", "Total time"}
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		for _, kw := range keywords {
			if strings.Contains(line, kw) {
				lines = append(lines, line)
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

func filterDockerOutput(out string) string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "naming to") || strings.Contains(trimmed, "digest:") ||
			strings.Contains(trimmed, "ERROR") || strings.Contains(trimmed, "failed") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	handlerStart := time.Now()
	buildID := fmt.Sprint(handlerStart.Unix())
	startTime := handlerStart.Format("15:04:05")
	logger := &strings.Builder{}
	log := func(stage, msg string) {
		line := fmt.Sprintf("%s[%s]%s %s\n", blue, stage, reset, msg)
		logger.WriteString(line)
		fmt.Print(line)
	}

	printSection("Build Trigger")
	log("INIT", "Build triggered – ID: "+buildID)
	log("TIME", "Started at: "+startTime)

	uploadPath := fmt.Sprintf("/tmp/upload-%s.tar.gz", buildID)

	if err := r.ParseMultipartForm(64 << 20); err != nil {
		log("FAIL", "multipart parse error: "+err.Error())
		http.Error(w, "bad multipart form", http.StatusBadRequest)
		return
	}
	srcFile, _, err := r.FormFile("file")
	if err != nil {
		log("FAIL", "form file error: "+err.Error())
		http.Error(w, "missing 'file' field", http.StatusBadRequest)
		return
	}
	defer srcFile.Close()

	f, err := os.Create(uploadPath)
	if err != nil {
		log("FAIL", "create upload file: "+err.Error())
		http.Error(w, "cannot save upload", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(f, srcFile); err != nil {
		f.Close()
		log("FAIL", "copy body: "+err.Error())
		http.Error(w, "cannot save upload", http.StatusInternalServerError)
		return
	}
	f.Close()
	defer os.Remove(uploadPath)
	log("UPLOAD", fmt.Sprintf("Saved: %s", uploadPath))

	workspace := fmt.Sprintf("/tmp/workspace-%s", buildID)
	os.MkdirAll(workspace, 0755)
	defer os.RemoveAll(workspace)
	log("CHECKOUT", fmt.Sprintf("Workspace: %s", workspace))

	if err := extractTarGz(uploadPath, workspace); err != nil {
		log("FAIL", "extract error: "+err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	isSpring := false
	isNode := false
	isPython := false
	if _, err := os.Stat(filepath.Join(workspace, "package.json")); err == nil {
		isNode = true
	}
	if _, err := os.Stat(filepath.Join(workspace, "requirements.txt")); err == nil {
		isPython = true
	} else if _, err := os.Stat(filepath.Join(workspace, "pyproject.toml")); err == nil {
		isPython = true
	} else if _, err := os.Stat(filepath.Join(workspace, "setup.py")); err == nil {
		isPython = true
	}
	if _, err := os.Stat(filepath.Join(workspace, "pom.xml")); err == nil {
		isSpring = true
	}

	isBanking := false
	if isSpring {
		pomData, _ := os.ReadFile(filepath.Join(workspace, "pom.xml"))
		if strings.Contains(string(pomData), "<artifactId>banking</artifactId>") {
			isBanking = true
		}
	}

	projectName := "Node.js Employee Manager"
	if isSpring {
		if isBanking {
			projectName = "Banking API"
		} else {
			projectName = "Spring Boot Calculator"
		}
	} else if isNode {
		projectName = "Node.js App"
	} else if isPython {
		projectName = "Python App"
	}
	log("CHECKOUT", "Source code extracted – "+projectName)

	buildContainer := "build-" + buildID
	containerImage := "node@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e"
	if isSpring {
		containerImage = "maven@sha256:40fcff4c4043d6adc90286c2e38ec70950f34f6dd5784f7e524866c66520cc23"
	} else if isPython {
		containerImage = "python@sha256:0687a6bc9716edc2a6ee0fbfb0f87e7ee358b262b67c9215de91bc9b2d38ba71"
	}
	exec.Command("docker", "run", "-d", "--name", buildContainer,
		"-v", os.Getenv("HOME")+"/.m2:/root/.m2",
		"-v", workspace+":/app", "-w", "/app",
		containerImage, "sleep", "600").Run()
	defer exec.Command("docker", "rm", "-f", buildContainer).Run()

	cgroupPath := findCgroup(buildContainer)
	log("CGROUP", cgroupPath)

	policyHostPath := "/home/ubuntu/pipejack-docker/policy.yaml"
	dockerfileHostPath := "/home/ubuntu/custom-ci-node/Dockerfile.node"
	if isSpring {
		dockerfileHostPath = "/home/ubuntu/custom-ci/Dockerfile.spring"
		if isBanking {
			policyHostPath = "/home/ubuntu/custom-ci/policy-banking.yaml"
		} else {
			policyHostPath = "/home/ubuntu/custom-ci/policy-spring.yaml"
		}
	} else if isNode {
		policyHostPath = "/home/ubuntu/custom-ci/policy-node.yaml"
	} else if isPython {
		policyHostPath = "/home/ubuntu/custom-ci/policy-python.yaml"
		dockerfileHostPath = "/home/ubuntu/custom-ci/Dockerfile.python"
	}

	sidecarName := "sidecar-" + buildID
	sidecarCmd := exec.Command("docker", "run", "--rm", "--name", sidecarName,
		"--pid=container:"+buildContainer,
		"--network=container:"+buildContainer,
		"--privileged",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"-v", "/sys/fs/bpf:/sys/fs/bpf:rw",
		"-v", workspace+":/workspace:ro",
		"-v", policyHostPath+":/app/policy.yaml",
		"pipejack-daemon",
		"/workspace", "/app/policy.yaml", cgroupPath)
	var sidecarLog strings.Builder
	sidecarCmd.Stdout = &sidecarLog
	sidecarCmd.Stderr = &sidecarLog
	sidecarCmd.Start()
	log("SIDECAR", "PipeJack sidecar started (detection mode)")

	if os.Getenv("PIPEJACK_DEV") == "1" {
		log("DEV", "waiting 2500ms for sidecar pre-snapshot to complete")
		time.Sleep(2500 * time.Millisecond)
	}

	execInContainer := func(args ...string) (string, error) {
		cmdArgs := append([]string{"exec", "-w", "/app", buildContainer}, args...)
		cmd := exec.Command("docker", cmdArgs...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	printSection("Build & Test")
	if os.Getenv("PIPEJACK_DEV") == "1" {
		log("DEV", "skipping Maven, running attack.sh directly")
		ashPath := filepath.Join(workspace, "attack.sh")
		log("DEV-STAT", "workspace="+workspace)
		log("DEV-STAT", "attack.sh path="+ashPath)

		acc := filepath.Join(workspace, "src/main/java/com/pipejack/banking/controller/AccountController.java")
		if st, err := os.Stat(acc); err == nil {
			log("DEV-PRE", fmt.Sprintf("size=%d mtime=%s", st.Size(), st.ModTime().Format("15:04:05.000")))
		} else {
			log("DEV-PRE", "stat err: "+err.Error())
		}

		if _, err := os.Stat(ashPath); err == nil {
			log("DEV", "attack.sh found, executing")
			out, err := execInContainer("sh", "attack.sh")
			log("DEV-EXEC", fmt.Sprintf("err=%v", err))
			log("DEV-OUT", fmt.Sprintf("output_len=%d", len(out)))
			fmt.Println(out)
		} else if _, err := os.Stat(filepath.Join(workspace, "malicious.sh")); err == nil {
			log("DEV", "malicious.sh found, executing")
			out, err := execInContainer("sh", "malicious.sh")
			log("DEV-EXEC", fmt.Sprintf("err=%v", err))
			log("DEV-OUT", fmt.Sprintf("output_len=%d", len(out)))
			fmt.Println(out)
		} else {
			log("DEV", "no attack.sh or malicious.sh in workspace")
		}

		if st, err := os.Stat(acc); err == nil {
			log("DEV-POST", fmt.Sprintf("size=%d mtime=%s", st.Size(), st.ModTime().Format("15:04:05.000")))
		} else {
			log("DEV-POST", "stat err: "+err.Error())
		}
	} else if isSpring {
		log("BUILD", "Running Maven clean package...")
		out, _ := execInContainer("mvn", "clean", "package")
		fmt.Println(filterSpringBuild(out))
	} else if isPython {
		log("BUILD", "Running pip install...")
		var out string
		if _, err := os.Stat(filepath.Join(workspace, "setup.py")); err == nil {
			log("BUILD", "setup.py found, installing local package (pip install .)")
			out, _ = execInContainer("pip", "install", "--no-cache-dir", ".")
		} else {
			out, _ = execInContainer("pip", "install", "--no-cache-dir", "-r", "requirements.txt")
		}
		fmt.Println(out)
	} else {
		log("BUILD", "Running npm install...")
		out, _ := execInContainer("npm", "install")
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "added") || strings.Contains(line, "audited") ||
				strings.Contains(line, "vulnerabilities") {
				fmt.Println(line)
			}
		}
		log("BUILD", "Running npm run build...")
		out, _ = execInContainer("npm", "run", "build")
		fmt.Println(out)
		log("TEST", "Running npm test...")
		out, _ = execInContainer("npm", "test")
		fmt.Println(out)
	}

	if os.Getenv("PIPEJACK_DEV") == "1" {
		log("DEV", "waiting 1500ms for sidecar init before SIGTERM")
		time.Sleep(1500 * time.Millisecond)
	}

	exec.Command("docker", "kill", "--signal=SIGTERM", sidecarName).Run()
	sidecarCmd.Wait()
	sidecarOutput := sidecarLog.String()
	_ = os.WriteFile("/tmp/sidecar-diag-"+buildID+".log", []byte(sidecarOutput), 0644)
	log("SIDECAR-DIAG", "dumped to /tmp/sidecar-diag-"+buildID+".log")

	processViolations := extractProcessViolations(sidecarOutput)
	// Fail-closed: if the sidecar did not produce a valid detection summary,
	// treat it as a failure and block the build.
	sidecarHealthy := strings.Contains(sidecarOutput, "PIPEJACK DETECTION SUMMARY") ||
		strings.Contains(sidecarOutput, "POLICY DECISION")
	if !sidecarHealthy {
		reason := "sidecar produced no detection summary"
		if len(sidecarOutput) == 0 {
			reason = "sidecar produced no output"
		} else if strings.Contains(sidecarOutput, "docker:") {
			reason = "sidecar container failed to start"
		}
		log("SIDECAR-FAIL", reason)
	}

	networkViolations := extractNetworkViolations(sidecarOutput)
	buildBinaries := extractPIPEJACKBinaries(sidecarOutput)
	egressLines := extractEgressLines(sidecarOutput)
	for _, el := range egressLines {
		log("EGRESS-LINES", el)
	}
	fileChanges := extractFileChanges(sidecarOutput)
	preMerkle, postMerkle := extractMerkleRoots(sidecarOutput)
	processStatus := "CLEAN"
	if len(processViolations) > 0 {
		processStatus = "VIOLATION DETECTED"
	}
	fileStatus := "CLEAN"
	if len(fileChanges) > 0 {
		fileStatus = "VIOLATION DETECTED"
	}

	printSection("PipeJack Security Scan")
	fmt.Println("  🔍 Process Tree Differ")
	fmt.Printf("     Status: %s\n", colorStatus(processStatus))
	if processStatus == "VIOLATION DETECTED" {
		fmt.Printf("     Suspicious Processes Detected: %d\n", len(processViolations))
		for _, v := range processViolations {
			fmt.Printf("       • %s\n", v)
		}
	}
	fmt.Println()
	fmt.Println("  📁 Filesystem Baseline Checker")
	fmt.Printf("     Status: %s\n", colorStatus(fileStatus))
	fmt.Printf("     Pre‑build Merkle Root:  %s\n", preMerkle)
	fmt.Printf("     Post‑build Merkle Root: %s\n", postMerkle)
	if fileStatus == "VIOLATION DETECTED" {
		fmt.Printf("     Changed Files:\n")
		for _, ch := range fileChanges {
			fmt.Printf("       • %s\n", ch)
		}
	}
	fmt.Println()

	verdict := "ALLOW"
	if strings.Contains(sidecarOutput, "Decision: BLOCK") {
		verdict = "BLOCK"
	} else if !strings.Contains(sidecarOutput, "Decision: ALLOW") {
		// Sidecar did not produce an explicit decision — fail closed
		verdict = "BLOCK"
	}
	// Anomaly detection (may promote verdict to BLOCK if policy enables it)
	var anomalyStrs []string
	anomCfg := readAnomalyConfig(policyHostPath)
	if anomCfg.Enabled {
		metrics := anomaly.BuildMetrics{
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			ProcessCount:    len(buildBinaries),
			FileChangeCount: len(fileChanges),
			NetworkCount:    len(networkViolations),
			DurationMs:      time.Since(handlerStart).Milliseconds(),
			Binaries:        buildBinaries,
		}
		res, err := anomaly.Evaluate(projectName, metrics, anomCfg)
		if err != nil {
			log("ANOMALY", "evaluate error: "+err.Error())
		} else if res.WarmingUp {
			log("ANOMALY", fmt.Sprintf("baseline warming up (%d/%d)", res.BaselineSize+1, res.MinBaseline))
		} else if len(res.Findings) > 0 {
			for _, f := range res.Findings {
				msg := fmt.Sprintf("%s [%s] %s", f.Metric, f.Severity, f.Message)
				log("ANOMALIES", msg)
				anomalyStrs = append(anomalyStrs, msg)
			}
			if anomCfg.Block && verdict == "ALLOW" {
				verdict = "BLOCK"
				log("ANOMALY-BLOCK", "anomaly promoted verdict to BLOCK")
			}
		} else {
			log("ANOMALY", "no anomalies detected")
		}
	}

	if !sidecarHealthy {
		verdict = "BLOCK"
	}

	log("VERDICT", verdict)
	enforcementEnabled := os.Getenv("PIPEJACK_ENFORCE") == "1"
	if enforcementEnabled {
		log("ENFORCEMENT", "ENABLED")
	} else {
		log("ENFORCEMENT", "DISABLED")
	}
	if len(processViolations) > 0 {
		log("PROC-VIOLATIONS", strings.Join(processViolations, ", "))
	}
	if len(fileChanges) > 0 {
		log("FS-CHANGES", strings.Join(fileChanges, ", "))
	}
	if len(networkViolations) > 0 {
		log("NET-VIOLATIONS", strings.Join(networkViolations, " | "))
	}

	// Read quarantine flag from policy
	quarantineEnabled := policyQuarantine(policyHostPath)
	if err := writeAttestation(buildID, projectName, preMerkle, postMerkle, processViolations, fileChanges, networkViolations, anomalyStrs, verdict); err != nil {
		log("ATTEST", "Failed: "+err.Error())
	} else {
		log("ATTEST", "Attestation written and signed")
	}

	// Enforcement (non-quarantine path): block before any build work
	if enforcementEnabled && verdict == "BLOCK" && !quarantineEnabled {
		log("ENFORCEMENT", "Build blocked, no artifact published")
		printSection("BUILD BLOCKED")
		fmt.Printf("  Verdict:        BLOCK\n")
		fmt.Printf("  Action:         push/deploy skipped\n")
		fmt.Printf("  Reason:         policy violation detected\n")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"status":"blocked","build_id":"%s","verdict":"BLOCK"}`, buildID)
		return
	}

	// Fast mode (dev iteration only)
	if os.Getenv("PIPEJACK_FAST") == "1" {
		log("FAST-MODE", "Skipping Docker build/push/deploy")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"fast","build_id":"%s","verdict":"%s"}`, buildID, verdict)
		return
	}
	if len(processViolations) > 0 {
		log("PROC-VIOLATIONS", strings.Join(processViolations, ", "))
	}
	if len(fileChanges) > 0 {
		log("FS-CHANGES", strings.Join(fileChanges, ", "))
	}

	processArtifactManagement(
		w,
		buildID,
		projectName,
		isSpring,
		isBanking,
		workspace,
		dockerfileHostPath,
		verdict,
		enforcementEnabled,
		quarantineEnabled,
		buildContainer,
		processStatus,
		fileStatus,
		logger.String(),
		log,
	)
}

func processArtifactManagement(
	w http.ResponseWriter,
	buildID string,
	projectName string,
	isSpring bool,
	isBanking bool,
	workspace string,
	dockerfileHostPath string,
	verdict string,
	enforcementEnabled bool,
	quarantineEnabled bool,
	buildContainer string,
	processStatus string,
	fileStatus string,
	logStr string,
	log func(stage, msg string),
) {
	if log == nil {
		log = func(stage, msg string) {
			fmt.Printf("[%s] %s\n", stage, msg)
		}
	}
	printSection("Artifact Management")
	imageName := fmt.Sprintf("localhost:5000/calculator-api:%s", buildID)
	deployPort := "8080:8080"
	appName := "app-latest"
	if !isSpring {
		imageName = fmt.Sprintf("localhost:5000/vuln-app:%s", buildID)
		deployPort = "9090:3000"
		appName = "app-vuln-latest"
	} else if isBanking {
		imageName = fmt.Sprintf("localhost:5000/banking-api:%s", buildID)
		deployPort = "8081:8080"
		appName = "app-banking-latest"
	}
	log("DOCKER BUILD", fmt.Sprintf("Building image %s ...", imageName))
	if _, err := os.Stat(dockerfileHostPath); err == nil {
		copyFile(dockerfileHostPath, filepath.Join(workspace, "Dockerfile"))
	} else {
		log("FAIL", "Dockerfile missing: "+dockerfileHostPath)
		if enforcementEnabled && verdict == "BLOCK" {
			printSection("BUILD BLOCKED (QUARANTINE FAILED)")
			fmt.Printf("  Verdict:        BLOCK\n")
			fmt.Printf("  Action:         quarantine image creation failed (Dockerfile missing), not deployed\n")
			fmt.Printf("  Reason:         policy violation detected\n")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"status":"blocked","build_id":"%s","verdict":"BLOCK","quarantine":"failed","error":"quarantine Dockerfile missing"}`+"\n", buildID)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"status":"error","build_id":"%s","verdict":"%s","error":"Dockerfile missing"}`+"\n", buildID, verdict)
		return
	}
	out, err := execHost("docker", "build", "-t", imageName, workspace)
	log("DOCKER BUILD", filterDockerOutput(out))
	if err != nil {
		log("FAIL", "Docker build failed: "+err.Error())
		if enforcementEnabled && verdict == "BLOCK" {
			printSection("BUILD BLOCKED (QUARANTINE FAILED)")
			fmt.Printf("  Verdict:        BLOCK\n")
			fmt.Printf("  Action:         quarantine image build failed, not deployed\n")
			fmt.Printf("  Reason:         policy violation detected; code failed container compilation\n")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"status":"blocked","build_id":"%s","verdict":"BLOCK","quarantine":"failed","error":"quarantine build failed: compilation/build error"}`+"\n", buildID)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"status":"error","build_id":"%s","verdict":"%s","error":"Docker build failed"}`+"\n", buildID, verdict)
		return
	}

	// Quarantine path: build succeeded but verdict is BLOCK and quarantine is on
	if enforcementEnabled && verdict == "BLOCK" && quarantineEnabled {
		quarantineTag := imageName + "-quarantine"
		log("QUARANTINE", "Tagging image as "+quarantineTag)
		execHost("docker", "tag", imageName, quarantineTag)
		out, err := execHost("docker", "push", quarantineTag)
		log("QUARANTINE", filterDockerOutput(out))
		if err != nil {
			log("QUARANTINE", "Push failed: "+err.Error())
		}
		printSection("BUILD QUARANTINED")
		fmt.Printf("  Verdict:        BLOCK\n")
		fmt.Printf("  Action:         image quarantined, not deployed\n")
		fmt.Printf("  Quarantine tag: %s\n", quarantineTag)
		fmt.Printf("  Reason:         policy violation detected\n")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"status":"quarantined","build_id":"%s","verdict":"BLOCK","tag":"%s"}`+"\n", buildID, quarantineTag)
		return
	}

	log("PUBLISH", fmt.Sprintf("Pushing %s ...", imageName))
	out, err = execHost("docker", "push", imageName)
	log("PUBLISH", filterDockerOutput(out))
	if err != nil {
		log("FAIL", "Docker push failed: "+err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"status":"error","build_id":"%s","verdict":"%s","error":"Docker push failed"}`+"\n", buildID, verdict)
		return
	}

	log("DEPLOY", "Starting application container...")
	execHost("fuser", "-k", strings.Split(deployPort, ":")[0]+"/tcp")
	execHost("docker", "rm", "-f", appName)
	out, _ = execHost("docker", "run", "-d", "--name", appName, "-p", deployPort, imageName)
	log("DEPLOY", out)

	if buildContainer != "" {
		execHost("docker", "rm", "-f", buildContainer)
		log("CLEANUP", "Build container removed")
	}

	printSection("Final Summary")
	fmt.Printf("  Project:        %s\n", projectName)
	fmt.Printf("  Build ID:       %s\n", buildID)
	fmt.Printf("  Process Tree:   %s\n", colorStatus(processStatus))
	fmt.Printf("  Filesystem:     %s\n", colorStatus(fileStatus))
	fmt.Printf("  Build:          %s\n", colorStatus("SUCCESS"))
	fmt.Printf("  Mode:           %s\n", colorStatus("DETECTION ONLY"))
	fmt.Printf("  Enforcement:    %s\n", colorStatus("DISABLED"))
	fmt.Println()

	result := BuildResult{
		Status:  "pass",
		Log:     logStr,
		BuildID: buildID,
		Image:   imageName,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open tarball: %w", err)
	}
	defer f.Close()

	st, _ := f.Stat()
	if st != nil {
	}

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		cleanDst := filepath.Clean(dst)
		target := filepath.Join(cleanDst, hdr.Name)
		if target != cleanDst && !strings.HasPrefix(target, cleanDst+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path in tar: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", target, err)
			}
			out, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("create %s: %w", target, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("write %s: %w", target, err)
			}
			out.Close()
		}
	}
	return nil
}

func copyFile(src, dst string) {
	in, _ := os.Open(src)
	defer in.Close()
	out, _ := os.Create(dst)
	defer out.Close()
	io.Copy(out, in)
}

func findCgroup(containerName string) string {
	idBytes, _ := exec.Command("docker", "inspect", "-f", "{{.Id}}", containerName).Output()
	id := strings.TrimSpace(string(idBytes))
	if id == "" {
		return "/sys/fs/cgroup/pipejack"
	}
	path, _ := exec.Command("sh", "-c",
		`find /sys/fs/cgroup -name "docker-`+id+`*.scope" -type d 2>/dev/null | head -1`).Output()
	cgPath := strings.TrimSpace(string(path))
	if cgPath == "" {
		cgPath = "/sys/fs/cgroup/pipejack"
	}
	return cgPath
}

var execHost = func(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func policyQuarantine(policyPath string) bool {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return false
	}
	var p struct {
		ActionsOnViolation struct {
			Quarantine bool `yaml:"quarantine"`
		} `yaml:"actions_on_violation"`
	}
	if err := yaml.Unmarshal(data, &p); err != nil {
		return false
	}
	return p.ActionsOnViolation.Quarantine
}

func extractNetworkViolations(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "NETWORK VIOLATION:") {
			out = append(out, t)
		}
	}
	return out
}

func extractEgressLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Egress firewall") || strings.Contains(t, "PIPEJACK_EGRESS") {
			out = append(out, t)
		}
	}
	return out
}

func extractPIPEJACKBinaries(s string) []string {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "PIPEJACK_BINARIES:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(t, "PIPEJACK_BINARIES:"))
		if val == "" {
			return nil
		}
		parts := strings.Split(val, ",")
		var out []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

func readAnomalyConfig(policyPath string) anomaly.Config {
	cfg := anomaly.Config{
		Enabled:     true,
		Threshold:   3.0,
		MinBaseline: 5,
		MaxBuilds:   20,
		Block:       false,
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return cfg
	}
	var p struct {
		AnomalyEnabled     *bool    `yaml:"anomaly_enabled"`
		AnomalyThreshold   *float64 `yaml:"anomaly_threshold"`
		AnomalyMinBaseline *int     `yaml:"anomaly_min_baseline"`
		AnomalyBlock       *bool    `yaml:"anomaly_block"`
	}
	if err := yaml.Unmarshal(data, &p); err != nil {
		return cfg
	}
	if p.AnomalyEnabled != nil {
		cfg.Enabled = *p.AnomalyEnabled
	}
	if p.AnomalyThreshold != nil {
		cfg.Threshold = *p.AnomalyThreshold
	}
	if p.AnomalyMinBaseline != nil {
		cfg.MinBaseline = *p.AnomalyMinBaseline
	}
	if p.AnomalyBlock != nil {
		cfg.Block = *p.AnomalyBlock
	}
	return cfg
}
