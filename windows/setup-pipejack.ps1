#Requires -Version 5.1
<#
.SYNOPSIS
    PipeJack Master Windows Orchestrator

.DESCRIPTION
    Automates the transfer, installation, and end-to-end verification of the
    PipeJack two-node Zero-Trust CI/CD pipeline on Ubuntu VMware virtual machines.

    DRY-RUN BEHAVIOR:
    When -DryRun is specified, the script operates strictly in read-only audit mode:
    - Preflight checks (connectivity and SSH reachability) are performed read-only.
    - No remote directories are created or modified.
    - No package transfers (SCP) are initiated.
    - No remote installation scripts or system modifications are executed.
    - No services are restarted or changed.
    - A detailed execution preview is displayed showing all actions that would be
      taken during a live deployment.

.PARAMETER VM1_IP
    IP address of VM1 (Developer / Workload Client). Default: 192.168.88.132

.PARAMETER VM2_IP
    IP address of VM2 (Security Orchestrator / CI Server). Default: 192.168.88.133

.PARAMETER SSHUser
    SSH username. Default: ubuntu

.PARAMETER SSHKey
    Optional private SSH key file path.

.PARAMETER SSHPort
    SSH port. Default: 22

.PARAMETER KitDir
    Path to root of deployment kit. Default: parent of script directory.

.PARAMETER DryRun
    Runs in preview/dry-run mode without modifying VM state, creating files,
    transferring archives, or executing installation commands.

.PARAMETER SkipVM1
    Skip installation on VM1.

.PARAMETER SkipVM2
    Skip installation on VM2.

.PARAMETER SkipPreflight
    Skip initial preflight checks.

.PARAMETER SkipVerify
    Skip post-deployment verification.

.PARAMETER InteractiveSudo
    Allocates an interactive pseudo-terminal (ssh -t) during installer execution
    to allow entering a sudo password interactively when passwordless sudo is not configured.

.PARAMETER Force
    Bypass interactive deployment confirmation.
#>

[CmdletBinding()]
param(
    [string]$VM1_IP = "192.168.88.132",
    [string]$VM2_IP = "192.168.88.133",
    [string]$SSHUser = "ubuntu",
    [string]$SSHKey = "",
    [int]$SSHPort = 22,
    [string]$KitDir = "",
    [switch]$DryRun,
    [switch]$SkipVM1,
    [switch]$SkipVM2,
    [switch]$SkipPreflight,
    [switch]$SkipVerify,
    [switch]$InteractiveSudo,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PIPEJACK TWO-VM AUTOMATED DEPLOYMENT ORCHESTRATOR" -ForegroundColor Cyan
Write-Host " Host OS: Microsoft Windows | Target: Ubuntu VMware VMs" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Path Resolution
if (-not $KitDir) {
    $KitDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

$ModeString = if ($DryRun) { 'DRY-RUN / PREVIEW (NON-MODIFYING)' } else { 'LIVE DEPLOYMENT' }

Write-Host "[+] Local Kit Root: $KitDir"
Write-Host "    Target VM1 (Client):       $SSHUser@$VM1_IP"
Write-Host "    Target VM2 (Orchestrator): $SSHUser@$VM2_IP"
Write-Host "    Mode:                      $ModeString"
Write-Host "    Interactive Sudo:          $([string]$InteractiveSudo)"

# 2. Preflight Check (Read-only connectivity and environment inspection)
if (-not $SkipPreflight) {
    Write-Host "`n[+] Executing Preflight Checks..."
    $PreflightScript = Join-Path $PSScriptRoot "preflight.ps1"
    $pfParams = @{
        VM1_IP  = $VM1_IP
        VM2_IP  = $VM2_IP
        SSHUser = $SSHUser
        SSHPort = $SSHPort
        KitDir  = $KitDir
    }
    if ($SSHKey) { $pfParams["SSHKey"] = $SSHKey }

    & $PreflightScript @pfParams
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Deployment aborted due to preflight failure." -ForegroundColor Red
        exit 1
    }
}

# 3. Dry-Run Preview Mode
if ($DryRun) {
    Write-Host "`n============================================================" -ForegroundColor Yellow
    Write-Host " DRY-RUN PREVIEW: NO REMOTE MODIFICATIONS PERFORMED" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host " The following operations would be performed in a live deployment:`n"

    if (-not $SkipVM2) {
        Write-Host " [Phase 1: VM2 Security Orchestrator ($VM2_IP)]" -ForegroundColor Cyan
        Write-Host "   * Staging:  Create isolated directory /tmp/pipejack-deploy-<timestamp>-<pid>-vm2"
        Write-Host "   * Transfer: SCP '$KitDir\vm2' -> '$SSHUser@${VM2_IP}:/tmp/pipejack-deploy-...-vm2/'"
        Write-Host "   * Execute:  bash /tmp/pipejack-deploy-...-vm2/install.sh"
        Write-Host "   * Tasks:    Install Go toolchain (1.23+), build pipejack-ci binary, initialize Ed25519"
        Write-Host "               signing key, install pipejack-ci.service and pipejack-demo-console.service,"
        Write-Host "               start registry:2 Docker container (:5000), enable systemd units."
        Write-Host "   * Cleanup:  Remove temporary staging directory created by this deployment."
    }

    if (-not $SkipVM1) {
        Write-Host "`n [Phase 2: VM1 Workload Client ($VM1_IP)]" -ForegroundColor Cyan
        Write-Host "   * Staging:  Create isolated directory /tmp/pipejack-deploy-<timestamp>-<pid>-vm1"
        Write-Host "   * Transfer: SCP '$KitDir\vm1' -> '$SSHUser@${VM1_IP}:/tmp/pipejack-deploy-...-vm1/'"
        Write-Host "   * Execute:  bash /tmp/pipejack-deploy-...-vm1/install.sh --ci-endpoint http://${VM2_IP}:8888/upload"
        Write-Host "   * Tasks:    Install client tools (git, curl, jq, nodejs, python3), deploy applications,"
        Write-Host "               attacks suite, security fixtures, and configure pipejack-upload.sh."
        Write-Host "   * Cleanup:  Remove temporary staging directory created by this deployment."
    }

    if (-not $SkipVerify) {
        Write-Host "`n [Phase 3: Post-Deployment Verification]" -ForegroundColor Cyan
        Write-Host "   * Probe CI endpoint:       http://${VM2_IP}:8888/health (expect status: 'ok')"
        Write-Host "   * Probe Demo Console:      http://${VM2_IP}:8090/api/status (expect ci_healthy: true)"
        Write-Host "   * Probe Docker Registry:   http://${VM2_IP}:5000/v2/ (expect HTTP 200)"
        Write-Host "   * End-to-end Upload Test:  Execute sample workload upload from VM1 and verify"
        Write-Host "                              cryptographically signed attestation record in VM2 ledger."
    }

    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host " DRY-RUN PREVIEW COMPLETED: System state is completely unchanged." -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    exit 0
}

# 4. User Confirmation for Live Deployment
if (-not $Force) {
    Write-Host "`n[?] Proceed with transferring packages and executing installation on both VMs? [Y/N]: " -NoNewline -ForegroundColor Yellow
    $ans = Read-Host
    if ($ans -notmatch "^[Yy]$") {
        Write-Host "[-] Deployment cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# SSH & SCP Execution Helpers using Argument Arrays
$SSHKeyArgs = @()
if ($SSHKey -and (Test-Path $SSHKey)) {
    $SSHKeyArgs = @("-i", $SSHKey)
}

function Invoke-RemoteCommand {
    param(
        [string]$IP,
        [string]$Command,
        [string]$Description,
        [switch]$Interactive
    )
    Write-Host "`n[+] $Description on $IP..." -ForegroundColor Cyan
    $Target = "$SSHUser@$IP"
    $CommonArgs = @(
        "-p", [string]$SSHPort,
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new"
    )
    if ($Interactive -or $InteractiveSudo) {
        $CommonArgs += @("-t")
    } else {
        $CommonArgs += @("-o", "BatchMode=yes")
    }

    $CommonArgs += $SSHKeyArgs + @($Target, $Command)

    & "ssh.exe" @CommonArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host "[-] Command failed on $IP (Exit Code: $code)" -ForegroundColor Red
        throw "Remote command execution failed on $IP with exit code $code"
    }
    Write-Host "  [OK] $Description succeeded." -ForegroundColor Green
}

function Test-RemoteSudo {
    param(
        [string]$IP
    )
    $Target = "$SSHUser@$IP"
    $TestCmd = "sudo -n true 2>/dev/null"
    $CommonArgs = @(
        "-p", [string]$SSHPort,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=accept-new"
    )
    if ($SSHKey -and (Test-Path $SSHKey)) {
        $CommonArgs += @("-i", $SSHKey)
    }
    $CommonArgs += @($Target, $TestCmd)

    & "ssh.exe" @CommonArgs 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Send-RemotePackage {
    param(
        [string]$IP,
        [string]$LocalSourceDir,
        [string]$RemoteTargetDir
    )
    Write-Host "`n[+] Transferring $(Split-Path $LocalSourceDir -Leaf) -> $SSHUser@${IP}:${RemoteTargetDir}..."

    # Create the isolated, uniquely owned staging directory
    $InitCmd = "mkdir -m 0700 -p '$RemoteTargetDir'"
    Invoke-RemoteCommand -IP $IP -Command $InitCmd -Description "Creating isolated staging directory"

    $Target = "$SSHUser@${IP}:${RemoteTargetDir}/"
    $ScpArgs = @(
        "-P", [string]$SSHPort,
        "-r",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new"
    ) + $SSHKeyArgs + @($LocalSourceDir, $Target)

    & "scp.exe" @ScpArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host "[-] SCP Transfer failed for $IP (Exit Code: $code)" -ForegroundColor Red
        throw "SCP transfer error to $IP with exit code $code"
    }
    Write-Host "  [OK] Transfer completed." -ForegroundColor Green
}

function Remove-RemoteStaging {
    param(
        [string]$IP,
        [string]$RemoteStagingDir
    )
    # Safely verify path matches pattern and belongs to current user before removal
    $SafeCleanCmd = "if [ -d '$RemoteStagingDir' ] && echo '$RemoteStagingDir' | grep -q '^/tmp/pipejack-deploy-' && [ `$(id -u) -eq `$(stat -c '%u' '$RemoteStagingDir' 2>/dev/null || echo -1) ]; then rm -rf '$RemoteStagingDir'; fi"
    try {
        Invoke-RemoteCommand -IP $IP -Command $SafeCleanCmd -Description "Cleaning isolated staging directory"
    } catch {
        Write-Host "  [!] Staging cleanup notice: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Unique Deployment Staging Identifiers
$DeployTimestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$VM2_Staging = "/tmp/pipejack-deploy-$DeployTimestamp-$PID-vm2"
$VM1_Staging = "/tmp/pipejack-deploy-$DeployTimestamp-$PID-vm1"

try {
    # 5. Deploy VM2 (Server Orchestrator first)
    if (-not $SkipVM2) {
        Write-Host "`n============================================================" -ForegroundColor Cyan
        Write-Host " PHASE 1: DEPLOYING VM2 (ORCHESTRATOR & CI SERVER)" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan

        # Validate privilege escalation requirement before initiating transfer
        $vm2SudoOk = Test-RemoteSudo -IP $VM2_IP
        if (-not $vm2SudoOk) {
            if (-not $InteractiveSudo) {
                Write-Host "`n[-] PREFLIGHT PRIVILEGE ERROR: Remote user '$SSHUser' on $VM2_IP requires interactive password authentication for sudo." -ForegroundColor Red
                Write-Host "    Deployment requires elevated privileges. Either:" -ForegroundColor Yellow
                Write-Host "    1. Configure passwordless sudo on ${VM2_IP}:" -ForegroundColor Gray
                Write-Host "       echo '$SSHUser ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/99-pipejack" -ForegroundColor Gray
                Write-Host "    2. Run setup-pipejack.ps1 with -InteractiveSudo to prompt for your sudo password via ssh -t." -ForegroundColor Gray
                throw "Sudo privilege escalation error on ${VM2_IP}: password required but -InteractiveSudo was not specified."
            } else {
                Write-Host "`n[!] Notice: Interactive sudo mode active. You may be prompted for your remote sudo password on $VM2_IP." -ForegroundColor Yellow
            }
        }

        $VM2_Local = Join-Path $KitDir "vm2"
        Send-RemotePackage -IP $VM2_IP -LocalSourceDir $VM2_Local -RemoteTargetDir $VM2_Staging

        $VM2_Cmd = "chmod +x '$VM2_Staging/vm2/install.sh' && bash '$VM2_Staging/vm2/install.sh'"
        Invoke-RemoteCommand -IP $VM2_IP -Command $VM2_Cmd -Description "Executing VM2 Installer" -Interactive:$InteractiveSudo

        # Clean staging directory owned by this deployment attempt
        Remove-RemoteStaging -IP $VM2_IP -RemoteStagingDir $VM2_Staging
    }

    # 6. Deploy VM1 (Client / Developer Node)
    if (-not $SkipVM1) {
        Write-Host "`n============================================================" -ForegroundColor Cyan
        Write-Host " PHASE 2: DEPLOYING VM1 (WORKLOAD CLIENT & ATTACKS)" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan

        # Validate privilege escalation requirement before initiating transfer
        $vm1SudoOk = Test-RemoteSudo -IP $VM1_IP
        if (-not $vm1SudoOk) {
            if (-not $InteractiveSudo) {
                Write-Host "`n[-] PREFLIGHT PRIVILEGE ERROR: Remote user '$SSHUser' on $VM1_IP requires interactive password authentication for sudo." -ForegroundColor Red
                Write-Host "    Deployment requires elevated privileges. Either:" -ForegroundColor Yellow
                Write-Host "    1. Configure passwordless sudo on ${VM1_IP}:" -ForegroundColor Gray
                Write-Host "       echo '$SSHUser ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/99-pipejack" -ForegroundColor Gray
                Write-Host "    2. Run setup-pipejack.ps1 with -InteractiveSudo to prompt for your sudo password via ssh -t." -ForegroundColor Gray
                throw "Sudo privilege escalation error on ${VM1_IP}: password required but -InteractiveSudo was not specified."
            } else {
                Write-Host "`n[!] Notice: Interactive sudo mode active. You may be prompted for your remote sudo password on $VM1_IP." -ForegroundColor Yellow
            }
        }

        $VM1_Local = Join-Path $KitDir "vm1"
        Send-RemotePackage -IP $VM1_IP -LocalSourceDir $VM1_Local -RemoteTargetDir $VM1_Staging

        $VM1_Cmd = "chmod +x '$VM1_Staging/vm1/install.sh' && bash '$VM1_Staging/vm1/install.sh' --ci-endpoint 'http://${VM2_IP}:8888/upload'"
        Invoke-RemoteCommand -IP $VM1_IP -Command $VM1_Cmd -Description "Executing VM1 Installer" -Interactive:$InteractiveSudo

        # Clean staging directory owned by this deployment attempt
        Remove-RemoteStaging -IP $VM1_IP -RemoteStagingDir $VM1_Staging
    }

    # 7. Post-Deployment Verification
    if (-not $SkipVerify) {
        Write-Host "`n============================================================" -ForegroundColor Cyan
        Write-Host " PHASE 3: END-TO-END VERIFICATION" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan

        $VerifyScript = Join-Path $PSScriptRoot "verify-pipejack.ps1"
        $vParams = @{
            VM1_IP  = $VM1_IP
            VM2_IP  = $VM2_IP
            SSHUser = $SSHUser
        }
        if ($SSHKey) { $vParams["SSHKey"] = $SSHKey }

        & $VerifyScript @vParams
        if ($LASTEXITCODE -ne 0) {
            throw "Post-deployment verification reported failure."
        }
    }

    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " PIPEJACK TWO-VM DEPLOYMENT ORCHESTRATION COMPLETED" -ForegroundColor Green
    Write-Host " Web Demo Console:   http://${VM2_IP}:8090" -ForegroundColor Cyan
    Write-Host " CI Upload Endpoint: http://${VM2_IP}:8888/upload" -ForegroundColor Cyan
    Write-Host " Local Registry:     http://${VM2_IP}:5000" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0

} catch {
    Write-Host "`n[-] DEPLOYMENT FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    exit 1
}

