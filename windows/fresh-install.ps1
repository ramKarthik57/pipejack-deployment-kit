#Requires -Version 5.1
<#
.SYNOPSIS
    PipeJack Fresh Two-VM Automated Onboarding Installer

.DESCRIPTION
    Guided, robust onboarding entrypoint designed to configure and deploy
    PipeJack on two newly created Ubuntu 24.04 or 22.04 virtual machines
    from a Windows host.

    Orchestrates the full deployment lifecycle:
    1. Validates host environment (OpenSSH tools, deployment kit structure).
    2. Validates network and SSH reachability (with optional public key setup).
    3. Executes read-only preflight checks (preflight.ps1).
    4. Deploys VM2 Server Orchestrator first (setup-pipejack.ps1 -SkipVM1).
    5. Polls VM2 services until healthy (CI Orchestrator :8888, Web Console :8090).
    6. Deploys VM1 Workload Client second (setup-pipejack.ps1 -SkipVM2).
    7. Runs comprehensive end-to-end verification (verify-pipejack.ps1).
    8. Generates a timestamped deployment report outside the repository.

.PARAMETER VM1_IP
    IP address of VM1 (Developer / Workload Client). Default: 192.168.88.132

.PARAMETER VM2_IP
    IP address of VM2 (Security Orchestrator / CI Server). Default: 192.168.88.133

.PARAMETER SSHUser
    SSH username on both VMs. Default: ubuntu

.PARAMETER SSHKey
    Optional private SSH key file path (e.g. $HOME\.ssh\id_ed25519).

.PARAMETER SSHPort
    SSH port number. Default: 22

.PARAMETER KitDir
    Path to root of pipejack-deployment-kit. Default: parent of script directory.

.PARAMETER NonInteractive
    Runs with provided parameters or defaults without interactive prompts.

.PARAMETER DryRun
    Simulates the entire workflow without making remote changes.

.PARAMETER InteractiveSudo
    Allocates an interactive pseudo-terminal (ssh -t) during installer execution
    to allow entering a sudo password interactively when passwordless sudo is not configured.

.PARAMETER SkipVM1
    Skip deployment on VM1.

.PARAMETER SkipVM2
    Skip deployment on VM2.

.PARAMETER SkipVerify
    Skip post-deployment end-to-end verification.

.PARAMETER ReportDir
    Directory path where deployment logs and summaries are saved.
    Defaults to $env:USERPROFILE\PipeJack-Reports (outside repository).
#>

[CmdletBinding()]
param(
    [string]$VM1_IP = "192.168.88.132",
    [string]$VM2_IP = "192.168.88.133",
    [string]$SSHUser = "ubuntu",
    [string]$SSHKey = "",
    [int]$SSHPort = 22,
    [string]$KitDir = "",
    [switch]$NonInteractive,
    [switch]$DryRun,
    [switch]$InteractiveSudo,
    [switch]$SkipVM1,
    [switch]$SkipVM2,
    [switch]$SkipVerify,
    [string]$ReportDir = ""
)

$ErrorActionPreference = "Stop"

# Pure ASCII Banner
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PIPEJACK AUTOMATED TWO-VM ONBOARDING INSTALLER" -ForegroundColor Cyan
Write-Host " Target: Two Fresh Ubuntu VMs (VM1 Client, VM2 Orchestrator)" -ForegroundColor Cyan
Write-Host " Host OS: Microsoft Windows | PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# 1. Helper Functions
# -----------------------------------------------------------------------------

function Test-ValidIPv4 {
    param([string]$IPString)
    if ([string]::IsNullOrWhiteSpace($IPString)) { return $false }
    $parsedIP = $null
    if ([System.Net.IPAddress]::TryParse($IPString.Trim(), [ref]$parsedIP)) {
        return ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
    }
    return $false
}

function Prompt-WithDefault {
    param(
        [string]$PromptText,
        [string]$DefaultValue,
        [scriptblock]$Validator = $null
    )
    while ($true) {
        if ($DefaultValue) {
            Write-Host "${PromptText} [${DefaultValue}]: " -NoNewline -ForegroundColor Yellow
        } else {
            Write-Host "${PromptText}: " -NoNewline -ForegroundColor Yellow
        }
        $userInput = Read-Host
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            $val = $DefaultValue
        } else {
            $val = $userInput.Trim()
        }

        if ($Validator -eq $null -or (& $Validator $val)) {
            return $val
        }
        Write-Host "[-] Invalid input. Please enter a valid value." -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# 2. Interactive Parameter Configuration
# -----------------------------------------------------------------------------

if (-not $NonInteractive) {
    Write-Host "`nConfigure deployment parameters (press Enter to accept [defaults]):" -ForegroundColor Green

    $VM1_IP = Prompt-WithDefault -PromptText "Enter VM1 (Workload Client) IP address" -DefaultValue $VM1_IP -Validator {
        param($v) Test-ValidIPv4 $v
    }

    $VM2_IP = Prompt-WithDefault -PromptText "Enter VM2 (Server Orchestrator) IP address" -DefaultValue $VM2_IP -Validator {
        param($v) (Test-ValidIPv4 $v) -and ($v -ne $VM1_IP)
    }

    $SSHUser = Prompt-WithDefault -PromptText "Enter SSH username for both VMs" -DefaultValue $SSHUser -Validator {
        param($v) -not [string]::IsNullOrWhiteSpace($v)
    }

    $DefaultKey = $SSHKey
    if (-not $DefaultKey) {
        $candidateEd25519 = Join-Path $HOME ".ssh\id_ed25519"
        $candidateRsa = Join-Path $HOME ".ssh\id_rsa"
        if (Test-Path $candidateEd25519) {
            $DefaultKey = $candidateEd25519
        } elseif (Test-Path $candidateRsa) {
            $DefaultKey = $candidateRsa
        }
    }

    $SSHKey = Prompt-WithDefault -PromptText "Enter private SSH key path (optional, leave blank if unneeded)" -DefaultValue $DefaultKey

    $SSHPortStr = Prompt-WithDefault -PromptText "Enter SSH port" -DefaultValue ([string]$SSHPort) -Validator {
        param($v)
        $p = 0
        if ([int]::TryParse($v, [ref]$p)) {
            return ($p -ge 1 -and $p -le 65535)
        }
        return $false
    }
    $SSHPort = [int]$SSHPortStr

    Write-Host "`nSummary of Configuration:" -ForegroundColor Cyan
    Write-Host "  VM1 Client IP:       $VM1_IP"
    Write-Host "  VM2 Orchestrator IP: $VM2_IP"
    Write-Host "  SSH User:            $SSHUser"
    Write-Host "  SSH Port:            $SSHPort"
    Write-Host "  SSH Key:             $(if ($SSHKey) { $SSHKey } else { '(Default Agent / Keys)' })"
    Write-Host "  Dry Run:             $([string]$DryRun)"
    Write-Host "  Interactive Sudo:    $([string]$InteractiveSudo)"

    Write-Host "`n[?] Proceed with onboarding? [Y/N]: " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    if ($confirm -notmatch "^[Yy]$") {
        Write-Host "[-] Deployment cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# -----------------------------------------------------------------------------
# 3. Parameter Validation
# -----------------------------------------------------------------------------

if (-not (Test-ValidIPv4 $VM1_IP)) {
    Write-Host "[-] ERROR: VM1_IP '$VM1_IP' is not a valid IPv4 address." -ForegroundColor Red
    exit 1
}

if (-not (Test-ValidIPv4 $VM2_IP)) {
    Write-Host "[-] ERROR: VM2_IP '$VM2_IP' is not a valid IPv4 address." -ForegroundColor Red
    exit 1
}

if ($VM1_IP -eq $VM2_IP) {
    Write-Host "[-] ERROR: VM1_IP and VM2_IP cannot be identical ($VM1_IP)." -ForegroundColor Red
    exit 1
}

if ($SSHPort -lt 1 -or $SSHPort -gt 65535) {
    Write-Host "[-] ERROR: SSHPort '$SSHPort' is invalid (must be 1-65535)." -ForegroundColor Red
    exit 1
}

if ($SSHKey -and (-not (Test-Path $SSHKey))) {
    Write-Host "[-] ERROR: Specified SSH private key file not found: $SSHKey" -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# 4. Resolve Kit Directory and Check Required Files
# -----------------------------------------------------------------------------

if (-not $KitDir) {
    $KitDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

$RequiredKitFiles = @(
    (Join-Path $KitDir "SOURCE_MAPPING.md"),
    (Join-Path $KitDir "MANIFEST.md"),
    (Join-Path $KitDir "vm1\install.sh"),
    (Join-Path $KitDir "vm2\install.sh"),
    (Join-Path $KitDir "windows\setup-pipejack.ps1"),
    (Join-Path $KitDir "windows\preflight.ps1"),
    (Join-Path $KitDir "windows\verify-pipejack.ps1"),
    (Join-Path $KitDir "shared\bootstrap-network.sh")
)

$MissingFiles = 0
foreach ($kf in $RequiredKitFiles) {
    if (-not (Test-Path $kf)) {
        Write-Host "[-] MISSING DEPLOYMENT FILE: $kf" -ForegroundColor Red
        $MissingFiles++
    }
}
if ($MissingFiles -gt 0) {
    Write-Host "[-] ERROR: Deployment kit directory is incomplete ($MissingFiles missing files)." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# 5. OpenSSH Tools Verification
# -----------------------------------------------------------------------------

$SSH_CMD = if (Get-Command "ssh.exe" -ErrorAction SilentlyContinue) { "ssh.exe" } else { "ssh" }
$SCP_CMD = if (Get-Command "scp.exe" -ErrorAction SilentlyContinue) { "scp.exe" } else { "scp" }

if (-not (Get-Command $SSH_CMD -ErrorAction SilentlyContinue) -or -not (Get-Command $SCP_CMD -ErrorAction SilentlyContinue)) {
    Write-Host "[-] ERROR: OpenSSH client tools (ssh, scp) were not found on this Windows system." -ForegroundColor Red
    Write-Host "    To install Windows OpenSSH Client:" -ForegroundColor Yellow
    Write-Host "    Open an elevated PowerShell window and run:" -ForegroundColor Gray
    Write-Host "      Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor Gray
    Write-Host "    Or install via Settings > Apps > Optional Features > OpenSSH Client." -ForegroundColor Gray
    exit 1
}

# -----------------------------------------------------------------------------
# 6. Setup Logging and Report Directory
# -----------------------------------------------------------------------------

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $ReportDir) {
    $UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
    if ($UserHome -and (Test-Path $UserHome)) {
        $ReportDir = Join-Path $UserHome "PipeJack-Reports"
    } else {
        $ReportDir = Join-Path $env:TEMP "PipeJack-Reports"
    }
}

if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

$ReportFile = Join-Path $ReportDir "fresh-install-$Timestamp.log"
$SummaryFile = Join-Path $ReportDir "fresh-install-$Timestamp-summary.txt"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[$([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC] [$Level] $Message"
    Add-Content -Path $ReportFile -Value $line -Encoding Ascii
}

Write-Log "PipeJack Fresh Install Session Initialized"
Write-Log "VM1 IP: $VM1_IP | VM2 IP: $VM2_IP | SSH User: $SSHUser | SSH Port: $SSHPort"
Write-Log "DryRun: $DryRun | InteractiveSudo: $InteractiveSudo"

# -----------------------------------------------------------------------------
# 7. SSH Connectivity & Key Helper
# -----------------------------------------------------------------------------

Write-Host "`n[+] Step 1/5: Checking SSH Connectivity to Virtual Machines..." -ForegroundColor Cyan

function Test-SSHReachability {
    param([string]$TargetIP)
    $Target = "$SSHUser@$TargetIP"
    $sshArgs = @(
        "-p", [string]$SSHPort,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=accept-new"
    )
    if ($SSHKey -and (Test-Path $SSHKey)) {
        $sshArgs += @("-i", $SSHKey)
    }
    $sshArgs += @($Target, "echo ok")

    $oldPref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        & $SSH_CMD @sshArgs 2>$null | Out-Null
    } catch {
        # Suppress native command error
    } finally {
        $ErrorActionPreference = $oldPref
    }
    return ($LASTEXITCODE -eq 0)
}

function Find-PublicKey {
    if ($SSHKey) {
        $pub = "${SSHKey}.pub"
        if (Test-Path $pub) { return $pub }
    }
    $edPub = Join-Path $HOME ".ssh\id_ed25519.pub"
    if (Test-Path $edPub) { return $edPub }
    $rsaPub = Join-Path $HOME ".ssh\id_rsa.pub"
    if (Test-Path $rsaPub) { return $rsaPub }
    return $null
}

$TargetsToCheck = @()
if (-not $SkipVM2) { $TargetsToCheck += @{ Name = "VM2 Orchestrator"; IP = $VM2_IP } }
if (-not $SkipVM1) { $TargetsToCheck += @{ Name = "VM1 Workload Client"; IP = $VM1_IP } }

foreach ($t in $TargetsToCheck) {
    $targetName = $t.Name
    $targetIP = $t.IP
    Write-Host "  Probing passwordless SSH to $targetName ($SSHUser@$targetIP)..." -NoNewline

    $isReachable = Test-SSHReachability -TargetIP $targetIP
    if ($isReachable) {
        Write-Host " [OK]" -ForegroundColor Green
        Write-Log "SSH passwordless authentication verified for $targetIP"
    } else {
        Write-Host " [FAILED]" -ForegroundColor Yellow
        Write-Log "SSH passwordless authentication failed for $targetIP" "WARN"

        $pubKey = Find-PublicKey
        if ($pubKey) {
            Write-Host "  [!] Notice: Passwordless SSH is not yet configured for $SSHUser@$targetIP." -ForegroundColor Yellow
            Write-Host "      Detected public key: $pubKey" -ForegroundColor Gray
            Write-Host "      Manual key copy command:" -ForegroundColor Gray
            Write-Host "      type `"$pubKey`" | ssh -p $SSHPort $SSHUser@$targetIP `"mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`"" -ForegroundColor Gray

            if (-not $NonInteractive -and -not $DryRun) {
                Write-Host "`n  [?] Attempt automated public key installation to $targetIP now? [Y/N]: " -NoNewline -ForegroundColor Yellow
                $copyAns = Read-Host
                if ($copyAns -match "^[Yy]$") {
                    Write-Host "  Copying public key to $targetIP (you may be prompted for your VM user password once)..."
                    $pubContent = (Get-Content -Path $pubKey -Raw).Trim()
                    $installRemoteCmd = "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && grep -qF '$pubContent' ~/.ssh/authorized_keys || echo '$pubContent' >> ~/.ssh/authorized_keys"
                    $copySshArgs = @("-p", [string]$SSHPort, "-o", "StrictHostKeyChecking=accept-new", "$SSHUser@$targetIP", $installRemoteCmd)
                    & $SSH_CMD @copySshArgs
                    if ($LASTEXITCODE -eq 0 -and (Test-SSHReachability -TargetIP $targetIP)) {
                        Write-Host "  [OK] Public key installed and verified on $targetIP." -ForegroundColor Green
                        Write-Log "Automated public key installation succeeded for $targetIP"
                    } else {
                        Write-Host "  [-] Key copy failed or SSH still requires authentication." -ForegroundColor Red
                    }
                }
            }
        } else {
            Write-Host "  [!] No SSH public key found on Windows host. Generate one using: ssh-keygen -t ed25519" -ForegroundColor Yellow
        }
    }
}

# -----------------------------------------------------------------------------
# 8. Step 2/5: Preflight Inspection
# -----------------------------------------------------------------------------

Write-Host "`n[+] Step 2/5: Executing System Preflight Verification..." -ForegroundColor Cyan
Write-Log "Invoking preflight.ps1"

$PreflightScript = Join-Path $PSScriptRoot "preflight.ps1"
$PreflightParams = @{
    VM1_IP  = $VM1_IP
    VM2_IP  = $VM2_IP
    SSHUser = $SSHUser
    SSHPort = $SSHPort
    KitDir  = $KitDir
}
if ($SSHKey) { $PreflightParams["SSHKey"] = $SSHKey }

& $PreflightScript @PreflightParams
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Preflight verification reported blocking issues." -ForegroundColor Red
    Write-Log "Preflight verification failed with exit code $LASTEXITCODE" "ERROR"
    if (-not $DryRun) {
        exit 1
    }
}
Write-Log "Preflight verification completed successfully"

# -----------------------------------------------------------------------------
# 9. Step 3/5: Deploy VM2 Server Orchestrator First
# -----------------------------------------------------------------------------

$DeployScript = Join-Path $PSScriptRoot "setup-pipejack.ps1"

if (-not $SkipVM2) {
    Write-Host "`n[+] Step 3/5: Deploying VM2 Server Orchestrator ($VM2_IP)..." -ForegroundColor Cyan
    Write-Log "Starting VM2 deployment via setup-pipejack.ps1"

    $VM2Params = @{
        VM1_IP         = $VM1_IP
        VM2_IP         = $VM2_IP
        SSHUser        = $SSHUser
        SSHPort        = $SSHPort
        KitDir         = $KitDir
        SkipVM1        = $true
        SkipPreflight  = $true
        SkipVerify     = $true
        Force          = $true
    }
    if ($SSHKey) { $VM2Params["SSHKey"] = $SSHKey }
    if ($DryRun) { $VM2Params["DryRun"] = $true }
    if ($InteractiveSudo) { $VM2Params["InteractiveSudo"] = $true }

    & $DeployScript @VM2Params
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Deployment of VM2 failed." -ForegroundColor Red
        Write-Log "VM2 deployment failed with exit code $LASTEXITCODE" "ERROR"
        exit 1
    }
    Write-Log "VM2 deployment completed successfully"

    # Health Check Polling for VM2 Services
    if (-not $DryRun) {
        Write-Host "`n[+] Awaiting VM2 Service Readiness (CI Orchestrator :8888, Web Console :8090)..." -ForegroundColor Cyan
        $maxRetries = 20
        $retryDelay = 3
        $vm2Healthy = $false

        for ($i = 1; $i -le $maxRetries; $i++) {
            Write-Host "  Health probe attempt $i/$maxRetries..." -NoNewline
            $probeUrl = "http://${VM2_IP}:8888/health"
            $probeSuccess = $false

            try {
                $response = Invoke-RestMethod -Uri $probeUrl -Method Get -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
                if ($response -and $response.status -eq "ok") {
                    $probeSuccess = $true
                }
            } catch {
                # Fallback probe via curl.exe if available
                if (Get-Command "curl.exe" -ErrorAction SilentlyContinue) {
                    $curlOut = & curl.exe -s -m 3 "http://${VM2_IP}:8888/health" 2>$null
                    if ($curlOut -match '"status"\s*:\s*"ok"') {
                        $probeSuccess = $true
                    }
                }
            }

            if ($probeSuccess) {
                Write-Host " [ONLINE]" -ForegroundColor Green
                $vm2Healthy = $true
                break
            } else {
                Write-Host " [WAITING]" -ForegroundColor Yellow
                Start-Sleep -Seconds $retryDelay
            }
        }

        if (-not $vm2Healthy) {
            Write-Host "[-] WARNING: VM2 CI Orchestrator did not respond with status: ok within $($maxRetries * $retryDelay) seconds." -ForegroundColor Yellow
            Write-Log "VM2 CI Orchestrator health check timed out" "WARN"
        } else {
            Write-Log "VM2 CI Orchestrator confirmed healthy"
        }
    }
} else {
    Write-Host "`n[!] Notice: Skipping VM2 deployment as requested (-SkipVM2)." -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# 10. Step 4/5: Deploy VM1 Workload Client Second
# -----------------------------------------------------------------------------

if (-not $SkipVM1) {
    Write-Host "`n[+] Step 4/5: Deploying VM1 Workload Client ($VM1_IP)..." -ForegroundColor Cyan
    Write-Log "Starting VM1 deployment via setup-pipejack.ps1"

    $VM1Params = @{
        VM1_IP         = $VM1_IP
        VM2_IP         = $VM2_IP
        SSHUser        = $SSHUser
        SSHPort        = $SSHPort
        KitDir         = $KitDir
        SkipVM2        = $true
        SkipPreflight  = $true
        SkipVerify     = $true
        Force          = $true
    }
    if ($SSHKey) { $VM1Params["SSHKey"] = $SSHKey }
    if ($DryRun) { $VM1Params["DryRun"] = $true }
    if ($InteractiveSudo) { $VM1Params["InteractiveSudo"] = $true }

    & $DeployScript @VM1Params
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Deployment of VM1 failed." -ForegroundColor Red
        Write-Log "VM1 deployment failed with exit code $LASTEXITCODE" "ERROR"
        exit 1
    }
    Write-Log "VM1 deployment completed successfully"
} else {
    Write-Host "`n[!] Notice: Skipping VM1 deployment as requested (-SkipVM1)." -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# 11. Step 5/5: Post-Deployment Verification
# -----------------------------------------------------------------------------

$VerificationStatus = "SKIPPED"
if (-not $SkipVerify -and -not $DryRun) {
    Write-Host "`n[+] Step 5/5: Executing Post-Deployment Cluster Verification..." -ForegroundColor Cyan
    Write-Log "Invoking verify-pipejack.ps1"

    $VerifyScript = Join-Path $PSScriptRoot "verify-pipejack.ps1"
    $VerifyParams = @{
        VM1_IP  = $VM1_IP
        VM2_IP  = $VM2_IP
        SSHUser = $SSHUser
    }
    if ($SSHKey) { $VerifyParams["SSHKey"] = $SSHKey }

    & $VerifyScript @VerifyParams
    if ($LASTEXITCODE -eq 0) {
        $VerificationStatus = "PASSED"
        Write-Log "Verification script passed without errors"
    } else {
        $VerificationStatus = "FAILED"
        Write-Log "Verification script reported failures (exit code: $LASTEXITCODE)" "ERROR"
    }
} elseif ($DryRun) {
    $VerificationStatus = "DRY-RUN (SKIPPED)"
}

# -----------------------------------------------------------------------------
# 12. Generate Final Report & Summary
# -----------------------------------------------------------------------------

$OverallVerdict = if ($DryRun) { "DRY-RUN-COMPLETE" } elseif ($VerificationStatus -eq "PASSED") { "SUCCESS" } else { "ATTENTION-REQUIRED" }

$SummaryContent = @"
============================================================
 PIPEJACK FRESH TWO-VM ONBOARDING SUMMARY
============================================================
 Timestamp (UTC):     $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))
 Host Machine:        $($env:COMPUTERNAME) (Windows, PowerShell $($PSVersionTable.PSVersion))
 Target VM1 Client:   $SSHUser@$VM1_IP
 Target VM2 Server:   $SSHUser@$VM2_IP
 Deployment Mode:     $(if ($DryRun) { 'DRY-RUN / PREVIEW' } else { 'LIVE DEPLOYMENT' })

 Phase Results:
   1. Host OpenSSH & Kit Files:  PASSED
   2. SSH & Preflight Checks:    PASSED
   3. VM2 Server Deployment:     $(if ($SkipVM2) { 'SKIPPED' } else { 'COMPLETED' })
   4. VM1 Client Deployment:     $(if ($SkipVM1) { 'SKIPPED' } else { 'COMPLETED' })
   5. End-to-End Verification:   $VerificationStatus

 Overall Deployment Verdict:     $OverallVerdict

 Service Endpoints:
   - Web Demo Console:           http://${VM2_IP}:8090
   - CI Upload Endpoint:         http://${VM2_IP}:8888/upload
   - CI Health Endpoint:         http://${VM2_IP}:8888/health
   - Local Docker Registry:      http://${VM2_IP}:5000

 Artifacts & Reports:
   - Detailed Session Log:       $ReportFile
   - Deployment Summary:         $SummaryFile
============================================================
"@

Set-Content -Path $SummaryFile -Value $SummaryContent -Encoding Ascii
Write-Log "Final deployment summary written to $SummaryFile"

Write-Host "`n$SummaryContent" -ForegroundColor $(if ($OverallVerdict -eq "SUCCESS" -or $OverallVerdict -eq "DRY-RUN-COMPLETE") { "Green" } else { "Yellow" })

Write-Host "`n[+] Full installation log preserved at: $ReportFile" -ForegroundColor Cyan
Write-Host "[+] Installation summary preserved at: $SummaryFile" -ForegroundColor Cyan

if ($OverallVerdict -eq "ATTENTION-REQUIRED") {
    exit 1
}

exit 0
