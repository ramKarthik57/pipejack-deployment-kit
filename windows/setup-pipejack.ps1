#Requires -Version 5.1
<#
.SYNOPSIS
    PipeJack Master Windows Orchestrator

.DESCRIPTION
    Automates the transfer, installation, and end-to-end verification of the
    PipeJack two-node Zero-Trust CI/CD pipeline on Ubuntu VMware virtual machines.

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
    Runs installers in preflight/dry-run mode without modifying VM state.

.PARAMETER SkipVM1
    Skip installation on VM1.

.PARAMETER SkipVM2
    Skip installation on VM2.

.PARAMETER SkipPreflight
    Skip initial preflight checks.

.PARAMETER SkipVerify
    Skip post-deployment verification.

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
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PIPEJACK TWO-VM AUTOMATED DEPLOYMENT ORCHESTRATOR" -ForegroundColor Cyan
Write-Host " Host OS: Microsoft Windows | Target: Ubuntu VMware VMs" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Path Resolution
if (-not $KitDir) {
    $KitDir = Resolve-Path (Join-Path $PSScriptRoot "..")
}
Write-Host "[+] Local Kit Root: $KitDir"
Write-Host "    Target VM1 (Client):       $SSHUser@$VM1_IP"
Write-Host "    Target VM2 (Orchestrator): $SSHUser@$VM2_IP"
Write-Host "    Mode:                      $($DryRun ? 'DRY-RUN / AUDIT' : 'LIVE DEPLOYMENT')"

# 2. Preflight Check
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

# 3. User Confirmation
if (-not $Force -and -not $DryRun) {
    Write-Host "`n[?] Proceed with transferring packages and executing installation on both VMs? [Y/N]: " -NoNewline -ForegroundColor Yellow
    $ans = Read-Host
    if ($ans -notmatch "^[Yy]$") {
        Write-Host "[-] Deployment cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# SSH & SCP Argument Builders
$SSHKeyArgs = @()
if ($SSHKey -and (Test-Path $SSHKey)) {
    $SSHKeyArgs = @("-i", $SSHKey)
}

function Invoke-RemoteCommand {
    param(
        [string]$IP,
        [string]$Command,
        [string]$Description
    )
    Write-Host "`n[+] $Description on $IP..." -ForegroundColor Cyan
    $Target = "$SSHUser@$IP"
    $CommonArgs = @(
        "-p", $SSHPort,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new"
    ) + $SSHKeyArgs + @($Target, $Command)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "ssh.exe"
    $psi.Arguments = $CommonArgs -join " "
    $psi.UseShellExecute = $false
    
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        Write-Host "[-] Command failed on $IP (Exit Code: $($proc.ExitCode))" -ForegroundColor Red
        throw "Remote command execution error on $IP"
    }
    Write-Host "  [OK] $Description succeeded." -ForegroundColor Green
}

function Send-RemotePackage {
    param(
        [string]$IP,
        [string]$LocalSourceDir,
        [string]$RemoteTargetDir
    )
    Write-Host "`n[+] Transferring $(Split-Path $LocalSourceDir -Leaf) -> $SSHUser@${IP}:${RemoteTargetDir}..."
    
    # Ensure remote directory exists and is clean
    $InitCmd = "mkdir -p $RemoteTargetDir && rm -rf $RemoteTargetDir/*"
    Invoke-RemoteCommand -IP $IP -Command $InitCmd -Description "Preparing remote staging directory"

    $Target = "$SSHUser@${IP}:${RemoteTargetDir}/"
    $ScpArgs = @(
        "-P", $SSHPort,
        "-r",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new"
    ) + $SSHKeyArgs + @("$LocalSourceDir\*", $Target)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "scp.exe"
    $psi.Arguments = $ScpArgs -join " "
    $psi.UseShellExecute = $false

    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        Write-Host "[-] SCP Transfer failed for $IP (Exit Code: $($proc.ExitCode))" -ForegroundColor Red
        throw "SCP transfer error to $IP"
    }
    Write-Host "  [OK] Transfer completed." -ForegroundColor Green
}

# 4. Deploy VM2 (Server Orchestrator first)
if (-not $SkipVM2) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " PHASE 1: DEPLOYING VM2 (ORCHESTRATOR & CI SERVER)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $VM2_Local = Join-Path $KitDir "vm2"
    Send-RemotePackage -IP $VM2_IP -LocalSourceDir $VM2_Local -RemoteTargetDir "/tmp/pipejack-vm2"

    $InstallArgs = ""
    if ($DryRun) { $InstallArgs = "--dry-run" }

    $VM2_Cmd = "chmod +x /tmp/pipejack-vm2/install.sh && bash /tmp/pipejack-vm2/install.sh $InstallArgs"
    Invoke-RemoteCommand -IP $VM2_IP -Command $VM2_Cmd -Description "Executing VM2 Installer"
}

# 5. Deploy VM1 (Client / Developer Node)
if (-not $SkipVM1) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " PHASE 2: DEPLOYING VM1 (WORKLOAD CLIENT & ATTACKS)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $VM1_Local = Join-Path $KitDir "vm1"
    Send-RemotePackage -IP $VM1_IP -LocalSourceDir $VM1_Local -RemoteTargetDir "/tmp/pipejack-vm1"

    $InstallArgs = "--ci-endpoint http://${VM2_IP}:8888/upload"
    if ($DryRun) { $InstallArgs += " --dry-run" }

    $VM1_Cmd = "chmod +x /tmp/pipejack-vm1/install.sh && bash /tmp/pipejack-vm1/install.sh $InstallArgs"
    Invoke-RemoteCommand -IP $VM1_IP -Command $VM1_Cmd -Description "Executing VM1 Installer"
}

# 6. Post-Deployment Verification
if (-not $SkipVerify -and -not $DryRun) {
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
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " PIPEJACK TWO-VM DEPLOYMENT ORCHESTRATION COMPLETED" -ForegroundColor Green
Write-Host " Web Demo Console:   http://${VM2_IP}:8090" -ForegroundColor Cyan
Write-Host " CI Upload Endpoint: http://${VM2_IP}:8888/upload" -ForegroundColor Cyan
Write-Host " Local Registry:     http://${VM2_IP}:5000" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
exit 0
