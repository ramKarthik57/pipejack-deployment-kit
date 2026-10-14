#Requires -Version 5.1
<#
.SYNOPSIS
    PipeJack Windows Preflight Connectivity and Prerequisite Checker

.DESCRIPTION
    Validates host Windows OpenSSH client tools, local kit structure,
    network reachability, SSH credentials, and remote VM prerequisites
    prior to executing PipeJack deployment.

.PARAMETER VM1_IP
    IPv4 address of VM1 (Developer / Workload Client). Default: 192.168.88.132

.PARAMETER VM2_IP
    IPv4 address of VM2 (Security Orchestrator / CI Server). Default: 192.168.88.133

.PARAMETER SSHUser
    SSH username for Ubuntu virtual machines. Default: ubuntu

.PARAMETER SSHKey
    Optional path to private SSH key file (e.g. $HOME\.ssh\id_ed25519)

.PARAMETER SSHPort
    SSH port number. Default: 22

.PARAMETER KitDir
    Path to root of pipejack-deployment-kit. Default: parent of script directory
#>

[CmdletBinding()]
param(
    [string]$VM1_IP = "192.168.88.132",
    [string]$VM2_IP = "192.168.88.133",
    [string]$SSHUser = "ubuntu",
    [string]$SSHKey = "",
    [int]$SSHPort = 22,
    [string]$KitDir = ""
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PIPEJACK DEPLOYMENT KIT — WINDOWS PREFLIGHT CHECK" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Resolve Kit Directory
if (-not $KitDir) {
    $KitDir = Resolve-Path (Join-Path $PSScriptRoot "..")
}
Write-Host "[+] Deployment Kit Directory: $KitDir"

# Validate local required files
$RequiredFiles = @(
    (Join-Path $KitDir "vm1\install.sh"),
    (Join-Path $KitDir "vm2\install.sh"),
    (Join-Path $KitDir "SOURCE_MAPPING.md"),
    (Join-Path $KitDir "MANIFEST.md")
)

$LocalFilesMissing = $false
foreach ($f in $RequiredFiles) {
    if (-not (Test-Path $f)) {
        Write-Host "  [-] Missing required local file: $f" -ForegroundColor Red
        $LocalFilesMissing = $true
    }
}
if ($LocalFilesMissing) {
    Write-Host "[-] Preflight FAILED: Deployment kit files are missing or incomplete." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Local repository layout and installer files verified." -ForegroundColor Green

# 2. Check OpenSSH Client Tools
Write-Host "`n[+] Checking Windows OpenSSH Client Tools..."
$SSHBin = Get-Command "ssh.exe" -ErrorAction SilentlyContinue
$SCPBin = Get-Command "scp.exe" -ErrorAction SilentlyContinue

if (-not $SSHBin) {
    Write-Host "  [-] ssh.exe not found in PATH. Install Windows OpenSSH Client feature." -ForegroundColor Red
    exit 1
}
if (-not $SCPBin) {
    Write-Host "  [-] scp.exe not found in PATH." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] OpenSSH client tools available: $($SSHBin.Source)" -ForegroundColor Green

# 3. Network Ping Reachability
Write-Host "`n[+] Checking Network Ping Reachability..."
foreach ($ip in @($VM1_IP, $VM2_IP)) {
    $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($ping) {
        Write-Host "  [OK] $ip responds to ping." -ForegroundColor Green
    } else {
        Write-Host "  [!] WARNING: $ip did not respond to ICMP ping. (Check VMware network adapter / firewall)" -ForegroundColor Yellow
    }
}

# 4. SSH Connectivity & Remote System Checks
$SSHKeyArgs = @()
if ($SSHKey -and (Test-Path $SSHKey)) {
    $SSHKeyArgs = @("-i", $SSHKey)
}

function Test-RemoteHost {
    param(
        [string]$NodeName,
        [string]$IP
    )
    Write-Host "`n[+] Verifying SSH Access and Environment on $NodeName ($IP)..."
    $Target = "$SSHUser@$IP"
    $Cmd = "uname -s -m && cat /etc/os-release | grep PRETTY_NAME && df -h / | tail -1 && (sudo -n true 2>/dev/null && echo 'SUDO_STATUS: PASSWORDLESS' || echo 'SUDO_STATUS: PASSWORD_REQUIRED')"
    $CommonArgs = @(
        "-p", [string]$SSHPort,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=accept-new"
    ) + $SSHKeyArgs + @($Target, $Cmd)

    $output = & "ssh.exe" @CommonArgs 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host "  [OK] SSH authentication succeeded for $Target" -ForegroundColor Green
        foreach ($l in $output) {
            if ($l -match "SUDO_STATUS: PASSWORD_REQUIRED") {
                Write-Host "       $l" -ForegroundColor Yellow
            } else {
                Write-Host "       $l" -ForegroundColor Gray
            }
        }
        return $true
    } else {
        Write-Host "  [-] SSH authentication failed for $Target (Exit code: $exitCode)" -ForegroundColor Red
        foreach ($l in $output) {
            Write-Host "       $l" -ForegroundColor Red
        }
        return $false
    }
}

$VM1_OK = Test-RemoteHost -NodeName "VM1 (Client)" -IP $VM1_IP
$VM2_OK = Test-RemoteHost -NodeName "VM2 (Orchestrator)" -IP $VM2_IP

Write-Host "`n============================================================" -ForegroundColor Cyan
if ($VM1_OK -and $VM2_OK) {
    Write-Host " PREFLIGHT PASSED: Both VMs are reachable and ready for deployment." -ForegroundColor Green
    Write-Host " Sudo Notice: If PASSWORD_REQUIRED was reported, run setup-pipejack.ps1 with -InteractiveSudo" -ForegroundColor Yellow
    Write-Host "              or configure passwordless sudo on the VMs." -ForegroundColor Yellow
    Write-Host " Run .\setup-pipejack.ps1 to proceed with installation." -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host " PREFLIGHT FAILED: One or more targets are unreachable or failed authentication." -ForegroundColor Red
    Write-Host " Please verify VM IP addresses, VMware network adapters, and SSH keys." -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 1
}
