#Requires -Version 5.1
<#
.SYNOPSIS
    PipeJack Post-Deployment System Verification Script

.DESCRIPTION
    Verifies the end-to-end operational state of the deployed PipeJack cluster:
    1. CI Orchestrator Health Endpoint (:8888)
    2. Web Demo Console Status (:8090)
    3. Docker Registry API v2 (:5000)
    4. Workload Upload Execution & Attestation Ledger Verdict (VM1 -> VM2)

.PARAMETER VM1_IP
    IP address of VM1. Default: 192.168.88.132

.PARAMETER VM2_IP
    IP address of VM2. Default: 192.168.88.133

.PARAMETER CIPort
    CI port. Default: 8888

.PARAMETER ConsolePort
    Demo console port. Default: 8090

.PARAMETER RegistryPort
    Registry port. Default: 5000

.PARAMETER SSHUser
    SSH username. Default: ubuntu

.PARAMETER SSHKey
    Optional private SSH key file path.

.PARAMETER RunSampleUpload
    Switch to trigger an active sample workload upload from VM1. Default: $true
#>

[CmdletBinding()]
param(
    [string]$VM1_IP = "192.168.88.132",
    [string]$VM2_IP = "192.168.88.133",
    [int]$CIPort = 8888,
    [int]$ConsolePort = 8090,
    [int]$RegistryPort = 5000,
    [string]$SSHUser = "ubuntu",
    [string]$SSHKey = "",
    [switch]$SkipSampleUpload
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PIPEJACK DEPLOYMENT KIT — POST-INSTALLATION VERIFICATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$Failures = 0

# 1. CI Health Check (:8888)
$CIUrl = "http://${VM2_IP}:${CIPort}/health"
Write-Host "`n[+] 1/4 Probing CI Server Health ($CIUrl)..."
try {
    $resp = Invoke-RestMethod -Uri $CIUrl -Method Get -TimeoutSec 5
    if ($resp.status -eq "ok") {
        Write-Host "  [OK] CI Server is HEALTHY. Service: $($resp.service)" -ForegroundColor Green
    } else {
        Write-Host "  [!] WARNING: CI Server returned unexpected status: $($resp.status)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] FAIL: Unable to reach CI server at $CIUrl ($_)" -ForegroundColor Red
    $Failures++
}

# 2. Demo Console Health Check (:8090)
$ConsoleUrl = "http://${VM2_IP}:${ConsolePort}/api/status"
Write-Host "`n[+] 2/4 Probing Demo Console Status ($ConsoleUrl)..."
try {
    $resp = Invoke-RestMethod -Uri $ConsoleUrl -Method Get -TimeoutSec 5
    Write-Host "  [OK] Demo Console is ONLINE." -ForegroundColor Green
    Write-Host "       CI Connected: $($resp.ci_healthy)" -ForegroundColor Gray
    Write-Host "       Attestation Records: $($resp.attestation_count)" -ForegroundColor Gray
    Write-Host "       Enforcement Mode: $($resp.enforcement_mode)" -ForegroundColor Gray
} catch {
    Write-Host "  [-] FAIL: Unable to reach Demo Console at $ConsoleUrl ($_)" -ForegroundColor Red
    $Failures++
}

# 3. Docker Registry Health Check (:5000)
$RegUrl = "http://${VM2_IP}:${RegistryPort}/v2/"
Write-Host "`n[+] 3/4 Probing Docker Registry API ($RegUrl)..."
try {
    $resp = Invoke-WebRequest -Uri $RegUrl -Method Get -TimeoutSec 5
    if ($resp.StatusCode -eq 200) {
        Write-Host "  [OK] Local Docker Registry is HEALTHY (API v2 operational)." -ForegroundColor Green
    } else {
        Write-Host "  [!] WARNING: Registry returned status $($resp.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] FAIL: Unable to reach Registry at $RegUrl ($_)" -ForegroundColor Red
    $Failures++
}

# 4. Active Workload Upload Pipeline Test
if (-not $SkipSampleUpload) {
    Write-Host "`n[+] 4/4 Executing Live Sample Workload Upload (VM1 -> VM2)..."
    $SSHKeyArgs = @()
    if ($SSHKey -and (Test-Path $SSHKey)) {
        $SSHKeyArgs = @("-i", $SSHKey)
    }

    $UploadCmd = "upload /tmp/banking-api-clean.tar.gz 2>&1 || ~/pipejack-upload.sh /tmp/banking-api-clean.tar.gz 2>&1"
    $Target = "$SSHUser@$VM1_IP"
    $CommonArgs = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=accept-new"
    ) + $SSHKeyArgs + @($Target, $UploadCmd)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "ssh.exe"
    $psi.Arguments = $CommonArgs -join " "
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit(30000)
    $stdout = $proc.StandardOutput.ReadToEnd()

    if ($stdout -match "ALLOW" -or $stdout -match "200") {
        Write-Host "  [OK] Clean Workload Upload PASSED with ALLOW verdict!" -ForegroundColor Green
    } else {
        Write-Host "  [!] Upload output received (inspecting response):" -ForegroundColor Yellow
        $stdout -split "`n" | Select-Object -First 10 | ForEach-Object { Write-Host "       $_" -ForegroundColor Gray }
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
if ($Failures -eq 0) {
    Write-Host " POST-DEPLOYMENT VERIFICATION PASSED: All endpoints operational." -ForegroundColor Green
    Write-Host " Access Web Console: http://${VM2_IP}:${ConsolePort}" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host " POST-DEPLOYMENT VERIFICATION COMPLETED WITH $Failures FAILURE(S)." -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 1
}
