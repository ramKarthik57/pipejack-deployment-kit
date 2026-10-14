#Requires -Version 5.1
<#
.SYNOPSIS
    PipeJack Post-Deployment System Verification Script

.DESCRIPTION
    Verifies the end-to-end operational state of the deployed PipeJack cluster:
    1. CI Orchestrator Health Endpoint (:8888) — validates status: "ok"
    2. Web Demo Console Status (:8090) — validates ci_healthy: true
    3. Docker Registry API v2 (:5000) — validates HTTP 200 & API v2
    4. Workload Upload Execution & Attestation Ledger Verdict (VM1 -> VM2)
       Strictly verifies that a newly generated signed attestation record is
       committed to the VM2 cryptographic ledger with verdict ALLOW.

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

.PARAMETER SkipSampleUpload
    Switch to skip active sample workload upload test.
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
$InitialAttestCount = 0

# 1. CI Health Check (:8888)
$CIUrl = "http://${VM2_IP}:${CIPort}/health"
Write-Host "`n[+] 1/4 Probing CI Server Health ($CIUrl)..."
try {
    $resp = Invoke-RestMethod -Uri $CIUrl -Method Get -TimeoutSec 5
    if ($resp -and $resp.status -eq "ok" -and $resp.service -eq "pipejack-ci") {
        Write-Host "  [OK] CI Server is HEALTHY. Service: $($resp.service)" -ForegroundColor Green
    } else {
        Write-Host "  [-] FAIL: CI Server returned invalid payload: $(ConvertTo-Json $resp -Compress)" -ForegroundColor Red
        $Failures++
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
    if ($resp -and $resp.ci_healthy -eq $true) {
        Write-Host "  [OK] Demo Console is ONLINE and CI connected." -ForegroundColor Green
        Write-Host "       Attestation Records: $($resp.attestation_count)" -ForegroundColor Gray
        Write-Host "       Enforcement Mode:    $($resp.enforcement_mode)" -ForegroundColor Gray
        $InitialAttestCount = [int]$resp.attestation_count
    } else {
        Write-Host "  [-] FAIL: Demo Console reported unhealthy state: $(ConvertTo-Json $resp -Compress)" -ForegroundColor Red
        $Failures++
    }
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
        Write-Host "  [OK] Local Docker Registry is HEALTHY (API v2 operational, HTTP 200)." -ForegroundColor Green
    } else {
        Write-Host "  [-] FAIL: Registry returned unexpected status: $($resp.StatusCode)" -ForegroundColor Red
        $Failures++
    }
} catch {
    Write-Host "  [-] FAIL: Unable to reach Registry at $RegUrl ($_)" -ForegroundColor Red
    $Failures++
}

# 4. Active Workload Upload Pipeline & Attestation Ledger Test
if (-not $SkipSampleUpload) {
    Write-Host "`n[+] 4/4 Executing Live Sample Workload Upload & Ledger Verification..."
    $SSHKeyArgs = @()
    if ($SSHKey -and (Test-Path $SSHKey)) {
        $SSHKeyArgs = @("-i", $SSHKey)
    }

    $SSH_CMD = if (Get-Command "ssh.exe" -ErrorAction SilentlyContinue) { "ssh.exe" } else { "ssh" }
    $UploadCmd = "upload /tmp/banking-api-clean.tar.gz || ~/pipejack-upload.sh /tmp/banking-api-clean.tar.gz"
    $Target = "$SSHUser@$VM1_IP"
    $CommonArgs = @(
        "-p", "22",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new"
    ) + $SSHKeyArgs + @($Target, $UploadCmd)

    $stdout = & $SSH_CMD @CommonArgs 2>&1
    $uploadCode = $LASTEXITCODE

    if ($uploadCode -ne 0) {
        Write-Host "  [-] FAIL: Upload command on VM1 exited with non-zero code ($uploadCode)" -ForegroundColor Red
        $stdout | Select-Object -Last 10 | ForEach-Object { Write-Host "       $_" -ForegroundColor Gray }
        $Failures++
    } else {
        Write-Host "  [OK] Upload command completed successfully on VM1." -ForegroundColor Green

        # Strictly verify that VM2 attestation ledger recorded the new entry
        Start-Sleep -Seconds 2
        try {
            $newResp = Invoke-RestMethod -Uri $ConsoleUrl -Method Get -TimeoutSec 5
            $newCount = [int]$newResp.attestation_count
            $latest = $newResp.latest_attestation

            if ($newCount -ge ($InitialAttestCount + 1) -and $latest -and $latest.verdict -eq "ALLOW") {
                if ($latest.signature -and $latest.self_hash) {
                    Write-Host "  [OK] Attestation Ledger Verified on VM2:" -ForegroundColor Green
                    Write-Host "       Build ID:  $($latest.build_id)" -ForegroundColor Gray
                    Write-Host "       Verdict:   $($latest.verdict)" -ForegroundColor Gray
                    Write-Host "       Signature: $($latest.signature.Substring(0, [Math]::Min(32, $latest.signature.Length)))..." -ForegroundColor Gray
                    Write-Host "       Records:   $newCount (incremented from $InitialAttestCount)" -ForegroundColor Gray
                } else {
                    Write-Host "  [-] FAIL: Latest attestation record is missing signature or hash" -ForegroundColor Red
                    $Failures++
                }
            } else {
                Write-Host "  [-] FAIL: Attestation ledger was not updated with ALLOW verdict." -ForegroundColor Red
                Write-Host "       Expected count >= $($InitialAttestCount + 1), got $newCount" -ForegroundColor Red
                Write-Host "       Verdict: $($latest.verdict)" -ForegroundColor Red
                $Failures++
            }
        } catch {
            Write-Host "  [-] FAIL: Failed to query Demo Console status API after upload: $_" -ForegroundColor Red
            $Failures++
        }
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
if ($Failures -eq 0) {
    Write-Host " POST-DEPLOYMENT VERIFICATION PASSED: All endpoints and ledger operational." -ForegroundColor Green
    Write-Host " Access Web Console: http://${VM2_IP}:${ConsolePort}" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host " POST-DEPLOYMENT VERIFICATION FAILED WITH $Failures FAILURE(S)." -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 1
}

