param(
    [string]$ScanId = "day2-full-v4-20260804",
    [int]$JobTimeoutSeconds = 7200,
    [int]$PollSeconds = 30,
    [int]$RetryPasses = 3
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$scanRoot = Join-Path $projectRoot "artifacts/scans/$ScanId"
$outputRoot = Join-Path $projectRoot "artifacts/normalized/$ScanId-semgrep-only"
$statePath = Join-Path $scanRoot "finalizer-status.json"
$scannerExecutable = Join-Path $projectRoot ".venv/Scripts/vulngym-scan.exe"
$pipelineExecutable = Join-Path $projectRoot ".venv/Scripts/vulngym-full-pipeline.exe"

if ($PollSeconds -lt 5 -or $RetryPasses -lt 1) {
    throw "PollSeconds must be at least 5 and RetryPasses must be positive"
}
foreach ($path in @($scannerExecutable, $pipelineExecutable)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required executable does not exist: $path"
    }
}
$null = New-Item -ItemType Directory -Path $scanRoot -Force

function Write-FinalizerState {
    param(
        [string]$Status,
        [int]$ResumePass = 0,
        [int]$ExitCode = 0,
        [string]$Detail = ""
    )
    [ordered]@{
        schema_version = 1
        scan_id = $ScanId
        status = $Status
        resume_pass = $ResumePass
        exit_code = $ExitCode
        detail = $Detail
        updated_at = [DateTimeOffset]::UtcNow.ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
}

Set-Location -LiteralPath $projectRoot
Write-FinalizerState -Status "WAITING_FOR_PARTITIONS"
while ($true) {
    $activeScanners = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $_.Name -eq "vulngym-scan.exe" -and
                $_.CommandLine -and
                $_.CommandLine -match [regex]::Escape($ScanId)
            }
    )
    if ($activeScanners.Count -eq 0) {
        break
    }
    Start-Sleep -Seconds $PollSeconds
}

$resumeSucceeded = $false
$retryablePasses = 0
$resumeInvocation = 0
$busyWaits = 0
while (-not $resumeSucceeded) {
    $resumeInvocation++
    Write-FinalizerState -Status "RESUMING" -ResumePass $resumeInvocation
    & $scannerExecutable `
        --manifest artifacts/manifests/vulngym-v0.1.4.json `
        --scan-id $ScanId `
        --job-timeout-seconds $JobTimeoutSeconds `
        --prefetch `
        --scanner semgrep
    $scannerExitCode = $LASTEXITCODE
    if ($scannerExitCode -eq 0) {
        $resumeSucceeded = $true
        break
    }

    if ($scannerExitCode -eq 3) {
        Write-FinalizerState `
            -Status "BLOCKED_QUARANTINED" `
            -ResumePass $resumeInvocation `
            -ExitCode $scannerExitCode `
            -Detail (
                "Scanner reported settled quarantine blockers. No later automatic " +
                "resume pass or full pipeline was run."
            )
        exit $scannerExitCode
    }

    if ($scannerExitCode -eq 4) {
        $busyWaits++
        Write-FinalizerState `
            -Status "BUSY" `
            -ResumePass $resumeInvocation `
            -ExitCode $scannerExitCode `
            -Detail (
                "Scanner reported a live job-lock owner. The finalizer will wait " +
                "and poll without consuming the retryable-pass budget."
            )
        $busyDelaySeconds = [Math]::Min(
            $PollSeconds * [Math]::Min($busyWaits, 10),
            300
        )
        Start-Sleep -Seconds $busyDelaySeconds
        continue
    } elseif ($scannerExitCode -eq 1) {
        $retryablePasses++
        $busyWaits = 0
        if ($retryablePasses -ge $RetryPasses) {
            Write-FinalizerState `
                -Status "BLOCKED_AFTER_RETRIES" `
                -ResumePass $resumeInvocation `
                -ExitCode $scannerExitCode `
                -Detail (
                    "Scanner batch still had retryable failures after " +
                    "$retryablePasses bounded retryable passes; no full pipeline was run."
                )
            exit $scannerExitCode
        }
        Write-FinalizerState `
            -Status "RESUME_RETRY_REQUIRED" `
            -ResumePass $resumeInvocation `
            -ExitCode $scannerExitCode `
            -Detail "A later bounded pass may retry FAILED/TIMEOUT or fill missing jobs."
    } else {
        Write-FinalizerState `
            -Status "BLOCKED_SCANNER_ERROR" `
            -ResumePass $resumeInvocation `
            -ExitCode $scannerExitCode `
            -Detail (
                "Scanner exited with a terminal configuration or runtime error. " +
                "No later resume pass or full pipeline was run."
            )
        exit $scannerExitCode
    }

    $retryDelaySeconds = [Math]::Min($PollSeconds * $retryablePasses, 300)
    Start-Sleep -Seconds $retryDelaySeconds
}

Write-FinalizerState -Status "RUNNING_FULL_PIPELINE" -ResumePass $resumeInvocation
& $pipelineExecutable `
    --scan-root $scanRoot `
    --output-dir $outputRoot `
    --scanner semgrep
$pipelineExitCode = $LASTEXITCODE
if ($pipelineExitCode -ne 0) {
    Write-FinalizerState `
        -Status "PIPELINE_BLOCKED" `
        -ResumePass $resumeInvocation `
        -ExitCode $pipelineExitCode `
        -Detail "Coverage/provenance gate rejected the final output; inspect the finalizer log."
    exit $pipelineExitCode
}

Write-FinalizerState `
    -Status "COMPLETE" `
    -ResumePass $resumeInvocation `
    -Detail "Complete Semgrep matrix passed and full-pipeline-summary.json was written."
