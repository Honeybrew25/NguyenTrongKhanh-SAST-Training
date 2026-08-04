param(
    [string]$ScanId = "day2-full-v4-20260804",
    [int]$JobTimeoutSeconds = 7200,
    [int]$PollSeconds = 30,
    [int]$RetryPasses = 3
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$scanRoot = Join-Path $projectRoot "artifacts/scans/$ScanId"
$outputRoot = Join-Path $projectRoot "artifacts/normalized/$ScanId"
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
for ($pass = 1; $pass -le $RetryPasses; $pass++) {
    Write-FinalizerState -Status "RESUMING" -ResumePass $pass
    & $scannerExecutable `
        --manifest artifacts/manifests/vulngym-v0.1.4.json `
        --scan-id $ScanId `
        --job-timeout-seconds $JobTimeoutSeconds `
        --prefetch
    $scannerExitCode = $LASTEXITCODE
    if ($scannerExitCode -eq 0) {
        $resumeSucceeded = $true
        break
    }
    Write-FinalizerState `
        -Status "RESUME_RETRY_REQUIRED" `
        -ResumePass $pass `
        -ExitCode $scannerExitCode `
        -Detail "A later pass will retry FAILED/TIMEOUT or fill missing jobs."
}

if (-not $resumeSucceeded) {
    Write-FinalizerState `
        -Status "BLOCKED_AFTER_RETRIES" `
        -ResumePass $RetryPasses `
        -ExitCode $scannerExitCode `
        -Detail "Full pipeline was not run because the scanner batch did not pass."
    exit $scannerExitCode
}

Write-FinalizerState -Status "RUNNING_FULL_PIPELINE" -ResumePass $pass
& $pipelineExecutable --scan-root $scanRoot --output-dir $outputRoot
$pipelineExitCode = $LASTEXITCODE
if ($pipelineExitCode -ne 0) {
    Write-FinalizerState `
        -Status "PIPELINE_BLOCKED" `
        -ResumePass $pass `
        -ExitCode $pipelineExitCode `
        -Detail "Coverage/provenance gate rejected the final output; inspect the finalizer log."
    exit $pipelineExitCode
}

Write-FinalizerState `
    -Status "COMPLETE" `
    -ResumePass $pass `
    -Detail "Complete scanner matrix passed and full-pipeline-summary.json was written."

