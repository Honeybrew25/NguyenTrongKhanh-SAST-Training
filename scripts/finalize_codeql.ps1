param(
    [Parameter(Mandatory = $true)]
    [int]$RunnerProcessId,
    [int]$MaxRetryPasses = 2,
    [int]$PollSeconds = 15
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($MaxRetryPasses -lt 0) {
    throw "MaxRetryPasses must be non-negative"
}
if ($PollSeconds -lt 5) {
    throw "PollSeconds must be at least 5"
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$scanId = "codeql-full-security-extended-v3-20260805"
$scanRoot = Join-Path $projectRoot "artifacts\scans\$scanId"
$planPath = Join-Path $projectRoot "artifacts\manifests\$scanId.json"
$logRoot = Join-Path $projectRoot "artifacts\logs"
$statusPath = Join-Path $scanRoot "finalizer-status.json"
$finalizerLog = Join-Path $logRoot "codeql-finalizer-v3.log"
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$semgrepRoot = Join-Path $projectRoot "artifacts\normalized\day2-full-v4-20260804-semgrep-only"
$semgrepFindings = Join-Path $semgrepRoot "security-deduplicated.jsonl"
$semgrepMatches = Join-Path $semgrepRoot "canonical-security-matches.jsonl"

New-Item -ItemType Directory -Path $scanRoot, $logRoot -Force | Out-Null
Set-Location $projectRoot

function Write-FinalizerStatus {
    param(
        [string]$State,
        [hashtable]$Details
    )
    $payload = @{
        schema_version = 1
        scan_id = $scanId
        state = $State
        updated_at = [DateTimeOffset]::UtcNow.ToString("o")
        runner_process_id = $RunnerProcessId
        max_retry_passes = $MaxRetryPasses
        details = $Details
    }
    $temporary = "$statusPath.tmp-$PID"
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding utf8
    Move-Item -LiteralPath $temporary -Destination $statusPath -Force
}

function Get-CodeQLCoverage {
    $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
    $pointers = @(
        Get-ChildItem -LiteralPath $scanRoot -Recurse -Filter status.json -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/]attempts[\\/]' }
    )
    $states = @(
        $pointers | ForEach-Object {
            try {
                (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json).status
            }
            catch {
                "INVALID"
            }
        }
    )
    $counts = @{}
    $states | Group-Object | ForEach-Object { $counts[$_.Name] = $_.Count }
    $success = if ($counts.ContainsKey("SUCCESS")) { [int]$counts["SUCCESS"] } else { 0 }
    return @{
        planned = [int]$plan.job_count
        pointers = $pointers.Count
        success = $success
        status_counts = $counts
        complete = ($success -eq [int]$plan.job_count -and $pointers.Count -eq [int]$plan.job_count)
    }
}

Write-FinalizerStatus -State "WAITING_FOR_PRIMARY_RUNNER" -Details @{ poll_seconds = $PollSeconds }
while (Get-Process -Id $RunnerProcessId -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds $PollSeconds
}

$coverage = Get-CodeQLCoverage
Add-Content -LiteralPath $finalizerLog -Value "$(Get-Date -Format o) primary runner ended: $($coverage | ConvertTo-Json -Compress)"

$retryPass = 0
while (-not $coverage.complete -and $retryPass -lt $MaxRetryPasses) {
    $retryPass += 1
    Write-FinalizerStatus -State "RETRYING" -Details @{ retry_pass = $retryPass; coverage = $coverage }
    Add-Content -LiteralPath $finalizerLog -Value "$(Get-Date -Format o) retry pass $retryPass started"
    & $python -m vulngym_enrich.codeql_runner --retry-failed *>&1 |
        Out-File -LiteralPath $finalizerLog -Append -Encoding utf8
    $runnerExit = $LASTEXITCODE
    $coverage = Get-CodeQLCoverage
    Add-Content -LiteralPath $finalizerLog -Value "$(Get-Date -Format o) retry pass $retryPass exit=$runnerExit coverage=$($coverage | ConvertTo-Json -Compress)"
}

Write-FinalizerStatus -State "POSTPROCESSING" -Details @{ retry_passes = $retryPass; coverage = $coverage }
& $python -m vulngym_enrich.codeql_pipeline `
    --semgrep-findings $semgrepFindings `
    --semgrep-matches $semgrepMatches *>&1 |
    Out-File -LiteralPath $finalizerLog -Append -Encoding utf8
$postprocessExit = $LASTEXITCODE

$finalState = if ($coverage.complete -and $postprocessExit -eq 0) { "COMPLETE" } else { "INCOMPLETE" }
Write-FinalizerStatus -State $finalState -Details @{
    retry_passes = $retryPass
    coverage = $coverage
    postprocess_exit_code = $postprocessExit
    summary = "artifacts/normalized/$scanId/summary.json"
}
Add-Content -LiteralPath $finalizerLog -Value "$(Get-Date -Format o) finalizer state=$finalState postprocess_exit=$postprocessExit"

if ($finalState -ne "COMPLETE") {
    exit 1
}
