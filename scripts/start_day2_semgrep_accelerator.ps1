param(
    [string]$ScanId = "day2-full-v4-20260804",
    [int]$JobTimeoutSeconds = 7200,
    [double]$MinimumFreeMemoryGiB = 10
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$scanRoot = Join-Path $projectRoot "artifacts/scans/$ScanId"
$scannerExecutable = Join-Path $projectRoot ".venv/Scripts/vulngym-scan.exe"
$null = New-Item -ItemType Directory -Path $scanRoot -Force

if (-not (Test-Path -LiteralPath $scannerExecutable -PathType Leaf)) {
    throw "scanner entry point does not exist: $scannerExecutable"
}

$existing = @(
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -eq "vulngym-scan.exe" -and
            $_.CommandLine -and
            $_.CommandLine -match [regex]::Escape($ScanId) -and
            $_.CommandLine -match "--scanner\s+semgrep(?:\s|$)"
        }
)
if ($existing.Count -gt 0) {
    throw "a Semgrep accelerator for scan-id $ScanId is already running"
}

$operatingSystem = Get-CimInstance Win32_OperatingSystem
$freeMemoryGiB = $operatingSystem.FreePhysicalMemory / 1MB
if ($freeMemoryGiB -lt $MinimumFreeMemoryGiB) {
    throw (
        "not enough free memory for another worker: " +
        "$([math]::Round($freeMemoryGiB, 2)) GiB < $MinimumFreeMemoryGiB GiB"
    )
}

$arguments = @(
    "--manifest", "artifacts/manifests/vulngym-v0.1.4.json",
    "--scan-id", $ScanId,
    "--job-timeout-seconds", "$JobTimeoutSeconds",
    "--prefetch",
    "--scanner", "semgrep"
)
$launchId = Get-Date -Format "yyyyMMddTHHmmss"
$stdout = Join-Path $scanRoot "accelerator-semgrep-$launchId.stdout.log"
$stderr = Join-Path $scanRoot "accelerator-semgrep-$launchId.stderr.log"
$process = Start-Process `
    -FilePath $scannerExecutable `
    -ArgumentList $arguments `
    -WorkingDirectory $projectRoot `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -WindowStyle Hidden `
    -PassThru

try {
    $process.PriorityClass = "BelowNormal"
} catch {
    # Priority is only a scheduling hint; failure does not invalidate the run.
}

[pscustomobject]@{
    ScanId = $ScanId
    ProcessId = $process.Id
    Scanner = "semgrep"
    Priority = $process.PriorityClass
    FreeMemoryGiBAtLaunch = [math]::Round($freeMemoryGiB, 2)
    Stdout = $stdout
    Stderr = $stderr
}
