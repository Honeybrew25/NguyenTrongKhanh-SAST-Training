param(
    [string]$ScanId = "day2-full-v4-20260804",
    [int]$JobTimeoutSeconds = 7200
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$scanRoot = Join-Path $projectRoot "artifacts/scans/$ScanId"
$workerRelative = "scripts/finalize_day2_worker.ps1"
$workerName = Split-Path $workerRelative -Leaf
$null = New-Item -ItemType Directory -Path $scanRoot -Force

$existing = @(
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -eq "pwsh.exe" -and
            $_.CommandLine -and
            $_.CommandLine -match [regex]::Escape($workerName) -and
            $_.CommandLine -match [regex]::Escape($ScanId)
        }
)
if ($existing.Count -gt 0) {
    throw "a finalizer for scan-id $ScanId is already running"
}

$launchId = Get-Date -Format "yyyyMMddTHHmmss"
$stdout = Join-Path $scanRoot "finalizer-$launchId.stdout.log"
$stderr = Join-Path $scanRoot "finalizer-$launchId.stderr.log"
$pwsh = (Get-Command pwsh).Source
$arguments = @(
    "-NoProfile",
    "-File", $workerRelative,
    "-ScanId", $ScanId,
    "-JobTimeoutSeconds", "$JobTimeoutSeconds"
)
$process = Start-Process `
    -FilePath $pwsh `
    -ArgumentList $arguments `
    -WorkingDirectory $projectRoot `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -WindowStyle Hidden `
    -PassThru

[pscustomobject]@{
    ScanId = $ScanId
    ProcessId = $process.Id
    State = Join-Path $scanRoot "finalizer-status.json"
    Stdout = $stdout
    Stderr = $stderr
}
