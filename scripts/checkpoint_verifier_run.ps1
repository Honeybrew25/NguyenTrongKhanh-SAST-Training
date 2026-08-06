[CmdletBinding()]
param(
    [string]$RunDirectory = 'artifacts/verifier-runs/semgrep-day2-official-v1-20260806',
    [string]$FrozenInput = 'artifacts/verifier-corpora/semgrep-day2-v1-20260806/blind-verifier-input.jsonl',
    [string]$Model = 'gpt-5.6-sol'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Resolve-ProjectPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$runPath = Resolve-ProjectPath $RunDirectory
$inputPath = Resolve-ProjectPath $FrozenInput
if (-not (Test-Path -LiteralPath $runPath -PathType Container)) {
    throw "Verifier run directory is missing: $runPath"
}
if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
    throw "Frozen verifier input is missing: $inputPath"
}

$runName = Split-Path -Leaf $runPath
$liveProcesses = @(
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.CommandLine -match [regex]::Escape($runName) -and
            $_.Name -in @('uv.exe', 'vulngym-verify-agent.exe', 'python.exe', 'codex.exe')
        }
)
if ($liveProcesses.Count -ne 0) {
    throw 'Refusing checkpoint while verifier/provider processes are still alive.'
}

$expectedRecords = @(
    Get-Content -LiteralPath $inputPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
).Count
$caseRows = @(
    Get-ChildItem -LiteralPath (Join-Path $runPath 'cases') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object {
            $statusPath = Join-Path $_.FullName 'status.json'
            if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
                return
            }
            $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
            $errorProperty = $status.PSObject.Properties['error']
            $completedProperty = $status.PSObject.Properties['completed_at']
            $errorText = if ($null -ne $errorProperty) {
                [string]$errorProperty.Value
            }
            else {
                ''
            }
            $blocker = if ($errorText -match 'usage limit') {
                'PROVIDER_USAGE_LIMIT'
            }
            elseif ($errorText -match 'token_revoked|invalidated oauth token|sign in again') {
                'PROVIDER_TOKEN_REVOKED'
            }
            elseif ($status.status -eq 'RUNNING') {
                'INTERRUPTED_AFTER_PROVIDER_STALL'
            }
            elseif ($status.status -eq 'FAILED') {
                'OTHER_PROVIDER_FAILURE'
            }
            else {
                $null
            }
            $predictionPath = Join-Path $_.FullName 'prediction.json'
            [ordered]@{
                case = $_.Name
                status = [string]$status.status
                blocker = $blocker
                started_at = $status.started_at
                completed_at = if ($null -ne $completedProperty) {
                    $completedProperty.Value
                }
                else {
                    $null
                }
                prediction_sha256 = if (Test-Path -LiteralPath $predictionPath) {
                    Get-Sha256 $predictionPath
                }
                else {
                    $null
                }
            }
        }
)

$counts = [ordered]@{}
foreach ($group in ($caseRows | Group-Object { $_['status'] } | Sort-Object Name)) {
    $counts[$group.Name] = $group.Count
}
$checkpoint = [ordered]@{
    schema_version = 1
    run_id = $runName
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
    status = 'BLOCKED_PROVIDER'
    complete = $false
    model = $Model
    input = [ordered]@{
        path = [IO.Path]::GetRelativePath($projectRoot, $inputPath).Replace('\', '/')
        sha256 = Get-Sha256 $inputPath
        records = $expectedRecords
    }
    case_counts = [ordered]@{
        expected = $expectedRecords
        started = $caseRows.Count
        not_started = $expectedRecords - $caseRows.Count
        by_status = $counts
    }
    blockers = @('PROVIDER_USAGE_LIMIT', 'PROVIDER_TOKEN_REVOKED')
    live_processes = 0
    prediction_freeze_allowed = $false
    human_review_allowed = $false
    resume_policy = 'Rerun the same official command after authentication and quota are restored; successful checksum-matching cases may be reused.'
    cases = $caseRows
}

$outputPath = Join-Path $runPath 'interruption-checkpoint.json'
$temporary = "$outputPath.tmp-$PID"
$checkpoint | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding utf8
Move-Item -LiteralPath $temporary -Destination $outputPath -Force
$checkpoint
