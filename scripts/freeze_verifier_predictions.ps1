[CmdletBinding()]
param(
    [string]$RunDirectory = 'artifacts/verifier-runs/semgrep-day2-official-v1-20260806'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runPath = if ([IO.Path]::IsPathRooted($RunDirectory)) {
    [IO.Path]::GetFullPath($RunDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $projectRoot $RunDirectory))
}
$manifestPath = Join-Path $runPath 'verifier-run.json'
$predictionsPath = Join-Path $runPath 'verifier-predictions.jsonl'
$freezePath = Join-Path $runPath 'prediction-freeze.json'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Verifier run is incomplete; manifest is missing: $manifestPath"
}
if (-not (Test-Path -LiteralPath $predictionsPath -PathType Leaf)) {
    throw "Verifier predictions are missing: $predictionsPath"
}

$run = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($run.complete -ne $true -or $run.status -ne 'COMPLETE') {
    throw 'Only a COMPLETE verifier run can be frozen.'
}
if ($run.evaluation_mode -ne 'OFFICIAL') {
    throw 'Development predictions cannot be frozen as official predictions.'
}
if ($run.provider.model_explicitly_pinned -ne $true -or [string]::IsNullOrWhiteSpace($run.provider.model)) {
    throw 'Official prediction freeze requires an explicitly pinned model.'
}
if (
    [int]$run.case_counts.failed -ne 0 -or
    [int]$run.case_counts.success -ne [int]$run.case_counts.total
) {
    throw 'Every verifier case must be successful before prediction freeze.'
}

$predictionHash = Get-Sha256 $predictionsPath
if ([string]$run.predictions.sha256 -ne $predictionHash) {
    throw 'Prediction checksum does not match verifier-run.json.'
}
$records = @(
    Get-Content -LiteralPath $predictionsPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)
if ($records.Count -ne [int]$run.predictions.records) {
    throw 'Prediction record count does not match verifier-run.json.'
}
if ($records.Count -ne [int]$run.input.records) {
    throw 'Prediction count does not cover the complete frozen input.'
}
$findingIds = @($records | ForEach-Object { [string]$_.finding_id })
if (@($findingIds | Sort-Object -Unique).Count -ne $records.Count) {
    throw 'Predictions contain duplicate finding IDs.'
}
if (@($records | Where-Object { $_.evaluation_eligible -ne $true }).Count -ne 0) {
    throw 'Every frozen prediction must be official-evaluation eligible.'
}
$frozenInputPath = Join-Path $runPath ([string]$run.input.frozen_copy)
if (-not (Test-Path -LiteralPath $frozenInputPath -PathType Leaf)) {
    throw "Frozen run input is missing: $frozenInputPath"
}
if ((Get-Sha256 $frozenInputPath) -ne [string]$run.input.sha256) {
    throw 'Frozen run input checksum does not match verifier-run.json.'
}
$inputIds = @(
    Get-Content -LiteralPath $frozenInputPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [string]($_ | ConvertFrom-Json).finding_id }
)
if ($inputIds.Count -ne $findingIds.Count) {
    throw 'Prediction IDs do not cover the frozen input.'
}
for ($index = 0; $index -lt $inputIds.Count; $index++) {
    if ($inputIds[$index] -ne $findingIds[$index]) {
        throw 'Prediction finding IDs or ordering differ from the frozen input.'
    }
}
$caseIds = @($run.cases | ForEach-Object { [string]$_.identity.finding_id })
if (
    $caseIds.Count -ne $inputIds.Count -or
    (Compare-Object -ReferenceObject @($inputIds | Sort-Object) -DifferenceObject @($caseIds | Sort-Object))
) {
    throw 'Verifier case identities do not exactly match the frozen input.'
}

$freeze = [ordered]@{
    schema_version = 1
    freeze_id = "prediction-freeze-$($run.run_id)"
    frozen_at = [DateTimeOffset]::UtcNow.ToString('o')
    status = 'FROZEN'
    run = [ordered]@{
        path = 'verifier-run.json'
        sha256 = Get-Sha256 $manifestPath
        run_id = [string]$run.run_id
        evaluation_mode = [string]$run.evaluation_mode
    }
    input = [ordered]@{
        sha256 = [string]$run.input.sha256
        records = [int]$run.input.records
    }
    predictions = [ordered]@{
        path = 'verifier-predictions.jsonl'
        sha256 = $predictionHash
        records = $records.Count
    }
    provider = [ordered]@{
        id = [string]$run.provider.id
        version = [string]$run.provider.version
        model = [string]$run.provider.model
    }
    policy = [ordered]@{
        checksum_detects_post_freeze_changes = $true
        labels_loaded_before_freeze = $false
        human_review_may_start = $true
    }
}

if (Test-Path -LiteralPath $freezePath -PathType Leaf) {
    $existing = Get-Content -LiteralPath $freezePath -Raw | ConvertFrom-Json
    if (
        [string]$existing.predictions.sha256 -ne $predictionHash -or
        [string]$existing.run.sha256 -ne (Get-Sha256 $manifestPath) -or
        [string]$existing.input.sha256 -ne [string]$run.input.sha256 -or
        [int]$existing.input.records -ne $inputIds.Count
    ) {
        throw 'An incompatible prediction freeze already exists.'
    }
}
else {
    $temporary = "$freezePath.tmp-$PID"
    $freeze | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding utf8
    Move-Item -LiteralPath $temporary -Destination $freezePath
}

Get-Content -LiteralPath $freezePath -Raw | ConvertFrom-Json
