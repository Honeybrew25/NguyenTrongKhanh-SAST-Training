[CmdletBinding()]
param(
    [string]$SourceDirectory = 'artifacts/normalized/codeql-full-security-extended-wsl-v1-20260806-final-20260806-155300',
    [string]$OutputDirectory = 'artifacts/verifier-corpora/codeql-wsl-73-final-v1-20260806'
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

function Get-RelativeProjectPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetRelativePath($projectRoot, $Path).Replace('\', '/')
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$sourcePath = Resolve-ProjectPath $SourceDirectory
$sourceInputPath = Join-Path $sourcePath 'blind-verifier-input.jsonl'
$sourceSummaryPath = Join-Path $sourcePath 'summary.json'
$queueSummaryPath = Join-Path $sourcePath 'candidate-review-summary.json'
$outputPath = Resolve-ProjectPath $OutputDirectory
$frozenInputPath = Join-Path $outputPath 'blind-verifier-input.jsonl'
$summaryPath = Join-Path $outputPath 'summary.json'

foreach ($required in @($sourceInputPath, $sourceSummaryPath, $queueSummaryPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required CodeQL corpus input is missing: $required"
    }
}

$pipeline = Get-Content -LiteralPath $sourceSummaryPath -Raw | ConvertFrom-Json
$queue = Get-Content -LiteralPath $queueSummaryPath -Raw | ConvertFrom-Json
$records = @(
    Get-Content -LiteralPath $sourceInputPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)

if ($pipeline.complete -ne $true) {
    throw 'The CodeQL pipeline is partial; an official verifier corpus cannot be frozen.'
}
if ([int]$pipeline.coverage.planned_jobs -ne [int]$pipeline.coverage.successful_jobs) {
    throw 'The CodeQL pipeline does not have a successful result for every planned job.'
}
$statusNames = @($pipeline.coverage.status_counts.PSObject.Properties.Name)
if ($statusNames.Count -ne 1 -or $statusNames[0] -ne 'SUCCESS') {
    throw 'The CodeQL pipeline contains a non-success job status.'
}
if ([string]$pipeline.separate_baseline -ne 'codeql') {
    throw 'The source summary is not an isolated CodeQL baseline.'
}
if ($records.Count -eq 0) {
    throw 'The blind verifier input is empty.'
}
if ([int]$queue.candidate_findings -ne $records.Count) {
    throw 'Candidate review count does not match the blind verifier input.'
}
if ([int]$pipeline.blind_verifier_input.records -ne $records.Count) {
    throw 'Pipeline blind-input count does not match the actual file.'
}

$findingIds = @($records | ForEach-Object { [string]$_.finding_id })
if (@($findingIds | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
    throw 'At least one blind record is missing finding_id.'
}
if (@($findingIds | Sort-Object -Unique).Count -ne $records.Count) {
    throw 'The blind verifier input contains duplicate finding_id values.'
}
if (@($records | Where-Object { [string]$_.scanner.name -ne 'codeql' }).Count -ne 0) {
    throw 'The blind verifier input contains a non-CodeQL record.'
}

$sourceHash = Get-Sha256 $sourceInputPath
if ([string]$pipeline.blind_verifier_input.sha256 -ne $sourceHash) {
    throw 'Pipeline blind-input checksum does not match the actual file.'
}
$snapshots = @(
    $records |
        ForEach-Object { '{0}@{1}' -f ([string]$_.repo_url), ([string]$_.commit) } |
        Sort-Object -Unique
)

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
if (Test-Path -LiteralPath $frozenInputPath -PathType Leaf) {
    if ((Get-Sha256 $frozenInputPath) -ne $sourceHash) {
        throw "Frozen input already exists with different content: $frozenInputPath"
    }
}
else {
    Copy-Item -LiteralPath $sourceInputPath -Destination $frozenInputPath
}

$summary = [ordered]@{
    schema_version = 1
    corpus_id = Split-Path -Leaf $outputPath
    created_at = [DateTimeOffset]::UtcNow.ToString('o')
    complete = $true
    scope = [ordered]@{
        scanner = 'codeql'
        scan_id = [string]$pipeline.scan_id
        candidate_policy = 'MATCHED_CANDIDATES_REQUIRE_INDEPENDENT_REVIEW'
        label_policy = 'UNLABELED_NOT_FALSE_POSITIVE'
        baseline_isolated = $true
    }
    source_pipeline = [ordered]@{
        path = Get-RelativeProjectPath $sourceSummaryPath
        sha256 = Get-Sha256 $sourceSummaryPath
        planned_jobs = [int]$pipeline.coverage.planned_jobs
        successful_jobs = [int]$pipeline.coverage.successful_jobs
        complete = $true
        profile_sha256 = [string]$pipeline.inputs.profile_sha256
        plan_sha256 = [string]$pipeline.inputs.plan_sha256
    }
    source_queue = [ordered]@{
        path = Get-RelativeProjectPath $queueSummaryPath
        sha256 = Get-Sha256 $queueSummaryPath
        candidate_findings = [int]$queue.candidate_findings
        codeql_only_locations = [int]$queue.counts_by_novelty_vs_semgrep.CODEQL_ONLY_LOCATION
    }
    blind_verifier_input = [ordered]@{
        path = 'blind-verifier-input.jsonl'
        sha256 = Get-Sha256 $frozenInputPath
        records = $records.Count
        snapshots = $snapshots.Count
    }
    leakage_control = [ordered]@{
        vulngym_match_metadata_included = $false
        human_labels_included = $false
        prior_predictions_included = $false
        provisional_metrics_included = $false
    }
}

if (Test-Path -LiteralPath $summaryPath -PathType Leaf) {
    $existing = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    if (
        $existing.complete -ne $true -or
        [string]$existing.blind_verifier_input.sha256 -ne $sourceHash -or
        [int]$existing.blind_verifier_input.records -ne $records.Count
    ) {
        throw "Corpus summary already exists with incompatible proof: $summaryPath"
    }
}
else {
    $temporary = "$summaryPath.tmp-$PID"
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding utf8
    Move-Item -LiteralPath $temporary -Destination $summaryPath
}

[pscustomobject]@{
    Status = 'FROZEN'
    Corpus = Get-RelativeProjectPath $outputPath
    Records = $records.Count
    Snapshots = $snapshots.Count
    InputSha256 = $sourceHash
    SummarySha256 = Get-Sha256 $summaryPath
}
