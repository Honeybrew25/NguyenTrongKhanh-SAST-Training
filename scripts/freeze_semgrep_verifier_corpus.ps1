[CmdletBinding()]
param(
    [string]$SourceQueue = 'artifacts/annotation-queue/day2-full-v4-20260804-semgrep-only',
    [string]$SourcePipelineSummary = 'artifacts/normalized/day2-full-v4-20260804-semgrep-only/full-pipeline-summary.json',
    [string]$OutputDirectory = 'artifacts/verifier-corpora/semgrep-day2-v1-20260806'
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

$sourceQueuePath = Resolve-ProjectPath $SourceQueue
$sourceInputPath = Join-Path $sourceQueuePath 'blind-verifier-input.jsonl'
$queueSummaryPath = Join-Path $sourceQueuePath 'queue-summary.json'
$pipelineSummaryPath = Resolve-ProjectPath $SourcePipelineSummary
$outputPath = Resolve-ProjectPath $OutputDirectory
$frozenInputPath = Join-Path $outputPath 'blind-verifier-input.jsonl'
$summaryPath = Join-Path $outputPath 'summary.json'

foreach ($required in @($sourceInputPath, $queueSummaryPath, $pipelineSummaryPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required corpus input is missing: $required"
    }
}

$pipeline = Get-Content -LiteralPath $pipelineSummaryPath -Raw | ConvertFrom-Json
if ($pipeline.coverage.complete -ne $true) {
    throw 'The Semgrep pipeline is partial; an official verifier corpus cannot be frozen.'
}
if ([int]$pipeline.coverage.jobs_expected -ne [int]$pipeline.coverage.jobs_accounted) {
    throw 'The Semgrep pipeline does not account for every expected job.'
}
if (@($pipeline.coverage.blocking_statuses.PSObject.Properties).Count -ne 0) {
    throw 'The Semgrep pipeline still contains blocking job statuses.'
}
$pipelineScanners = @($pipeline.coverage.scanners_expected | ForEach-Object { [string]$_ })
if ($pipelineScanners.Count -ne 1 -or $pipelineScanners[0] -ne 'semgrep') {
    throw 'The source pipeline must contain only the Semgrep scanner.'
}

$queue = Get-Content -LiteralPath $queueSummaryPath -Raw | ConvertFrom-Json
if ([string]$queue.scanner -ne 'semgrep') {
    throw 'The source queue is not Semgrep-only.'
}
$records = @(
    Get-Content -LiteralPath $sourceInputPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)
if ($records.Count -eq 0) {
    throw 'The blind verifier input is empty.'
}
$findingIds = @($records | ForEach-Object { [string]$_.finding_id })
if (@($findingIds | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
    throw 'At least one blind record is missing finding_id.'
}
if (@($findingIds | Sort-Object -Unique).Count -ne $records.Count) {
    throw 'The blind verifier input contains duplicate finding_id values.'
}
if ([int]$queue.candidate_clusters -ne $records.Count) {
    throw 'Queue candidate count does not match the blind verifier input.'
}
$nonSemgrepRecords = @(
    $records | Where-Object {
        $_.scanner -isnot [psobject] -or
        [string]$_.scanner.name -ne 'semgrep' -or
        [string]::IsNullOrWhiteSpace([string]$_.scanner.version)
    }
)
if ($nonSemgrepRecords.Count -ne 0) {
    throw 'Every blind record must come from a versioned Semgrep scanner.'
}
$nonSemgrepObservations = @(
    $records |
        ForEach-Object { @($_.provenance.observed_by) } |
        Where-Object { $null -ne $_ -and [string]$_.scanner -ne 'semgrep' }
)
if ($nonSemgrepObservations.Count -ne 0) {
    throw 'Blind input provenance contains a non-Semgrep observation.'
}

$candidatePath = Join-Path $sourceQueuePath 'candidate-findings.jsonl'
if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
    throw "Candidate finding input is missing: $candidatePath"
}
$candidateIds = @(
    Get-Content -LiteralPath $candidatePath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [string]($_ | ConvertFrom-Json).finding_id }
)
$sortedFindingIds = @($findingIds | Sort-Object)
$sortedCandidateIds = @($candidateIds | Sort-Object)
if (
    $sortedFindingIds.Count -ne $sortedCandidateIds.Count -or
    (Compare-Object -ReferenceObject $sortedFindingIds -DifferenceObject $sortedCandidateIds)
) {
    throw 'Blind verifier IDs do not exactly match the Semgrep candidate queue.'
}

$sourceHash = Get-Sha256 $sourceInputPath
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
        scanner = 'semgrep'
        scan_id = [string]$queue.scan_id
        candidate_policy = 'CANDIDATE_REVIEW_ONLY'
        label_policy = 'UNLABELED_NOT_FALSE_POSITIVE'
    }
    source_pipeline = [ordered]@{
        path = Get-RelativeProjectPath $pipelineSummaryPath
        sha256 = Get-Sha256 $pipelineSummaryPath
        jobs_expected = [int]$pipeline.coverage.jobs_expected
        jobs_accounted = [int]$pipeline.coverage.jobs_accounted
        complete = $true
    }
    source_queue = [ordered]@{
        path = Get-RelativeProjectPath $queueSummaryPath
        sha256 = Get-Sha256 $queueSummaryPath
        candidate_clusters = [int]$queue.candidate_clusters
    }
    blind_verifier_input = [ordered]@{
        path = 'blind-verifier-input.jsonl'
        sha256 = Get-Sha256 $frozenInputPath
        records = $records.Count
    }
    leakage_control = [ordered]@{
        human_match_metadata_included = $false
        prior_predictions_included = $false
        prior_technical_labels_included = $false
        provisional_metrics_included = $false
    }
}

if (Test-Path -LiteralPath $summaryPath -PathType Leaf) {
    $existing = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    if (
        $existing.complete -ne $true -or
        [string]$existing.scope.scanner -ne 'semgrep' -or
        [string]$existing.scope.scan_id -ne [string]$queue.scan_id -or
        [string]$existing.source_pipeline.sha256 -ne (Get-Sha256 $pipelineSummaryPath) -or
        [string]$existing.source_queue.sha256 -ne (Get-Sha256 $queueSummaryPath) -or
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

$unexpectedFiles = @(
    Get-ChildItem -LiteralPath $outputPath -File |
        Where-Object { $_.Name -notin @('blind-verifier-input.jsonl', 'summary.json') }
)
if ($unexpectedFiles.Count -ne 0) {
    throw "Frozen corpus contains unexpected files: $($unexpectedFiles.Name -join ', ')"
}

[pscustomobject]@{
    Status = 'FROZEN'
    Corpus = Get-RelativeProjectPath $outputPath
    Records = $records.Count
    InputSha256 = $sourceHash
    SummarySha256 = Get-Sha256 $summaryPath
}
