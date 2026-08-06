[CmdletBinding()]
param(
    [string]$VerifierRun = 'artifacts/verifier-runs/semgrep-day2-official-v1-20260806',
    [string]$SourceQueue = 'artifacts/annotation-queue/day2-full-v4-20260804-semgrep-only',
    [string]$OutputDirectory = 'artifacts/human-review/semgrep-day2-v1-20260806'
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

$runPath = Resolve-ProjectPath $VerifierRun
$sourceQueuePath = Resolve-ProjectPath $SourceQueue
$outputPath = Resolve-ProjectPath $OutputDirectory
$freezePath = Join-Path $runPath 'prediction-freeze.json'
if (-not (Test-Path -LiteralPath $freezePath -PathType Leaf)) {
    throw 'Human review must not start before official predictions are completely frozen.'
}
$freeze = Get-Content -LiteralPath $freezePath -Raw | ConvertFrom-Json
if ($freeze.status -ne 'FROZEN' -or $freeze.policy.human_review_may_start -ne $true) {
    throw 'Prediction freeze does not authorize human review.'
}

$candidatePath = Join-Path $sourceQueuePath 'candidate-findings.jsonl'
$matchPath = Join-Path $sourceQueuePath 'human-candidate-matches.jsonl'
$schemaPath = Join-Path $projectRoot 'schemas\human-gold-label.schema.json'
foreach ($required in @($candidatePath, $matchPath, $schemaPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Human-review input is missing: $required"
    }
}

$candidates = @(
    Get-Content -LiteralPath $candidatePath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)
if ($candidates.Count -ne [int]$freeze.input.records) {
    throw 'Human-review candidate count does not match the frozen verifier corpus.'
}
$candidateIds = @($candidates | ForEach-Object { [string]$_.finding_id })
if (@($candidateIds | Sort-Object -Unique).Count -ne $candidateIds.Count) {
    throw 'Human-review candidates contain duplicate finding IDs.'
}
$runManifestPath = Join-Path $runPath ([string]$freeze.run.path)
if (-not (Test-Path -LiteralPath $runManifestPath -PathType Leaf)) {
    throw "Frozen verifier manifest is missing: $runManifestPath"
}
if ((Get-Sha256 $runManifestPath) -ne [string]$freeze.run.sha256) {
    throw 'Verifier manifest changed after prediction freeze.'
}
$run = Get-Content -LiteralPath $runManifestPath -Raw | ConvertFrom-Json
$frozenInputPath = Join-Path $runPath ([string]$run.input.frozen_copy)
if (
    -not (Test-Path -LiteralPath $frozenInputPath -PathType Leaf) -or
    (Get-Sha256 $frozenInputPath) -ne [string]$freeze.input.sha256
) {
    throw 'Frozen blind input is missing or changed.'
}
$inputIds = @(
    Get-Content -LiteralPath $frozenInputPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [string]($_ | ConvertFrom-Json).finding_id }
)
if (
    $inputIds.Count -ne $candidateIds.Count -or
    (Compare-Object -ReferenceObject @($inputIds | Sort-Object) -DifferenceObject @($candidateIds | Sort-Object))
) {
    throw 'Human-review candidate IDs do not exactly match the frozen verifier input.'
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
foreach ($file in @($candidatePath, $matchPath, $schemaPath)) {
    $destination = Join-Path $outputPath (Split-Path -Leaf $file)
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-Sha256 $destination) -ne (Get-Sha256 $file)) {
            throw "Review packet contains a conflicting file: $destination"
        }
    }
    else {
        Copy-Item -LiteralPath $file -Destination $destination
    }
}

$templatePath = Join-Path $outputPath 'human-gold-labels.template.jsonl'
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
    $rendered = foreach ($candidate in $candidates) {
        [ordered]@{
            schema_version = 1
            finding_id = [string]$candidate.finding_id
            label = $null
            reason_codes = @()
            reasoning = ''
            reviewer = [ordered]@{ id = ''; kind = 'HUMAN' }
            reviewed_at = ''
            evidence = @()
            linked_entry_ids = @()
            linked_report_ids = @()
        } | ConvertTo-Json -Compress
    }
    ($rendered -join "`n") + "`n" | Set-Content -LiteralPath $templatePath -Encoding utf8
}
else {
    $templateIds = @(
        Get-Content -LiteralPath $templatePath |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { [string]($_ | ConvertFrom-Json).finding_id }
    )
    if (
        $templateIds.Count -ne $candidateIds.Count -or
        (Compare-Object -ReferenceObject @($candidateIds | Sort-Object) -DifferenceObject @($templateIds | Sort-Object))
    ) {
        throw 'Existing human-label template has incompatible finding IDs.'
    }
}

$checklistPath = Join-Path $outputPath 'README.md'
if (-not (Test-Path -LiteralPath $checklistPath -PathType Leaf)) {
    @'
# Gói thẩm định độc lập

Người thẩm định đọc `candidate-findings.jsonl`, source tại đúng commit và metadata đối sánh trong `human-candidate-matches.jsonl`. Không mở prediction của agent trước khi hoàn tất và khóa toàn bộ nhãn.

Với từng finding:

1. Xác định khả năng attacker kiểm soát input.
2. Kiểm tra đường đi tới sink và các biện pháp chặn.
3. Ghi nhãn, lý do và ít nhất một tham chiếu `file:dòng` vào bản sao của template.
4. `FP_CONFIRMED` phải có reason code; không khớp VulnGym không phải bằng chứng false positive.
5. `TP_KNOWN` phải có cả `linked_entry_ids` và `linked_report_ids`.
6. Dùng `UNCERTAIN` khi bằng chứng chưa đủ; không ép thành TP hoặc FP.

Sau khi đủ nhãn, lưu thành `human-gold-labels.jsonl`. Evaluator chính thức sẽ từ chối file thiếu người review, timestamp, evidence hoặc liên kết bắt buộc.
'@ | Set-Content -LiteralPath $checklistPath -Encoding utf8
}

$packetManifestPath = Join-Path $outputPath 'review-manifest.json'
if (-not (Test-Path -LiteralPath $packetManifestPath -PathType Leaf)) {
    $manifest = [ordered]@{
        schema_version = 1
        review_id = Split-Path -Leaf $outputPath
        created_at = [DateTimeOffset]::UtcNow.ToString('o')
        status = 'AWAITING_INDEPENDENT_HUMAN'
        records = $candidates.Count
        prediction_commitment = [ordered]@{
            freeze_sha256 = Get-Sha256 $freezePath
            prediction_sha256 = [string]$freeze.predictions.sha256
            prediction_contents_included = $false
        }
        files = [ordered]@{
            candidates = [ordered]@{ path = 'candidate-findings.jsonl'; sha256 = Get-Sha256 (Join-Path $outputPath 'candidate-findings.jsonl') }
            matches = [ordered]@{ path = 'human-candidate-matches.jsonl'; sha256 = Get-Sha256 (Join-Path $outputPath 'human-candidate-matches.jsonl') }
            template = [ordered]@{ path = 'human-gold-labels.template.jsonl'; sha256 = Get-Sha256 $templatePath }
            schema = [ordered]@{ path = 'human-gold-label.schema.json'; sha256 = Get-Sha256 (Join-Path $outputPath 'human-gold-label.schema.json') }
        }
        exclusions = @(
            'verifier-predictions.jsonl',
            'technical-review-labels.jsonl',
            'provisional-metrics.json'
        )
    }
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $packetManifestPath -Encoding utf8
}

$allowedFiles = @(
    'candidate-findings.jsonl',
    'human-candidate-matches.jsonl',
    'human-gold-label.schema.json',
    'human-gold-labels.template.jsonl',
    'README.md',
    'review-manifest.json'
)
$unexpectedFiles = @(
    Get-ChildItem -LiteralPath $outputPath -File |
        Where-Object { $_.Name -notin $allowedFiles }
)
if ($unexpectedFiles.Count -ne 0) {
    throw "Human-review packet contains unexpected files: $($unexpectedFiles.Name -join ', ')"
}

Get-Content -LiteralPath $packetManifestPath -Raw | ConvertFrom-Json
