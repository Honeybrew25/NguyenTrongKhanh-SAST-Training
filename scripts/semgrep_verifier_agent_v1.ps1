[CmdletBinding()]
param(
    [ValidateSet('Doctor', 'Validate', 'Status', 'Run', 'Freeze', 'PrepareHumanReview', 'Evaluate')]
    [string]$Action = 'Status',
    [string]$ReleaseManifest = 'config/semgrep-verifier-agent-v1.json'
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

function Assert-FileIdentity {
    param([Parameter(Mandatory = $true)]$Identity)
    $path = Resolve-ProjectPath ([string]$Identity.path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Release file is missing: $path"
    }
    $actual = Get-Sha256 $path
    if ($actual -ne [string]$Identity.sha256) {
        throw "Release checksum mismatch: $($Identity.path)"
    }
}

function Invoke-Uv {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    Push-Location $projectRoot
    try {
        & uv @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "uv command exited with code $exitCode"
    }
}

$releasePath = Resolve-ProjectPath $ReleaseManifest
if (-not (Test-Path -LiteralPath $releasePath -PathType Leaf)) {
    throw "Release manifest is missing: $releasePath"
}
$release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
if (
    [int]$release.schema_version -ne 1 -or
    [string]$release.release_id -ne 'semgrep-verifier-agent-v1' -or
    [string]$release.scope.scanner -ne 'semgrep'
) {
    throw 'Release manifest is not the Semgrep verifier agent v1.'
}
foreach ($identity in @($release.identity.files)) {
    Assert-FileIdentity $identity
}

$inputPath = Resolve-ProjectPath ([string]$release.corpus.input.path)
$summaryPath = Resolve-ProjectPath ([string]$release.corpus.summary.path)
Assert-FileIdentity $release.corpus.input
Assert-FileIdentity $release.corpus.summary
$summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
if (
    $summary.complete -ne $true -or
    [string]$summary.scope.scanner -ne 'semgrep' -or
    [string]$summary.blind_verifier_input.sha256 -ne [string]$release.corpus.input.sha256 -or
    [int]$summary.blind_verifier_input.records -ne [int]$release.corpus.input.records
) {
    throw 'Frozen corpus summary is incompatible with this release.'
}
$records = @(
    Get-Content -LiteralPath $inputPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)
if ($records.Count -ne [int]$release.corpus.input.records) {
    throw 'Frozen corpus record count is incompatible with this release.'
}
$findingIds = @($records | ForEach-Object { [string]$_.finding_id })
if (
    @($findingIds | Sort-Object -Unique).Count -ne $records.Count -or
    @($records | Where-Object { [string]$_.scanner.name -ne 'semgrep' }).Count -ne 0
) {
    throw 'Release input is not a unique Semgrep-only corpus.'
}
$snapshotCount = @(
    $records |
        ForEach-Object { "$($_.repo_url)@$($_.commit)" } |
        Sort-Object -Unique
).Count
if ($snapshotCount -ne [int]$release.corpus.snapshots) {
    throw 'Frozen corpus snapshot count is incompatible with this release.'
}

$runPath = Resolve-ProjectPath ([string]$release.run.directory)
$snapshotRoot = Resolve-ProjectPath ([string]$release.source.snapshot_root)
$profilePath = Resolve-ProjectPath ([string]$release.agent.profile.path)
$promptPath = Resolve-ProjectPath ([string]$release.agent.prompt.path)
$responseSchemaPath = Resolve-ProjectPath ([string]$release.agent.response_schema.path)

$validateArguments = @(
    'run', 'vulngym-verify-agent',
    '--input', $inputPath,
    '--snapshot-root', $snapshotRoot,
    '--run-dir', $runPath,
    '--profile', $profilePath,
    '--prompt', $promptPath,
    '--response-schema', $responseSchemaPath,
    '--validate-only'
)

switch ($Action) {
    'Doctor' {
        $uv = Get-Command uv -ErrorAction SilentlyContinue
        $codex = Get-Command codex -ErrorAction SilentlyContinue
        $codexVersion = $null
        $codexSha256 = $null
        if ($null -ne $codex) {
            $codexVersion = (& codex --version 2>$null | Select-Object -First 1)
            if (Test-Path -LiteralPath $codex.Source -PathType Leaf) {
                $codexSha256 = Get-Sha256 $codex.Source
            }
        }
        $providerIdentityMatches = (
            $codexVersion -eq [string]$release.agent.provider.version -and
            $codexSha256 -eq [string]$release.agent.provider.executable_sha256
        )
        [pscustomobject]@{
            Release = [string]$release.release_id
            Corpus = 'READY'
            Records = $records.Count
            Snapshots = $snapshotCount
            UvAvailable = $null -ne $uv
            CodexAvailable = $null -ne $codex
            CodexVersion = $codexVersion
            CodexSha256 = $codexSha256
            ProviderIdentityMatches = $providerIdentityMatches
            ProviderAuthentication = 'UNVERIFIED_UNTIL_RUN'
            LocalComponentsReady = ($null -ne $uv -and $providerIdentityMatches)
        }
    }
    'Validate' {
        Invoke-Uv $validateArguments
    }
    'Status' {
        $statePath = Join-Path $runPath 'run-state.json'
        $freezePath = Join-Path $runPath 'prediction-freeze.json'
        $reviewPath = Resolve-ProjectPath ([string]$release.human_review.directory)
        $goldPath = Join-Path $reviewPath 'human-gold-labels.jsonl'
        $metricsPath = Resolve-ProjectPath ([string]$release.metrics.output)
        $runName = Split-Path -Leaf $runPath
        try {
            $liveProcesses = @(
                Get-CimInstance Win32_Process -ErrorAction Stop |
                    Where-Object {
                        $_.Name -in @('uv.exe', 'python.exe', 'codex.exe') -and
                        [string]$_.CommandLine -match [regex]::Escape($runName)
                    }
            )
        }
        catch {
            $liveProcesses = @()
        }
        if (Test-Path -LiteralPath $statePath -PathType Leaf) {
            $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            $runState = [string]$state.state
            $counts = $state.case_counts
        }
        else {
            $runState = 'NOT_STARTED'
            $counts = [pscustomobject]@{
                total = $records.Count
                success = 0
                failed = 0
                interrupted = 0
                running = 0
                pending = $records.Count
            }
        }
        $nextAction = switch ($runState) {
            'COMPLETE' {
                if (-not (Test-Path -LiteralPath $freezePath -PathType Leaf)) { 'Freeze' }
                elseif (-not (Test-Path -LiteralPath $goldPath -PathType Leaf)) { 'PrepareHumanReview' }
                elseif (-not (Test-Path -LiteralPath $metricsPath -PathType Leaf)) { 'Evaluate' }
                else { 'DONE' }
            }
            'BLOCKED_PROVIDER' { 'RESTORE_PROVIDER_THEN_RUN' }
            default { 'Run' }
        }
        [pscustomobject]@{
            Release = [string]$release.release_id
            Scope = 'SEMGREP_ONLY'
            RunState = $runState
            Total = [int]$counts.total
            Success = [int]$counts.success
            Failed = [int]$counts.failed
            Interrupted = [int]$counts.interrupted
            Running = [int]$counts.running
            Pending = [int]$counts.pending
            LiveProcesses = $liveProcesses.Count
            PredictionsFrozen = Test-Path -LiteralPath $freezePath -PathType Leaf
            HumanGoldAvailable = Test-Path -LiteralPath $goldPath -PathType Leaf
            MetricsAvailable = Test-Path -LiteralPath $metricsPath -PathType Leaf
            NextAction = $nextAction
        }
    }
    'Run' {
        $codex = Get-Command codex -ErrorAction SilentlyContinue
        if ($null -eq $codex -or -not (Test-Path -LiteralPath $codex.Source -PathType Leaf)) {
            throw 'Pinned Codex CLI executable is unavailable.'
        }
        $codexVersion = (& codex --version 2>$null | Select-Object -First 1)
        $codexSha256 = Get-Sha256 $codex.Source
        if (
            $codexVersion -ne [string]$release.agent.provider.version -or
            $codexSha256 -ne [string]$release.agent.provider.executable_sha256
        ) {
            throw 'Codex CLI identity differs from the pinned v1 provider.'
        }
        Invoke-Uv $validateArguments
        Invoke-Uv @(
            'run', 'vulngym-verify-agent',
            '--input', $inputPath,
            '--snapshot-root', $snapshotRoot,
            '--run-dir', $runPath,
            '--profile', $profilePath,
            '--prompt', $promptPath,
            '--response-schema', $responseSchemaPath,
            '--model', [string]$release.agent.model
        )
    }
    'Freeze' {
        & (Resolve-ProjectPath 'scripts/freeze_verifier_predictions.ps1') -RunDirectory $runPath
    }
    'PrepareHumanReview' {
        & (Resolve-ProjectPath 'scripts/prepare_human_review_packet.ps1') `
            -VerifierRun $runPath `
            -SourceQueue (Resolve-ProjectPath ([string]$release.human_review.source_queue)) `
            -OutputDirectory (Resolve-ProjectPath ([string]$release.human_review.directory))
    }
    'Evaluate' {
        $freezePath = Join-Path $runPath 'prediction-freeze.json'
        $predictionsPath = Join-Path $runPath 'verifier-predictions.jsonl'
        $labelsPath = Join-Path (Resolve-ProjectPath ([string]$release.human_review.directory)) 'human-gold-labels.jsonl'
        foreach ($required in @($freezePath, $predictionsPath, $labelsPath)) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
                throw "Evaluation input is missing: $required"
            }
        }
        $freeze = Get-Content -LiteralPath $freezePath -Raw | ConvertFrom-Json
        if ((Get-Sha256 $predictionsPath) -ne [string]$freeze.predictions.sha256) {
            throw 'Predictions changed after freeze.'
        }
        Invoke-Uv @(
            'run', 'vulngym-evaluate', 'classify',
            '--labels', $labelsPath,
            '--predictions', $predictionsPath,
            '--output', (Resolve-ProjectPath ([string]$release.metrics.output))
        )
    }
}
