param(
    [string]$ScanId = "day2-full-v4-20260804",
    [int]$JobTimeoutSeconds = 7200,
    [ValidateSet("A", "B", "C", "D")]
    [string[]]$Partitions = @("A", "B", "C", "D")
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifestRelative = "artifacts/manifests/vulngym-v0.1.4.json"
$manifestPath = Join-Path $projectRoot $manifestRelative
$scanRoot = Join-Path $projectRoot "artifacts/scans/$ScanId"
$scannerExecutable = Join-Path $projectRoot ".venv/Scripts/vulngym-scan.exe"
$null = New-Item -ItemType Directory -Path $scanRoot -Force

if (-not (Test-Path -LiteralPath $scannerExecutable -PathType Leaf)) {
    throw "scanner entry point does not exist: $scannerExecutable"
}

$running = @(
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.CommandLine -and
            $_.CommandLine -match [regex]::Escape($ScanId) -and
            $_.Name -in @("vulngym-scan.exe", "python.exe", "uv.exe")
        }
)
$partitionMarkers = @{
    A = "041c47419f5a821fd4adcd46dfc7d85a7eda340e"
    B = "777c6f7580918e6711c4457cbd91161cbaefe311"
    C = "https://github.com/n8n-io/n8n"
    D = "https://github.com/apache/airflow"
}
foreach ($partition in $Partitions) {
    if (@($running | Where-Object CommandLine -like "*$($partitionMarkers[$partition])*").Count) {
        throw "partition $partition for scan-id $ScanId is already running"
    }
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$all = @($manifest.snapshots)
$openclawUrl = "https://github.com/openclaw/openclaw"
$openclaw = @($all | Where-Object repo_url -eq $openclawUrl | Sort-Object commit)
$groupA = @($openclaw[0..47])
$groupB = @($openclaw[48..95])
$groupCUrls = @(
    "https://github.com/n8n-io/n8n",
    "https://github.com/FlowiseAI/Flowise",
    "https://github.com/langflow-ai/langflow",
    "https://github.com/open-webui/open-webui",
    "https://github.com/paperclipai/paperclip"
)
$groupC = @($all | Where-Object { $_.repo_url -in $groupCUrls })
$groupD = @(
    $all | Where-Object {
        $_.repo_url -ne $openclawUrl -and $_.repo_url -notin $groupCUrls
    }
)

$combined = @($groupA + $groupB + $groupC + $groupD)
$unique = @(
    $combined |
        ForEach-Object { "$($_.repo_url)@$($_.commit)" } |
        Sort-Object -Unique
)
if (
    $groupA.Count -ne 48 -or
    $groupB.Count -ne 48 -or
    $groupC.Count -ne 42 -or
    $groupD.Count -ne 28 -or
    $combined.Count -ne 166 -or
    $unique.Count -ne 166
) {
    throw (
        "invalid partition coverage: A=$($groupA.Count), B=$($groupB.Count), " +
        "C=$($groupC.Count), D=$($groupD.Count), total=$($combined.Count), " +
        "unique=$($unique.Count)"
    )
}

$common = @(
    "--manifest", $manifestRelative,
    "--scan-id", $ScanId,
    "--job-timeout-seconds", "$JobTimeoutSeconds",
    "--prefetch",
    "--scanner", "semgrep"
)

$argsA = @($common + @("--repo-url", $openclawUrl))
foreach ($snapshot in $groupA) {
    $argsA += @("--commit", $snapshot.commit)
}
$argsB = @($common + @("--repo-url", $openclawUrl))
foreach ($snapshot in $groupB) {
    $argsB += @("--commit", $snapshot.commit)
}
$argsC = @($common)
foreach ($repoUrl in $groupCUrls) {
    $argsC += @("--repo-url", $repoUrl)
}
$argsD = @($common)
foreach ($repoUrl in @($groupD.repo_url | Sort-Object -Unique)) {
    $argsD += @("--repo-url", $repoUrl)
}

$specifications = @(
    [pscustomobject]@{ Name = "A"; SnapshotCount = 48; Arguments = $argsA },
    [pscustomobject]@{ Name = "B"; SnapshotCount = 48; Arguments = $argsB },
    [pscustomobject]@{ Name = "C"; SnapshotCount = 42; Arguments = $argsC },
    [pscustomobject]@{ Name = "D"; SnapshotCount = 28; Arguments = $argsD }
) | Where-Object Name -in $Partitions

$launchId = Get-Date -Format "yyyyMMddTHHmmss"
$started = foreach ($specification in $specifications) {
    $stdout = Join-Path $scanRoot "partition-$($specification.Name)-$launchId.stdout.log"
    $stderr = Join-Path $scanRoot "partition-$($specification.Name)-$launchId.stderr.log"
    $process = Start-Process `
        -FilePath $scannerExecutable `
        -ArgumentList $specification.Arguments `
        -WorkingDirectory $projectRoot `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru
    [pscustomobject]@{
        Partition = $specification.Name
        ProcessId = $process.Id
        SnapshotCount = $specification.SnapshotCount
        Stdout = $stdout
        Stderr = $stderr
    }
}

$started
