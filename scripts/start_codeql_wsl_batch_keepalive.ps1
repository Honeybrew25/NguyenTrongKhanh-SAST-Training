[CmdletBinding()]
param(
    [string]$Distribution = 'Ubuntu'
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$relativeScript = 'scripts/keep_codeql_wsl_batch_alive.sh'
$windowsScript = Join-Path $projectRoot $relativeScript

if (-not (Test-Path -LiteralPath $windowsScript -PathType Leaf)) {
    throw "Keepalive script not found: $windowsScript"
}

$pathRoot = [IO.Path]::GetPathRoot($windowsScript)
$drive = $pathRoot.Substring(0, 1).ToLowerInvariant()
$pathWithoutDrive = $windowsScript.Substring($pathRoot.Length)
$wslScript = "/mnt/$drive/$($pathWithoutDrive.Replace('\', '/'))"
$arguments = "-d $Distribution -- bash `"$wslScript`""

$startParams = @{
    FilePath     = "$env:SystemRoot\System32\wsl.exe"
    ArgumentList = $arguments
    WindowStyle  = 'Hidden'
    PassThru     = $true
}
$process = Start-Process @startParams

[pscustomobject]@{
    WindowsKeepalivePid = $process.Id
    Distribution        = $Distribution
    Script              = $wslScript
}
