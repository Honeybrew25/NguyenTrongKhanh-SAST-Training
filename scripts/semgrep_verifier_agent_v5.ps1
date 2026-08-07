[CmdletBinding()]
param(
    [ValidateSet('Doctor', 'Validate', 'Status', 'Run', 'Freeze', 'PrepareHumanReview', 'Evaluate')]
    [string]$Action = 'Status'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

& (Join-Path $PSScriptRoot 'semgrep_verifier_agent_v1.ps1') `
    -Action $Action `
    -ReleaseManifest 'config/semgrep-verifier-agent-v5.json'
