#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Audit', 'Plan', 'Prepare', 'Apply', 'Verify')]
    [string]$Mode = 'Audit',

    [string]$ManifestPath,

    [string]$BackupRoot = "$env:ProgramData\CTyunTrim\Runs",

    [string]$RunId,

    [string]$LgpoPath,

    [switch]$Force,

    [switch]$Restart,

    [switch]$Json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $PSScriptRoot 'config\CTyunTrim.psd1'
}

$modulePath = Join-Path $PSScriptRoot 'src\CTyunTrim.psd1'
Import-Module -Name $modulePath -Force -ErrorAction Stop

$invokeParameters = @{
    Mode         = $Mode
    ManifestPath = $ManifestPath
    BackupRoot   = $BackupRoot
    Force        = $Force
    Restart      = $Restart
    Json         = $Json
}

if ($RunId) {
    $invokeParameters.RunId = $RunId
}

if ($LgpoPath) {
    $invokeParameters.LgpoPath = $LgpoPath
}

if ($WhatIfPreference) {
    $invokeParameters.WhatIf = $true
}

$result = Invoke-CTyunTrim @invokeParameters
$result

if ($Mode -eq 'Verify') {
    $passed = if ($Json) { [bool](($result | ConvertFrom-Json).Passed) } else { [bool]$result.Passed }
    if (-not $passed) { throw 'CTyunTrim verification failed. Review the emitted Failures collection.' }
}
