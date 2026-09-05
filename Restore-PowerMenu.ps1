#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param([switch]$Force,[switch]$Json)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'src\CTyunTrim.psd1') -Force -ErrorAction Stop
$options=@{ Force=$Force; Json=$Json }
if ($WhatIfPreference) { $options.WhatIf=$true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $options.Confirm=$PSBoundParameters.Confirm }
$result=Restore-CTyunTrimPowerMenu @options
if (-not $Json -and $result.RefreshRequired) {
    Write-Host 'Power-menu restrictions cleared. Reopen Start; if the shell caches the old menu, sign out/in or restart Windows when convenient. No restart was performed.'
}
$result
