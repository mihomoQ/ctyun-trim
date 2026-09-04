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

    [switch]$Diagnostic,

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
    Json         = $false
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

function New-CTDiagnosticEnvelope {
    param(
        [object]$PrimaryResult,
        [bool]$PrimarySucceeded,
        [object]$Bundle,
        [string]$DiagnosticErrorCode
    )

    $items = @($PrimaryResult)
    $resultSummary = if ($null -eq $PrimaryResult) {
        [PSCustomObject]@{ Available = $false; ItemCount = 0 }
    }
    elseif ($items.Count -ne 1) {
        [PSCustomObject]@{ Available = $true; ItemCount = $items.Count }
    }
    else {
        $item = $items[0]
        $runIdProperty = $item.PSObject.Properties['RunId']
        $statusProperty = $item.PSObject.Properties['Status']
        $passedProperty = $item.PSObject.Properties['Passed']
        $rebootProperty = $item.PSObject.Properties['RebootNeeded']
        $warningCountProperty = $item.PSObject.Properties['WarningCount']
        $status = if ($null -ne $statusProperty -and [string]$statusProperty.Value -in @('Running', 'Prepared', 'PendingReboot', 'Applied', 'Failed')) { [string]$statusProperty.Value } else { $null }
        $runId = if ($null -ne $runIdProperty -and [string]$runIdProperty.Value -match '^[0-9]{8}-[0-9]{6}-[0-9a-fA-F]{8}$') { [string]$runIdProperty.Value } else { $null }
        [PSCustomObject]@{
            Available    = $true
            ItemCount    = 1
            RunId        = $runId
            Status       = $status
            Passed       = if ($null -ne $passedProperty -and $passedProperty.Value -is [bool]) { [bool]$passedProperty.Value } else { $null }
            RebootNeeded = if ($null -ne $rebootProperty -and $rebootProperty.Value -is [bool]) { [bool]$rebootProperty.Value } else { $null }
            WarningCount = if ($null -ne $warningCountProperty -and
                ($warningCountProperty.Value -is [byte] -or $warningCountProperty.Value -is [int16] -or $warningCountProperty.Value -is [int32] -or $warningCountProperty.Value -is [int64])) {
                $count = [int64]$warningCountProperty.Value
                if ($count -lt 0) { 0 } elseif ($count -gt 100000) { 100000 } else { $count }
            }
            else { $null }
            NextAction   = if ($status -eq 'Prepared') { 'UpdateThenReviOSThenApplySameRunId' } elseif ($status -eq 'PendingReboot') { 'RebootThenApplySameRunId' } elseif ($status -eq 'Applied') { 'VerifySameRunId' } else { 'None' }
        }
    }

    [PSCustomObject]@{
        Result            = $resultSummary
        PrimarySucceeded  = $PrimarySucceeded
        Diagnostic        = if ($null -ne $Bundle) {
            [PSCustomObject]@{
                Succeeded       = $true
                BundlePath      = [string]$Bundle.BundlePath
                SHA256          = [string]$Bundle.SHA256
                Bytes           = [long]$Bundle.Bytes
                EntryCount      = [int]$Bundle.EntryCount
                RunBound        = [bool]$Bundle.RunBound
                SanitizerSchema = [string]$Bundle.SanitizerSchema
                ErrorCode       = 'None'
            }
        }
        else {
            [PSCustomObject]@{
                Succeeded       = $false
                BundlePath      = $null
                SHA256          = $null
                Bytes           = 0
                EntryCount      = 0
                RunBound        = $false
                SanitizerSchema = '1.0'
                ErrorCode       = $DiagnosticErrorCode
            }
        }
    }
}

$result = $null
$bundle = $null
try {
    if ($Diagnostic) { [void](Start-CTyunTrimDiagnosticCapture -Mode $Mode) }
    try {
        if ($Diagnostic -and $Restart) { throw 'DiagnosticCannotCombineWithRestart' }
        $result = Invoke-CTyunTrim @invokeParameters
    }
    catch {
        $primaryError = $_
        $diagnosticErrorCode = 'NotRequested'
        if ($Diagnostic) {
            try {
                $bundle = New-CTyunTrimDiagnosticBundle -Mode $Mode -ManifestPath $ManifestPath -BackupRoot $BackupRoot -RunId $RunId -Result $null -PrimarySucceeded $false -FailureMessage $primaryError.Exception.Message
                $diagnosticErrorCode = 'None'
                $primaryError.Exception.Data['DiagnosticBundlePath'] = [string]$bundle.BundlePath
            }
            catch {
                $diagnosticErrorCode = if ($_.Exception.Message -match '^Diagnostic[A-Za-z0-9]+$|^UnsafeDiagnosticOutputPath$') { $_.Exception.Message } else { 'DiagnosticExportFailed' }
            }
        }
        if ($Diagnostic) {
            $envelope = New-CTDiagnosticEnvelope -PrimaryResult $null -PrimarySucceeded $false -Bundle $bundle -DiagnosticErrorCode $diagnosticErrorCode
            if ($Json) { $envelope | ConvertTo-Json -Depth 14 } else { $envelope }
        }
        throw $primaryError
    }

    $verificationFailed = $Mode -eq 'Verify' -and -not [bool]$result.Passed
    $diagnosticErrorCode = 'NotRequested'
    if ($Diagnostic) {
        try {
            $bundle = New-CTyunTrimDiagnosticBundle -Mode $Mode -ManifestPath $ManifestPath -BackupRoot $BackupRoot -RunId $RunId -Result $result -PrimarySucceeded (-not $verificationFailed) -FailureMessage $(if ($verificationFailed) { 'Verification failed.' } else { $null })
            $diagnosticErrorCode = 'None'
        }
        catch {
            $diagnosticErrorCode = if ($_.Exception.Message -match '^Diagnostic[A-Za-z0-9]+$|^UnsafeDiagnosticOutputPath$') { $_.Exception.Message } else { 'DiagnosticExportFailed' }
        }
    }

    $output = if ($Diagnostic) {
        New-CTDiagnosticEnvelope -PrimaryResult $result -PrimarySucceeded (-not $verificationFailed) -Bundle $bundle -DiagnosticErrorCode $diagnosticErrorCode
    }
    else { $result }

    if ($Json) { $output | ConvertTo-Json -Depth 14 } else { $output }
    if ($verificationFailed) { throw 'CTyunTrim verification failed. Review the emitted Failures collection.' }
    $diagnosticFailureIsFatal = $Diagnostic -and $null -eq $bundle -and
        ($WhatIfPreference -or $Mode -in @('Audit', 'Plan', 'Verify'))
    if ($diagnosticFailureIsFatal) {
        throw "CTyunTrim diagnostic export failed: $diagnosticErrorCode"
    }
}
finally {
    if ($Diagnostic) {
        try { Stop-CTyunTrimDiagnosticCapture } catch { }
    }
}
