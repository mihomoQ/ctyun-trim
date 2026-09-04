#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Core trust tests must run under Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) { throw 'Core trust tests require a 64-bit process.' }

$root = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $root 'config\CTyunTrim.psd1'
$modulePath = Join-Path $root 'src\CTyunTrim.psd1'
$failures = New-Object Collections.Generic.List[string]

function Assert-CTCoreTrust {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { $script:failures.Add($Message) }
}

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$balloon = @($manifest.CoreFingerprint.Services | Where-Object { $_.Name -eq 'BalloonService' }) | Select-Object -First 1
$ordinary = @($manifest.CoreFingerprint.Services | Where-Object { $_.Name -eq 'clink_service' }) | Select-Object -First 1

$systemEvidence = & $module { Get-CTCoreFileEvidence -Path "$env:SystemRoot\System32\notepad.exe" }
Assert-CTCoreTrust -Condition ([string]$systemEvidence.FileSha256 -match '^[0-9A-F]{64}$') -Message 'Locked core evidence did not produce a SHA256.'
Assert-CTCoreTrust -Condition $systemEvidence.SecureSource -Message 'Locked core evidence rejected the protected Windows notepad path ACL.'
Assert-CTCoreTrust -Condition (-not [string]::IsNullOrWhiteSpace([string]$systemEvidence.SignerThumbprint)) -Message 'Locked core evidence did not capture an embedded or catalog signer.'

function New-CTTrustEvidence {
    param(
        [AllowNull()][string]$FileSha256 = $balloon.ExpectedSha256,
        [AllowNull()][string]$SignatureStatus = 'UnknownError',
        [AllowNull()][string]$SignerThumbprint = $balloon.ExpectedSignerThumbprint,
        [AllowNull()][string]$SignerSubject = $balloon.ExpectedSignerSubject,
        [AllowNull()][string]$SignerIssuer = $balloon.ExpectedSignerIssuer,
        [bool]$SecureSource = $true
    )

    [PSCustomObject]@{
        FileSha256       = $FileSha256
        SignatureStatus  = $SignatureStatus
        SignerThumbprint = $SignerThumbprint
        SignerSubject    = $SignerSubject
        SignerIssuer     = $SignerIssuer
        SecureSource     = $SecureSource
    }
}

function Invoke-CTTrustCheck {
    param([hashtable]$Entry, [PSObject]$Evidence)
    & $module { param($CoreEntry, $CoreEvidence) Test-CTCoreBinaryTrust -Entry $CoreEntry -Evidence $CoreEvidence } $Entry $Evidence
}

function New-CTBaseline {
    param([PSObject]$Evidence, [hashtable]$Entry = $balloon)
    [PSCustomObject]@{
        TrustMode        = $Entry.TrustMode
        ExpectedImage    = $Entry.ExpectedImage
        FileSha256       = $Evidence.FileSha256
        SignatureStatus  = $Evidence.SignatureStatus
        SignerThumbprint = $Evidence.SignerThumbprint
        SignerSubject    = $Evidence.SignerSubject
        SignerIssuer     = $Evidence.SignerIssuer
        SecureSource     = $Evidence.SecureSource
    }
}

function Invoke-CTContinuityCheck {
    param([hashtable]$Entry, [PSObject]$Baseline, [PSObject]$Current, [switch]$AllowTrustDegradation)
    & $module {
        param($CoreEntry, $BaselineEntry, $CurrentEvidence, $AllowDegradation)
        Test-CTCoreBaselineContinuity -Entry $CoreEntry -BaselineEntry $BaselineEntry -CurrentEvidence $CurrentEvidence -AllowTrustDegradation:$AllowDegradation
    } $Entry $Baseline $Current ([bool]$AllowTrustDegradation)
}

$positiveUnknown = Invoke-CTTrustCheck -Entry $balloon -Evidence (New-CTTrustEvidence -SignatureStatus 'UnknownError')
$positiveValid = Invoke-CTTrustCheck -Entry $balloon -Evidence (New-CTTrustEvidence -SignatureStatus 'Valid')
Assert-CTCoreTrust -Condition $positiveUnknown.TrustSatisfied -Message 'Pinned Balloon UnknownError reference tuple was rejected.'
Assert-CTCoreTrust -Condition $positiveValid.TrustSatisfied -Message 'Pinned Balloon Valid reference tuple was rejected.'

$negativeCases = @(
    @{ Name = 'wrong hash'; Evidence = New-CTTrustEvidence -FileSha256 (('0' * 64) -join ''); Code = 'PinnedHashMismatch' },
    @{ Name = 'wrong thumbprint'; Evidence = New-CTTrustEvidence -SignerThumbprint (('0' * 40) -join ''); Code = 'PinnedSignerMismatch' },
    @{ Name = 'wrong subject'; Evidence = New-CTTrustEvidence -SignerSubject 'CN=Different'; Code = 'PinnedSignerMismatch' },
    @{ Name = 'wrong issuer'; Evidence = New-CTTrustEvidence -SignerIssuer 'CN=Different'; Code = 'PinnedSignerMismatch' },
    @{ Name = 'missing signer'; Evidence = New-CTTrustEvidence -SignerThumbprint $null -SignerSubject $null -SignerIssuer $null; Code = 'SignerMissing' },
    @{ Name = 'HashMismatch status'; Evidence = New-CTTrustEvidence -SignatureStatus 'HashMismatch'; Code = 'SignatureStatusRejected' },
    @{ Name = 'NotSigned status'; Evidence = New-CTTrustEvidence -SignatureStatus 'NotSigned'; Code = 'SignatureStatusRejected' },
    @{ Name = 'NotTrusted status'; Evidence = New-CTTrustEvidence -SignatureStatus 'NotTrusted'; Code = 'SignatureStatusRejected' },
    @{ Name = 'NotSupported status'; Evidence = New-CTTrustEvidence -SignatureStatus 'NotSupported'; Code = 'SignatureStatusRejected' },
    @{ Name = 'Incompatible status'; Evidence = New-CTTrustEvidence -SignatureStatus 'Incompatible'; Code = 'SignatureStatusRejected' },
    @{ Name = 'unsafe ACL'; Evidence = New-CTTrustEvidence -SecureSource $false; Code = 'UnsafeSource' }
)
foreach ($case in $negativeCases) {
    $result = Invoke-CTTrustCheck -Entry $balloon -Evidence $case.Evidence
    Assert-CTCoreTrust -Condition (-not $result.TrustSatisfied) -Message "Pinned Balloon accepted $($case.Name)."
    Assert-CTCoreTrust -Condition ([string]$result.FailureCode -eq [string]$case.Code) -Message "Pinned Balloon returned the wrong failure code for $($case.Name): $($result.FailureCode)"
}

$missingSecureEvidence = [PSCustomObject]@{
    FileSha256 = $balloon.ExpectedSha256
    SignatureStatus = 'UnknownError'
    SignerThumbprint = $balloon.ExpectedSignerThumbprint
    SignerSubject = $balloon.ExpectedSignerSubject
    SignerIssuer = $balloon.ExpectedSignerIssuer
}
$stringSecureEvidence = New-CTTrustEvidence
$stringSecureEvidence.SecureSource = 'false'
foreach ($unsafeEvidence in @($missingSecureEvidence, $stringSecureEvidence)) {
    $unsafeResult = Invoke-CTTrustCheck -Entry $balloon -Evidence $unsafeEvidence
    Assert-CTCoreTrust -Condition (-not $unsafeResult.TrustSatisfied -and $unsafeResult.FailureCode -eq 'UnsafeSource') -Message 'Pinned Balloon accepted missing or non-Boolean SecureSource evidence.'
}

$ordinaryValidEvidence = New-CTTrustEvidence -FileSha256 (('A' * 64) -join '') -SignatureStatus 'Valid' -SignerThumbprint (('B' * 40) -join '') -SignerSubject 'CN=Ordinary' -SignerIssuer 'CN=Issuer'
$ordinaryUnknownEvidence = New-CTTrustEvidence -FileSha256 (('A' * 64) -join '') -SignatureStatus 'UnknownError' -SignerThumbprint (('B' * 40) -join '') -SignerSubject 'CN=Ordinary' -SignerIssuer 'CN=Issuer'
Assert-CTCoreTrust -Condition (Invoke-CTTrustCheck -Entry $ordinary -Evidence $ordinaryValidEvidence).TrustSatisfied -Message 'AuthenticodeValidAtBaseline core entry rejected a valid signature.'
Assert-CTCoreTrust -Condition (-not (Invoke-CTTrustCheck -Entry $ordinary -Evidence $ordinaryUnknownEvidence).TrustSatisfied) -Message 'Balloon exception leaked into an ordinary core entry.'

$transplantedPin = @{
    Name                     = 'clink_service'
    ExpectedImage            = $ordinary.ExpectedImage
    TrustMode                = 'PinnedHashAndSigner'
    ExpectedSha256           = $balloon.ExpectedSha256
    ExpectedSignerThumbprint = $balloon.ExpectedSignerThumbprint
    ExpectedSignerSubject    = $balloon.ExpectedSignerSubject
    ExpectedSignerIssuer     = $balloon.ExpectedSignerIssuer
}
$transplantedResult = Invoke-CTTrustCheck -Entry $transplantedPin -Evidence (New-CTTrustEvidence)
Assert-CTCoreTrust -Condition (-not $transplantedResult.TrustSatisfied -and $transplantedResult.FailureCode -eq 'UnapprovedPinnedIdentity') -Message 'PinnedHashAndSigner was transplanted to another component.'

$ordinaryWithPin = @{
    Name = $ordinary.Name
    ExpectedImage = $ordinary.ExpectedImage
    TrustMode = 'AuthenticodeValidAtBaseline'
    ExpectedSha256 = $balloon.ExpectedSha256
}
$unexpectedPinResult = Invoke-CTTrustCheck -Entry $ordinaryWithPin -Evidence $ordinaryValidEvidence
Assert-CTCoreTrust -Condition (-not $unexpectedPinResult.TrustSatisfied -and $unexpectedPinResult.FailureCode -eq 'UnexpectedPinFields') -Message 'AuthenticodeValidAtBaseline accepted a hidden pin field.'

$balloonCurrent = New-CTTrustEvidence
$balloonBaseline = New-CTBaseline -Evidence $balloonCurrent
Assert-CTCoreTrust -Condition (Invoke-CTContinuityCheck -Entry $balloon -Baseline $balloonBaseline -Current $balloonCurrent).Matches -Message 'Matching pinned Balloon baseline continuity was rejected.'
Assert-CTCoreTrust -Condition (-not (Invoke-CTContinuityCheck -Entry $balloon -Baseline $balloonBaseline -Current (New-CTTrustEvidence -FileSha256 (('F' * 64) -join ''))).Matches) -Message 'Pinned Balloon baseline allowed a changed current hash.'
Assert-CTCoreTrust -Condition (-not (Invoke-CTContinuityCheck -Entry $balloon -Baseline $balloonBaseline -Current (New-CTTrustEvidence -SignerThumbprint (('F' * 40) -join ''))).Matches) -Message 'Pinned Balloon baseline allowed a changed current signer.'
Assert-CTCoreTrust -Condition (-not (Invoke-CTContinuityCheck -Entry $balloon -Baseline $balloonBaseline -Current (New-CTTrustEvidence -SignatureStatus 'HashMismatch')).Matches) -Message 'Pinned Balloon baseline allowed HashMismatch.'

$badBaselineHash = New-CTBaseline -Evidence (New-CTTrustEvidence -FileSha256 (('E' * 64) -join ''))
Assert-CTCoreTrust -Condition (-not (Invoke-CTContinuityCheck -Entry $balloon -Baseline $badBaselineHash -Current $balloonCurrent).Matches) -Message 'A baseline that fails the immutable Balloon pin was accepted.'
$legacyBaseline = [PSCustomObject]@{ ExpectedImage = $balloon.ExpectedImage; FileSha256 = $balloon.ExpectedSha256 }
Assert-CTCoreTrust -Condition (-not (Invoke-CTContinuityCheck -Entry $balloon -Baseline $legacyBaseline -Current $balloonCurrent).Matches) -Message 'A legacy baseline missing trust evidence was accepted.'

$ordinaryBaseline = New-CTBaseline -Evidence $ordinaryValidEvidence -Entry $ordinary
Assert-CTCoreTrust -Condition (-not (Invoke-CTContinuityCheck -Entry $ordinary -Baseline $ordinaryBaseline -Current $ordinaryUnknownEvidence).Matches) -Message 'Baseline continuity accepted ordinary trust degradation before certificate-removal evidence existed.'
Assert-CTCoreTrust -Condition (Invoke-CTContinuityCheck -Entry $ordinary -Baseline $ordinaryBaseline -Current $ordinaryUnknownEvidence -AllowTrustDegradation).Matches -Message 'Baseline continuity rejected expected post-cleanup trust degradation for an unchanged ordinary core file.'
$ordinaryHashMismatch = New-CTTrustEvidence -FileSha256 (('A' * 64) -join '') -SignatureStatus 'HashMismatch' -SignerThumbprint (('B' * 40) -join '') -SignerSubject 'CN=Ordinary' -SignerIssuer 'CN=Issuer'
Assert-CTCoreTrust -Condition (-not (Invoke-CTContinuityCheck -Entry $ordinary -Baseline $ordinaryBaseline -Current $ordinaryHashMismatch).Matches) -Message 'Ordinary baseline continuity allowed HashMismatch.'

$healthWiring = & $module {
    param($FixtureManifest)

    $script:CoreTrustFixtureManifest = $FixtureManifest
    $script:CoreTrustFixtureOrdinaryStatus = 'Valid'
    $script:CoreTrustFixtureBalloon = [PSCustomObject]@{
        FileSha256 = $FixtureManifest.CoreFingerprint.Services[0].ExpectedSha256
        FileVersion = '0.0.0.0'
        SignatureStatus = 'UnknownError'
        SignerThumbprint = $FixtureManifest.CoreFingerprint.Services[0].ExpectedSignerThumbprint
        SignerSubject = $FixtureManifest.CoreFingerprint.Services[0].ExpectedSignerSubject
        SignerIssuer = $FixtureManifest.CoreFingerprint.Services[0].ExpectedSignerIssuer
        SecureSource = $true
    }

    function Get-CTServiceByName {
        param([string]$Name, [switch]$Driver)
        $entries = if ($Driver) { @($script:CoreTrustFixtureManifest.CoreFingerprint.Drivers) } else { @($script:CoreTrustFixtureManifest.CoreFingerprint.Services) }
        $entry = @($entries | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
        if ($null -eq $entry) { return $null }
        [PSCustomObject]@{ Name = $Name; State = 'Running'; StartMode = 'Auto'; PathName = $entry.ExpectedImage }
    }
    function Test-Path { param([string]$LiteralPath, [string]$PathType) return $true }
    function Test-CTPathHasReparsePoint { param([string]$Path) return $false }
    function Get-CTCoreFileEvidence {
        param([string]$Path)
        $balloonEntry = $script:CoreTrustFixtureManifest.CoreFingerprint.Services[0]
        if ([string]$Path -ieq [string]$balloonEntry.ExpectedImage) { return $script:CoreTrustFixtureBalloon }
        return [PSCustomObject]@{
            FileSha256 = (('A' * 64) -join '')
            FileVersion = '2.1.0.0'
            SignatureStatus = $script:CoreTrustFixtureOrdinaryStatus
            SignerThumbprint = (('B' * 40) -join '')
            SignerSubject = 'CN=Fixture'
            SignerIssuer = 'CN=Fixture CA'
            SecureSource = $true
        }
    }
    function New-CTCoreTrustFixtureBaseline {
        $services = foreach ($entry in $script:CoreTrustFixtureManifest.CoreFingerprint.Services) {
            $evidence = Get-CTCoreFileEvidence -Path $entry.ExpectedImage
            [PSCustomObject]@{
                Name = $entry.Name
                ExpectedImage = $entry.ExpectedImage
                TrustMode = $entry.TrustMode
                FileSha256 = $evidence.FileSha256
                FileVersion = $evidence.FileVersion
                SignatureStatus = $evidence.SignatureStatus
                SignerThumbprint = $evidence.SignerThumbprint
                SignerSubject = $evidence.SignerSubject
                SignerIssuer = $evidence.SignerIssuer
                SecureSource = $evidence.SecureSource
            }
        }
        $drivers = foreach ($entry in $script:CoreTrustFixtureManifest.CoreFingerprint.Drivers) {
            $evidence = Get-CTCoreFileEvidence -Path $entry.ExpectedImage
            [PSCustomObject]@{
                Name = $entry.Name
                ExpectedImage = $entry.ExpectedImage
                TrustMode = $entry.TrustMode
                FileSha256 = $evidence.FileSha256
                FileVersion = $evidence.FileVersion
                SignatureStatus = $evidence.SignatureStatus
                SignerThumbprint = $evidence.SignerThumbprint
                SignerSubject = $evidence.SignerSubject
                SignerIssuer = $evidence.SignerIssuer
                SecureSource = $evidence.SecureSource
            }
        }
        [PSCustomObject]@{ CoreServices = @($services); CoreDrivers = @($drivers) }
    }

    $script:CoreTrustFixtureBaseline = New-CTCoreTrustFixtureBaseline
    function Get-CTBaselineCoreInventory { param([PSObject]$Context) return $script:CoreTrustFixtureBaseline }

    $initialGood = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning
    $script:CoreTrustFixtureBalloon.FileSha256 = (('F' * 64) -join '')
    $initialWrongHash = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning
    $script:CoreTrustFixtureBalloon.FileSha256 = $FixtureManifest.CoreFingerprint.Services[0].ExpectedSha256
    $resumeGood = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning -Context ([PSCustomObject]@{})
    $script:CoreTrustFixtureBalloon.SignatureStatus = 'HashMismatch'
    $resumeHashMismatch = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning -Context ([PSCustomObject]@{})
    $script:CoreTrustFixtureBalloon.SignatureStatus = 'UnknownError'
    $script:CoreTrustFixtureOrdinaryStatus = 'NotTrusted'
    $resumePrematureDegradation = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning -Context ([PSCustomObject]@{ Operations = @() })
    $resumePostCertificateDegradation = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning -Context ([PSCustomObject]@{
        Operations = @([PSCustomObject]@{ Type = 'Certificate'; Status = 'Completed'; Target = $FixtureManifest.KnownCertificates[0].Thumbprint })
    })
    $resumePendingCertificate = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning -Context ([PSCustomObject]@{
        Operations = @([PSCustomObject]@{ Type = 'Certificate'; Status = 'Pending'; Target = $FixtureManifest.KnownCertificates[0].Thumbprint })
    })
    $resumeUnknownCertificate = Test-CTCoreHealth -Manifest $FixtureManifest -RequireRunning -Context ([PSCustomObject]@{
        Operations = @([PSCustomObject]@{ Type = 'Certificate'; Status = 'Completed'; Target = (('F' * 40) -join '') })
    })

    [PSCustomObject]@{
        InitialGood = $initialGood
        InitialWrongHash = $initialWrongHash
        ResumeGood = $resumeGood
        ResumeHashMismatch = $resumeHashMismatch
        ResumePrematureDegradation = $resumePrematureDegradation
        ResumePostCertificateDegradation = $resumePostCertificateDegradation
        ResumePendingCertificate = $resumePendingCertificate
        ResumeUnknownCertificate = $resumeUnknownCertificate
    }
} $manifest
Assert-CTCoreTrust -Condition $healthWiring.InitialGood.Healthy -Message "Test-CTCoreHealth rejected the pinned Balloon reference: $($healthWiring.InitialGood.Failures -join '; ')"
Assert-CTCoreTrust -Condition (-not $healthWiring.InitialWrongHash.Healthy) -Message 'Test-CTCoreHealth accepted a wrong initial Balloon hash.'
Assert-CTCoreTrust -Condition $healthWiring.ResumeGood.Healthy -Message "Test-CTCoreHealth rejected matching pinned baseline continuity: $($healthWiring.ResumeGood.Failures -join '; ')"
Assert-CTCoreTrust -Condition (-not $healthWiring.ResumeHashMismatch.Healthy) -Message 'Test-CTCoreHealth baseline resume accepted Balloon HashMismatch.'
Assert-CTCoreTrust -Condition (-not $healthWiring.ResumePrematureDegradation.Healthy) -Message 'Test-CTCoreHealth accepted ordinary trust degradation before certificate-removal evidence.'
Assert-CTCoreTrust -Condition $healthWiring.ResumePostCertificateDegradation.Healthy -Message "Test-CTCoreHealth rejected baseline-pinned trust degradation after certificate-removal evidence: $($healthWiring.ResumePostCertificateDegradation.Failures -join '; ')"
Assert-CTCoreTrust -Condition (-not $healthWiring.ResumePendingCertificate.Healthy) -Message 'Test-CTCoreHealth accepted trust degradation for a write-ahead Pending certificate operation.'
Assert-CTCoreTrust -Condition (-not $healthWiring.ResumeUnknownCertificate.Healthy) -Message 'Test-CTCoreHealth accepted trust degradation for an unknown completed certificate target.'

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "Core trust policy tests passed ($($negativeCases.Count) pinned negative cases)."
exit 0
