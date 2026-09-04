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

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$preflightRegression = & $module {
    param($FixtureManifest)

    $script:PreflightFixtureGuardMode = 'Absent'
    $script:PreflightFixtureGuardImage = [string]$FixtureManifest.ExecutionGuards[0]
    $script:PreflightFixtureUsers = @()
    $script:PreflightFixtureProfiles = @()
    $script:PreflightFixtureCloudbaseService = $false
    $script:PreflightFixtureHiveMounted = $false
    $script:PreflightFixtureOwnedProcesses = @()
    $script:PreflightFixtureReferences = @()
    $script:PreflightFixtureIdentityAnchors = @()
    function Test-CTCoreHealth {
        param([hashtable]$Manifest, [switch]$RequireRunning, [PSObject]$Context)
        [PSCustomObject]@{ Healthy = $true; Failures = @() }
    }
    function Test-CTPathHasReparsePoint { param([string]$Path) return $false }
    function Test-CTSecureSourcePath { param([string]$Path) return $true }
    function Get-CTServiceByName {
        param([string]$Name, [switch]$Driver)
        if (-not $Driver -and $script:PreflightFixtureCloudbaseService -and $Name -eq 'cloudbase-init') {
            $entry = @($script:PreflightFixtureManifest.Services | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1
            return [PSCustomObject]@{ Name = $Name; State = 'Stopped'; PathName = $entry.ExpectedImage; StartName = '.\cloudbase-init' }
        }
        return $null
    }
    function Get-CTIfEOState {
        param([string]$Image)
        $present = $script:PreflightFixtureGuardMode -eq 'Conflict' -or
            ($script:PreflightFixtureGuardMode -eq 'PendingOwned' -and $Image -eq $script:PreflightFixtureGuardImage)
        [PSCustomObject]@{
            Present = $present
            Debugger = if ($script:PreflightFixtureGuardMode -eq 'Conflict') { 'C:\Unrelated\debugger.exe' } elseif ($present) { $script:GuardDebugger } else { $null }
            Marker = $null
            RunId = $null
        }
    }
    function Get-CTRunValue { param([hashtable]$Entry, [switch]$Strict) return $null }
    function Get-CTWsusPolicySignature {
        param([hashtable]$Manifest)
        [PSCustomObject]@{ Classification = 'Absent'; States = @() }
    }
    function Get-ScheduledTask { [CmdletBinding()] param() return @() }
    function Get-LocalUser { [CmdletBinding()] param() return @($script:PreflightFixtureUsers) }
    function Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName, [string]$Filter)
        if ($ClassName -eq 'Win32_UserProfile') { return @($script:PreflightFixtureProfiles) }
        return @()
    }
    function Get-ChildItem { [CmdletBinding()] param([string]$Path) return @() }
    function Test-Path {
        [CmdletBinding()]
        param([string]$LiteralPath, [string]$PathType)
        if ([string]$LiteralPath -like 'Registry::HKEY_USERS\*') { return [bool]$script:PreflightFixtureHiveMounted }
        return $true
    }
    function Get-AuthenticodeSignature { [CmdletBinding()] param([string]$LiteralPath) [PSCustomObject]@{ Status = 'Valid' } }
    function Get-CTMachineSid { return 'S-1-5-21-1-2-3' }
    function Get-CTCloudbaseOwnedProcessEvidence { param([string]$Sid, [hashtable]$Manifest) return @($script:PreflightFixtureOwnedProcesses) }
    function Get-CTCloudbaseIdentityReferences { param([string]$Sid) return @($script:PreflightFixtureReferences) }
    function Get-CTCloudbaseIdentityAnchors { param([string]$Sid, [hashtable]$Manifest, [object[]]$TaskSnapshot) return @($script:PreflightFixtureIdentityAnchors) }

    $script:PreflightFixtureManifest = $FixtureManifest

    $initial = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $script:PreflightFixtureGuardMode = 'Conflict'
    $guardConflict = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $script:PreflightFixtureGuardMode = 'PendingOwned'
    $pendingRunId = '20260904-233000-1234abcd'
    $pendingGuard = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -RunId $pendingRunId -Context ([PSCustomObject]@{
        RunId = $pendingRunId
        Operations = @([PSCustomObject]@{
            Type = 'ExecutionGuard'
            Status = 'Pending'
            Target = $script:PreflightFixtureGuardImage
            Data = @{ RunId = $pendingRunId }
        })
    })
    $script:PreflightFixtureGuardMode = 'Absent'
    $machineSid = 'S-1-5-21-1-2-3'
    $archivedIdentity = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Context ([PSCustomObject]@{
        MachineSid = $machineSid
        Operations = @([PSCustomObject]@{
            Type = 'CloudbaseIdentityEvidence'
            Status = 'Completed'
            Data = @{
                State = 'AbsentAtBaseline'
                MachineSid = $machineSid
                CloudbaseRoot = $FixtureManifest.Roots.Cloudbase
                AccountSid = $null
                ProfileSid = $null
            }
        })
    })

    $cloudbaseSid = 'S-1-5-21-1-2-3-1001'
    $script:PreflightFixtureUsers = @([PSCustomObject]@{ Name = 'cloudbase-init'; SID = $cloudbaseSid; Enabled = $true })
    $script:PreflightFixtureProfiles = @([PSCustomObject]@{ LocalPath = 'C:\Users\cloudbase-init'; SID = $cloudbaseSid; Loaded = $true; Special = $false })
    $script:PreflightFixtureCloudbaseService = $true
    $script:PreflightFixtureHiveMounted = $true
    $script:PreflightFixtureOwnedProcesses = @([PSCustomObject]@{ Approved = $true; Failures = @() })
    $script:PreflightFixtureReferences = @('service:cloudbase-init', 'task:\ecloud_update_agent_detect')
    $script:PreflightFixtureIdentityAnchors = @('task:\ecloud_update_agent_detect')
    $loadedPrepare = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Prepare
    $loadedApply = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Apply
    $script:PreflightFixtureProfiles[0].Special = $true
    $specialPrepare = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Prepare
    $script:PreflightFixtureProfiles[0].Special = $false
    $script:PreflightFixtureOwnedProcesses = @()
    $unexplainedLoadedPrepare = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Prepare
    $script:PreflightFixtureOwnedProcesses = @([PSCustomObject]@{ Approved = $true; Failures = @() })
    $script:PreflightFixtureIdentityAnchors = @()
    $unanchoredLoadedPrepare = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Prepare
    $script:PreflightFixtureIdentityAnchors = @('task:\ecloud_update_agent_detect')
    $script:PreflightFixtureProfiles += [PSCustomObject]@{ LocalPath = 'C:\Users\cloudbase-init.MACHINE'; SID = $cloudbaseSid; Loaded = $true; Special = $true }
    $alternateProfileApply = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Apply
    $script:PreflightFixtureUsers = @()
    $script:PreflightFixtureProfiles = @([PSCustomObject]@{ LocalPath = 'C:\Users\cloudbase-init.MACHINE'; SID = $cloudbaseSid; Loaded = $true; Special = $true })
    $script:PreflightFixtureCloudbaseService = $false
    $archivedAlternateProfileApply = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Apply -Context ([PSCustomObject]@{
        MachineSid = 'S-1-5-21-1-2-3'
        Operations = @([PSCustomObject]@{
            Type = 'CloudbaseIdentityEvidence'
            Status = 'Completed'
            Data = @{
                State = 'PresentAtBaseline'
                MachineSid = 'S-1-5-21-1-2-3'
                CloudbaseRoot = $FixtureManifest.Roots.Cloudbase
                AccountSid = $cloudbaseSid
                ProfileSid = $cloudbaseSid
                IdentityAnchors = @('task:\ecloud_update_agent_detect')
            }
        })
    })
    [PSCustomObject]@{
        Initial = $initial
        GuardConflict = $guardConflict
        PendingGuard = $pendingGuard
        ArchivedIdentity = $archivedIdentity
        LoadedPrepare = $loadedPrepare
        LoadedApply = $loadedApply
        SpecialPrepare = $specialPrepare
        UnexplainedLoadedPrepare = $unexplainedLoadedPrepare
        UnanchoredLoadedPrepare = $unanchoredLoadedPrepare
        AlternateProfileApply = $alternateProfileApply
        ArchivedAlternateProfileApply = $archivedAlternateProfileApply
    }
} $manifest
Assert-CTCoreTrust -Condition $preflightRegression.Initial.Passed -Message "Initial preflight with empty context collections failed: $($preflightRegression.Initial.Errors -join '; ')"
Assert-CTCoreTrust -Condition (-not $preflightRegression.GuardConflict.Passed) -Message 'Preflight accepted an existing unknown execution guard.'
Assert-CTCoreTrust -Condition (@($preflightRegression.GuardConflict.Errors | Where-Object { $_ -match 'Existing unknown or differently owned IFEO' }).Count -gt 0) -Message 'Execution-guard regression test did not reach the intended conflict check.'
Assert-CTCoreTrust -Condition $preflightRegression.PendingGuard.Passed -Message "Preflight failed with exactly one owned pending guard: $($preflightRegression.PendingGuard.Errors -join '; ')"
Assert-CTCoreTrust -Condition $preflightRegression.ArchivedIdentity.Passed -Message "Preflight failed with exactly one archived Cloudbase identity record: $($preflightRegression.ArchivedIdentity.Errors -join '; ')"
Assert-CTCoreTrust -Condition $preflightRegression.LoadedPrepare.Passed -Message "Prepare rejected the exact approved loaded Cloudbase profile holder: $($preflightRegression.LoadedPrepare.Errors -join '; ')"
Assert-CTCoreTrust -Condition (@($preflightRegression.LoadedPrepare.Warnings | Where-Object { $_ -match 'loaded only by the approved TaskAgentDetect' }).Count -eq 1) -Message 'Prepare did not report the loaded Cloudbase profile deferral warning.'
Assert-CTCoreTrust -Condition (-not $preflightRegression.LoadedApply.Passed) -Message 'Apply accepted a loaded Cloudbase profile.'
Assert-CTCoreTrust -Condition (-not $preflightRegression.SpecialPrepare.Passed) -Message 'Prepare accepted a Special Cloudbase profile.'
Assert-CTCoreTrust -Condition (-not $preflightRegression.UnexplainedLoadedPrepare.Passed) -Message 'Prepare accepted a loaded Cloudbase profile with no approved owner process.'
Assert-CTCoreTrust -Condition (-not $preflightRegression.UnanchoredLoadedPrepare.Passed) -Message 'Prepare accepted a Cloudbase account/Profile with no service or scheduled-task principal SID anchor.'
Assert-CTCoreTrust -Condition (-not $preflightRegression.AlternateProfileApply.Passed) -Message 'Apply accepted an additional same-SID Cloudbase Profile at an alternate path.'
Assert-CTCoreTrust -Condition (-not $preflightRegression.ArchivedAlternateProfileApply.Passed) -Message 'Apply mutation-boundary preflight ignored an alternate-path Profile found only through archived SID evidence.'

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$anchorPolicy = & $module {
    param($FixtureManifest)
    function Get-CTServiceByName { param([string]$Name, [switch]$Driver) return $null }
    $sid = 'S-1-5-21-1-2-3-1001'
    $entry = @($FixtureManifest.ScheduledTasks | Where-Object { $_.Name -eq 'ecloud_update_agent_detect' }) | Select-Object -First 1
    function New-AnchorTask {
        param([string]$PrincipalSid)
        [PSCustomObject]@{
            TaskName = $entry.Name
            TaskPath = $entry.TaskPath
            Principal = [PSCustomObject]@{ UserId = $PrincipalSid; GroupId = $null }
            Actions = @([PSCustomObject]@{
                Execute = $entry.ExpectedImage
                Arguments = ''
                CimClass = [PSCustomObject]@{ CimClassName = 'MSFT_TaskExecAction' }
            })
        }
    }
    [PSCustomObject]@{
        Exact = @(Get-CTCloudbaseIdentityAnchors -Sid $sid -Manifest $FixtureManifest -TaskSnapshot @((New-AnchorTask -PrincipalSid $sid)))
        Wrong = @(Get-CTCloudbaseIdentityAnchors -Sid $sid -Manifest $FixtureManifest -TaskSnapshot @((New-AnchorTask -PrincipalSid 'S-1-5-21-1-2-3-1002')))
    }
} $manifest
Assert-CTCoreTrust -Condition ($anchorPolicy.Exact.Count -eq 1 -and $anchorPolicy.Exact[0] -eq 'task:\ecloud_update_agent_detect') -Message 'Exact scheduled-task principal SID did not establish the Cloudbase identity anchor.'
Assert-CTCoreTrust -Condition ($anchorPolicy.Wrong.Count -eq 0) -Message 'A different scheduled-task principal SID established the Cloudbase identity anchor.'

$cloudbaseProcessPolicy = & $module {
    param($FixtureManifest)
    $sid = 'S-1-5-21-1-2-3-1001'
    $expectedImage = [string](@($FixtureManifest.ScheduledTasks | Where-Object { $_.Name -eq 'ecloud_update_agent_detect' })[0].ExpectedImage)
    function New-ProcessEvidence {
        param(
            [string]$Path = $expectedImage,
            [string]$OwnerSid = $sid,
            [uint32]$SessionId = 0,
            [string]$SignatureStatus = 'Valid',
            [bool]$HasReparsePoint = $false,
            [bool]$SecureSource = $true,
            [bool]$Stable = $true
        )
        [PSCustomObject]@{
            ProcessId = [int]4321
            ProcessName = 'TaskAgentDetect'
            CimName = 'TaskAgentDetect.exe'
            Path = $Path
            CimPath = $Path
            OwnerSid = $OwnerSid
            SessionId = $SessionId
            StartTimeUtcTicks = '638925120000000000'
            SignatureStatus = $SignatureStatus
            FileSha256 = (('A' * 64) -join '')
            HasReparsePoint = $HasReparsePoint
            SecureSource = $SecureSource
            Stable = $Stable
        }
    }
    $stringSecure = New-ProcessEvidence
    $stringSecure.SecureSource = 'false'
    $stringStable = New-ProcessEvidence
    $stringStable.Stable = 'true'
    $stringSession = New-ProcessEvidence
    $stringSession.SessionId = '0'
    [PSCustomObject]@{
        Good = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence) -ExpectedSid $sid -ExpectedImage $expectedImage
        WrongPath = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence -Path 'C:\Temp\TaskAgentDetect.exe') -ExpectedSid $sid -ExpectedImage $expectedImage
        WrongOwner = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence -OwnerSid 'S-1-5-21-1-2-3-1002') -ExpectedSid $sid -ExpectedImage $expectedImage
        Interactive = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence -SessionId 2) -ExpectedSid $sid -ExpectedImage $expectedImage
        InvalidSignature = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence -SignatureStatus 'UnknownError') -ExpectedSid $sid -ExpectedImage $expectedImage
        Reparse = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence -HasReparsePoint $true) -ExpectedSid $sid -ExpectedImage $expectedImage
        UnsafeAcl = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence -SecureSource $false) -ExpectedSid $sid -ExpectedImage $expectedImage
        Unstable = Test-CTCloudbasePrepareProcessEvidence -Evidence (New-ProcessEvidence -Stable $false) -ExpectedSid $sid -ExpectedImage $expectedImage
        StringSecure = Test-CTCloudbasePrepareProcessEvidence -Evidence $stringSecure -ExpectedSid $sid -ExpectedImage $expectedImage
        StringStable = Test-CTCloudbasePrepareProcessEvidence -Evidence $stringStable -ExpectedSid $sid -ExpectedImage $expectedImage
        StringSession = Test-CTCloudbasePrepareProcessEvidence -Evidence $stringSession -ExpectedSid $sid -ExpectedImage $expectedImage
    }
} $manifest
Assert-CTCoreTrust -Condition $cloudbaseProcessPolicy.Good.Passed -Message "Exact TaskAgentDetect process evidence was rejected: $($cloudbaseProcessPolicy.Good.Failures -join ', ')"
foreach ($property in @('WrongPath', 'WrongOwner', 'Interactive', 'InvalidSignature', 'Reparse', 'UnsafeAcl', 'Unstable', 'StringSecure', 'StringStable', 'StringSession')) {
    Assert-CTCoreTrust -Condition (-not $cloudbaseProcessPolicy.$property.Passed) -Message "Unsafe Cloudbase process evidence passed: $property"
}

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$ownerEnumeration = & $module {
    $targetSid = 'S-1-5-21-1-2-3-1001'
    $otherSid = 'S-1-5-18'
    $script:OwnerFixtureInaccessiblePid = $null
    $script:OwnerFixtureQueryThrowsPid = $null
    $script:OwnerFixtureProcesses = @(
        [PSCustomObject]@{ ProcessId = [uint32]100; Name = 'TaskAgentDetect.exe'; ExecutablePath = 'C:\Approved\TaskAgentDetect.exe'; SessionId = [uint32]0; CreationDate = '20260905000100.000000+480'; OwnerSid = $targetSid; OwnerReturn = [uint32]0 },
        [PSCustomObject]@{ ProcessId = [uint32]101; Name = 'Other.exe'; ExecutablePath = 'C:\Approved\Other.exe'; SessionId = [uint32]0; CreationDate = '20260905000200.000000+480'; OwnerSid = $targetSid; OwnerReturn = [uint32]0 },
        [PSCustomObject]@{ ProcessId = [uint32]102; Name = 'SystemLike.exe'; ExecutablePath = 'C:\Windows\System32\SystemLike.exe'; SessionId = [uint32]0; CreationDate = '20260905000300.000000+480'; OwnerSid = $otherSid; OwnerReturn = [uint32]0 }
    )
    function Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName, [string]$Filter)
        if ([string]::IsNullOrWhiteSpace($Filter)) { return @($script:OwnerFixtureProcesses) }
        if ($Filter -match 'ProcessId = (?<pid>[0-9]+)') {
            if ($null -ne $script:OwnerFixtureQueryThrowsPid -and [uint32]$matches.pid -eq [uint32]$script:OwnerFixtureQueryThrowsPid) {
                throw 'Synthetic targeted CIM query failure.'
            }
            return @($script:OwnerFixtureProcesses | Where-Object { [uint32]$_.ProcessId -eq [uint32]$matches.pid })
        }
        return @()
    }
    function Invoke-CimMethod {
        [CmdletBinding()]
        param([PSObject]$InputObject, [string]$MethodName)
        [PSCustomObject]@{ ReturnValue = [uint32]$InputObject.OwnerReturn; Sid = [string]$InputObject.OwnerSid }
    }
    function Get-Process {
        [CmdletBinding()]
        param([int]$Id)
        if ($null -ne $script:OwnerFixtureInaccessiblePid -and $Id -eq [int]$script:OwnerFixtureInaccessiblePid) { return $null }
        $item = @($script:OwnerFixtureProcesses | Where-Object { [int]$_.ProcessId -eq $Id }) | Select-Object -First 1
        if ($null -eq $item) { return $null }
        [PSCustomObject]@{ Id = $Id; ProcessName = [IO.Path]::GetFileNameWithoutExtension([string]$item.Name); Path = [string]$item.ExecutablePath; StartTime = [datetime]'2026-09-05T00:00:00Z' }
    }

    $twoOwners = @(Get-CTProcessesByOwnerSid -Sid $targetSid)
    $script:OwnerFixtureInaccessiblePid = 100
    $inaccessibleTargetRejected = $false
    try { $null = @(Get-CTProcessesByOwnerSid -Sid $targetSid) }
    catch { $inaccessibleTargetRejected = $_.Exception.Message -match 'live target-SID process could not be inspected' }
    $script:OwnerFixtureQueryThrowsPid = 100
    $targetQueryFailureRejected = $false
    try { $null = @(Get-CTProcessesByOwnerSid -Sid $targetSid) }
    catch { $targetQueryFailureRejected = $_.Exception.Message -match 'Targeted process liveness query failed' }
    $script:OwnerFixtureInaccessiblePid = $null
    $script:OwnerFixtureProcesses += [PSCustomObject]@{ ProcessId = [uint32]103; Name = 'Unresolved.exe'; ExecutablePath = $null; SessionId = [uint32]0; CreationDate = '20260905000400.000000+480'; OwnerSid = $null; OwnerReturn = [uint32]2 }
    $script:OwnerFixtureQueryThrowsPid = 103
    $initialQueryFailureRejected = $false
    try { $null = @(Get-CTProcessesByOwnerSid -Sid $targetSid) }
    catch { $initialQueryFailureRejected = $_.Exception.Message -match 'remained unresolved' }
    $script:OwnerFixtureQueryThrowsPid = $null
    $unresolvedRejected = $false
    try { $null = @(Get-CTProcessesByOwnerSid -Sid $targetSid) }
    catch { $unresolvedRejected = $_.Exception.Message -match 'remained unresolved' }
    [PSCustomObject]@{
        TargetOwnerCount = $twoOwners.Count
        InaccessibleTargetRejected = $inaccessibleTargetRejected
        TargetQueryFailureRejected = $targetQueryFailureRejected
        InitialQueryFailureRejected = $initialQueryFailureRejected
        UnresolvedRejected = $unresolvedRejected
    }
}
Assert-CTCoreTrust -Condition ($ownerEnumeration.TargetOwnerCount -eq 2) -Message 'Full Win32_Process owner-SID enumeration missed a target-owned process without UserName filtering.'
Assert-CTCoreTrust -Condition $ownerEnumeration.InaccessibleTargetRejected -Message 'Owner-SID enumeration treated an inaccessible live target-owned process as exited.'
Assert-CTCoreTrust -Condition $ownerEnumeration.TargetQueryFailureRejected -Message 'Owner-SID enumeration treated a failed target liveness query as process exit.'
Assert-CTCoreTrust -Condition $ownerEnumeration.InitialQueryFailureRejected -Message 'Owner-SID enumeration treated a failed owner retry query as process exit.'
Assert-CTCoreTrust -Condition $ownerEnumeration.UnresolvedRejected -Message 'Owner-SID enumeration did not fail closed for a persistent unresolved process.'

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$alternateProfileRemoval = & $module {
    param($FixtureManifest)
    $machineSid = 'S-1-5-21-1-2-3'
    $expectedSid = "$machineSid-1001"
    $script:AccountDeletionReached = $false
    $account = [PSCustomObject]@{ Name = 'cloudbase-init'; SID = $expectedSid; Enabled = $true }
    $alternateProfile = [PSCustomObject]@{ LocalPath = 'C:\Users\cloudbase-init.MACHINE'; SID = $expectedSid; Loaded = $true; Special = $true }
    function Get-LocalUser { [CmdletBinding()] param() return @($account) }
    function Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName, [string]$Filter)
        if ($ClassName -eq 'Win32_UserProfile') { return @($alternateProfile) }
        return @()
    }
    function Remove-LocalUser { [CmdletBinding()] param([object]$SID) $script:AccountDeletionReached = $true }
    function Invoke-RemovalFixture {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param()
        Remove-CTCloudbaseIdentity -Context $context -Manifest $FixtureManifest -Caller $PSCmdlet
    }
    $serviceEntry = @($FixtureManifest.Services | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1
    $context = [PSCustomObject]@{
        MachineSid = $machineSid
        Operations = @([PSCustomObject]@{
            Type = 'CloudbaseIdentityEvidence'
            Status = 'Completed'
            Data = @{
                State = 'PresentAtBaseline'
                MachineSid = $machineSid
                CloudbaseRoot = $FixtureManifest.Roots.Cloudbase
                AccountSid = $expectedSid
                ProfileSid = $expectedSid
                Services = @([PSCustomObject]@{ Name = 'cloudbase-init'; ResolvedImage = $serviceEntry.ExpectedImage })
                IdentityAnchors = @('task:\ecloud_update_agent_detect')
            }
        })
    }
    $blocked = $false
    try { Invoke-RemovalFixture -Confirm:$false | Out-Null }
    catch { $blocked = $_.Exception.Message -match 'unexpected or additional user Profile path' }
    [PSCustomObject]@{ Blocked = $blocked; AccountDeletionReached = $script:AccountDeletionReached }
} $manifest
Assert-CTCoreTrust -Condition $alternateProfileRemoval.Blocked -Message 'Cloudbase removal did not block an alternate-path Profile sharing the archived SID.'
Assert-CTCoreTrust -Condition (-not $alternateProfileRemoval.AccountDeletionReached) -Message 'Cloudbase account deletion was reached despite an unsafe alternate-path Profile.'

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "Core trust policy tests passed ($($negativeCases.Count) pinned negative cases)."
exit 0
