#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Tests must run under Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Tests must run under a 64-bit PowerShell process.'
}

$root = Split-Path -Parent $PSScriptRoot
$failures = New-Object Collections.Generic.List[string]

function Assert-CT {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        $script:failures.Add($Message)
    }
}

$powerShellFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File |
    Where-Object {
        ($_.Extension -in @('.ps1', '.psm1', '.psd1')) -and
        ($_.FullName -notmatch '[\\/]artifacts[\\/]')
    })

foreach ($file in $powerShellFiles) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $parseMessage = if ($errors.Count -gt 0) { ($errors | ForEach-Object { $_.Message }) -join '; ' } else { '' }
    Assert-CT -Condition ($errors.Count -eq 0) -Message "Parser errors in $($file.FullName): $parseMessage"

    if ($file.Extension -in @('.ps1', '.psm1', '.psd1')) {
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        $hasNonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count -gt 0
        Assert-CT -Condition (-not $hasNonAscii) -Message "Executable PowerShell source must remain ASCII for Windows PowerShell 5.1: $($file.FullName)"
    }
}

$manifestPath = Join-Path $root 'config\CTyunTrim.psd1'
$modulePath = Join-Path $root 'src\CTyunTrim.psd1'
$moduleManifest = Import-PowerShellDataFile -LiteralPath $modulePath
Import-Module -Name $modulePath -Force

$validation = Test-CTyunTrimManifest -ManifestPath $manifestPath
Assert-CT -Condition $validation.Valid -Message "Manifest validation failed: $($validation.Errors -join '; ')"

$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$removeServiceNames = @($manifest.Services | ForEach-Object { $_.Name })
$removeDriverNames = @($manifest.DriverServices | ForEach-Object { $_.Name })

foreach ($name in $manifest.Preserve.Services) {
    Assert-CT -Condition ($removeServiceNames -notcontains $name) -Message "Protected service appears in removal list: $name"
}
foreach ($name in $manifest.Preserve.Drivers) {
    Assert-CT -Condition ($removeDriverNames -notcontains $name) -Message "Protected driver appears in removal list: $name"
}

$allRemovalText = (@($manifest.Directories) + @($manifest.Files) + @($manifest.Processes)) -join "`n"
Assert-CT -Condition ($allRemovalText -notmatch '(?i)WinDivertProxy-Port') -Message 'Protected WinDivertProxy-Port appears in a removal list.'
Assert-CT -Condition ($allRemovalText -notmatch '(?i)dokan2\.dll') -Message 'Protected dokan2.dll appears in a removal list.'
Assert-CT -Condition ($allRemovalText -notmatch '(?i)FileCrypt\.sys') -Message 'Windows FileCrypt.sys appears in a removal list.'

$implementationFiles = @($powerShellFiles | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' })
$sourceText = ($implementationFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
Assert-CT -Condition ($sourceText -notmatch '(?i)Win32_Product') -Message 'Win32_Product is forbidden because it can trigger MSI self-repair.'
Assert-CT -Condition ($sourceText -notmatch '(?i)Invoke-Expression') -Message 'Invoke-Expression is forbidden.'
Assert-CT -Condition ($sourceText -notmatch '(?i)Start-Transcript') -Message 'Unstructured PowerShell transcripts are forbidden.'
Assert-CT -Condition ($sourceText -notmatch '(?i)Remove-Item.+System32\\GroupPolicy') -Message 'Deleting the complete GroupPolicy directory is forbidden.'
Assert-CT -Condition (@([regex]::Matches($sourceText, 'Test-CTApplyPreflight[^\r\n]+-Phase Prepare')).Count -eq 2) -Message 'Prepare must use its loaded-profile phase at initial and mutation-boundary preflight.'
Assert-CT -Condition (@([regex]::Matches($sourceText, 'Test-CTApplyPreflight[^\r\n]+-Phase Apply')).Count -eq 3) -Message 'Initial, resumed and mutation-boundary Apply must explicitly select the strict Apply preflight phase.'
$profileRemovalPosition = $sourceText.IndexOf("-Action 'Remove orphaned cloudbase-init user profile'", [StringComparison]::Ordinal)
$accountDisablePosition = $sourceText.IndexOf("-Action 'Disable and remove exact local service account SID'", [StringComparison]::Ordinal)
$profileProcessBoundaryPosition = $sourceText.IndexOf('$boundaryProcesses = @(Get-CTProcessesByOwnerSid', [StringComparison]::Ordinal)
$profileDeletePosition = $sourceText.IndexOf('$profile | Remove-CimInstance -ErrorAction Stop', [StringComparison]::Ordinal)
$accountRemovalPosition = $sourceText.IndexOf('Remove-LocalUser -SID $account.SID -ErrorAction Stop', [StringComparison]::Ordinal)
Assert-CT -Condition ($accountDisablePosition -ge 0 -and $profileRemovalPosition -gt $accountDisablePosition -and $accountRemovalPosition -gt $profileRemovalPosition) -Message 'Cloudbase identity order must confirm/disable the account, remove the unloaded Profile, then remove the account.'
Assert-CT -Condition ($profileProcessBoundaryPosition -ge 0 -and $profileDeletePosition -gt $profileProcessBoundaryPosition) -Message 'Cloudbase Profile deletion lacks a final owner-SID process boundary check.'
Assert-CT -Condition ($sourceText -match 'Disable-LocalUser -SID \$account\.SID -ErrorAction Stop') -Message 'Cloudbase account disable is not fail-closed.'
Assert-CT -Condition ([string]$moduleManifest.ModuleVersion -eq '0.1.4') -Message 'ModuleVersion is not 0.1.4.'
Assert-CT -Condition ([string]$moduleManifest.PrivateData.PSData.Prerelease -eq 'Diagnostic') -Message 'Module prerelease label is not Diagnostic.'
Assert-CT -Condition (@($moduleManifest.FunctionsToExport) -contains 'New-CTyunTrimDiagnosticBundle') -Message 'Diagnostic bundle exporter is not declared in the module manifest.'
$diagnosticResultSafety = & (Get-Module CTyunTrim) {
    $view = Get-CTDiagnosticResultView -Result ([PSCustomObject]@{
        Status = 'ULTRA_PRIVATE_CANARY_7F8B2D'
        Passed = 'not-a-boolean'
        RebootNeeded = 'not-a-boolean'
        WarningCount = 'CANARY_COUNT'
    })
    $view | ConvertTo-Json -Compress
}
Assert-CT -Condition ($diagnosticResultSafety -notmatch 'ULTRA_PRIVATE_CANARY_7F8B2D|CANARY_COUNT|not-a-boolean') -Message 'Diagnostic result projection copied an untrusted scalar.'
Assert-CT -Condition ($diagnosticResultSafety -match 'Unknown') -Message 'Diagnostic result projection did not map an unknown status to a stable enum.'
$diagnosticCodes = & (Get-Module CTyunTrim) {
    [PSCustomObject]@{
        CloudbaseLoaded = Get-CTDiagnosticCode -Message 'Cloudbase profile is loaded or its user hive is mounted.'
        DriverLoaded = Get-CTDiagnosticCode -Message 'Driver is currently loaded and may require a reboot.'
        ContextLoaded = Get-CTDiagnosticCode -Message 'Loaded protected run context.'
        PreflightFailed = Get-CTDiagnosticCode -Message 'Prepare preflight failed: cloudbase-init profile is loaded or special.'
        CloudbaseDeferred = Get-CTDiagnosticCode -Message 'Cloudbase profile is loaded only by the approved TaskAgentDetect process.'
        CurrentCloudbaseIdentity = Get-CTDiagnosticCode -Message 'CTyunTrim is running as the loaded Cloudbase identity.'
    }
}
Assert-CT -Condition ([string]$diagnosticCodes.CloudbaseLoaded -eq 'CloudbaseProfileUnsafe') -Message 'A loaded Cloudbase profile was mislabeled as diagnostic success.'
Assert-CT -Condition ([string]$diagnosticCodes.DriverLoaded -eq 'RebootRequired') -Message 'A loaded driver warning was mislabeled as diagnostic success.'
Assert-CT -Condition ([string]$diagnosticCodes.ContextLoaded -eq 'Success') -Message 'The exact successful run-context load event was not retained as success.'
Assert-CT -Condition ([string]$diagnosticCodes.PreflightFailed -ne 'Success') -Message 'A failed preflight containing the word loaded was mislabeled as success.'
Assert-CT -Condition ([string]$diagnosticCodes.CloudbaseDeferred -eq 'CloudbaseProfileDeferred') -Message 'The approved loaded Cloudbase Prepare warning has no stable deferred code.'
Assert-CT -Condition ([string]$diagnosticCodes.CurrentCloudbaseIdentity -eq 'CloudbaseProfileUnsafe') -Message 'Running as the loaded Cloudbase identity was mislabeled as diagnostic success.'

$plan = @(Invoke-CTyunTrim -Mode Plan -ManifestPath $manifestPath)
Assert-CT -Condition ($plan.Count -gt 20) -Message 'Plan unexpectedly contains too few actions.'
Assert-CT -Condition (@($plan | Where-Object { $_.Type -eq 'ProcessStop' }).Count -eq @($manifest.Processes).Count) -Message 'Plan does not expose every process stop performed by Prepare.'
Assert-CT -Condition (@($plan | Where-Object { $_.Type -eq 'ScheduledTask' }).Count -eq @($manifest.ScheduledTasks).Count) -Message 'Plan does not expose every scheduled-task removal performed by Prepare.'
$preparePlan = @(Invoke-CTyunTrim -Mode Prepare -ManifestPath $manifestPath -WhatIf)
$unexpectedPrepareActions = @($preparePlan | Where-Object { $_.Type -notin @('ExecutionGuard', 'ScheduledTask', 'ProcessStop', 'LocalPolicy') })
Assert-CT -Condition ($unexpectedPrepareActions.Count -eq 0) -Message 'Prepare WhatIf includes an action that Prepare does not perform.'
Assert-CT -Condition (@($preparePlan | Where-Object { $_.Type -eq 'ExecutionGuard' }).Count -eq @($manifest.ExecutionGuards).Count) -Message 'Prepare WhatIf omits execution guards.'
Assert-CT -Condition (@($preparePlan | Where-Object { $_.Type -eq 'ScheduledTask' }).Count -eq @($manifest.ScheduledTasks).Count) -Message 'Prepare WhatIf omits scheduled tasks.'
Assert-CT -Condition (@($preparePlan | Where-Object { $_.Type -eq 'ProcessStop' }).Count -eq @($manifest.Processes).Count) -Message 'Prepare WhatIf omits process stops.'
Assert-CT -Condition (@($preparePlan | Where-Object { $_.Type -eq 'LocalPolicy' }).Count -eq 1) -Message 'Prepare WhatIf omits LocalGPO cleanup.'
$unboundVerification = Invoke-CTyunTrim -Mode Verify -ManifestPath $manifestPath
Assert-CT -Condition (@($unboundVerification.Failures | Where-Object { $_ -match 'trusted RunId' }).Count -eq 1) -Message 'Verify without RunId did not disclose that SID-bound identity verification is unavailable.'
Assert-CT -Condition ($sourceText -notmatch '__SET_AFTER_MANIFEST_UPDATE__') -Message 'The immutable manifest hash placeholder remains in source.'

$coreServiceNames = @($manifest.CoreFingerprint.Services | ForEach-Object { [string]$_.Name } | Sort-Object)
$preservedServiceNames = @($manifest.Preserve.Services | ForEach-Object { [string]$_ } | Sort-Object)
$coreDriverNames = @($manifest.CoreFingerprint.Drivers | ForEach-Object { [string]$_.Name } | Sort-Object)
$preservedDriverNames = @($manifest.Preserve.Drivers | ForEach-Object { [string]$_ } | Sort-Object)
Assert-CT -Condition (($coreServiceNames -join "`n") -ceq ($preservedServiceNames -join "`n")) -Message 'Core service fingerprint differs from the preserved service set.'
Assert-CT -Condition (($coreDriverNames -join "`n") -ceq ($preservedDriverNames -join "`n")) -Message 'Core driver fingerprint differs from the preserved driver set.'
$clipaFingerprint = @($manifest.CoreFingerprint.Services | Where-Object { $_.Name -eq 'clipa' }) | Select-Object -First 1
Assert-CT -Condition ([string]$clipaFingerprint.ExpectedFileVersion -eq '2.1.0.0') -Message 'The clipa 2.1.0.0 reference fingerprint is missing.'
$pinnedCoreEntries = @($manifest.CoreFingerprint.Services + $manifest.CoreFingerprint.Drivers | Where-Object { $_.TrustMode -eq 'PinnedHashAndSigner' })
Assert-CT -Condition ($pinnedCoreEntries.Count -eq 1) -Message 'The manifest must contain exactly one pinned core identity.'
$balloonFingerprint = @($pinnedCoreEntries | Where-Object { $_.Name -eq 'BalloonService' }) | Select-Object -First 1
Assert-CT -Condition ($null -ne $balloonFingerprint) -Message 'The pinned core identity is not BalloonService.'
if ($null -ne $balloonFingerprint) {
    Assert-CT -Condition ([string]$balloonFingerprint.ExpectedImage -eq 'C:\Program Files (x86)\ctyun\clink\drivers\Balloon\blnsvr.exe') -Message 'The BalloonService pinned path changed.'
    Assert-CT -Condition ([string]$balloonFingerprint.ExpectedSha256 -eq '1B821F556FFC8F998196CDBFEE6D84846600D39EB1B584D182BFCC5AB6DFCD4E') -Message 'The BalloonService pinned SHA256 changed.'
    Assert-CT -Condition ([string]$balloonFingerprint.ExpectedSignerThumbprint -eq '301C73596BAC4FE8EE33487687BD75FCC307FFC6') -Message 'The BalloonService signer thumbprint changed.'
    Assert-CT -Condition ([string]$balloonFingerprint.ExpectedSignerSubject -eq 'CN=Red Hat Inc., OU=Dev, O=virtio-win') -Message 'The BalloonService signer subject changed.'
    Assert-CT -Condition ([string]$balloonFingerprint.ExpectedSignerIssuer -eq [string]$balloonFingerprint.ExpectedSignerSubject) -Message 'The BalloonService signer is no longer the observed self-issued identity.'
}
$nonPinnedCoreEntries = @($manifest.CoreFingerprint.Services + $manifest.CoreFingerprint.Drivers | Where-Object { $_.Name -ne 'BalloonService' })
Assert-CT -Condition (@($nonPinnedCoreEntries | Where-Object { $_.TrustMode -ne 'AuthenticodeValidAtBaseline' }).Count -eq 0) -Message 'A non-Balloon core entry no longer requires AuthenticodeValidAtBaseline.'

$module = Get-Module CTyunTrim
$programFilesAclSafe = & $module { Test-CTSecureSourcePath -Path 'C:\Program Files' }
Assert-CT -Condition $programFilesAclSafe -Message 'Default Program Files ACL was incorrectly classified as untrusted/writable.'
$programDataAclResults = & $module {
    [PSCustomObject]@{
        RootWritable = Test-CTPathWritableByStandardUsers -Path 'C:\ProgramData'
        AbsentChildSafe = Test-CTSecureSourcePath -Path 'C:\ProgramData\CTyunTrim-ACL-Test\Runs'
    }
}
Assert-CT -Condition $programDataAclResults.RootWritable -Message 'Directory Write rights were omitted from the untrusted ACL mask.'
Assert-CT -Condition $programDataAclResults.AbsentChildSafe -Message 'Write-only creation rights on a trusted ancestor were confused with the ability to replace an existing protected child.'
$lgpoTrustProfile = & $module { [PSCustomObject]@{ Hashes = @($script:ApprovedLgpoSha256); Version = $script:ApprovedLgpoVersion } }
Assert-CT -Condition ($lgpoTrustProfile.Hashes.Count -gt 0 -and $lgpoTrustProfile.Hashes[0] -match '^[0-9A-F]{64}$') -Message 'No immutable official LGPO binary hash is pinned.'
Assert-CT -Condition ($lgpoTrustProfile.Version -eq '3.0.2004.13001') -Message 'Unexpected LGPO trust-profile version.'
$cloudbaseSidSafety = & $module {
    [PSCustomObject]@{
        Ordinary = Test-CTSafeCloudbaseSid -Sid 'S-1-5-21-1-2-3-1000' -MachineSid 'S-1-5-21-1-2-3'
        Admin    = Test-CTSafeCloudbaseSid -Sid 'S-1-5-21-1-2-3-500' -MachineSid 'S-1-5-21-1-2-3'
        Guest    = Test-CTSafeCloudbaseSid -Sid 'S-1-5-21-1-2-3-501' -MachineSid 'S-1-5-21-1-2-3'
        Foreign  = Test-CTSafeCloudbaseSid -Sid 'S-1-5-21-9-8-7-1000' -MachineSid 'S-1-5-21-1-2-3'
    }
}
Assert-CT -Condition $cloudbaseSidSafety.Ordinary -Message 'Ordinary machine-local Cloudbase SID was rejected.'
Assert-CT -Condition (-not $cloudbaseSidSafety.Admin -and -not $cloudbaseSidSafety.Guest -and -not $cloudbaseSidSafety.Foreign) -Message 'Built-in or foreign SID passed Cloudbase identity safety checks.'
$runOwnership = & $module {
    [PSCustomObject]@{
        Vendor = Test-CTRunValueOwned -RunValue ([PSCustomObject]@{ Value = '"C:\Program Files (x86)\ctyun\app.exe"' })
        Other  = Test-CTRunValueOwned -RunValue ([PSCustomObject]@{ Value = '"C:\Program Files\Unrelated\app.exe"' })
    }
}
Assert-CT -Condition ($runOwnership.Vendor -and -not $runOwnership.Other) -Message 'Run-value ownership classification is inconsistent.'
$taskDefinitionResults = & $module {
    param([hashtable]$Entry)

    function New-TestAction {
        param([string]$Execute)
        [PSCustomObject]@{
            Execute  = $Execute
            Arguments = ''
            CimClass = [PSCustomObject]@{ CimClassName = 'MSFT_TaskExecAction' }
        }
    }
    function New-TestTask {
        param([string]$Name, [string]$Path, [object[]]$Actions)
        [PSCustomObject]@{ TaskName = $Name; TaskPath = $Path; Actions = $Actions }
    }

    $exact = New-TestTask -Name $Entry.Name -Path $Entry.TaskPath -Actions @((New-TestAction -Execute $Entry.ExpectedImage))
    $wrongDirectory = New-TestTask -Name $Entry.Name -Path $Entry.TaskPath -Actions @((New-TestAction -Execute 'C:\Temp\ecloud_img_conf.exe'))
    $wrongTaskPath = New-TestTask -Name $Entry.Name -Path '\Other\' -Actions @((New-TestAction -Execute $Entry.ExpectedImage))
    $multiple = New-TestTask -Name $Entry.Name -Path $Entry.TaskPath -Actions @((New-TestAction -Execute $Entry.ExpectedImage), (New-TestAction -Execute $Entry.ExpectedImage))
    $trailingText = New-TestTask -Name $Entry.Name -Path $Entry.TaskPath -Actions @((New-TestAction -Execute ('"' + $Entry.ExpectedImage + '" extra')))
    $caseVariant = New-TestTask -Name $Entry.Name.ToUpperInvariant() -Path $Entry.TaskPath -Actions @((New-TestAction -Execute $Entry.ExpectedImage.ToUpperInvariant()))

    [PSCustomObject]@{
        Exact          = Test-CTScheduledTaskDefinition -Task $exact -Entry $Entry
        WrongDirectory = Test-CTScheduledTaskDefinition -Task $wrongDirectory -Entry $Entry
        WrongTaskPath  = Test-CTScheduledTaskDefinition -Task $wrongTaskPath -Entry $Entry
        Multiple       = Test-CTScheduledTaskDefinition -Task $multiple -Entry $Entry
        TrailingText   = Test-CTScheduledTaskDefinition -Task $trailingText -Entry $Entry
        CaseVariant    = Test-CTScheduledTaskDefinition -Task $caseVariant -Entry $Entry
    }
} $manifest.ScheduledTasks[0]
Assert-CT -Condition $taskDefinitionResults.Exact -Message 'Exact scheduled-task definition was rejected.'
Assert-CT -Condition (-not $taskDefinitionResults.WrongDirectory) -Message 'Scheduled-task basename in a different directory was accepted.'
Assert-CT -Condition (-not $taskDefinitionResults.WrongTaskPath) -Message 'Scheduled task in a different TaskPath was accepted.'
Assert-CT -Condition (-not $taskDefinitionResults.Multiple) -Message 'Multi-action scheduled task was accepted.'
Assert-CT -Condition (-not $taskDefinitionResults.TrailingText) -Message 'Scheduled task Execute with trailing text was accepted.'
Assert-CT -Condition $taskDefinitionResults.CaseVariant -Message 'Windows path casing differences were not handled case-insensitively.'

try {
    $allowed = & $module {
        Invoke-CTNativeCommand -FilePath "$env:SystemRoot\System32\cmd.exe" -Arguments @('/d', '/c', 'echo expected-stderr 1>&2 & exit /b 7') -SuccessExitCodes @(7)
    }
    Assert-CT -Condition ($allowed.ExitCode -eq 7) -Message 'Native stderr with an allowed exit code did not return normally under Windows PowerShell 5.1.'
}
catch {
    Assert-CT -Condition $false -Message "Native allowed-exit regression test threw: $($_.Exception.Message)"
}

$disallowedThrew = $false
try {
    & $module {
        Invoke-CTNativeCommand -FilePath "$env:SystemRoot\System32\cmd.exe" -Arguments @('/d', '/c', 'echo expected-stderr 1>&2 & exit /b 9') -SuccessExitCodes @(0)
    } | Out-Null
}
catch { $disallowedThrew = $true }
Assert-CT -Condition $disallowedThrew -Message 'Native disallowed exit code did not throw.'

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('CTyunTrim-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    $dictionaryStatePath = Join-Path $fixtureRoot 'dictionary-state.clixml'
    $liveDictionary = @{ Foo = 'bar' }
    [PSCustomObject]@{ Data = $liveDictionary } | Export-Clixml -LiteralPath $dictionaryStatePath -Depth 4
    $roundTripDictionary = (Import-Clixml -LiteralPath $dictionaryStatePath).Data
    $dictionaryValues = & $module {
        param($Live, $RoundTrip)
        @((Get-CTPropertyValue -InputObject $Live -Name 'Foo'), (Get-CTPropertyValue -InputObject $RoundTrip -Name 'Foo'))
    } $liveDictionary $roundTripDictionary
    Assert-CT -Condition ($dictionaryValues.Count -eq 2 -and $dictionaryValues[0] -eq 'bar' -and $dictionaryValues[1] -eq 'bar') -Message 'Journal hashtable lookup failed before or after a CLIXML round trip.'

    $missingFixture = Join-Path $fixtureRoot 'missing.psd1'
    "@{ SchemaVersion = '1.0' }" | Set-Content -LiteralPath $missingFixture -Encoding ASCII
    $missingResult = Test-CTyunTrimManifest -ManifestPath $missingFixture
    Assert-CT -Condition (-not $missingResult.Valid) -Message 'Malformed manifest unexpectedly validated.'

    $originalManifestText = Get-Content -LiteralPath $manifestPath -Raw
    $tamperedFixture = Join-Path $fixtureRoot 'tampered.psd1'
    $originalManifestText.Replace("Description   = 'Remove CTyun", "Description   = 'Changed CTyun") | Set-Content -LiteralPath $tamperedFixture -Encoding ASCII
    $tamperedResult = Test-CTyunTrimManifest -ManifestPath $tamperedFixture
    Assert-CT -Condition (-not $tamperedResult.Valid) -Message 'A harmless-looking manifest content change bypassed the immutable profile hash.'

    $rootFixture = Join-Path $fixtureRoot 'root-escape.psd1'
    $originalManifestText.Replace("CTyun       = 'C:\Program Files (x86)\ctyun'", "CTyun       = 'C:\'") | Set-Content -LiteralPath $rootFixture -Encoding ASCII
    $rootResult = Test-CTyunTrimManifest -ManifestPath $rootFixture
    Assert-CT -Condition (-not $rootResult.Valid) -Message 'A drive-root manifest trust boundary unexpectedly validated.'

    $lfHashFixture = Join-Path $fixtureRoot 'lf.txt'
    $crlfHashFixture = Join-Path $fixtureRoot 'crlf.txt'
    [IO.File]::WriteAllText($lfHashFixture, "alpha`nbeta`n", (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($crlfHashFixture, "alpha`r`nbeta`r`n", (New-Object Text.UTF8Encoding($false)))
    $normalizedHashes = & $module { param($A, $B) @((Get-CTNormalizedTextHash -Path $A), (Get-CTNormalizedTextHash -Path $B)) } $lfHashFixture $crlfHashFixture
    Assert-CT -Condition ($normalizedHashes[0] -eq $normalizedHashes[1]) -Message 'Manifest hash normalization differs between LF and CRLF.'

    $lfManifestFixture = Join-Path $fixtureRoot 'reference-lf.psd1'
    [IO.File]::WriteAllText($lfManifestFixture, $originalManifestText.Replace("`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
    $lfManifestResult = Test-CTyunTrimManifest -ManifestPath $lfManifestFixture
    Assert-CT -Condition $lfManifestResult.Valid -Message "The immutable reference manifest failed after a CRLF-to-LF-only conversion: $($lfManifestResult.Errors -join '; ')"

    $validRegFixture = Join-Path $fixtureRoot 'valid.reg'
    $wrongRegFixture = Join-Path $fixtureRoot 'wrong.reg'
    @('Windows Registry Editor Version 5.00', '', '[HKEY_LOCAL_MACHINE\SOFTWARE\CTyunTrimTest]', '"Value"="data"') | Set-Content -LiteralPath $validRegFixture -Encoding Unicode
    @('Windows Registry Editor Version 5.00', '', '[HKEY_LOCAL_MACHINE\SOFTWARE\DifferentKey]', '"Value"="data"') | Set-Content -LiteralPath $wrongRegFixture -Encoding Unicode
    $regFixtureResults = & $module {
        param($ValidPath, $WrongPath)
        [PSCustomObject]@{
            Valid = Test-CTRegistryExportFile -Path $ValidPath -NativeKey 'HKLM\SOFTWARE\CTyunTrimTest'
            Wrong = Test-CTRegistryExportFile -Path $WrongPath -NativeKey 'HKLM\SOFTWARE\CTyunTrimTest'
        }
    } $validRegFixture $wrongRegFixture
    Assert-CT -Condition $regFixtureResults.Valid -Message 'Valid exact-key registry export fixture was rejected.'
    Assert-CT -Condition (-not $regFixtureResults.Wrong) -Message 'Registry backup for a different key was accepted.'

    $escapeFixture = Join-Path $fixtureRoot 'escape.psd1'
    $escapeText = $originalManifestText.Replace("'C:\Program Files (x86)\ctyun\AppMarketSvc'", "'C:\Windows'")
    $escapeText | Set-Content -LiteralPath $escapeFixture -Encoding ASCII
    $escapeResult = Test-CTyunTrimManifest -ManifestPath $escapeFixture
    Assert-CT -Condition (-not $escapeResult.Valid) -Message 'Out-of-root removal path unexpectedly validated.'

    $encodedFixture = Join-Path $fixtureRoot 'encoded-escape.psd1'
    $encodedEscape = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('..\escape.lnk'))
    $encodedText = $originalManifestText.Replace('5aSp57+85LqR55S16ISR5biu5Yqp5omL5YaMLmxuaw==', $encodedEscape)
    $encodedText | Set-Content -LiteralPath $encodedFixture -Encoding ASCII
    $encodedResult = Test-CTyunTrimManifest -ManifestPath $encodedFixture
    Assert-CT -Condition (-not $encodedResult.Valid) -Message 'Encoded path traversal unexpectedly validated.'

    $buildThrew = $false
    try { & (Join-Path $root 'build\Build-Release.ps1') -Version '..\..\config' | Out-Null } catch { $buildThrew = $true }
    Assert-CT -Condition $buildThrew -Message 'Release builder accepted a path-traversal version.'
    foreach ($invalidVersion in @('0.1.4-Diagnostic.', '0.1.4--Diagnostic', '0.1.4-Diagnostic:')) {
        $invalidVersionThrew = $false
        try { & (Join-Path $root 'build\Build-Release.ps1') -Version $invalidVersion | Out-Null } catch { $invalidVersionThrew = $true }
        Assert-CT -Condition $invalidVersionThrew -Message "Release builder accepted an unsafe prerelease version: $invalidVersion"
    }

    $junctionVersion = '0.1.0-junction-test'
    $junctionStage = Join-Path (Join-Path $root 'artifacts') "CTyunTrim-$junctionVersion"
    $junctionTarget = Join-Path $fixtureRoot 'outside-target'
    $junctionPath = Join-Path $junctionStage 'escape-junction'
    New-Item -ItemType Directory -Path $junctionStage -Force | Out-Null
    New-Item -ItemType Directory -Path $junctionTarget -Force | Out-Null
    $markerPath = Join-Path $junctionTarget 'must-survive.txt'
    'preserve' | Set-Content -LiteralPath $markerPath -Encoding ASCII
    try {
        New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget | Out-Null
        $junctionBuildThrew = $false
        try { & (Join-Path $root 'build\Build-Release.ps1') -Version $junctionVersion | Out-Null } catch { $junctionBuildThrew = $true }
        Assert-CT -Condition $junctionBuildThrew -Message 'Release builder accepted a nested junction in its recursive cleanup target.'
        Assert-CT -Condition (Test-Path -LiteralPath $markerPath -PathType Leaf) -Message 'Release builder traversed a junction and damaged the external marker.'
    }
    finally {
        if (Test-Path -LiteralPath $junctionPath) { [IO.Directory]::Delete($junctionPath) }
        if (Test-Path -LiteralPath $junctionStage) { Remove-Item -LiteralPath $junctionStage -Recurse -Force }
    }

    $sidecarVersion = '0.1.0-sidecar-test'
    $sidecarPath = Join-Path (Join-Path $root 'artifacts') "CTyunTrim-$sidecarVersion.zip.sha256"
    $sidecarTarget = Join-Path $fixtureRoot 'sidecar-target'
    New-Item -ItemType Directory -Path $sidecarTarget | Out-Null
    $sidecarMarker = Join-Path $sidecarTarget 'must-survive.txt'
    'must-survive' | Set-Content -LiteralPath $sidecarMarker -Encoding ASCII
    try {
        New-Item -ItemType Junction -Path $sidecarPath -Target $sidecarTarget | Out-Null
        $sidecarBuildThrew = $false
        $sidecarBuildMessage = $null
        try { & (Join-Path $root 'build\Build-Release.ps1') -Version $sidecarVersion | Out-Null } catch { $sidecarBuildThrew = $true; $sidecarBuildMessage = $_.Exception.Message }
        Assert-CT -Condition $sidecarBuildThrew -Message 'Release builder accepted a checksum sidecar reparse point.'
        Assert-CT -Condition ($sidecarBuildMessage -match 'checksum path contains a reparse point') -Message 'Release builder did not reject the checksum sidecar through its explicit reparse guard.'
        Assert-CT -Condition ((Get-Content -LiteralPath $sidecarMarker -Raw).Trim() -eq 'must-survive') -Message 'Release builder damaged the checksum sidecar junction target.'
    }
    finally {
        if (Test-Path -LiteralPath $sidecarPath) {
            $sidecarItem = Get-Item -LiteralPath $sidecarPath -Force
            if (($sidecarItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw 'Sidecar test cleanup refused a non-reparse target.' }
            [IO.Directory]::Delete($sidecarPath)
        }
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}

$launcherText = Get-Content -LiteralPath (Join-Path $root 'Start-CTyunTrim.cmd') -Raw
Assert-CT -Condition ($launcherText -match 'Sysnative') -Message 'Launcher does not contain a WOW64 Sysnative path.'

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "All $($powerShellFiles.Count) PowerShell files parsed under 64-bit Windows PowerShell $($PSVersionTable.PSVersion)."
Write-Host "Manifest and $($plan.Count) planned actions passed static safety checks."
exit 0
