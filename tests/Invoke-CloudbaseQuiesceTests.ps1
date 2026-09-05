#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Cloudbase quiesce tests must run under Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) { throw 'Cloudbase quiesce tests require a 64-bit process.' }

$root = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'src\CTyunTrim.psd1'
$manifestPath = Join-Path $root 'config\CTyunTrim.psd1'
$sourcePath = Join-Path $root 'src\CTyunTrim.psm1'
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$failures = New-Object Collections.Generic.List[string]

function Assert-CTQuiesce {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { $script:failures.Add($Message) }
}

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$helper = & $module {
    param($FixtureManifest)

    $machineSid = 'S-1-5-21-1-2-3'
    $targetSid = "$machineSid-1001"
    $otherSid = "$machineSid-1002"
    $entry = @($FixtureManifest.Services | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1

    function Reset-QuiesceFixture {
        $script:QuiesceBoot = 'BOOT-A'
        $script:QuiesceExpectedPath = [string]$entry.ExpectedImage
        $script:QuiesceService = [PSCustomObject]@{
            Name = 'cloudbase-init'; State = 'Stopped'; StartMode = 'Auto'
            StartName = '.\cloudbase-init'; PathName = [string]$entry.ExpectedImage
        }
        $script:QuiesceAccount = [PSCustomObject]@{ Name = 'cloudbase-init'; SID = $targetSid; Enabled = $true }
        $script:QuiesceProfile = [PSCustomObject]@{ LocalPath = 'C:\Users\cloudbase-init'; SID = $targetSid; Loaded = $true; Special = $false }
        $script:QuiesceResolvedSid = $targetSid
        $script:QuiesceOwnedProcesses = @()
        $script:QuiesceReferences = @('service:cloudbase-init')
        $script:QuiesceHiveMounted = $true
        $script:QuiesceClassesHiveMounted = $true
        $script:QuiesceReparse = $false
        $script:QuiesceSafeSid = $true
        $script:QuiesceExpectedService = $true
        $script:QuiesceCoreHealthy = $true
        $script:QuiesceSignatureValid = $true
        $script:QuiesceSecureSource = $true
        $script:QuiesceBackupValid = $true
        $script:QuiesceExportThrows = $false
        $script:QuiesceStartThrows = $false
        $script:QuiesceSetThrows = $false
        $script:QuiesceSetNoEffect = $false
        $script:QuiesceMutationAfterConfirmation = $null
        $script:QuiesceMutationAfterJournal = $null
        $script:QuiesceExportCalls = 0
        $script:QuiesceStartCalls = 0
        $script:QuiesceSetCalls = 0
        $script:QuiesceCompleteCalls = 0
        $script:QuiesceDeleteCalls = 0
        $script:QuiesceSaveCalls = 0
    }

    function New-QuiesceContext {
        param([string]$OperationStatus, [string]$QuiescedBoot = 'BOOT-A')
        $operations = New-Object Collections.Generic.List[object]
        $evidence = [PSCustomObject]@{
            Id = 'identity-evidence'; Type = 'CloudbaseIdentityEvidence'; Target = 'cloudbase-init'
            Status = 'Completed'; Reversible = $false
            Data = @{
                State = 'PresentAtBaseline'; MachineSid = $machineSid; CloudbaseRoot = $FixtureManifest.Roots.Cloudbase
                AccountSid = $targetSid; ProfileSid = $targetSid
                Services = @([PSCustomObject]@{ Name = 'cloudbase-init'; ResolvedImage = [string]$entry.ExpectedImage })
                IdentityAnchors = @('service:cloudbase-init')
            }
        }
        [void]$operations.Add($evidence)
        if (-not [string]::IsNullOrWhiteSpace($OperationStatus)) {
            [void]$operations.Add([PSCustomObject]@{
                Id = 'quiesce-op'; Type = 'ServiceQuiesce'; Target = 'cloudbase-init'; Status = $OperationStatus
                Reversible = $true; CompletedAt = if ($OperationStatus -eq 'Completed') { 'now' } else { $null }
                Data = @{
                    Backup = 'C:\ProgramData\CTyunTrim\Runs\fixture\registry\service-quiesce.reg'
                    BackupSha256 = ('A' * 64); ExpectedImage = [string]$entry.ExpectedImage; SID = $targetSid
                    ImageSha256 = ('C' * 64)
                    StartMode = 'Auto'; State = 'Stopped'; StartName = '.\cloudbase-init'; QuiescedBoot = $QuiescedBoot
                }
            })
        }
        [PSCustomObject]@{
            RunId = 'fixture'; Root = 'C:\ProgramData\CTyunTrim\Runs\fixture'; MachineSid = $machineSid
            Status = 'Prepared'; RebootNeeded = $false; CompletedAt = $null; LastBootUpTime = 'BOOT-A'
            Warnings = (New-Object Collections.Generic.List[string]); Operations = $operations
        }
    }

    function Save-CTCloudbaseIdentityEvidence {
        param([PSObject]$Context, [hashtable]$Manifest)
        return @($Context.Operations | Where-Object { $_.Type -eq 'CloudbaseIdentityEvidence' }) | Select-Object -First 1
    }
    function Test-CTSafeCloudbaseSid { param([string]$Sid, [string]$MachineSid) return [bool]$script:QuiesceSafeSid }
    function Get-LocalUser { [CmdletBinding()] param() return @($script:QuiesceAccount) }
    function Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName, [string]$Filter)
        if ($ClassName -eq 'Win32_UserProfile') { return @($script:QuiesceProfile) }
        return @()
    }
    function Get-CTProcessesByOwnerSid { param([string]$Sid) return @($script:QuiesceOwnedProcesses) }
    function Get-CTCloudbaseIdentityReferences { param([string]$Sid) return @($script:QuiesceReferences) }
    function Get-CTServiceByName { param([string]$Name, [switch]$Driver) if (-not $Driver -and $Name -eq 'cloudbase-init') { return $script:QuiesceService }; return $null }
    function Test-CTExpectedService { param($Service, [string]$ExpectedImage) return [bool]$script:QuiesceExpectedService }
    function Resolve-CTAccountSid { param([string]$Identity) return [string]$script:QuiesceResolvedSid }
    function Get-CTImageExecutable { param([string]$PathName) return [string]$PathName }
    function ConvertTo-CTFullPath { param([string]$Path) return ([IO.Path]::GetFullPath($Path).TrimEnd('\')) }
    function Get-CTCoreFileEvidence {
        param([string]$Path)
        [PSCustomObject]@{
            SignatureStatus = if ($script:QuiesceSignatureValid) { 'Valid' } else { 'NotTrusted' }
            SecureSource = [bool]$script:QuiesceSecureSource; SignerThumbprint = ('B' * 40); FileSha256 = ('C' * 64)
        }
    }
    function Test-CTCoreHealth {
        param([hashtable]$Manifest, [switch]$RequireRunning, [PSObject]$Context)
        [PSCustomObject]@{ Healthy = [bool]$script:QuiesceCoreHealthy; Failures = if ($script:QuiesceCoreHealthy) { @() } else { @('fixture core change') } }
    }
    function Test-CTPathHasReparsePoint { param([string]$Path) return [bool]$script:QuiesceReparse }
    function Test-Path {
        [CmdletBinding()]
        param([string]$LiteralPath, [string]$PathType)
        if ($LiteralPath -like 'Registry::HKEY_USERS\*_Classes') { return [bool]$script:QuiesceClassesHiveMounted }
        if ($LiteralPath -like 'Registry::HKEY_USERS\*') { return [bool]$script:QuiesceHiveMounted }
        return $true
    }
    function Test-CTPathWithinRoot { param([string]$Path, [string]$Root) return [bool]$script:QuiesceBackupValid }
    function Test-CTRegistryExportFile { param([string]$Path, [string]$NativeKey) return [bool]$script:QuiesceBackupValid }
    function Test-CTSecureSourcePath { param([string]$Path) return [bool]$script:QuiesceBackupValid }
    function Get-FileHash { [CmdletBinding()] param([string]$LiteralPath, [string]$Algorithm) [PSCustomObject]@{ Hash = ('A' * 64) } }
    function Get-CTOperatingSystem { [PSCustomObject]@{ LastBootUpTime = [string]$script:QuiesceBoot } }
    function Export-CTRegistryKey {
        param([PSObject]$Context, [string]$NativeKey, [string]$Name)
        $script:QuiesceExportCalls++
        if ($script:QuiesceExportThrows) { throw 'fixture export failed' }
        [PSCustomObject]@{ Path = 'C:\ProgramData\CTyunTrim\Runs\fixture\registry\service-quiesce.reg'; SHA256 = ('A' * 64) }
    }
    function Start-CTOperation {
        param([PSObject]$Context, [string]$Type, [string]$Target, [hashtable]$Data, [bool]$Reversible = $true)
        $script:QuiesceStartCalls++
        if ($script:QuiesceStartThrows) { throw 'fixture journal failed' }
        $operation = [PSCustomObject]@{ Id = 'new-quiesce-op'; Type = $Type; Target = $Target; Status = 'Pending'; Data = $Data; Reversible = $Reversible; CompletedAt = $null }
        [void]$Context.Operations.Add($operation)
        if ($script:QuiesceMutationAfterJournal -eq 'Path') { $script:QuiesceService.PathName = 'C:\Windows\System32\svchost.exe' }
        elseif ($script:QuiesceMutationAfterJournal -eq 'State') { $script:QuiesceService.State = 'Running' }
        elseif ($script:QuiesceMutationAfterJournal -eq 'SID') { $script:QuiesceResolvedSid = $otherSid }
        return [string]$operation.Id
    }
    function Complete-CTOperation {
        param([PSObject]$Context, [string]$Id)
        $script:QuiesceCompleteCalls++
        $operation = @($Context.Operations | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
        if ($null -eq $operation) { throw 'fixture operation absent' }
        $operation.Status = 'Completed'; $operation.CompletedAt = 'now'
    }
    function Set-Service {
        [CmdletBinding()]
        param([string]$Name, [string]$StartupType)
        $script:QuiesceSetCalls++
        if ($script:QuiesceSetThrows) { throw 'fixture Set-Service failed' }
        if (-not $script:QuiesceSetNoEffect) { $script:QuiesceService.StartMode = 'Disabled' }
    }
    function Save-CTRunContext { param([PSObject]$Context) $script:QuiesceSaveCalls++ }
    function Add-CTWarning { param([PSObject]$Context, [string]$Message) [void]$Context.Warnings.Add($Message); Save-CTRunContext -Context $Context }
    function Add-CTDiagnosticEvent {
        param([string]$Level, [string]$Stage, [string]$Message, [hashtable]$Data)
        if ($Stage -eq 'Confirmation' -and $Message -eq 'Required operation was confirmed.') {
            if ($script:QuiesceMutationAfterConfirmation -eq 'Path') { $script:QuiesceService.PathName = 'C:\Windows\System32\svchost.exe' }
            elseif ($script:QuiesceMutationAfterConfirmation -eq 'State') { $script:QuiesceService.State = 'Running' }
            elseif ($script:QuiesceMutationAfterConfirmation -eq 'SID') { $script:QuiesceResolvedSid = $otherSid }
        }
    }
    function Remove-LocalUser { [CmdletBinding()] param([object]$SID) $script:QuiesceDeleteCalls++ }
    function Remove-CimInstance { [CmdletBinding()] param() $script:QuiesceDeleteCalls++ }

    function Invoke-QuiesceFixture {
        [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
        param([PSObject]$Context, [hashtable]$Manifest)
        Invoke-CTCloudbaseServiceQuiesce -Context $Context -Manifest $Manifest -Caller $PSCmdlet
    }

    Reset-QuiesceFixture
    $positiveContext = New-QuiesceContext
    $positiveResult = Invoke-QuiesceFixture -Context $positiveContext -Manifest $FixtureManifest -Confirm:$false
    $positiveOperation = @($positiveContext.Operations | Where-Object { $_.Type -eq 'ServiceQuiesce' }) | Select-Object -First 1
    $positive = [PSCustomObject]@{
        Status = $positiveResult.Status; RebootNeeded = $positiveResult.RebootNeeded; ContextStatus = $positiveContext.Status
        SetCalls = $script:QuiesceSetCalls; ExportCalls = $script:QuiesceExportCalls; StartCalls = $script:QuiesceStartCalls
        CompleteCalls = $script:QuiesceCompleteCalls; DeleteCalls = $script:QuiesceDeleteCalls
        OperationStatus = $positiveOperation.Status; OperationType = $positiveOperation.Type; Reversible = $positiveOperation.Reversible
        Data = $positiveOperation.Data
    }

    Reset-QuiesceFixture
    $declinedContext = New-QuiesceContext
    $declined = $false
    try { Invoke-QuiesceFixture -Context $declinedContext -Manifest $FixtureManifest -WhatIf | Out-Null }
    catch { $declined = $_.Exception -is [System.OperationCanceledException] }
    $decline = [PSCustomObject]@{ Blocked=$declined; SetCalls=$script:QuiesceSetCalls; ExportCalls=$script:QuiesceExportCalls; StartCalls=$script:QuiesceStartCalls }

    Reset-QuiesceFixture
    $script:QuiesceExportThrows = $true
    $exportContext = New-QuiesceContext
    try { Invoke-QuiesceFixture -Context $exportContext -Manifest $FixtureManifest -Confirm:$false | Out-Null } catch { }
    $exportFailure = [PSCustomObject]@{ SetCalls=$script:QuiesceSetCalls; StartCalls=$script:QuiesceStartCalls; OperationCount=@($exportContext.Operations | Where-Object { $_.Type -eq 'ServiceQuiesce' }).Count }

    Reset-QuiesceFixture
    $script:QuiesceStartThrows = $true
    $journalContext = New-QuiesceContext
    try { Invoke-QuiesceFixture -Context $journalContext -Manifest $FixtureManifest -Confirm:$false | Out-Null } catch { }
    $journalFailure = [PSCustomObject]@{ SetCalls=$script:QuiesceSetCalls; ExportCalls=$script:QuiesceExportCalls; OperationCount=@($journalContext.Operations | Where-Object { $_.Type -eq 'ServiceQuiesce' }).Count }

    $journalBoundaryResults = @()
    foreach ($mutation in @('Path','State','SID')) {
        Reset-QuiesceFixture
        $script:QuiesceMutationAfterJournal = $mutation
        $context = New-QuiesceContext
        $blocked = $false
        try { Invoke-QuiesceFixture -Context $context -Manifest $FixtureManifest -Confirm:$false | Out-Null }
        catch { $blocked = $true }
        $journalBoundaryResults += [PSCustomObject]@{ Mutation=$mutation; Blocked=$blocked; SetCalls=$script:QuiesceSetCalls; ExportCalls=$script:QuiesceExportCalls; StartCalls=$script:QuiesceStartCalls }
    }

    $boundaryResults = @()
    foreach ($mutation in @('Path','State','SID')) {
        Reset-QuiesceFixture
        $script:QuiesceMutationAfterConfirmation = $mutation
        $context = New-QuiesceContext
        $blocked = $false
        try { Invoke-QuiesceFixture -Context $context -Manifest $FixtureManifest -Confirm:$false | Out-Null }
        catch { $blocked = $true }
        $boundaryResults += [PSCustomObject]@{ Mutation=$mutation; Blocked=$blocked; SetCalls=$script:QuiesceSetCalls; ExportCalls=$script:QuiesceExportCalls; StartCalls=$script:QuiesceStartCalls }
    }

    $safetyResults = @()
    foreach ($case in @('WrongPath','WrongSid','CoreChanged','OwnedProcess','Reparse')) {
        Reset-QuiesceFixture
        switch ($case) {
            'WrongPath' { $script:QuiesceExpectedService = $false }
            'WrongSid' { $script:QuiesceResolvedSid = $otherSid }
            'CoreChanged' { $script:QuiesceCoreHealthy = $false }
            'OwnedProcess' { $script:QuiesceOwnedProcesses = @([PSCustomObject]@{ ProcessId = 99 }) }
            'Reparse' { $script:QuiesceReparse = $true }
        }
        $context = New-QuiesceContext
        $blocked = $false
        try { Invoke-QuiesceFixture -Context $context -Manifest $FixtureManifest -Confirm:$false | Out-Null }
        catch { $blocked = $true }
        $safetyResults += [PSCustomObject]@{ Case=$case; Blocked=$blocked; SetCalls=$script:QuiesceSetCalls; ExportCalls=$script:QuiesceExportCalls }
    }

    Reset-QuiesceFixture
    $script:QuiesceService.StartMode = 'Disabled'
    $pendingContext = New-QuiesceContext -OperationStatus Pending
    $pendingResult = Invoke-QuiesceFixture -Context $pendingContext -Manifest $FixtureManifest -Confirm:$false
    $pendingOperation = @($pendingContext.Operations | Where-Object { $_.Type -eq 'ServiceQuiesce' }) | Select-Object -First 1
    $powerLoss = [PSCustomObject]@{
        Status=$pendingResult.Status; ExistingStatus=$pendingOperation.Status; SetCalls=$script:QuiesceSetCalls
        ExportCalls=$script:QuiesceExportCalls; StartCalls=$script:QuiesceStartCalls; CompleteCalls=$script:QuiesceCompleteCalls
    }

    Reset-QuiesceFixture
    $script:QuiesceService.StartMode = 'Disabled'; $script:QuiesceBoot = 'BOOT-B'
    $newBootContext = New-QuiesceContext -OperationStatus Completed -QuiescedBoot 'BOOT-A'
    $newBootBlocked = $false
    try { Invoke-QuiesceFixture -Context $newBootContext -Manifest $FixtureManifest -Confirm:$false | Out-Null }
    catch { $newBootBlocked = $_.Exception.Message -match 'remains loaded after the ServiceQuiesce reboot' }
    $newBoot = [PSCustomObject]@{ Blocked=$newBootBlocked; SetCalls=$script:QuiesceSetCalls; ExportCalls=$script:QuiesceExportCalls }

    Reset-QuiesceFixture
    $script:QuiesceService.StartMode = 'Disabled'; $script:QuiesceBoot = 'BOOT-B'
    $script:QuiesceProfile.Loaded = $false; $script:QuiesceHiveMounted = $false; $script:QuiesceClassesHiveMounted = $true
    $classesContext = New-QuiesceContext -OperationStatus Completed -QuiescedBoot 'BOOT-A'
    $classesBlocked = $false
    try { Invoke-QuiesceFixture -Context $classesContext -Manifest $FixtureManifest -Confirm:$false | Out-Null }
    catch { $classesBlocked = $_.Exception.Message -match 'remains loaded after the ServiceQuiesce reboot' }
    $classesOnly = [PSCustomObject]@{ Blocked=$classesBlocked; SetCalls=$script:QuiesceSetCalls; ExportCalls=$script:QuiesceExportCalls }

    [PSCustomObject]@{
        Positive=$positive; Decline=$decline; ExportFailure=$exportFailure; JournalFailure=$journalFailure
        Boundary=$boundaryResults; JournalBoundary=$journalBoundaryResults; Safety=$safetyResults; PowerLoss=$powerLoss; NewBoot=$newBoot; ClassesOnly=$classesOnly
    }
} $manifest

Assert-CTQuiesce -Condition ($helper.Positive.Status -eq 'PendingReboot' -and $helper.Positive.ContextStatus -eq 'PendingReboot' -and [bool]$helper.Positive.RebootNeeded) -Message 'Positive quiesce did not return and persist PendingReboot.'
Assert-CTQuiesce -Condition ($helper.Positive.SetCalls -eq 1 -and $helper.Positive.ExportCalls -eq 1 -and $helper.Positive.StartCalls -eq 1 -and $helper.Positive.CompleteCalls -eq 1) -Message 'Positive quiesce did not perform exactly one backup, journal, disable and completion.'
Assert-CTQuiesce -Condition ($helper.Positive.DeleteCalls -eq 0) -Message 'Service quiesce reached account or Profile deletion.'
Assert-CTQuiesce -Condition ($helper.Positive.OperationType -eq 'ServiceQuiesce' -and $helper.Positive.OperationStatus -eq 'Completed' -and [bool]$helper.Positive.Reversible) -Message 'Service quiesce journal type/status/reversibility is wrong.'
foreach ($field in @('Backup','BackupSha256','ExpectedImage','ImageSha256','SID','StartMode','State','StartName','QuiescedBoot')) {
    Assert-CTQuiesce -Condition ($null -ne $helper.Positive.Data[$field] -and -not [string]::IsNullOrWhiteSpace([string]$helper.Positive.Data[$field])) -Message "Service quiesce journal omitted $field."
}
Assert-CTQuiesce -Condition ($helper.Decline.Blocked -and $helper.Decline.SetCalls -eq 0 -and $helper.Decline.ExportCalls -eq 0 -and $helper.Decline.StartCalls -eq 0) -Message 'ShouldProcess refusal did not stop before backup, journal and service mutation.'
Assert-CTQuiesce -Condition ($helper.ExportFailure.SetCalls -eq 0 -and $helper.ExportFailure.StartCalls -eq 0 -and $helper.ExportFailure.OperationCount -eq 0) -Message 'Backup failure reached the journal or service mutation.'
Assert-CTQuiesce -Condition ($helper.JournalFailure.SetCalls -eq 0 -and $helper.JournalFailure.ExportCalls -eq 1 -and $helper.JournalFailure.OperationCount -eq 0) -Message 'Write-ahead journal failure reached service mutation.'
foreach ($case in @($helper.Boundary)) {
    Assert-CTQuiesce -Condition ($case.Blocked -and $case.SetCalls -eq 0) -Message "Confirmation-boundary $($case.Mutation) change reached Set-Service."
}
foreach ($case in @($helper.JournalBoundary)) {
    Assert-CTQuiesce -Condition ($case.Blocked -and $case.SetCalls -eq 0 -and $case.ExportCalls -eq 1 -and $case.StartCalls -eq 1) -Message "Post-journal $($case.Mutation) race reached Set-Service."
}
foreach ($case in @($helper.Safety)) {
    Assert-CTQuiesce -Condition ($case.Blocked -and $case.SetCalls -eq 0 -and $case.ExportCalls -eq 0) -Message "Unsafe quiesce case reached mutation: $($case.Case)"
}
Assert-CTQuiesce -Condition ($helper.PowerLoss.Status -eq 'PendingReboot' -and $helper.PowerLoss.ExistingStatus -eq 'Completed' -and $helper.PowerLoss.SetCalls -eq 0 -and $helper.PowerLoss.ExportCalls -eq 0 -and $helper.PowerLoss.StartCalls -eq 0 -and $helper.PowerLoss.CompleteCalls -eq 1) -Message 'Pending already-disabled ServiceQuiesce did not resume idempotently after a power loss.'
Assert-CTQuiesce -Condition ($helper.NewBoot.Blocked -and $helper.NewBoot.SetCalls -eq 0 -and $helper.NewBoot.ExportCalls -eq 0) -Message 'A new boot with a still-loaded Profile was not hard-blocked.'
Assert-CTQuiesce -Condition ($helper.ClassesOnly.Blocked -and $helper.ClassesOnly.SetCalls -eq 0 -and $helper.ClassesOnly.ExportCalls -eq 0) -Message 'A new boot with only the SID_Classes hive mounted was allowed toward deletion.'

# Candidate classification is security-sensitive: only the one loaded/hive error
# may opt into the service-only checkpoint. Reuse an isolated preflight fixture.
Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$candidate = & $module {
    param($FixtureManifest)
    $sid = 'S-1-5-21-1-2-3-1001'
    $script:CandidateGuardConflict = $false
    function Test-CTCoreHealth { param([hashtable]$Manifest,[switch]$RequireRunning,[PSObject]$Context) [PSCustomObject]@{Healthy=$true;Failures=@()} }
    function Test-CTPathHasReparsePoint { param([string]$Path) return $false }
    function Test-CTSecureSourcePath { param([string]$Path) return $true }
    function Get-CTServiceByName {
        param([string]$Name,[switch]$Driver)
        if (-not $Driver -and $Name -eq 'cloudbase-init') {
            $serviceEntry=@($FixtureManifest.Services|Where-Object{$_.Name -eq 'cloudbase-init'})|Select-Object -First 1
            return [PSCustomObject]@{Name=$Name;State='Stopped';StartMode='Auto';PathName=$serviceEntry.ExpectedImage;StartName='.\cloudbase-init'}
        }
        return $null
    }
    function Get-CTIfEOState {
        param([string]$Image)
        [PSCustomObject]@{Present=[bool]$script:CandidateGuardConflict;Debugger=if($script:CandidateGuardConflict){'C:\Other\debugger.exe'}else{$null};Marker=$null;RunId=$null}
    }
    function Get-CTRunValue { param([hashtable]$Entry,[switch]$Strict) return $null }
    function Get-CTWsusPolicySignature { param([hashtable]$Manifest) [PSCustomObject]@{Classification='Absent';States=@()} }
    function Get-ScheduledTask { [CmdletBinding()] param() return @() }
    function Get-LocalUser { [CmdletBinding()] param() [PSCustomObject]@{Name='cloudbase-init';SID=$sid;Enabled=$true} }
    function Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName,[string]$Filter)
        if($ClassName -eq 'Win32_UserProfile'){return [PSCustomObject]@{LocalPath='C:\Users\cloudbase-init';SID=$sid;Loaded=$true;Special=$false}}
        return @()
    }
    function Get-ChildItem { [CmdletBinding()] param([string]$Path) return @() }
    function Test-Path { [CmdletBinding()] param([string]$LiteralPath,[string]$PathType) if($LiteralPath -like 'Registry::HKEY_USERS\*'){return $true};return $true }
    function Get-AuthenticodeSignature { [CmdletBinding()] param([string]$LiteralPath) [PSCustomObject]@{Status='Valid'} }
    function Get-CTMachineSid { return 'S-1-5-21-1-2-3' }
    function Get-CTCloudbaseIdentityAnchors { param([string]$Sid,[hashtable]$Manifest,[object[]]$TaskSnapshot) return @('service:cloudbase-init') }
    $loadedOnly = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Apply
    $script:CandidateGuardConflict = $true
    $loadedPlusOther = Test-CTApplyPreflight -Manifest $FixtureManifest -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Phase Apply
    [PSCustomObject]@{LoadedOnly=$loadedOnly;LoadedPlusOther=$loadedPlusOther}
} $manifest
Assert-CTQuiesce -Condition (-not $candidate.LoadedOnly.Passed -and [bool]$candidate.LoadedOnly.CloudbaseServiceQuiesceCandidate -and @($candidate.LoadedOnly.Errors).Count -eq 1) -Message 'The one exact loaded-Profile Apply error was not classified as a quiesce candidate.'
Assert-CTQuiesce -Condition (-not $candidate.LoadedPlusOther.Passed -and -not [bool]$candidate.LoadedPlusOther.CloudbaseServiceQuiesceCandidate -and @($candidate.LoadedPlusOther.Errors).Count -gt 1) -Message 'A second preflight error was incorrectly bypassable through service quiesce.'

# Exercise the resume routing separately from destructive implementations. This
# proves the checkpoint returns early and that durable later history does not
# make a completed quiesce a permanent blocker.
Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
$routing = & $module {
    param($FixtureManifest)
    $script:RouteContext = $null
    $script:RouteBoot = 'BOOT-A'
    $script:RoutePreflight = [PSCustomObject]@{ Passed=$true; Errors=@(); Warnings=@(); CloudbaseServiceQuiesceCandidate=$false }
    $script:RouteQuiesceCalls = 0
    $script:RouteDeleteCalls = 0
    $script:RouteStateCalls = 0
    $script:RouteProfileLoaded = $false
    $script:RouteHiveMounted = $false
    $script:RouteClassesHiveMounted = $false

    function New-RouteOperation {
        param([string]$Type,[string]$Target,[string]$Status='Completed',[hashtable]$Data=@{})
        [PSCustomObject]@{Id=[guid]::NewGuid().ToString('N');Type=$Type;Target=$Target;Status=$Status;Data=$Data;Reversible=$true;CompletedAt='now'}
    }
    function New-RouteContext {
        param([switch]$Quiesce,[switch]$LaterRunValue,[switch]$ServiceRemoval,[string]$QuiescedBoot='BOOT-A')
        $ops=New-Object Collections.Generic.List[object]
        [void]$ops.Add((New-RouteOperation -Type Baseline -Target Baseline))
        if($Quiesce){
            [void]$ops.Add((New-RouteOperation -Type ServiceQuiesce -Target 'cloudbase-init' -Data @{
                Backup='C:\ProgramData\CTyunTrim\Runs\route\registry\quiesce.reg';BackupSha256=('A'*64)
                ExpectedImage=(@($FixtureManifest.Services|Where-Object{$_.Name -eq 'cloudbase-init'})|Select-Object -First 1).ExpectedImage
                ImageSha256=('C'*64);SID='S-1-5-21-1-2-3-1001';StartMode='Auto';State='Stopped';StartName='.\cloudbase-init';QuiescedBoot=$QuiescedBoot
            }))
        }
        if($LaterRunValue){[void]$ops.Add((New-RouteOperation -Type RunValue -Target 'later::value'))}
        if($ServiceRemoval){
            [void]$ops.Add((New-RouteOperation -Type Service -Target 'cloudbase-init' -Data @{
                Backup='C:\ProgramData\CTyunTrim\Runs\route\registry\remove.reg';BackupSha256=('D'*64)
                ExpectedImage=(@($FixtureManifest.Services|Where-Object{$_.Name -eq 'cloudbase-init'})|Select-Object -First 1).ExpectedImage
            }))
        }
        [PSCustomObject]@{RunId='route';Root='C:\ProgramData\CTyunTrim\Runs\route';ManifestHash='HASH';ManifestPath='C:\fixture\manifest.psd1';MachineSid='S-1-5-21-1-2-3';Status='Prepared';RebootNeeded=$false;CompletedAt=$null;LastBootUpTime='BOOT-A';Warnings=(New-Object Collections.Generic.List[string]);Operations=$ops}
    }
    function Reset-Route { $script:RouteQuiesceCalls=0;$script:RouteDeleteCalls=0;$script:RouteStateCalls=0;$script:RouteProfileLoaded=$false;$script:RouteHiveMounted=$false;$script:RouteClassesHiveMounted=$false }
    function Get-CTOperatingSystem { [PSCustomObject]@{Build=$FixtureManifest.SupportedBuilds[0];LastBootUpTime=$script:RouteBoot} }
    function Test-Path { [CmdletBinding()] param([string]$LiteralPath,[string]$PathType) return $true }
    function Get-CTRunContext { param([string]$BackupRoot,[string]$RunId) return $script:RouteContext }
    function Get-CTNormalizedTextHash { param([string]$Path) return 'HASH' }
    function Save-CTRunContext { param([PSObject]$Context) }
    function Save-CTFailedRunContextSafe { param([PSObject]$Context,[string]$FailureMessage) }
    function Add-CTDiagnosticEvent { param([string]$Level,[string]$Stage,[string]$Message,[hashtable]$Data) }
    function Resolve-CTPendingOperations { param([PSObject]$Context,[hashtable]$Manifest) }
    function Get-CTCloudbaseServiceQuiesceState {
        param([PSObject]$Context,[hashtable]$Manifest,[PSObject]$Operation)
        $script:RouteStateCalls++
        [PSCustomObject]@{Service=[PSCustomObject]@{State='Stopped';StartMode='Disabled'};ProfileLoaded=[bool]$script:RouteProfileLoaded;HiveMounted=[bool]$script:RouteHiveMounted;ClassesHiveMounted=[bool]$script:RouteClassesHiveMounted;FileSha256=('C'*64)}
    }
    function Test-CTApplyPreflight { param([hashtable]$Manifest,[string]$BackupRoot,[string]$LgpoPath,[string]$RunId,[PSObject]$Context,[string]$Phase) return $script:RoutePreflight }
    function Invoke-CTCloudbaseServiceQuiesce {
        param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller)
        $script:RouteQuiesceCalls++
        [PSCustomObject]@{RunId=$Context.RunId;Status='PendingReboot';RebootNeeded=$true}
    }
    function Set-CTCloudbaseQuiescePendingReboot { param([PSObject]$Context) [PSCustomObject]@{RunId=$Context.RunId;Status='PendingReboot';RebootNeeded=$true} }
    function Test-CTPathWithinRoot { param([string]$Path,[string]$Root) return $true }
    function Test-CTRegistryExportFile { param([string]$Path,[string]$NativeKey) return $true }
    function Test-CTSecureSourcePath { param([string]$Path) return $true }
    function Get-FileHash { [CmdletBinding()] param([string]$LiteralPath,[string]$Algorithm) [PSCustomObject]@{Hash=if($LiteralPath -like '*remove.reg'){'D'*64}else{'A'*64}} }
    function Test-CTCoreHealth { param([hashtable]$Manifest,[switch]$RequireRunning,[PSObject]$Context) throw 'ROUTE_REACHED_NORMAL_APPLY' }
    function Remove-CTServices { param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller) $script:RouteDeleteCalls++ }
    function Remove-CTCloudbaseIdentity { param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller) $script:RouteDeleteCalls++ }
    function Invoke-RouteApply {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param([hashtable]$Manifest)
        Invoke-CTApply -Manifest $Manifest -ManifestPath 'C:\fixture\manifest.psd1' -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -RunId 'route' -Caller $PSCmdlet
    }

    Reset-Route
    $script:RouteContext=New-RouteContext
    $script:RoutePreflight=[PSCustomObject]@{Passed=$false;Errors=@('loaded');Warnings=@();CloudbaseServiceQuiesceCandidate=$true}
    $candidateResult=Invoke-RouteApply -Manifest $FixtureManifest -Confirm:$false
    $candidateRoute=[PSCustomObject]@{Status=$candidateResult.Status;QuiesceCalls=$script:RouteQuiesceCalls;DeleteCalls=$script:RouteDeleteCalls}

    Reset-Route
    $script:RouteContext=New-RouteContext
    $script:RoutePreflight=[PSCustomObject]@{Passed=$false;Errors=@('unrelated');Warnings=@();CloudbaseServiceQuiesceCandidate=$false}
    $otherBlocked=$false
    try{Invoke-RouteApply -Manifest $FixtureManifest -Confirm:$false|Out-Null}catch{$otherBlocked=$_.Exception.Message -match 'Apply resume preflight failed'}
    $otherRoute=[PSCustomObject]@{Blocked=$otherBlocked;QuiesceCalls=$script:RouteQuiesceCalls;DeleteCalls=$script:RouteDeleteCalls}

    Reset-Route
    $script:RouteBoot='BOOT-A';$script:RouteContext=New-RouteContext -Quiesce -QuiescedBoot 'BOOT-A'
    $script:RoutePreflight=[PSCustomObject]@{Passed=$true;Errors=@();Warnings=@();CloudbaseServiceQuiesceCandidate=$false}
    $sameBootResult=Invoke-RouteApply -Manifest $FixtureManifest -Confirm:$false
    $sameBoot=[PSCustomObject]@{Status=$sameBootResult.Status;DeleteCalls=$script:RouteDeleteCalls}

    Reset-Route
    $script:RouteBoot='BOOT-B';$script:RouteContext=New-RouteContext -Quiesce -QuiescedBoot 'BOOT-A'
    $script:RoutePreflight=[PSCustomObject]@{Passed=$false;Errors=@('loaded');Warnings=@();CloudbaseServiceQuiesceCandidate=$true}
    $stillLoadedBlocked=$false
    try{Invoke-RouteApply -Manifest $FixtureManifest -Confirm:$false|Out-Null}catch{$stillLoadedBlocked=$_.Exception.Message -match 'remains loaded after the ServiceQuiesce reboot'}
    $stillLoaded=[PSCustomObject]@{Blocked=$stillLoadedBlocked;QuiesceCalls=$script:RouteQuiesceCalls;DeleteCalls=$script:RouteDeleteCalls}

    Reset-Route
    $script:RouteBoot='BOOT-B';$script:RouteClassesHiveMounted=$true;$script:RouteContext=New-RouteContext -Quiesce -QuiescedBoot 'BOOT-A'
    $script:RoutePreflight=[PSCustomObject]@{Passed=$true;Errors=@();Warnings=@();CloudbaseServiceQuiesceCandidate=$false}
    $classesRouteBlocked=$false
    try{Invoke-RouteApply -Manifest $FixtureManifest -Confirm:$false|Out-Null}catch{$classesRouteBlocked=$_.Exception.Message -match 'remains loaded after the ServiceQuiesce reboot'}
    $classesRoute=[PSCustomObject]@{Blocked=$classesRouteBlocked;QuiesceCalls=$script:RouteQuiesceCalls;DeleteCalls=$script:RouteDeleteCalls}

    Reset-Route
    $script:RouteBoot='BOOT-B';$script:RouteContext=New-RouteContext -Quiesce -LaterRunValue -QuiescedBoot 'BOOT-A'
    $script:RoutePreflight=[PSCustomObject]@{Passed=$true;Errors=@();Warnings=@();CloudbaseServiceQuiesceCandidate=$false}
    $laterReached=$false
    try{Invoke-RouteApply -Manifest $FixtureManifest -Confirm:$false|Out-Null}catch{$laterReached=$_.Exception.Message -eq 'ROUTE_REACHED_NORMAL_APPLY'}
    $laterHistory=[PSCustomObject]@{Reached=$laterReached;StateCalls=$script:RouteStateCalls;DeleteCalls=$script:RouteDeleteCalls}

    Reset-Route
    $script:RouteBoot='BOOT-C';$script:RouteContext=New-RouteContext -Quiesce -ServiceRemoval -QuiescedBoot 'BOOT-A'
    $script:RoutePreflight=[PSCustomObject]@{Passed=$true;Errors=@();Warnings=@();CloudbaseServiceQuiesceCandidate=$false}
    $removedReached=$false
    try{Invoke-RouteApply -Manifest $FixtureManifest -Confirm:$false|Out-Null}catch{$removedReached=$_.Exception.Message -eq 'ROUTE_REACHED_NORMAL_APPLY'}
    $removedHistory=[PSCustomObject]@{Reached=$removedReached;StateCalls=$script:RouteStateCalls;DeleteCalls=$script:RouteDeleteCalls}

    [PSCustomObject]@{Candidate=$candidateRoute;Other=$otherRoute;SameBoot=$sameBoot;StillLoaded=$stillLoaded;ClassesOnly=$classesRoute;LaterHistory=$laterHistory;RemovedHistory=$removedHistory}
} $manifest
Assert-CTQuiesce -Condition ($routing.Candidate.Status -eq 'PendingReboot' -and $routing.Candidate.QuiesceCalls -eq 1 -and $routing.Candidate.DeleteCalls -eq 0) -Message 'Unique loaded-Profile candidate did not return directly through ServiceQuiesce.'
Assert-CTQuiesce -Condition ($routing.Other.Blocked -and $routing.Other.QuiesceCalls -eq 0 -and $routing.Other.DeleteCalls -eq 0) -Message 'An unrelated Apply error bypassed through ServiceQuiesce.'
Assert-CTQuiesce -Condition ($routing.SameBoot.Status -eq 'PendingReboot' -and $routing.SameBoot.DeleteCalls -eq 0) -Message 'Same-boot completed quiesce entered destructive Apply.'
Assert-CTQuiesce -Condition ($routing.StillLoaded.Blocked -and $routing.StillLoaded.QuiesceCalls -eq 0 -and $routing.StillLoaded.DeleteCalls -eq 0) -Message 'New-boot still-loaded Profile retried quiesce or entered deletion.'
Assert-CTQuiesce -Condition ($routing.ClassesOnly.Blocked -and $routing.ClassesOnly.QuiesceCalls -eq 0 -and $routing.ClassesOnly.DeleteCalls -eq 0) -Message 'Actual Apply resume route ignored a classes-only Cloudbase hive mount.'
Assert-CTQuiesce -Condition ($routing.LaterHistory.Reached -and $routing.LaterHistory.DeleteCalls -eq 0) -Message 'Completed quiesce plus legitimate later Apply history became a permanent resume blocker.'
Assert-CTQuiesce -Condition ($routing.RemovedHistory.Reached -and $routing.RemovedHistory.StateCalls -eq 0 -and $routing.RemovedHistory.DeleteCalls -eq 0) -Message 'Durable completed cloudbase service removal still required the deleted service object.'

$source = Get-Content -LiteralPath $sourcePath -Raw
$prepareStart = $source.IndexOf('function Invoke-CTPrepare', [StringComparison]::Ordinal)
$entryStart = $source.IndexOf('function Invoke-CTyunTrim', [StringComparison]::Ordinal)
$prepareText = if ($prepareStart -ge 0 -and $entryStart -gt $prepareStart) { $source.Substring($prepareStart, $entryStart - $prepareStart) } else { '' }
Assert-CTQuiesce -Condition (-not [string]::IsNullOrWhiteSpace($prepareText) -and $prepareText.IndexOf('Invoke-CTCloudbaseServiceQuiesce', [StringComparison]::Ordinal) -lt 0) -Message 'Prepare/Prepare -WhatIf was wired to the Apply-only ServiceQuiesce mutation.'

if ($failures.Count -gt 0) {
    throw "Cloudbase quiesce tests failed:`n - $($failures -join "`n - ")"
}

Write-Host 'Cloudbase quiesce tests passed.'
