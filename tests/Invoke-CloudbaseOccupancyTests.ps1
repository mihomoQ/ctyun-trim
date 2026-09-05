#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Cloudbase occupancy tests must run under Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) { throw 'Cloudbase occupancy tests require a 64-bit process.' }

$root = Split-Path -Parent $PSScriptRoot
$collectorPath = Join-Path $root 'tools\Get-CTCloudbaseOccupancy.ps1'
$failures = New-Object Collections.Generic.List[string]
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("CTyunTrim-OccupancyTests-{0}" -f [Guid]::NewGuid().ToString('N'))

function Assert-CTOccupancy {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { $script:failures.Add($Message) }
}

function Get-CTFixturePrelude {
    @'
$script:Fixture = [ordered]@{
    Accounts = @()
    Profiles = @()
    UserAccounts = @()
    Processes = @()
    Logons = @()
    LoggedOnUsers = @()
    AssociatedLogons = @()
    Services = @()
    Tasks = @()
    HkuMounted = $false
    HkuClassesMounted = $false
    HiveQueryThrows = $false
    LocalUserQueryThrows = $false
    ProfileQueryThrows = $false
    ProcessQueryThrows = $false
    ProcessRequeryThrows = $false
    LogonQueryThrows = $false
    AssociationQueryThrows = $false
    ServiceQueryThrows = $false
    TaskQueryThrows = $false
    TaskInfoQueryThrows = $false
}

function Get-LocalUser {
    [CmdletBinding()]
    param()
    if ($script:Fixture.LocalUserQueryThrows) { throw 'mock access denied: local user' }
    return @($script:Fixture.Accounts)
}

function Get-CimInstance {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$ClassName,
        [string]$Filter
    )

    switch ($ClassName) {
        'Win32_UserProfile' {
            if ($script:Fixture.ProfileQueryThrows) { throw 'mock access denied: user profile' }
            return @($script:Fixture.Profiles)
        }
        'Win32_UserAccount' { return @($script:Fixture.UserAccounts) }
        'Win32_Process' {
            if (-not [string]::IsNullOrWhiteSpace($Filter)) {
                if ($script:Fixture.ProcessRequeryThrows) { throw 'mock access denied: process liveness' }
                if ($Filter -match 'ProcessId\s*=\s*([0-9]+)') {
                    $wanted = [uint32]$Matches[1]
                    return @($script:Fixture.Processes | Where-Object { [uint32]$_.ProcessId -eq $wanted -and -not [bool]$_.DisappearsOnRequery })
                }
                return @()
            }
            if ($script:Fixture.ProcessQueryThrows) { throw 'mock access denied: process inventory' }
            return @($script:Fixture.Processes)
        }
        'Win32_LogonSession' {
            if ($script:Fixture.LogonQueryThrows) { throw 'mock access denied: logon session' }
            return @($script:Fixture.Logons)
        }
        'Win32_LoggedOnUser' {
            if ($script:Fixture.LogonQueryThrows) { throw 'mock access denied: logged-on association' }
            return @($script:Fixture.LoggedOnUsers)
        }
        'Win32_Service' {
            if ($script:Fixture.ServiceQueryThrows) { throw 'mock access denied: service inventory' }
            return @($script:Fixture.Services)
        }
        default { throw "unexpected mock CIM class: $ClassName" }
    }
}

function Get-CimAssociatedInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [string]$Association,
        [string]$ResultClassName
    )
    if ($script:Fixture.AssociationQueryThrows -or $script:Fixture.LogonQueryThrows) {
        throw 'mock access denied: logon association'
    }
    return @($script:Fixture.AssociatedLogons)
}

function Invoke-CimMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [string]$MethodName
    )
    if ([bool]$InputObject.OwnerQueryThrows) { throw 'mock access denied: process owner' }
    return [PSCustomObject]@{
        ReturnValue = if ($null -eq $InputObject.OwnerReturn) { [uint32]0 } else { [uint32]$InputObject.OwnerReturn }
        Sid = [string]$InputObject.OwnerSid
    }
}

function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$PathType)
    if ($script:Fixture.HiveQueryThrows -and $LiteralPath -like 'Registry::HKEY_USERS\*') {
        throw 'CANARY-PRIVATE-HIVE-ERROR'
    }
    if ($LiteralPath -like 'Registry::HKEY_USERS\*_Classes') { return [bool]$script:Fixture.HkuClassesMounted }
    if ($LiteralPath -like 'Registry::HKEY_USERS\*') { return [bool]$script:Fixture.HkuMounted }
    return $false
}

function Get-ScheduledTask {
    [CmdletBinding()]
    param()
    if ($script:Fixture.TaskQueryThrows) { throw 'mock access denied: scheduled-task inventory' }
    return @($script:Fixture.Tasks)
}

function Get-ScheduledTaskInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$InputObject)
    if ($script:Fixture.TaskInfoQueryThrows -or [bool]$InputObject.InfoQueryThrows) {
        throw 'mock access denied: scheduled-task info'
    }
    return [PSCustomObject]@{ LastTaskResult = [int64]$InputObject.MockLastTaskResult }
}
'@
}

function Invoke-CTOccupancyFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Setup
    )

    $source = Get-Content -LiteralPath $collectorPath -Raw
    $source = $source -replace '(?m)^\s*#requires[^\r\n]*(?:\r?\n)?', ''
    $harnessPath = Join-Path $testRoot ("{0}.ps1" -f $Name)
    # Keep the collector's [CmdletBinding()] param() declaration first in its
    # own script block while allowing the parent script scope to provide mocks.
    $harness = (Get-CTFixturePrelude) + "`r`n" + $Setup + "`r`n& {`r`n" + $source + "`r`n}`r`n"
    Set-Content -LiteralPath $harnessPath -Value $harness -Encoding UTF8

    $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $output = @(& $powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $harnessPath 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { [string]$_ }) -join "`n"
    $json = $null
    try { $json = $text | ConvertFrom-Json }
    catch { $script:failures.Add("$Name did not emit one valid JSON document: $text") }

    [PSCustomObject]@{ Name = $Name; ExitCode = $exitCode; Text = $text; Json = $json }
}

$targetSid = 'S-1-5-21-111111111-222222222-333333333-1001'
$otherSid = 'S-1-5-21-111111111-222222222-333333333-1002'
$baseSetup = @'
$targetSid = 'S-1-5-21-111111111-222222222-333333333-1001'
$script:Fixture.Accounts = @([PSCustomObject]@{ Name='cloudbase-init'; SID=$targetSid; Enabled=$true })
$script:Fixture.UserAccounts = @([PSCustomObject]@{ Name='cloudbase-init'; SID=$targetSid; LocalAccount=$true })
$script:Fixture.Profiles = @([PSCustomObject]@{ LocalPath='C:\Users\cloudbase-init'; SID=$targetSid; Loaded=$true; Special=$false; refCount=[uint32]7 })
$script:Fixture.HkuMounted = $true
$script:Fixture.HkuClassesMounted = $true
$script:Fixture.Processes = @(
    [PSCustomObject]@{ ProcessId=[uint32]101; SessionId=[uint32]0; Name='TaskAgentDetect.exe'; ExecutablePath='C:\Program Files (x86)\ctyun\clink\Mirror\Launch\TaskAgentDetect.exe'; OwnerSid=$targetSid; OwnerReturn=[uint32]0; OwnerQueryThrows=$false; DisappearsOnRequery=$false },
    [PSCustomObject]@{ ProcessId=[uint32]102; SessionId=[uint32]0; Name='CANARY-SECRET-PROCESS.exe'; ExecutablePath='C:\Private\CANARY-SECRET-PATH\private.exe'; OwnerSid=$targetSid; OwnerReturn=[uint32]0; OwnerQueryThrows=$false; DisappearsOnRequery=$false }
)
$serviceLogon = [PSCustomObject]@{ LogonId='42'; LogonType=[uint32]5 }
$script:Fixture.Logons = @($serviceLogon)
$script:Fixture.AssociatedLogons = @($serviceLogon)
$script:Fixture.LoggedOnUsers = @([PSCustomObject]@{ Antecedent=[PSCustomObject]@{ SID=$targetSid }; Dependent=[PSCustomObject]@{ LogonId='42' } })
$script:Fixture.Services = @(
    [PSCustomObject]@{ Name='cloudbase-init'; State='Stopped'; StartMode='Auto'; StartName=$targetSid },
    [PSCustomObject]@{ Name='clink_service'; State='Running'; StartMode='Auto'; StartName='S-1-5-18' },
    [PSCustomObject]@{ Name='CANARY-SECRET-SERVICE'; State='Running'; StartMode='Auto'; StartName=$targetSid }
)
$principal = [PSCustomObject]@{ UserId=$targetSid; GroupId=$null; LogonType='S4U' }
$script:Fixture.Tasks = @(
    [PSCustomObject]@{ TaskName='check_report_img_onstart'; TaskPath='\'; State='Ready'; Principal=$principal; MockLastTaskResult=[int64]0; InfoQueryThrows=$false },
    [PSCustomObject]@{ TaskName='CANARY-SECRET-TASK'; TaskPath='\Private\'; State='Ready'; Principal=$principal; MockLastTaskResult=[int64]0; InfoQueryThrows=$false }
)
'@

try {
    New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null

    $normal = Invoke-CTOccupancyFixture -Name 'normal' -Setup $baseSetup
    Assert-CTOccupancy -Condition ($normal.ExitCode -eq 0) -Message "Normal fixture returned exit code $($normal.ExitCode)."
    if ($null -ne $normal.Json) {
        Assert-CTOccupancy -Condition ([bool]$normal.Json.Succeeded) -Message 'Normal fixture was not successful.'
        Assert-CTOccupancy -Condition ([bool]$normal.Json.ProcessInventoryComplete) -Message 'Normal process inventory was not complete.'
        Assert-CTOccupancy -Condition ([int]$normal.Json.Identity.ExactProfileCount -eq 1) -Message 'One exact Profile was not reported.'
        Assert-CTOccupancy -Condition ([bool]$normal.Json.Identity.AccountProfileSidMatches) -Message 'Matching account/Profile SIDs were not reported.'
        Assert-CTOccupancy -Condition ([bool]$normal.Json.Identity.Profile.Loaded -and [bool]$normal.Json.Identity.Profile.HkuMounted -and [bool]$normal.Json.Identity.Profile.HkuClassesMounted) -Message 'Loaded Profile/HKU state was not preserved.'
        Assert-CTOccupancy -Condition ([int]$normal.Json.Processes.TargetProcessCount -eq 2) -Message 'Target-SID process count is wrong.'
        $taskAgent = @($normal.Json.Processes.Items | Where-Object { $_.Name -eq 'TaskAgentDetect' })
        $unknownProcess = @($normal.Json.Processes.Items | Where-Object { $_.Name -eq 'Unknown:001' })
        Assert-CTOccupancy -Condition ($taskAgent.Count -eq 1 -and $taskAgent[0].ImageClass -eq 'ExactTaskAgentDetect') -Message 'Exact TaskAgentDetect was not classified correctly.'
        Assert-CTOccupancy -Condition ($unknownProcess.Count -eq 1 -and $unknownProcess[0].ImageClass -eq 'OutsideRemovalRoots') -Message 'Unknown target process was not safely classified.'
        Assert-CTOccupancy -Condition (@($normal.Json.Logons.AssociatedLogonTypes | Where-Object { $_.Type -eq 'Service' -and [int]$_.Count -eq 1 }).Count -eq 1) -Message 'Known service logon association was not reported.'
        $cloudbaseService = @($normal.Json.Services.Items | Where-Object { $_.Id -eq 'Service:cloudbase-init' })
        Assert-CTOccupancy -Condition ($cloudbaseService.Count -eq 1 -and [bool]$cloudbaseService[0].Present -and [bool]$cloudbaseService[0].AccountSidMatches) -Message 'Known Cloudbase service principal was not matched.'
        Assert-CTOccupancy -Condition ([int]$normal.Json.Services.UnknownReferenceCount -eq 1) -Message 'Unknown target-SID service reference was not counted.'
        $knownTask = @($normal.Json.Tasks.Items | Where-Object { $_.Id -eq 'Task:check_report_img_onstart' })
        Assert-CTOccupancy -Condition ($knownTask.Count -eq 1 -and [bool]$knownTask[0].Present -and [bool]$knownTask[0].PrincipalSidMatches -and $knownTask[0].LogonType -eq 'S4U') -Message 'Known Cloudbase task principal was not matched.'
        Assert-CTOccupancy -Condition ([int]$normal.Json.Tasks.UnknownReferenceCount -eq 1) -Message 'Unknown target-SID task reference was not counted.'
    }
    foreach ($secret in @($targetSid, 'CANARY-SECRET-PROCESS', 'CANARY-SECRET-PATH', 'CANARY-SECRET-SERVICE', 'CANARY-SECRET-TASK', 'C:\Users\cloudbase-init')) {
        Assert-CTOccupancy -Condition ($normal.Text.IndexOf($secret, [StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "Normal JSON leaked a private fixture value: $secret"
    }

    $accountOnly = Invoke-CTOccupancyFixture -Name 'account-only' -Setup @"
$baseSetup
`$script:Fixture.Profiles = @()
`$script:Fixture.HkuMounted = `$false
`$script:Fixture.HkuClassesMounted = `$false
"@
    Assert-CTOccupancy -Condition ($accountOnly.ExitCode -eq 0) -Message 'A unique account with zero Profiles should remain diagnosable.'
    if ($null -ne $accountOnly.Json) {
        Assert-CTOccupancy -Condition ([bool]$accountOnly.Json.Succeeded -and [int]$accountOnly.Json.Identity.ExactProfileCount -eq 0 -and $null -eq $accountOnly.Json.Identity.Profile) -Message 'Zero-Profile account state was not represented safely.'
    }

    $absent = Invoke-CTOccupancyFixture -Name 'absent' -Setup ''
    Assert-CTOccupancy -Condition ($absent.ExitCode -ne 0) -Message 'Missing account and Profile incorrectly returned success.'
    if ($null -ne $absent.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$absent.Json.Succeeded -and $absent.Json.ErrorCode -eq 'CloudbaseLocalAccountNotUnique') -Message 'Missing identity was not an explicit local-account identity failure.'
        Assert-CTOccupancy -Condition (-not [bool]$absent.Json.Processes.QuerySucceeded) -Message 'Collector continued into process attribution without a unique identity.'
    }

    $multipleProfiles = Invoke-CTOccupancyFixture -Name 'multiple-profiles' -Setup @"
$baseSetup
`$script:Fixture.Profiles += [PSCustomObject]@{ LocalPath='C:\Users\cloudbase-init'; SID='$targetSid'; Loaded=`$false; Special=`$false; refCount=[uint32]0 }
"@
    Assert-CTOccupancy -Condition ($multipleProfiles.ExitCode -ne 0) -Message 'Multiple exact Profiles incorrectly returned success.'
    if ($null -ne $multipleProfiles.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$multipleProfiles.Json.Succeeded -and $multipleProfiles.Json.ErrorCode -eq 'CloudbaseIdentityNotUnique' -and [int]$multipleProfiles.Json.Identity.ExactProfileCount -eq 2) -Message 'Multiple exact Profiles were not reported as ambiguous.'
    }

    $sidConflict = Invoke-CTOccupancyFixture -Name 'sid-conflict' -Setup @"
$baseSetup
`$script:Fixture.Profiles = @([PSCustomObject]@{ LocalPath='C:\Users\cloudbase-init'; SID='$otherSid'; Loaded=`$true; Special=`$false; refCount=[uint32]1 })
"@
    Assert-CTOccupancy -Condition ($sidConflict.ExitCode -ne 0) -Message 'Account/Profile SID conflict incorrectly returned success.'
    if ($null -ne $sidConflict.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$sidConflict.Json.Succeeded -and $sidConflict.Json.ErrorCode -eq 'CloudbaseIdentityNotUnique') -Message 'SID conflict was not an explicit identity failure.'
        Assert-CTOccupancy -Condition (-not [bool]$sidConflict.Json.Processes.QuerySucceeded) -Message 'Collector attributed processes despite a SID conflict.'
    }

    $identityDenied = Invoke-CTOccupancyFixture -Name 'identity-denied' -Setup '$script:Fixture.LocalUserQueryThrows = $true'
    Assert-CTOccupancy -Condition ($identityDenied.ExitCode -ne 0) -Message 'Identity permission failure incorrectly returned success.'
    if ($null -ne $identityDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$identityDenied.Json.Succeeded -and $identityDenied.Json.ErrorCode -eq 'LocalAccountInventoryFailed') -Message 'Identity permission failure was not explicit.'
    }

    $processDenied = Invoke-CTOccupancyFixture -Name 'process-denied' -Setup @"
$baseSetup
`$script:Fixture.ProcessQueryThrows = `$true
"@
    Assert-CTOccupancy -Condition ($processDenied.ExitCode -ne 0) -Message 'Process inventory permission failure incorrectly returned success.'
    if ($null -ne $processDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$processDenied.Json.Succeeded -and $processDenied.Json.ErrorCode -eq 'ProcessInventoryQueryFailed' -and -not [bool]$processDenied.Json.ProcessInventoryComplete) -Message 'Process inventory permission failure was not explicit.'
    }

    $ownerDenied = Invoke-CTOccupancyFixture -Name 'owner-and-liveness-denied' -Setup @"
$baseSetup
`$script:Fixture.Processes = @([PSCustomObject]@{ ProcessId=[uint32]103; SessionId=[uint32]0; Name='TaskAgentDetect.exe'; ExecutablePath='C:\Program Files (x86)\ctyun\clink\Mirror\Launch\TaskAgentDetect.exe'; OwnerSid='$targetSid'; OwnerReturn=[uint32]0; OwnerQueryThrows=`$true; DisappearsOnRequery=`$false })
`$script:Fixture.ProcessRequeryThrows = `$true
"@
    Assert-CTOccupancy -Condition ($ownerDenied.ExitCode -ne 0) -Message 'Owner+liveness permission failure incorrectly returned success.'
    if ($null -ne $ownerDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$ownerDenied.Json.Succeeded -and [int]$ownerDenied.Json.OwnerQueryFailedCount -eq 1 -and [int]$ownerDenied.Json.Processes.DisappearedCount -eq 0) -Message 'A failed liveness query was incorrectly classified as process disappearance.'
    }

    $disappeared = Invoke-CTOccupancyFixture -Name 'process-disappeared' -Setup @"
$baseSetup
`$script:Fixture.Processes = @([PSCustomObject]@{ ProcessId=[uint32]104; SessionId=[uint32]0; Name='TaskAgentDetect.exe'; ExecutablePath='C:\Program Files (x86)\ctyun\clink\Mirror\Launch\TaskAgentDetect.exe'; OwnerSid='$targetSid'; OwnerReturn=[uint32]0; OwnerQueryThrows=`$true; DisappearsOnRequery=`$true })
"@
    Assert-CTOccupancy -Condition ($disappeared.ExitCode -eq 0) -Message 'A process proven absent on requery should not make inventory incomplete.'
    if ($null -ne $disappeared.Json) {
        Assert-CTOccupancy -Condition ([bool]$disappeared.Json.Succeeded -and [int]$disappeared.Json.Processes.DisappearedCount -eq 1 -and [int]$disappeared.Json.OwnerQueryFailedCount -eq 0) -Message 'A process proven absent on requery was not classified as disappeared.'
    }

    $logonDenied = Invoke-CTOccupancyFixture -Name 'logon-denied' -Setup @"
$baseSetup
`$script:Fixture.AssociationQueryThrows = `$true
`$script:Fixture.LogonQueryThrows = `$true
"@
    Assert-CTOccupancy -Condition ($logonDenied.ExitCode -ne 0) -Message 'Logon inventory permission failure incorrectly returned success.'
    if ($null -ne $logonDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$logonDenied.Json.Succeeded -and -not [bool]$logonDenied.Json.Logons.InventoryComplete -and $logonDenied.Json.ErrorCode -eq 'LogonInventoryIncomplete') -Message 'Logon permission failure was not explicit.'
    }

    $serviceDenied = Invoke-CTOccupancyFixture -Name 'service-denied' -Setup @"
$baseSetup
`$script:Fixture.ServiceQueryThrows = `$true
"@
    Assert-CTOccupancy -Condition ($serviceDenied.ExitCode -ne 0) -Message 'Service inventory permission failure incorrectly returned success.'
    if ($null -ne $serviceDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$serviceDenied.Json.Succeeded -and -not [bool]$serviceDenied.Json.Services.InventoryComplete -and $serviceDenied.Json.ErrorCode -eq 'ServiceInventoryIncomplete') -Message 'Service permission failure was not explicit.'
    }

    $taskDenied = Invoke-CTOccupancyFixture -Name 'task-denied' -Setup @"
$baseSetup
`$script:Fixture.TaskQueryThrows = `$true
"@
    Assert-CTOccupancy -Condition ($taskDenied.ExitCode -ne 0) -Message 'Task inventory permission failure incorrectly returned success.'
    if ($null -ne $taskDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$taskDenied.Json.Succeeded -and -not [bool]$taskDenied.Json.Tasks.InventoryComplete -and $taskDenied.Json.ErrorCode -eq 'TaskInventoryIncomplete') -Message 'Task permission failure was not explicit.'
    }

    $principalDenied = Invoke-CTOccupancyFixture -Name 'principal-resolution-denied' -Setup @"
$baseSetup
`$script:Fixture.Services += [PSCustomObject]@{ Name='CANARY-UNRESOLVED-SERVICE'; State='Running'; StartMode='Auto'; StartName='NT AUTHORITY\CTYUNTRIM_INVALID_PRINCIPAL_6E480BFD' }
`$script:Fixture.Tasks += [PSCustomObject]@{ TaskName='CANARY-UNRESOLVED-TASK'; TaskPath='\Private\'; State='Ready'; Principal=[PSCustomObject]@{ UserId='NT AUTHORITY\CTYUNTRIM_INVALID_PRINCIPAL_6E480BFD'; GroupId=`$null; LogonType='S4U' }; MockLastTaskResult=[int64]0; InfoQueryThrows=`$false }
"@
    Assert-CTOccupancy -Condition ($principalDenied.ExitCode -ne 0) -Message 'Principal resolution failures incorrectly returned success.'
    if ($null -ne $principalDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$principalDenied.Json.Succeeded -and ([int]$principalDenied.Json.Services.PrincipalResolutionFailedCount -gt 0) -and ([int]$principalDenied.Json.Tasks.PrincipalResolutionFailedCount -gt 0)) -Message 'Principal resolution failures were not exposed or did not make the result incomplete.'
    }

    $hiveDenied = Invoke-CTOccupancyFixture -Name 'hive-denied' -Setup @"
$baseSetup
`$script:Fixture.HiveQueryThrows = `$true
"@
    Assert-CTOccupancy -Condition ($hiveDenied.ExitCode -ne 0) -Message 'Unexpected hive-query exception incorrectly returned success.'
    if ($null -ne $hiveDenied.Json) {
        Assert-CTOccupancy -Condition (-not [bool]$hiveDenied.Json.Succeeded -and $hiveDenied.Json.ErrorCode -eq 'CollectorUnhandledFailure') -Message 'Top-level catch did not convert a hive-query exception to a fixed JSON failure.'
    }
    Assert-CTOccupancy -Condition ($hiveDenied.Text.IndexOf('CANARY-PRIVATE-HIVE-ERROR', [StringComparison]::Ordinal) -lt 0) -Message 'Top-level failure JSON leaked a raw exception message.'
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        $fullTestRoot = [IO.Path]::GetFullPath($testRoot).TrimEnd('\')
        $fullTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        $testLeaf = [IO.Path]::GetFileName($fullTestRoot)
        $testItem = Get-Item -LiteralPath $fullTestRoot -Force -ErrorAction Stop
        $safeCleanup = $fullTestRoot.StartsWith($fullTempRoot, [StringComparison]::OrdinalIgnoreCase) -and
            $testLeaf -match '^CTyunTrim-OccupancyTests-[0-9a-f]{32}$' -and
            -not [bool]($testItem.Attributes -band [IO.FileAttributes]::ReparsePoint)
        if (-not $safeCleanup) { throw "Refusing unsafe test cleanup path: $fullTestRoot" }
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failures.Count -gt 0) {
    throw "Cloudbase occupancy tests failed:`n - $($failures -join "`n - ")"
}

Write-Host 'Cloudbase occupancy tests passed.'
