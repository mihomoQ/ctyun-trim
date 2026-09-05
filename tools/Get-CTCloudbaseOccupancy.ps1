#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$knownProcessNames = @(
    'AppMarketSvc','cloud-printer-client','cloud-printer-client-service','clinkte_service','clinktetool','clinkteTray',
    'CtyunDesktopMaster','CtyunDesktopMasterSrv','CtyunDesktopDrtSrv','ecloudAiAssistant','ecloudAppManager','CloudUpdate',
    'ExternalLaunch','TaskAgentDetect','TaskLaunch','ecloud_img_conf','clink_service','clink_agent','clink_agent_data',
    'clink_agent_device','clink_agent_display','clink_cb_helper','clipa.win','cloudshare_service','cloudshare','blnsvr',
    'OpenStackService','python','pythonw','cmd','conhost','svchost','taskeng','taskhostw'
)
$knownProcessMap = @{}
foreach ($name in $knownProcessNames) { $knownProcessMap[$name] = $name }
$removalRoots = @(
    'C:\Program Files (x86)\ctyun\AppMarketSvc','C:\Program Files (x86)\ctyun\ecloudAiAssistant',
    'C:\Program Files (x86)\ctyun\ecloudAiAssistantUpdateLauncher','C:\Program Files (x86)\ctyun\CtyunDesktopMasterClient',
    'C:\Program Files (x86)\ctyun\ecloudAppManager','C:\Program Files (x86)\ctyun\PrinterManager',
    'C:\Program Files (x86)\ctyun\CloudPrinterClient','C:\Program Files (x86)\ctyun\CloudPrinterUsbDk',
    'C:\Program Files (x86)\ctyun\ecloudDisk','C:\Program Files (x86)\ctyun\cloud-sync-server',
    'C:\Program Files (x86)\ctyun\FirewallNetwork','C:\Program Files (x86)\ctyun\CertUpdate',
    'C:\Program Files (x86)\ctyun\clink\Mirror','C:\Program Files (x86)\ctyun\clink\eduMonitor',
    'C:\Program Files (x86)\ctyun\clink\help','C:\Program Files (x86)\ctyun\clink\Config\FileCrypto',
    'C:\Program Files (x86)\ctyun\clink\res\screenrecord','C:\Program Files (x86)\ctyun\clink\res\DrawArea',
    'C:\Program Files (x86)\ctyun\clink\res\WinDivertProxy','C:\Program Files (x86)\ctyun\clink\res\AutoCAD',
    'C:\Program Files (x86)\ctyun\clink\res\ZWCAD','C:\Program Files (x86)\ctyun\clink\res\GstarCAD',
    'C:\Program Files (x86)\ctyun\clink\res\EClassroom','C:\Program Files\Cloudbase Solutions\Cloudbase-Init'
)
$taskAgentImage = 'C:\Program Files (x86)\ctyun\clink\Mirror\Launch\TaskAgentDetect.exe'
$knownServiceNames = @('cloudbase-init','cloudbase-init-unattend')
$knownTaskNames = @('check_report_img_onstart','check_report_img_daily','check_report_img_random','ecloud_update_agent_detect','ecloud_update_task_launch')

function Get-CTValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-CTFullPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try { return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)).TrimEnd('\') }
    catch { return $null }
}

function Test-CTUnderRemovalRoot {
    param([string]$Path)
    $fullPath = Get-CTFullPath $Path
    if ($null -eq $fullPath) { return $false }
    foreach ($root in $removalRoots) {
        $fullRoot = Get-CTFullPath $root
        if ($fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Resolve-CTSid {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    if ($Identity -match '^S-1-[0-9-]+$') { return $Identity }
    $text = $Identity.Trim()
    if ($text -in @('SYSTEM','LocalSystem','NT AUTHORITY\SYSTEM')) { $text = 'NT AUTHORITY\SYSTEM' }
    elseif ($text -in @('LOCAL SERVICE','LocalService','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\LocalService')) { $text = 'NT AUTHORITY\LOCAL SERVICE' }
    elseif ($text -in @('NETWORK SERVICE','NetworkService','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\NetworkService')) { $text = 'NT AUTHORITY\NETWORK SERVICE' }
    elseif ($text.StartsWith('.\')) { $text = "$env:COMPUTERNAME\$($text.Substring(2))" }
    elseif ($text.IndexOf('\') -lt 0) { $text = "$env:COMPUTERNAME\$text" }
    try { return (New-Object Security.Principal.NTAccount($text)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { return $null }
}

function Get-CTEnum {
    param([string]$Value, [string[]]$Allowed)
    foreach ($item in $Allowed) { if ($Value -eq $item) { return $item } }
    return 'Unknown'
}

function Get-CTLogonType {
    param($Value)
    switch ([int]$Value) {
        2 { 'Interactive' }; 3 { 'Network' }; 4 { 'Batch' }; 5 { 'Service' }; 7 { 'Unlock' }
        8 { 'NetworkCleartext' }; 9 { 'NewCredentials' }; 10 { 'RemoteInteractive' }; 11 { 'CachedInteractive' }
        default { 'Unknown' }
    }
}

function Get-CTPrincipalAssessment {
    param($Principal, [string]$TargetSid)
    $userText = [string](Get-CTValue $Principal 'UserId')
    $groupText = [string](Get-CTValue $Principal 'GroupId')
    $userSid = Resolve-CTSid $userText
    $groupSid = Resolve-CTSid $groupText
    $failures = 0
    if (-not [string]::IsNullOrWhiteSpace($userText) -and $null -eq $userSid) { $failures++ }
    if (-not [string]::IsNullOrWhiteSpace($groupText) -and $null -eq $groupSid) { $failures++ }
    if ([string]::IsNullOrWhiteSpace($userText) -and [string]::IsNullOrWhiteSpace($groupText)) { $failures++ }
    $match = if ($userSid -eq $TargetSid -or $groupSid -eq $TargetSid) { $true }
        elseif ($null -ne $userSid -or $null -ne $groupSid) { $false } else { $null }
    return [pscustomobject]@{ Match=$match; Failures=$failures }
}

function Write-CTJson {
    param($Value, [int]$ExitCode)
    $Value | ConvertTo-Json -Depth 8
    exit $ExitCode
}

$result = [ordered]@{
    SchemaVersion='1.0'; CollectorVersion='1.0'; DiagnosticOnly=$true; ReadOnlyEvidenceNotAuthorization=$true
    Succeeded=$false; ErrorCode='None'; ProcessInventoryComplete=$false; OwnerQueryFailedCount=0
    Identity=[ordered]@{AccountPresent=$false;AccountEnabled=$null;ExactProfileCount=0;AccountProfileSidMatches=$null;CurrentIdentityMatches=$null;UnexpectedProfileCount=0;HkuMounted=$null;HkuClassesMounted=$null;Profile=$null}
    Processes=[ordered]@{QuerySucceeded=$false;DisappearedCount=0;TargetProcessCount=0;Items=@()}
    Logons=[ordered]@{InventoryComplete=$false;QueryFailedCount=0;Interpretation='HistoricalAssociationsNotActiveDesktopProof';AssociatedLogonTypes=@()}
    Services=[ordered]@{InventoryComplete=$false;PrincipalResolutionFailedCount=0;UnknownReferenceCount=0;Items=@()}
    Tasks=[ordered]@{InventoryComplete=$false;PrincipalResolutionFailedCount=0;InfoQueryFailedCount=0;UnknownReferenceCount=0;Items=@()}
}

try {
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess) {
        $result.ErrorCode='RequiresWindowsPowerShell51x64'; Write-CTJson $result 1
    }
    try { $accounts=@(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -eq 'cloudbase-init' }) }
    catch { $result.ErrorCode='LocalAccountInventoryFailed'; Write-CTJson $result 1 }
    try { $profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop) }
    catch { $result.ErrorCode='UserProfileInventoryFailed'; Write-CTJson $result 1 }

    $exactProfiles=@($profiles | Where-Object { [string]$_.LocalPath -ieq 'C:\Users\cloudbase-init' })
    $result.Identity.AccountPresent=$accounts.Count -eq 1
    $result.Identity.ExactProfileCount=$exactProfiles.Count
    if ($accounts.Count -ne 1) { $result.ErrorCode='CloudbaseLocalAccountNotUnique'; Write-CTJson $result 1 }
    if ($accounts.Count -eq 1) { $result.Identity.AccountEnabled=[bool]$accounts[0].Enabled }
    if ($exactProfiles.Count -eq 1) {
        $refCount=Get-CTValue $exactProfiles[0] 'refCount'
        $result.Identity.Profile=[ordered]@{Loaded=[bool]$exactProfiles[0].Loaded;Special=[bool]$exactProfiles[0].Special;RefCount=if($null -eq $refCount){$null}else{[uint32]$refCount};HkuMounted=$null;HkuClassesMounted=$null}
    }
    $candidateSids=@()
    if ($accounts.Count -eq 1) { $candidateSids += [string]$accounts[0].SID }
    if ($exactProfiles.Count -eq 1) { $candidateSids += [string]$exactProfiles[0].SID }
    $candidateSids=@($candidateSids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($accounts.Count -gt 1 -or $exactProfiles.Count -gt 1 -or $candidateSids.Count -ne 1 -or
        $candidateSids[0] -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') {
        $result.ErrorCode='CloudbaseIdentityNotUnique'; Write-CTJson $result 1
    }
    $targetSid=[string]$candidateSids[0]
    $result.Identity.AccountProfileSidMatches=if($accounts.Count -eq 1 -and $exactProfiles.Count -eq 1){[string]$accounts[0].SID -eq [string]$exactProfiles[0].SID}else{$null}
    $currentSid=[string]([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $result.Identity.CurrentIdentityMatches=$currentSid -eq $targetSid
    $result.Identity.UnexpectedProfileCount=@($profiles | Where-Object { [string]$_.SID -eq $targetSid -and [string]$_.LocalPath -ine 'C:\Users\cloudbase-init' }).Count
    $result.Identity.HkuMounted=Test-Path -LiteralPath "Registry::HKEY_USERS\$targetSid"
    $result.Identity.HkuClassesMounted=Test-Path -LiteralPath "Registry::HKEY_USERS\${targetSid}_Classes"
    if ($exactProfiles.Count -eq 1) {
        $result.Identity.Profile.HkuMounted=$result.Identity.HkuMounted
        $result.Identity.Profile.HkuClassesMounted=$result.Identity.HkuClassesMounted
    }

    try { $processSnapshot=@(Get-CimInstance Win32_Process -ErrorAction Stop | Sort-Object ProcessId); $result.Processes.QuerySucceeded=$true }
    catch { $processSnapshot=@(); $result.ErrorCode='ProcessInventoryQueryFailed' }
    $processItems=New-Object Collections.Generic.List[object]; $unknownIndex=0
    foreach ($process in $processSnapshot) {
        $processId=[uint32]$process.ProcessId
        if ($processId -in @(0,4)) { continue }
        $owner=$null
        try { $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop } catch { }
        if ($null -eq $owner -or [uint32]$owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$owner.Sid)) {
            $liveQueryFailed=$false
            try { $live=@(Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction Stop) }
            catch { $live=@(); $liveQueryFailed=$true }
            if ($liveQueryFailed) { $result.OwnerQueryFailedCount++; continue }
            if ($live.Count -eq 0) { $result.Processes.DisappearedCount++; continue }
            if ($live.Count -ne 1) { $result.OwnerQueryFailedCount++; continue }
            try { $owner=Invoke-CimMethod -InputObject $live[0] -MethodName GetOwnerSid -ErrorAction Stop } catch { $owner=$null }
            if ($null -eq $owner -or [uint32]$owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$owner.Sid)) { $result.OwnerQueryFailedCount++; continue }
            $process=$live[0]
        }
        if ([string]$owner.Sid -ne $targetSid) { continue }
        $baseName=[IO.Path]::GetFileNameWithoutExtension([string]$process.Name)
        $knownName=if($knownProcessMap.ContainsKey($baseName)){[string]$knownProcessMap[$baseName]}else{$null}
        if($null -eq $knownName){$unknownIndex++;$safeName='Unknown:{0:D3}' -f $unknownIndex}else{$safeName=$knownName}
        $path=Get-CTFullPath ([string]$process.ExecutablePath)
        $imageClass=if($null -eq $path){'Unavailable'}
            elseif($baseName -eq 'TaskAgentDetect' -and $path.Equals($taskAgentImage,[StringComparison]::OrdinalIgnoreCase)){'ExactTaskAgentDetect'}
            elseif(Test-CTUnderRemovalRoot $path){if($null -eq $knownName){'UnknownPathUnderRemovalRoot'}else{'PathUnderRemovalRoot'}}else{'OutsideRemovalRoots'}
        $processItems.Add([pscustomobject]@{ProcessId=$processId;SessionId=if($null -eq $process.SessionId){$null}else{[uint32]$process.SessionId};Name=$safeName;ImageClass=$imageClass})
    }
    $result.Processes.Items=$processItems.ToArray(); $result.Processes.TargetProcessCount=$processItems.Count
    $result.ProcessInventoryComplete=[bool]($result.Processes.QuerySucceeded -and $result.OwnerQueryFailedCount -eq 0)

    try {
        $cimUsers=@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | Where-Object { [string]$_.SID -eq $targetSid })
        if ($cimUsers.Count -ne 1) { throw 'Nonunique account key.' }
        $associated=@(Get-CimAssociatedInstance -InputObject $cimUsers[0] -Association Win32_LoggedOnUser -ResultClassName Win32_LogonSession -ErrorAction Stop)
        $types=@($associated | ForEach-Object { Get-CTLogonType $_.LogonType })
        $result.Logons.AssociatedLogonTypes=@($types | Group-Object | ForEach-Object { [pscustomobject]@{Type=[string]$_.Name;Count=[int]$_.Count} })
        $result.Logons.InventoryComplete=$true
    }
    catch { $result.Logons.QueryFailedCount++; $result.Logons.InventoryComplete=$false }

    try {
        $serviceSnapshot=@(Get-CimInstance Win32_Service -ErrorAction Stop); $serviceItems=New-Object Collections.Generic.List[object]
        foreach($service in $serviceSnapshot){$startName=[string]$service.StartName;$resolvedSid=Resolve-CTSid $startName;if(-not [string]::IsNullOrWhiteSpace($startName)-and $null -eq $resolvedSid){$result.Services.PrincipalResolutionFailedCount++};if($resolvedSid -eq $targetSid -and $knownServiceNames -notcontains [string]$service.Name){$result.Services.UnknownReferenceCount++}}
        foreach($name in $knownServiceNames){$matches=@($serviceSnapshot|Where-Object{$_.Name -eq $name});$service=$matches|Select-Object -First 1;$resolvedSid=if($null -eq $service){$null}else{Resolve-CTSid ([string]$service.StartName)};$serviceItems.Add([pscustomobject]@{Id="Service:$name";Present=$matches.Count -eq 1;Ambiguous=$matches.Count -gt 1;State=if($null -eq $service){'Unavailable'}else{Get-CTEnum ([string]$service.State) @('Running','Stopped','Paused','Start Pending','Stop Pending')};StartMode=if($null -eq $service){'Unavailable'}else{Get-CTEnum ([string]$service.StartMode) @('Auto','Manual','Disabled')};AccountSidMatches=if($null -eq $service -or $null -eq $resolvedSid){$null}else{$resolvedSid -eq $targetSid}})}
        $result.Services.Items=$serviceItems.ToArray();$result.Services.InventoryComplete=$result.Services.PrincipalResolutionFailedCount -eq 0
    }
    catch { $result.Services.InventoryComplete=$false }

    try {
        $taskSnapshot=@(Get-ScheduledTask -ErrorAction Stop);$taskRecords=New-Object Collections.Generic.List[object]
        foreach($task in $taskSnapshot){$assessment=Get-CTPrincipalAssessment (Get-CTValue $task 'Principal') $targetSid;$result.Tasks.PrincipalResolutionFailedCount += [int]$assessment.Failures;$taskRecords.Add([pscustomobject]@{Task=$task;PrincipalMatch=$assessment.Match});if($assessment.Match -eq $true -and -not([string]$task.TaskPath -eq '\' -and $knownTaskNames -contains [string]$task.TaskName)){$result.Tasks.UnknownReferenceCount++}}
        $taskItems=New-Object Collections.Generic.List[object]
        foreach($name in $knownTaskNames){$matches=@($taskRecords|Where-Object{[string]$_.Task.TaskPath -eq '\' -and [string]$_.Task.TaskName -eq $name});$record=$matches|Select-Object -First 1;$task=if($null -eq $record){$null}else{$record.Task};$principal=Get-CTValue $task 'Principal';$lastResult=$null;if($null -ne $task){try{$lastResult=[int64](Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop).LastTaskResult}catch{$result.Tasks.InfoQueryFailedCount++}};$taskItems.Add([pscustomobject]@{Id="Task:$name";Present=$matches.Count -eq 1;Ambiguous=$matches.Count -gt 1;State=if($null -eq $task){'Unavailable'}else{Get-CTEnum ([string]$task.State) @('Ready','Running','Disabled','Queued')};PrincipalSidMatches=if($null -eq $record){$null}else{$record.PrincipalMatch};LogonType=if($null -eq $principal){'Unavailable'}else{Get-CTEnum ([string](Get-CTValue $principal 'LogonType')) @('None','Password','S4U','Interactive','Group','ServiceAccount','InteractiveOrPassword')};LastTaskResult=$lastResult})}
        $result.Tasks.Items=$taskItems.ToArray();$result.Tasks.InventoryComplete=$result.Tasks.PrincipalResolutionFailedCount -eq 0 -and $result.Tasks.InfoQueryFailedCount -eq 0
    }
    catch { $result.Tasks.InventoryComplete=$false }

    $complete=$result.ProcessInventoryComplete -and $result.Logons.InventoryComplete -and $result.Services.InventoryComplete -and $result.Tasks.InventoryComplete
    $result.Succeeded=[bool]$complete
    if(-not $complete -and $result.ErrorCode -eq 'None'){$result.ErrorCode=if(-not $result.ProcessInventoryComplete){'ProcessInventoryIncomplete'}elseif(-not $result.Logons.InventoryComplete){'LogonInventoryIncomplete'}elseif(-not $result.Services.InventoryComplete){'ServiceInventoryIncomplete'}else{'TaskInventoryIncomplete'}}
    Write-CTJson $result $(if($result.Succeeded){0}else{1})
}
catch {
    $result.Succeeded=$false
    $result.ErrorCode='CollectorUnhandledFailure'
    Write-CTJson $result 1
}
