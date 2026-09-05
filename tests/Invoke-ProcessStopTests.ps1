#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Process-stop tests must run under Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) { throw 'Process-stop tests require a 64-bit process.' }

$root=Split-Path -Parent $PSScriptRoot
$modulePath=Join-Path $root 'src\CTyunTrim.psd1'
$manifestPath=Join-Path $root 'config\CTyunTrim.psd1'
$sourcePath=Join-Path $root 'src\CTyunTrim.psm1'
$manifest=Import-PowerShellDataFile -LiteralPath $manifestPath
$failures=New-Object Collections.Generic.List[string]

function Assert-CTProcessStop {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){$script:failures.Add($Message)}
}

Import-Module -Name $modulePath -Force
$module=Get-Module CTyunTrim
$fixture=& $module {
    param($FixtureManifest)

    $localFailures=New-Object Collections.Generic.List[string]
    function Assert-Fixture { param([bool]$Condition,[string]$Message) if(-not $Condition){$localFailures.Add($Message)} }
    function Reset-Fixture {
        $script:LiveProcesses=@{}
        $script:ProcessQueryThrows=@{}
        $script:CimQueryThrows=@{}
        $script:AutoExitOnStop=@{}
        $script:StopThrows=@{}
        $script:Sequence=New-Object Collections.Generic.List[string]
        $script:Events=New-Object Collections.Generic.List[object]
        $script:StopCalls=0
        $script:SleepCalls=0
        $script:ExitAllOnFirstSleep=$false
        $script:UseRealSleep=$false
        $script:MutateAfterFirstJournal=$false
        $script:MutationReplacement=$null
    }
    function New-Context {
        param([bool]$RebootNeeded=$false)
        [PSCustomObject]@{
            RunId='process-fixture';Root='C:\ProgramData\CTyunTrim\Runs\process-fixture'
            RebootNeeded=$RebootNeeded;Operations=(New-Object Collections.ArrayList);Warnings=(New-Object Collections.ArrayList)
        }
    }
    function New-ProcessFixture {
        param([int]$Id,[string]$Name='AppMarketSvc',[string]$Path,[int]$OffsetSeconds=0,[switch]$UnreadablePath)
        if([string]::IsNullOrWhiteSpace($Path)){$Path='C:\Program Files (x86)\ctyun\AppMarketSvc\'+$Name+'.exe'}
        $value=[PSCustomObject]@{
            Id=$Id;ProcessName=$Name
            StartTime=([DateTime]::SpecifyKind([datetime]'2026-09-05T00:00:00',[DateTimeKind]::Utc).AddSeconds($OffsetSeconds))
        }
        if($UnreadablePath){$value|Add-Member -MemberType ScriptProperty -Name Path -Value {throw 'fixture path denied'}}
        else{$value|Add-Member -NotePropertyName Path -NotePropertyValue $Path}
        return $value
    }
    function Add-LiveProcess { param($Process) $script:LiveProcesses[[string]$Process.Id]=$Process }
    function Add-PendingOperation {
        param([PSObject]$Context,$Process,[string]$Path,[string]$Name,[string]$StartTicks)
        if([string]::IsNullOrWhiteSpace($Path)){try{$Path=[string]$Process.Path}catch{$Path='C:\Program Files (x86)\ctyun\AppMarketSvc\unknown.exe'}}
        if([string]::IsNullOrWhiteSpace($Name)){$Name=[string]$Process.ProcessName}
        if([string]::IsNullOrWhiteSpace($StartTicks)){try{$StartTicks=[string]$Process.StartTime.ToUniversalTime().Ticks}catch{$StartTicks='639000000000000000'}}
        $operation=[PSCustomObject]@{
            Id=[guid]::NewGuid().ToString('N');Timestamp='now';CompletedAt=$null;Status='Pending';Type='ProcessStop';Target="$Name`:$($Process.Id)"
            Data=@{Path=$Path;StartTimeUtcTicks=$StartTicks};Reversible=$false
        }
        [void]$Context.Operations.Add($operation)
        return $operation
    }
    function Get-Process {
        [CmdletBinding()]
        param([int[]]$Id)
        if($PSBoundParameters.ContainsKey('Id')){
            if($Id.Count -ne 1){throw 'fixture accepts one process id'}
            $key=[string]$Id[0]
            if($script:ProcessQueryThrows.ContainsKey($key)){throw 'fixture process query denied'}
            if($script:LiveProcesses.ContainsKey($key)){return $script:LiveProcesses[$key]}
            throw 'Cannot find a process with the process identifier.'
        }
        return @($script:LiveProcesses.Values)
    }
    function Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName,[string]$Filter)
        if($ClassName -ne 'Win32_Process'){return @()}
        $id=0
        if($Filter -match 'ProcessId\s*=\s*([0-9]+)'){$id=[int]$Matches[1]}
        $key=[string]$id
        if($script:CimQueryThrows.ContainsKey($key)){throw 'fixture CIM liveness query denied'}
        if($script:LiveProcesses.ContainsKey($key)){return [PSCustomObject]@{ProcessId=$id}}
        return @()
    }
    function Stop-Process {
        [CmdletBinding()]
        param([Parameter(Mandatory=$true)]$InputObject,[switch]$Force)
        $script:StopCalls++
        $key=[string]$InputObject.Id
        $script:Sequence.Add("Stop:$key")
        if($script:StopThrows.ContainsKey($key)){throw 'fixture stop denied'}
        if($script:AutoExitOnStop.ContainsKey($key)){[void]$script:LiveProcesses.Remove($key)}
    }
    function Start-Sleep {
        [CmdletBinding()]
        param([int]$Milliseconds)
        $script:SleepCalls++
        if($script:ExitAllOnFirstSleep -and $script:SleepCalls -eq 1){$script:LiveProcesses=@{}}
        if($script:UseRealSleep){[Threading.Thread]::Sleep($Milliseconds)}
    }
    function Save-CTRunContext { param([PSObject]$Context) }
    function Add-CTDiagnosticEvent {
        param([string]$Level,[string]$Stage,[string]$Message,[hashtable]$Data)
        $event=[PSCustomObject]@{Level=$Level;Stage=$Stage;Message=$Message;Data=$Data}
        $script:Events.Add($event)
        if($Stage -eq 'Confirmation' -and $Message -eq 'Required operation was confirmed.'){$script:Sequence.Add("Confirm:$([string]$Data.Target)")}
        if($Stage -eq 'Operation' -and $Message -eq 'Started write-ahead operation.'){
            $script:Sequence.Add("Journal:$([string]$Data.Target)")
            if($script:MutateAfterFirstJournal -and $null -ne $script:MutationReplacement){
                $script:LiveProcesses[[string]$script:MutationReplacement.Id]=$script:MutationReplacement
                $script:MutateAfterFirstJournal=$false
            }
        }
    }
    function Add-CTWarning { param([PSObject]$Context,[string]$Message) [void]$Context.Warnings.Add($Message) }
    function Test-CTPathHasReparsePoint { param([string]$Path) return $false }
    function Invoke-StopFixture {
        [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
        param([PSObject]$Context,[hashtable]$Manifest,[int]$WaitSeconds=0)
        Stop-CTOptionalProcesses -Context $Context -Manifest $Manifest -Caller $PSCmdlet -WaitSeconds $WaitSeconds
    }
    function Invoke-FinalizeFixture {
        [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
        param([PSObject]$Context,[hashtable]$Manifest,[int]$WaitSeconds=0)
        Finalize-CTOptionalProcessStops -Context $Context -Manifest $Manifest -Caller $PSCmdlet -WaitSeconds $WaitSeconds
    }

    # Fifteen processes are confirmed, journaled and stopped as three batches,
    # with no per-process wait.
    Reset-Fixture
    $batchContext=New-Context
    $batchNames=@($FixtureManifest.Processes|Select-Object -First 15)
    for($index=0;$index -lt $batchNames.Count;$index++){
        $process=New-ProcessFixture -Id (1000+$index) -Name ([string]$batchNames[$index]) -OffsetSeconds $index
        Add-LiveProcess $process
        $script:AutoExitOnStop[[string]$process.Id]=$true
    }
    Invoke-StopFixture -Context $batchContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    $batchOperations=@($batchContext.Operations|Where-Object{$_.Type -eq 'ProcessStop'})
    $confirmPrefix=@($script:Sequence|Select-Object -First 15|Where-Object{$_ -like 'Confirm:*'}).Count
    $journalMiddle=@($script:Sequence|Select-Object -Skip 15 -First 15|Where-Object{$_ -like 'Journal:*'}).Count
    $stopSuffix=@($script:Sequence|Select-Object -Skip 30 -First 15|Where-Object{$_ -like 'Stop:*'}).Count
    Assert-Fixture ($script:StopCalls -eq 15 -and $batchOperations.Count -eq 15 -and @($batchOperations|Where-Object{$_.Status -eq 'Completed'}).Count -eq 15) 'Batch stop did not complete all 15 exact identities.'
    Assert-Fixture ($confirmPrefix -eq 15 -and $journalMiddle -eq 15 -and $stopSuffix -eq 15) 'Stops began before every confirmation and WAL record were complete.'
    Assert-Fixture ($batchContext.Warnings.Count -eq 0 -and -not $batchContext.RebootNeeded -and $script:SleepCalls -eq 0) 'Completed batch accumulated a warning, reboot reason, or serial wait.'

    # One process exceeds the shared window. This is historical only; if it
    # exits before the final pass its old Pending entry is completed silently.
    Reset-Fixture
    $lateContext=New-Context
    $late=New-ProcessFixture -Id 1100
    Add-LiveProcess $late
    $script:UseRealSleep=$true
    Invoke-StopFixture -Context $lateContext -Manifest $FixtureManifest -WaitSeconds 1 -Confirm:$false
    $script:UseRealSleep=$false
    $latePending=@($lateContext.Operations|Where-Object{$_.Type -eq 'ProcessStop' -and $_.Status -eq 'Pending'})
    $historicalEvents=@($script:Events|Where-Object{$_.Stage -eq 'ProcessStop' -and $_.Message -match 'Shared process-stop wait window ended'})
    Assert-Fixture ($latePending.Count -eq 1 -and $historicalEvents.Count -eq 1 -and [string]$historicalEvents[0].Data.Status -eq 'Pending' -and -not [bool]$historicalEvents[0].Data.RebootNeeded -and $lateContext.Warnings.Count -eq 0 -and -not $lateContext.RebootNeeded) 'Initial shared timeout became a persistent warning or reboot reason.'
    [void]$script:LiveProcesses.Remove('1100')
    $lateFinal=Resolve-CTPendingProcessStops -Context $lateContext -WaitSeconds 0 -Final
    Assert-Fixture ($lateFinal.PendingCount -eq 0 -and $lateContext.Warnings.Count -eq 0 -and -not $lateContext.RebootNeeded) 'A process that exited after the historical timeout remained actionable.'

    # A true final survivor produces exactly one current warning and a reboot
    # request, without duplicating that warning on a repeated final check.
    Reset-Fixture
    $runningContext=New-Context
    $running=New-ProcessFixture -Id 1200
    Add-LiveProcess $running
    [void](Add-PendingOperation -Context $runningContext -Process $running)
    $runningFirst=Resolve-CTPendingProcessStops -Context $runningContext -WaitSeconds 0 -Final
    $runningSecond=Resolve-CTPendingProcessStops -Context $runningContext -WaitSeconds 0 -Final
    $finalEvents=@($script:Events|Where-Object{$_.Stage -eq 'ProcessStop' -and [string]$_.Data.Status -eq 'Failed'})
    Assert-Fixture ($runningFirst.PendingCount -eq 1 -and $runningFirst.RunningCount -eq 1 -and $runningSecond.PendingCount -eq 1 -and $finalEvents.Count -eq 2 -and @($finalEvents|Where-Object{[bool]$_.Data.RebootNeeded}).Count -eq 2 -and $runningContext.Warnings.Count -eq 1 -and $runningContext.RebootNeeded) 'A final exact survivor was not reported once as current.'

    # The real two-pass sequence reuses one WAL entry for a stubborn exact
    # survivor; Finalize must not see duplicate tracked identities.
    Reset-Fixture
    $twoPassContext=New-Context
    $twoPassProcess=New-ProcessFixture -Id 1250
    Add-LiveProcess $twoPassProcess
    Invoke-StopFixture -Context $twoPassContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    Invoke-StopFixture -Context $twoPassContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    $twoPassResult=Invoke-FinalizeFixture -Context $twoPassContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    $twoPassOperations=@($twoPassContext.Operations|Where-Object{$_.Type -eq 'ProcessStop'})
    Assert-Fixture ($twoPassOperations.Count -eq 1 -and $twoPassOperations[0].Status -eq 'Pending' -and $twoPassResult.PendingCount -eq 1 -and $twoPassContext.Warnings.Count -eq 1) 'Two ordinary passes duplicated or lost the stubborn survivor WAL identity.'

    # PID reuse is resolved by path/start identity and the replacement is never
    # stopped. Existing non-process reboot reasons are never cleared.
    Reset-Fixture
    $reuseContext=New-Context -RebootNeeded $true
    [void]$reuseContext.Warnings.Add('driver-reboot-reason')
    $old=New-ProcessFixture -Id 1300 -OffsetSeconds 0
    [void](Add-PendingOperation -Context $reuseContext -Process $old)
    $replacement=New-ProcessFixture -Id 1300 -Name 'AppMarketSvc' -OffsetSeconds 50
    Add-LiveProcess $replacement
    $reuse=Resolve-CTPendingProcessStops -Context $reuseContext -WaitSeconds 0 -Final
    Assert-Fixture ($reuse.PendingCount -eq 0 -and $script:StopCalls -eq 0 -and $reuseContext.RebootNeeded -and @($reuseContext.Warnings|Where-Object{$_ -eq 'driver-reboot-reason'}).Count -eq 1) 'PID reuse was treated as the old process or another reboot reason was cleared.'

    # An inaccessible live identity fails closed. Failure of both process and
    # CIM liveness queries is also indeterminate, never ProcessAbsent.
    Reset-Fixture
    $unknownContext=New-Context
    $unknown=New-ProcessFixture -Id 1400
    Add-LiveProcess $unknown
    [void](Add-PendingOperation -Context $unknownContext -Process $unknown)
    $script:ProcessQueryThrows['1400']=$true;$script:CimQueryThrows['1400']=$true
    $unknownResult=Resolve-CTPendingProcessStops -Context $unknownContext -WaitSeconds 0 -Final
    Assert-Fixture ($unknownResult.PendingCount -eq 1 -and $unknownResult.IndeterminateCount -eq 1 -and $unknownContext.RebootNeeded -and $unknownContext.Warnings.Count -eq 1) 'Failed liveness queries were mistaken for process exit.'

    # A respawned process gets a distinct PID-bound operation on the next pass.
    Reset-Fixture
    $respawnContext=New-Context
    $first=New-ProcessFixture -Id 1500
    Add-LiveProcess $first;$script:AutoExitOnStop['1500']=$true
    Invoke-StopFixture -Context $respawnContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    $second=New-ProcessFixture -Id 1501 -OffsetSeconds 1
    Add-LiveProcess $second;$script:AutoExitOnStop['1501']=$true
    Invoke-StopFixture -Context $respawnContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    $respawnOperations=@($respawnContext.Operations|Where-Object{$_.Type -eq 'ProcessStop'})
    Assert-Fixture ($respawnOperations.Count -eq 2 -and @($respawnOperations|Where-Object{$_.Status -eq 'Completed'}).Count -eq 2 -and @($respawnOperations.Target|Select-Object -Unique).Count -eq 2) 'Respawned PID was conflated with the first process identity.'

    # A new PID appearing after the normal second snapshot is captured by the
    # bounded final mutation-boundary scan.
    Reset-Fixture
    $lateRespawnContext=New-Context
    $lateRespawn=New-ProcessFixture -Id 1550
    Add-LiveProcess $lateRespawn;$script:AutoExitOnStop['1550']=$true
    $lateRespawnResult=Invoke-FinalizeFixture -Context $lateRespawnContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    $lateRespawnOperations=@($lateRespawnContext.Operations|Where-Object{$_.Type -eq 'ProcessStop'})
    Assert-Fixture ($lateRespawnResult.PendingCount -eq 0 -and $script:StopCalls -eq 1 -and $lateRespawnOperations.Count -eq 1 -and $lateRespawnOperations[0].Status -eq 'Completed') 'Final mutation-boundary scan missed a newly respawned PID.'

    # A second pass with an empty process snapshot still reconciles an earlier
    # Pending identity that has since disappeared.
    Reset-Fixture
    $emptySecondContext=New-Context
    $gone=New-ProcessFixture -Id 1600
    [void](Add-PendingOperation -Context $emptySecondContext -Process $gone)
    Invoke-StopFixture -Context $emptySecondContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    Assert-Fixture (@($emptySecondContext.Operations|Where-Object{$_.Type -eq 'ProcessStop' -and $_.Status -eq 'Completed'}).Count -eq 1) 'An empty second snapshot did not reconcile the first-pass Pending operation.'

    # Identity replacement after WAL but before Stop is completed as the old
    # identity and the replacement is not killed.
    Reset-Fixture
    $raceContext=New-Context
    $raceOld=New-ProcessFixture -Id 1700
    Add-LiveProcess $raceOld
    $script:MutationReplacement=New-ProcessFixture -Id 1700 -OffsetSeconds 99
    $script:MutateAfterFirstJournal=$true
    Invoke-StopFixture -Context $raceContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    Assert-Fixture ($script:StopCalls -eq 0 -and @($raceContext.Operations|Where-Object{$_.Type -eq 'ProcessStop' -and $_.Status -eq 'Completed'}).Count -eq 1) 'A PID-reused replacement was stopped after WAL identity changed.'

    # Unsafe paths stay out of ProcessStop journaling and mutation.
    Reset-Fixture
    $unsafeContext=New-Context
    $unsafe=New-ProcessFixture -Id 1800 -Path 'C:\Windows\System32\not-a-vendor.exe'
    Add-LiveProcess $unsafe
    Invoke-StopFixture -Context $unsafeContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    $unsafeHistorical=@($script:Events|Where-Object{$_.Stage -eq 'ProcessStop' -and [string]$_.Data.Status -eq 'Pending'})
    Assert-Fixture ($script:StopCalls -eq 0 -and @($unsafeContext.Operations|Where-Object{$_.Type -eq 'ProcessStop'}).Count -eq 0 -and $unsafeContext.Warnings.Count -eq 0 -and -not $unsafeContext.RebootNeeded -and $unsafeHistorical.Count -eq 1) 'Initial unsafe process path reached mutation or became a persistent warning.'

    Reset-Fixture
    $unsafeFinalContext=New-Context
    $unsafeFinal=New-ProcessFixture -Id 1850 -Path 'C:\Windows\System32\unknown-vendor-path.exe'
    Add-LiveProcess $unsafeFinal
    [void](Invoke-FinalizeFixture -Context $unsafeFinalContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false)
    Assert-Fixture ($script:StopCalls -eq 0 -and $unsafeFinalContext.Warnings.Count -eq 1 -and $unsafeFinalContext.RebootNeeded) 'Final scan treated an unsafe/unverifiable target path as cleared.'

    # Public ShouldProcess refusal happens before WAL and all stop requests.
    Reset-Fixture
    $declineContext=New-Context
    $declineProcess=New-ProcessFixture -Id 1900
    Add-LiveProcess $declineProcess
    $declined=$false
    try{Invoke-StopFixture -Context $declineContext -Manifest $FixtureManifest -WaitSeconds 0 -WhatIf|Out-Null}catch{$declined=$_.Exception -is [OperationCanceledException]}
    Assert-Fixture ($declined -and $script:StopCalls -eq 0 -and @($declineContext.Operations).Count -eq 0) 'ShouldProcess refusal allowed a journal or stop mutation.'

    # Stop failure is historical until the caller invokes the final pass.
    Reset-Fixture
    $stopFailureContext=New-Context
    $stopFailure=New-ProcessFixture -Id 2000
    Add-LiveProcess $stopFailure;$script:StopThrows['2000']=$true
    Invoke-StopFixture -Context $stopFailureContext -Manifest $FixtureManifest -WaitSeconds 0 -Confirm:$false
    Assert-Fixture ($stopFailureContext.Warnings.Count -eq 0 -and -not $stopFailureContext.RebootNeeded) 'Stop request failure became persistent before final reconciliation.'
    [void](Resolve-CTPendingProcessStops -Context $stopFailureContext -WaitSeconds 0 -Final)
    Assert-Fixture ($stopFailureContext.Warnings.Count -eq 1 -and $stopFailureContext.RebootNeeded) 'Final reconciliation did not surface a failed stop request.'

    # Generic resume reconciliation must use the same identity decision.
    Reset-Fixture
    $genericContext=New-Context
    $genericOld=New-ProcessFixture -Id 2100
    [void](Add-PendingOperation -Context $genericContext -Process $genericOld)
    $genericReplacement=New-ProcessFixture -Id 2100 -OffsetSeconds 10
    Add-LiveProcess $genericReplacement
    Resolve-CTPendingOperations -Context $genericContext -Manifest $FixtureManifest
    Assert-Fixture (@($genericContext.Operations|Where-Object{$_.Type -eq 'ProcessStop' -and $_.Status -eq 'Completed'}).Count -eq 1) 'Generic resume reconciliation did not reuse full ProcessStop identity matching.'

    [PSCustomObject]@{Failures=@($localFailures.ToArray())}
} $manifest
foreach($failure in @($fixture.Failures)){$failures.Add([string]$failure)}

# Integration routing: a service-removal mock creates a new process after the
# two ordinary snapshots. The real finalizer must journal and stop it before
# Cloudbase identity/path deletion is reached.
Import-Module -Name $modulePath -Force
$module=Get-Module CTyunTrim
$applyBoundary=& $module {
    param($FixtureManifest)
    $script:BoundaryContext=[PSCustomObject]@{
        RunId='boundary';Root='C:\ProgramData\CTyunTrim\Runs\boundary';ManifestPath='C:\fixture\manifest.psd1';ManifestHash='HASH'
        Status='Prepared';RebootNeeded=$false;CompletedAt=$null;LastBootUpTime='BOOT-A'
        Operations=(New-Object Collections.ArrayList);Warnings=(New-Object Collections.ArrayList)
    }
    [void]$script:BoundaryContext.Operations.Add([PSCustomObject]@{Id='baseline';Type='Baseline';Target='Baseline';Status='Completed';Data=@{};Reversible=$false;CompletedAt='now'})
    $script:BoundaryProcesses=@{}
    $script:BoundaryStopCalls=0
    $script:BoundaryOrder=New-Object Collections.Generic.List[string]
    function Get-CTOperatingSystem {[PSCustomObject]@{Build=$FixtureManifest.SupportedBuilds[0];LastBootUpTime='BOOT-A'}}
    function Test-Path {[CmdletBinding()]param([string]$LiteralPath,[string]$PathType)return $true}
    function Get-CTRunContext {param([string]$BackupRoot,[string]$RunId)return $script:BoundaryContext}
    function Get-CTNormalizedTextHash {param([string]$Path)return 'HASH'}
    function Save-CTRunContext {param([PSObject]$Context)}
    function Save-CTFailedRunContextSafe {param([PSObject]$Context,[string]$FailureMessage)}
    function Add-CTDiagnosticEvent {param([string]$Level,[string]$Stage,[string]$Message,[hashtable]$Data)}
    function Add-CTWarning {param([PSObject]$Context,[string]$Message)[void]$Context.Warnings.Add($Message)}
    function Resolve-CTPendingOperations {param([PSObject]$Context,[hashtable]$Manifest)}
    function Test-CTApplyPreflight {param([hashtable]$Manifest,[string]$BackupRoot,[string]$LgpoPath,[string]$RunId,[PSObject]$Context,[string]$Phase)[PSCustomObject]@{Passed=$true;Errors=@();Warnings=@();CloudbaseServiceQuiesceCandidate=$false}}
    function Test-CTCoreHealth {param([hashtable]$Manifest,[switch]$RequireRunning,[PSObject]$Context)[PSCustomObject]@{Healthy=$true;Failures=@()}}
    function Save-CTCloudbaseIdentityEvidence {param([PSObject]$Context,[hashtable]$Manifest)return $null}
    function Add-CTExecutionGuards {param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller)}
    function Remove-CTScheduledTasks {param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller)}
    function Clear-CTFakeWsusPolicy {param([PSObject]$Context,[hashtable]$Manifest,[string]$LgpoPath,[Management.Automation.PSCmdlet]$Caller)}
    function Remove-CTRunValues {param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller)}
    function Remove-CTStartupApprovedEntries {param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller)}
    function Remove-CTServices {
        param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller)
        $script:BoundaryOrder.Add('RemoveServices')
        $process=[PSCustomObject]@{Id=2200;ProcessName='AppMarketSvc';Path='C:\Program Files (x86)\ctyun\AppMarketSvc\AppMarketSvc.exe';StartTime=[DateTime]::SpecifyKind([datetime]'2026-09-05T00:00:00',[DateTimeKind]::Utc)}
        $script:BoundaryProcesses['2200']=$process
    }
    function Remove-CTCloudbaseIdentity {
        param([PSObject]$Context,[hashtable]$Manifest,[Management.Automation.PSCmdlet]$Caller)
        $script:BoundaryOrder.Add('RemoveIdentity')
        [PSCustomObject]@{Deferred=$true;References=@()}
    }
    function Get-Process {
        [CmdletBinding()]
        param([int[]]$Id)
        if($PSBoundParameters.ContainsKey('Id')){
            $key=[string]$Id[0]
            if($script:BoundaryProcesses.ContainsKey($key)){return $script:BoundaryProcesses[$key]}
            throw 'process absent'
        }
        return @($script:BoundaryProcesses.Values)
    }
    function Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName,[string]$Filter)
        if($ClassName -eq 'Win32_Process' -and $Filter -match 'ProcessId\s*=\s*([0-9]+)' -and $script:BoundaryProcesses.ContainsKey([string]$Matches[1])){return [PSCustomObject]@{ProcessId=[int]$Matches[1]}}
        return @()
    }
    function Stop-Process {
        [CmdletBinding()]
        param($InputObject,[switch]$Force)
        $script:BoundaryStopCalls++
        $script:BoundaryOrder.Add('StopRespawn')
        [void]$script:BoundaryProcesses.Remove([string]$InputObject.Id)
    }
    function Test-CTPathHasReparsePoint {param([string]$Path)return $false}
    function Invoke-BoundaryApply {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param([hashtable]$Manifest)
        Invoke-CTApply -Manifest $Manifest -ManifestPath 'C:\fixture\manifest.psd1' -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -RunId 'boundary' -Caller $PSCmdlet
    }
    $result=Invoke-BoundaryApply -Manifest $FixtureManifest -Confirm:$false
    $operations=@($script:BoundaryContext.Operations|Where-Object{$_.Type -eq 'ProcessStop'})
    [PSCustomObject]@{
        ResultStatus=[string]$result.Status;StopCalls=$script:BoundaryStopCalls;Order=@($script:BoundaryOrder.ToArray())
        OperationCount=$operations.Count;CompletedCount=@($operations|Where-Object{$_.Status -eq 'Completed'}).Count
    }
} $manifest
Assert-CTProcessStop ($applyBoundary.ResultStatus -eq 'PendingReboot' -and $applyBoundary.StopCalls -eq 1 -and $applyBoundary.OperationCount -eq 1 -and $applyBoundary.CompletedCount -eq 1) 'Actual Apply route missed the process created by service removal.'
Assert-CTProcessStop (($applyBoundary.Order -join ',') -eq 'RemoveServices,StopRespawn,RemoveIdentity') 'Final process mutation boundary is not ordered after service removal and before identity deletion.'

$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$parseErrors)
Assert-CTProcessStop (@($parseErrors).Count -eq 0) 'CTyunTrim module failed to parse.'
$stopFunctions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Stop-CTOptionalProcesses'},$true))
Assert-CTProcessStop ($stopFunctions.Count -eq 1) 'Could not uniquely inspect Stop-CTOptionalProcesses.'
if($stopFunctions.Count -eq 1){
    $stopText=[string]$stopFunctions[0].Extent.Text
    Assert-CTProcessStop ($stopText -notmatch '(?i)\bWait-Process\b') 'Stop-CTOptionalProcesses still waits serially per process.'
    Assert-CTProcessStop (@([regex]::Matches($stopText,'Resolve-CTPendingProcessStops[^\r\n]+-WaitSeconds \$WaitSeconds')).Count -eq 1) 'Stop-CTOptionalProcesses does not use one shared wait window.'
    Assert-CTProcessStop (@([regex]::Matches($stopText,'(?i)\bStop-Process\b')).Count -eq 1) 'Stop-CTOptionalProcesses has multiple stop mutation sites.'
}
$source=Get-Content -LiteralPath $sourcePath -Raw
Assert-CTProcessStop (@([regex]::Matches($source,'Resolve-CTPendingProcessStops[^\r\n]+-WaitSeconds 0 -Final')).Count -eq 1) 'Finalizer does not contain exactly one final ProcessStop reconciliation site.'
Assert-CTProcessStop (@([regex]::Matches($source,'Finalize-CTOptionalProcessStops -Context \$context')).Count -eq 2) 'Apply and Prepare do not both invoke the bounded final process scan.'
$applyStart=$source.IndexOf('function Invoke-CTApply',[StringComparison]::Ordinal)
$prepareStart=$source.IndexOf('function Invoke-CTPrepare',[StringComparison]::Ordinal)
$applyText=if($applyStart -ge 0 -and $prepareStart -gt $applyStart){$source.Substring($applyStart,$prepareStart-$applyStart)}else{''}
$removeServicesPosition=$applyText.IndexOf('Remove-CTServices -Context',[StringComparison]::Ordinal)
$finalScanPosition=$applyText.IndexOf('Finalize-CTOptionalProcessStops -Context',[StringComparison]::Ordinal)
$identityRemovalPosition=$applyText.IndexOf('Remove-CTCloudbaseIdentity -Context',[StringComparison]::Ordinal)
Assert-CTProcessStop ($removeServicesPosition -ge 0 -and $finalScanPosition -gt $removeServicesPosition -and $identityRemovalPosition -gt $finalScanPosition) 'Apply final process scan is not between service removal and identity/path deletion.'

if($failures.Count -gt 0){throw "Process-stop tests failed:`n - $($failures -join "`n - ")"}
Write-Host 'Process-stop batching and reconciliation tests passed.'
exit 0
