#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess) {
    throw 'Trim workflow tests require 64-bit Windows PowerShell 5.1.'
}

$root = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'src\CTyunTrim.psd1'
$manifestPath = Join-Path $root 'config\CTyunTrim.psd1'
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$failures = New-Object Collections.Generic.List[string]
function Assert-CTTrim { param([bool]$Condition,[string]$Message) if(-not $Condition){$script:failures.Add($Message)} }

Import-Module $modulePath -Force
$module = Get-Module CTyunTrim
$selector = & $module {
    param($FixtureManifest,$FixtureManifestPath)
    $script:TrimRootExists=$false; $script:TrimEntries=@(); $script:TrimContexts=@{}; $script:TrimDamaged=@(); $script:TrimGuardRunId=$null; $script:TrimBoot='BOOT-A'
    function Test-Path { [CmdletBinding()] param([string]$LiteralPath,[string]$PathType) return [bool]$script:TrimRootExists }
    function Test-CTPathHasReparsePoint { param([string]$Path) return $false }
    function Test-CTSecureSourcePath { param([string]$Path) return $true }
    function Get-ChildItem { [CmdletBinding()] param([string]$LiteralPath,[switch]$Force) return @($script:TrimEntries) }
    function Get-CTNormalizedTextHash { param([string]$Path) return $script:ApprovedManifestSha256 }
    function Get-CTRunContext {
        param([string]$BackupRoot,[string]$RunId)
        if($script:TrimDamaged -contains $RunId){throw 'damaged'}
        return $script:TrimContexts[$RunId]
    }
    function Get-CTIfEOState {
        param([string]$Image)
        if([string]::IsNullOrWhiteSpace($script:TrimGuardRunId)){return [pscustomobject]@{Present=$false;Debugger=$null;Marker=$null;RunId=$null}}
        return [pscustomobject]@{Present=$true;Debugger=$script:GuardDebugger;Marker=$script:GuardOwner;RunId=$script:TrimGuardRunId}
    }
    function Get-CTOperatingSystem { [pscustomobject]@{LastBootUpTime=$script:TrimBoot} }
    function New-TrimContext {
        param([string]$RunId,[string]$Status,[string]$Boot='BOOT-A',[bool]$Reboot=$false,[bool]$CompleteEvidence=$true)
        $ops=New-Object Collections.ArrayList
        if($CompleteEvidence){
            [void]$ops.Add([pscustomobject]@{Type='Baseline';Status='Completed'})
            [void]$ops.Add([pscustomobject]@{Type='CloudbaseIdentityEvidence';Status='Completed'})
        }
        [pscustomobject]@{RunId=$RunId;Status=$Status;LastBootUpTime=$Boot;RebootNeeded=$Reboot;ManifestHash=$script:ApprovedManifestSha256;ManifestPath=$FixtureManifestPath;Operations=$ops;Warnings=(New-Object Collections.ArrayList)}
    }
    function Set-OneRun { param($Context) $script:TrimRootExists=$true;$script:TrimEntries=@([pscustomobject]@{Name=$Context.RunId;PSIsContainer=$true});$script:TrimContexts=@{$Context.RunId=$Context} }
    $new = Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $preparedContext=New-TrimContext '20260905-010101-a1b2c3d4' 'Prepared';Set-OneRun $preparedContext
    $prepared=Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $pendingContext=New-TrimContext '20260905-010102-a1b2c3d5' 'PendingReboot' 'BOOT-A' $true;Set-OneRun $pendingContext
    $pendingSame=Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $script:TrimBoot='BOOT-B';$pendingNew=Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $appliedContext=New-TrimContext '20260905-010103-a1b2c3d6' 'Applied';Set-OneRun $appliedContext
    $applied=Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $runningContext=New-TrimContext '20260905-010104-a1b2c3d7' 'Running';Set-OneRun $runningContext
    $running=Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'
    $incompleteBlocked=$false;Set-OneRun (New-TrimContext '20260905-010105-a1b2c3d8' 'Running' 'BOOT-A' $false $false)
    try{Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'|Out-Null}catch{$incompleteBlocked=$true}
    $multipleBlocked=$false;$one=New-TrimContext '20260905-010106-a1b2c3d9' 'Prepared';$two=New-TrimContext '20260905-010107-a1b2c3da' 'Applied';$script:TrimEntries=@([pscustomobject]@{Name=$one.RunId;PSIsContainer=$true},[pscustomobject]@{Name=$two.RunId;PSIsContainer=$true});$script:TrimContexts=@{$one.RunId=$one;$two.RunId=$two}
    try{Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'|Out-Null}catch{$multipleBlocked=$true}
    $damagedBlocked=$false;$script:TrimEntries=@([pscustomobject]@{Name=$one.RunId;PSIsContainer=$true});$script:TrimDamaged=@($one.RunId)
    try{Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'|Out-Null}catch{$damagedBlocked=$true}
    $guardBlocked=$false;$script:TrimDamaged=@();Set-OneRun $one;$script:TrimGuardRunId='20260905-999999-deadbeef'
    try{Get-CTTrimRunSelection -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs'|Out-Null}catch{$guardBlocked=$true}
    [pscustomobject]@{New=$new.Action;Prepared=$prepared.Action;PendingSame=$pendingSame.Action;PendingNew=$pendingNew.Action;Applied=$applied.Action;Running=$running.Action;IncompleteBlocked=$incompleteBlocked;MultipleBlocked=$multipleBlocked;DamagedBlocked=$damagedBlocked;GuardBlocked=$guardBlocked}
} $manifest $manifestPath

Assert-CTTrim ($selector.New -eq 'PrepareApply') 'Zero-run selection did not choose PrepareApply.'
Assert-CTTrim ($selector.Prepared -eq 'ResumeApply' -and $selector.PendingNew -eq 'ResumeApply' -and $selector.Running -eq 'ResumeApply') 'Trusted resumable status was not selected for Apply.'
Assert-CTTrim ($selector.PendingSame -eq 'RebootRequired') 'Same-boot PendingReboot did not stop for reboot.'
Assert-CTTrim ($selector.Applied -eq 'Verify') 'Applied run did not select Verify.'
Assert-CTTrim ($selector.IncompleteBlocked -and $selector.MultipleBlocked -and $selector.DamagedBlocked -and $selector.GuardBlocked) 'An ambiguous, damaged, incomplete, or guard-conflicting run was selected.'

Import-Module $modulePath -Force
$module=Get-Module CTyunTrim
$workflow=& $module {
    param($FixtureManifest,$FixtureManifestPath)
    $script:WorkflowAction='PrepareApply';$script:PrepareCalls=0;$script:ApplyCalls=0;$script:ApplyRunId=$null;$script:VerifyPassed=$true
    $context=[pscustomobject]@{RunId='20260905-020202-b1c2d3e4';Status='Prepared';ManifestPath=$FixtureManifestPath;Warnings=(New-Object Collections.ArrayList)}
    function Get-CTTrimRunSelection { param([hashtable]$Manifest,[string]$ManifestPath,[string]$BackupRoot) [pscustomobject]@{Action=$script:WorkflowAction;Context=$context} }
    function Add-CTDiagnosticEvent { param([string]$Level,[string]$Stage,[string]$Message,[hashtable]$Data) }
    function Invoke-CTPrepare { param([hashtable]$Manifest,[string]$ManifestPath,[string]$BackupRoot,[string]$LgpoPath,$Caller) $script:PrepareCalls++;[pscustomobject]@{RunId=$context.RunId;Status='Prepared';RebootNeeded=$true} }
    function Invoke-CTApply { param([hashtable]$Manifest,[string]$ManifestPath,[string]$BackupRoot,[string]$LgpoPath,[string]$RunId,$Caller) $script:ApplyCalls++;$script:ApplyRunId=$RunId;[pscustomobject]@{RunId=$RunId;Status='PendingReboot';RebootNeeded=$true} }
    function Get-CTVerification { param([hashtable]$Manifest,[string]$ManifestPath,$Context) [pscustomobject]@{Passed=$script:VerifyPassed;Failures=$(if($script:VerifyPassed){@()}else{@('failure')});Warnings=@();ManualChecks=@();RuntimeData=@([pscustomobject]@{Id='RuntimeData:001'});Inventory=[pscustomobject]@{}} }
    function Invoke-WorkflowFixture { [CmdletBinding(SupportsShouldProcess=$true)]param() Invoke-CTTrimWorkflow -Manifest $FixtureManifest -ManifestPath $FixtureManifestPath -BackupRoot 'C:\ProgramData\CTyunTrim\Runs' -Caller $PSCmdlet }
    $first=Invoke-WorkflowFixture -Confirm:$false
    $firstCounts=[pscustomobject]@{Prepare=$script:PrepareCalls;Apply=$script:ApplyCalls;RunId=$script:ApplyRunId;Status=$first.Status;SourceMode=$first.SourceMode;NextCommand=$first.NextCommand}
    $script:WorkflowAction='ResumeApply';$resume=Invoke-WorkflowFixture -Confirm:$false
    $script:WorkflowAction='RebootRequired';$before=$script:ApplyCalls;$reboot=Invoke-WorkflowFixture -Confirm:$false;$rebootApplied=$script:ApplyCalls-$before
    $script:WorkflowAction='Verify';$script:VerifyPassed=$true;$verified=Invoke-WorkflowFixture -Confirm:$false
    $script:VerifyPassed=$false;$failedVerify=Invoke-WorkflowFixture -Confirm:$false
    [pscustomobject]@{First=$firstCounts;ResumeStatus=$resume.Status;RebootStatus=$reboot.Status;RebootApplied=$rebootApplied;VerifiedPassed=$verified.Passed;FailedVerifyPassed=$failedVerify.Passed;RuntimeDataCount=@($verified.RuntimeData).Count}
} $manifest $manifestPath

Assert-CTTrim ($workflow.First.Prepare -eq 1 -and $workflow.First.Apply -eq 1 -and $workflow.First.RunId -eq '20260905-020202-b1c2d3e4') 'First Trim did not pass the exact Prepare RunId immediately to Apply.'
Assert-CTTrim ($workflow.First.SourceMode -eq 'Trim' -and $workflow.First.NextCommand -eq '.\Trim.cmd -Force') 'Trim result metadata did not preserve the single-command entrypoint.'
Assert-CTTrim ($workflow.ResumeStatus -eq 'PendingReboot') 'Resume Trim did not call Apply.'
Assert-CTTrim ($workflow.RebootStatus -eq 'PendingReboot' -and $workflow.RebootApplied -eq 0) 'Same-boot reboot state invoked Apply.'
Assert-CTTrim ($workflow.VerifiedPassed -and -not $workflow.FailedVerifyPassed) 'Trim Verify did not preserve Passed.'
Assert-CTTrim ($workflow.RuntimeDataCount -eq 1) 'Trim Verify dropped RuntimeData metadata.'

$entryText=Get-Content -LiteralPath (Join-Path $root 'CTyunTrim.ps1') -Raw
$moduleText=Get-Content -LiteralPath (Join-Path $root 'src\CTyunTrim.psm1') -Raw
$cmdText=Get-Content -LiteralPath (Join-Path $root 'Trim.cmd') -Raw
Assert-CTTrim ($entryText -match "ValidateSet\([^\r\n]+?'Trim'" -and $moduleText -match "ValidateSet\([^\r\n]+?'Trim'") 'Trim is missing from a public ValidateSet.'
Assert-CTTrim ($entryText -match '\$Mode -in @\(''Verify'',''Trim''\)' -and $entryText -match 'if \(\$verificationFailed\) \{ throw') 'Public Trim verification failure is not converted to a failing process exit.'
Assert-CTTrim ($entryText -match "'RebootThenRunTrim'" -and $entryText -match "'RunTrimToVerify'" -and $entryText -match "'\.\\Trim\.cmd -Force'") 'Diagnostic envelope does not retain the safe Trim retry command.'
Assert-CTTrim ($cmdText -match '(?i)-Mode\s+Trim' -and $cmdText -notmatch '(?i)-Force') 'Trim.cmd does not forward Trim safely or defaults Force.'
Assert-CTTrim (@([regex]::Matches($moduleText,"ValidateSet\('Audit', 'Plan', 'Prepare', 'Apply', 'Verify', 'Trim'\)")).Count -eq 3) 'Diagnostic/public Trim mode validation is incomplete.'

if($failures.Count -gt 0){throw "Trim workflow tests failed:`n - $($failures -join "`n - ")"}
Write-Host 'Trim workflow tests passed.'
exit 0
