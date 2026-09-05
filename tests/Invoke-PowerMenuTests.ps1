#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess) { throw 'Power-menu tests require 64-bit Windows PowerShell 5.1.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\CTyunTrim.psd1') -Force
$module=Get-Module CTyunTrim
$checks=& $module {
    $targets=@(Get-CTPowerMenuTargets)
    $script:MenuEntries=@(); $script:MenuBlockers=@(); $script:MenuBackups=0; $script:MenuWrites=0
    $script:MenuBackupFails=$false; $script:MenuReadbackFails=$false; $script:MenuPolicyChanges=$false; $script:MenuOrder=New-Object Collections.Generic.List[string]
    function Get-CTPowerMenuState { [pscustomobject]@{Entries=@($script:MenuEntries);Blockers=@($script:MenuBlockers);PolicyWarnings=@()} }
    function Save-CTPowerMenuBackup {
        param([object[]]$Entries)
        $script:MenuBackups++;$script:MenuOrder.Add('Backup')
        if($script:MenuBackupFails){throw 'backup failed'}
        if($script:MenuPolicyChanges){$script:MenuBlockers=@('New management policy')}
        return 'C:\fixture\before.json'
    }
    function Set-CTPowerMenuValue {
        param($Entry)
        $script:MenuWrites++;$script:MenuOrder.Add('Write')
        if(-not $script:MenuReadbackFails){$Entry.Value=0}
    }
    function Reset-MenuFixture {
        param([int]$Count=1)
        $script:MenuEntries=@($targets | ForEach-Object { [pscustomobject]@{Id=$_.Id;Path=$_.Path;Name=$_.Name;Present=$false;Kind=$null;Value=$null} })
        for($i=0;$i -lt $Count;$i++){$script:MenuEntries[$i].Present=$true;$script:MenuEntries[$i].Kind='DWord';$script:MenuEntries[$i].Value=1}
        $script:MenuBlockers=@();$script:MenuBackups=0;$script:MenuWrites=0;$script:MenuBackupFails=$false;$script:MenuReadbackFails=$false;$script:MenuPolicyChanges=$false;$script:MenuOrder.Clear()
    }
    function Invoke-MenuFixture { [CmdletBinding(SupportsShouldProcess=$true)]param() Invoke-CTPowerMenuRestore -Caller $PSCmdlet }
    Reset-MenuFixture
    $one=Invoke-MenuFixture -Confirm:$false
    $oneGood=$one.Passed -and $one.ChangedCount -eq 1 -and $one.RefreshRequired -and $script:MenuWrites -eq 1 -and ($script:MenuOrder -join ',') -eq 'Backup,Write'
    $again=Invoke-MenuFixture -Confirm:$false
    $idempotent=$again.Passed -and $again.ChangedCount -eq 0 -and $null -eq $again.BackupPath -and $script:MenuBackups -eq 1 -and $script:MenuWrites -eq 1
    Reset-MenuFixture 3
    $three=Invoke-MenuFixture -Confirm:$false
    $batchGood=$three.ChangedCount -eq 3 -and $script:MenuBackups -eq 1 -and $script:MenuWrites -eq 3 -and ($script:MenuOrder -join ',') -eq 'Backup,Write,Write,Write'
    Reset-MenuFixture 0
    $absent=Invoke-MenuFixture -Confirm:$false
    $absentGood=$absent.Passed -and $script:MenuWrites -eq 0 -and $script:MenuBackups -eq 0
    Reset-MenuFixture
    $preview=Invoke-MenuFixture -WhatIf
    $whatIfGood=-not $preview.Passed -and $script:MenuWrites -eq 0 -and $script:MenuBackups -eq 0
    Reset-MenuFixture
    $script:MenuBlockers=@('Unsupported type')
    $blocked=$false
    try{Invoke-MenuFixture -Confirm:$false|Out-Null}catch{$blocked=$true}
    $blockedGood=$blocked -and $script:MenuWrites -eq 0 -and $script:MenuBackups -eq 0
    Reset-MenuFixture
    $script:MenuBackupFails=$true;$backupFailed=$false
    try{Invoke-MenuFixture -Confirm:$false|Out-Null}catch{$backupFailed=$true}
    $backupGood=$backupFailed -and $script:MenuWrites -eq 0
    Reset-MenuFixture
    $script:MenuReadbackFails=$true;$readbackFailed=$false
    try{Invoke-MenuFixture -Confirm:$false|Out-Null}catch{$readbackFailed=$true}
    $readbackGood=$readbackFailed -and $script:MenuBackups -eq 1 -and $script:MenuWrites -eq 1
    Reset-MenuFixture
    $script:MenuPolicyChanges=$true;$boundaryBlocked=$false
    try{Invoke-MenuFixture -Confirm:$false|Out-Null}catch{$boundaryBlocked=$true}
    $boundaryGood=$boundaryBlocked -and $script:MenuBackups -eq 1 -and $script:MenuWrites -eq 0
    [pscustomobject]@{One=$oneGood;Repeat=$idempotent;Batch=$batchGood;Absent=$absentGood;WhatIf=$whatIfGood;Blocker=$blockedGood;Backup=$backupGood;Readback=$readbackGood;Boundary=$boundaryGood;Targets=$targets}
}
$failures=New-Object Collections.Generic.List[string]
foreach($name in @('One','Repeat','Batch','Absent','WhatIf','Blocker','Backup','Readback','Boundary')){if(-not $checks.$name){$failures.Add("Power-menu test failed: $name")}}
if(@($checks.Targets).Count -ne 3){$failures.Add('Power-menu target allowlist is not exact.')}
if(@($checks.Targets|Where-Object{$_.Id -eq 'MachineNoClose' -and $_.Path -ceq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -and $_.Name -ceq 'NoClose'}).Count -ne 1){$failures.Add('Observed machine NoClose is not correctly mapped.')}
if(@($checks.Targets|Where-Object{$_.Id -eq 'UserNoClose' -and $_.Path -ceq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -and $_.Name -ceq 'NoClose'}).Count -ne 1){$failures.Add('Current-user NoClose is not correctly mapped.')}
if(@($checks.Targets|Where-Object{$_.Id -eq 'MachineHidePowerOptions' -and $_.Name -ceq 'HidePowerOptions'}).Count -ne 1){$failures.Add('Machine HidePowerOptions is not correctly mapped.')}

# Exercise the real collector with registry-object fakes; never write host policies.
Import-Module (Join-Path $root 'src\CTyunTrim.psd1') -Force
$module=Get-Module CTyunTrim
$collector=& $module {
    $script:MenuRegKind='DWord';$script:MenuRegValue=1;$script:MenuManaged=$false
    $script:MenuDomain=$false;$script:MenuMdm=$false
    function Get-CTPowerMenuManagementState { [pscustomobject]@{DomainJoined=$script:MenuDomain;MdmRegistered=$script:MenuMdm} }
    function Get-CTPowerMenuPolicyFiles { @() }
    function Test-Path {
        [CmdletBinding()]param([string]$LiteralPath)
        if($LiteralPath -like '*PolicyManager*'){return $script:MenuManaged}
        return $LiteralPath -like '*Policies\Explorer'
    }
    function Get-Item {
        [CmdletBinding()]param([string]$LiteralPath)
        $item=[pscustomobject]@{Managed=($LiteralPath -like '*PolicyManager*')}
        $item|Add-Member ScriptMethod GetValueNames {if($this.Managed){@('HideRestart')}else{@('NoClose','UnrelatedSetting')}}
        $item|Add-Member ScriptMethod GetValueKind {param($Name) $script:MenuRegKind}
        $item|Add-Member ScriptMethod GetValue {param($Name) $script:MenuRegValue}
        $item|Add-Member ScriptMethod Close {}
        return $item
    }
    $good=Get-CTPowerMenuState
    $script:MenuRegKind='String';$script:MenuRegValue='1';$wrongKind=Get-CTPowerMenuState
    $script:MenuRegKind='DWord';$script:MenuRegValue=2;$wrongValue=Get-CTPowerMenuState
    $script:MenuRegValue=1;$script:MenuManaged=$true;$managed=Get-CTPowerMenuState
    $script:MenuManaged=$false;$script:MenuDomain=$true;$domain=Get-CTPowerMenuState
    $script:MenuDomain=$false;$script:MenuMdm=$true;$mdm=Get-CTPowerMenuState
    [pscustomobject]@{Normal=(@($good.Blockers).Count -eq 0 -and @($good.Entries|Where-Object{$_.Present}).Count -eq 2);WrongKind=(@($wrongKind.Blockers).Count -eq 2);WrongValue=(@($wrongValue.Blockers).Count -eq 2);Managed=(@($managed.Blockers).Count -eq 1);Domain=(@($domain.Blockers).Count -eq 1);Mdm=(@($mdm.Blockers).Count -eq 1)}
}
foreach($name in @('Normal','WrongKind','WrongValue','Managed','Domain','Mdm')){if(-not $collector.$name){$failures.Add("Power-menu collector failed: $name")}}
Import-Module (Join-Path $root 'src\CTyunTrim.psd1') -Force
$module=Get-Module CTyunTrim
$targetBoundary=& $module {
    $blocked=$false
    try{Set-CTPowerMenuValue -Entry ([pscustomobject]@{Id='MachineNoClose';Path='HKLM:\SOFTWARE\Unrelated';Name='NoClose';Present=$true;Kind='DWord';Value=1})}catch{$blocked=$true}
    $blocked
}
if(-not $targetBoundary){$failures.Add('Unapproved write target was accepted.')}
$publicWithoutForce=$false
try{Restore-CTyunTrimPowerMenu | Out-Null}catch{$publicWithoutForce=$_.Exception.Message -match 'explicit -Force'}
if(-not $publicWithoutForce){$failures.Add('Standalone repair accepted a missing Force.')}
$feature=Get-Content -LiteralPath (Join-Path $root 'src\PowerMenu.ps1') -Raw
$entry=Get-Content -LiteralPath (Join-Path $root 'Restore-PowerMenu.cmd') -Raw
$implementation=Get-Content -LiteralPath (Join-Path $root 'src\CTyunTrim.psm1') -Raw
if($feature -match '(?im)^\s*(Stop-Process|Restart-Computer|Stop-Service|Remove-Item|Remove-ItemProperty|shutdown\.exe)\b'){$failures.Add('Power-menu repair includes an unrelated destructive command.')}
if($feature -notmatch 'System32\\GroupPolicyUsers' -or $feature -notmatch 'Get-CTPowerMenuPolicyFiles' -or $feature -notmatch 'IsDeviceRegisteredWithManagement\(\[ref\]\$registered,0,\[IntPtr\]::Zero\)' -or $feature -notmatch 'DllImportSearchPath.System32'){$failures.Add('Management/per-user policy checks or restricted DLL resolution are missing.')}
if($entry -notmatch 'Restore-PowerMenu\.ps1' -or $entry -match '(?i)\s-Force\b'){$failures.Add('Standalone launcher does not forward arguments safely.')}
if($implementation -notmatch '\$powerMenu = Invoke-CTPowerMenuRestore -Caller \$Caller'){$failures.Add('Apply does not integrate the power-menu repair.')}
$workflowText=(& (Get-Module CTyunTrim) { (Get-Command Invoke-CTTrimWorkflow).Definition })
if($workflowText -match 'Invoke-CTPowerMenuRestore'){$failures.Add('Already-applied Trim no longer remains read-only.')}
if($failures.Count -gt 0){throw ($failures -join "`n")}
Write-Host 'Power-menu tests passed.'
exit 0
