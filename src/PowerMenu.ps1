# Exact, additive shell-policy repair. This file is loaded by CTyunTrim.psm1.
# It never shuts down Windows, restarts Explorer, or changes account privileges.

function Get-CTPowerMenuTargets {
    @(
        [pscustomobject]@{ Id='MachineNoClose'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoClose' },
        [pscustomobject]@{ Id='UserNoClose'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoClose' },
        [pscustomobject]@{ Id='MachineHidePowerOptions'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='HidePowerOptions' }
    )
}

function Get-CTPowerMenuManagementState {
    $computer = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)
    if ($computer.Count -ne 1 -or $computer[0].PartOfDomain -isnot [bool]) { throw 'Could not determine domain-management state.' }
    if (-not ('CTyunTrim.NativePowerMenuManagement' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CTyunTrim {
    public static class NativePowerMenuManagement {
        [DllImport("MDMRegistration.dll", ExactSpelling=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int IsDeviceRegisteredWithManagement(
            [MarshalAs(UnmanagedType.Bool)] out bool registered, uint upnLength, IntPtr upn);
    }
}
'@ -ErrorAction Stop | Out-Null
    }
    $registered = $false
    # The documented NULL-UPN form reads only the registration Boolean, no identity.
    $status = [CTyunTrim.NativePowerMenuManagement]::IsDeviceRegisteredWithManagement([ref]$registered,0,[IntPtr]::Zero)
    if ($status -ne 0) { throw "Could not determine MDM-management state (status $status)." }
    [pscustomobject]@{ DomainJoined=[bool]$computer[0].PartOfDomain; MdmRegistered=[bool]$registered }
}

function Get-CTPowerMenuPolicyFiles {
    $paths = New-Object Collections.Generic.List[string]
    $policyRoot = Join-Path $env:SystemRoot 'System32\GroupPolicy'
    foreach ($relative in @('Machine\Registry.pol','User\Registry.pol')) { $paths.Add((Join-Path $policyRoot $relative)) }
    $userPolicyRoot = Join-Path $env:SystemRoot 'System32\GroupPolicyUsers'
    if (Test-Path -LiteralPath $userPolicyRoot -ErrorAction Stop) {
        if (Test-CTPathHasReparsePoint -Path $userPolicyRoot) { throw 'Per-user policy root contains a reparse point.' }
        foreach ($directory in @(Get-ChildItem -LiteralPath $userPolicyRoot -Directory -Force -ErrorAction Stop)) {
            if (Test-CTPathHasReparsePoint -Path $directory.FullName) { throw 'Per-user policy directory contains a reparse point.' }
            $paths.Add((Join-Path $directory.FullName 'User\Registry.pol'))
        }
    }
    return $paths.ToArray()
}

function Get-CTPowerMenuState {
    $entries = New-Object Collections.Generic.List[object]
    $blockers = New-Object Collections.Generic.List[string]
    $management = Get-CTPowerMenuManagementState
    if ($management.DomainJoined) { $blockers.Add('Domain-joined systems require changing the domain policy source; automatic power-menu repair is refused.') }
    if ($management.MdmRegistered) { $blockers.Add('MDM-managed systems require changing the management policy source; automatic power-menu repair is refused.') }
    foreach ($target in @(Get-CTPowerMenuTargets)) {
        $present = $false; $kind = $null; $value = $null
        if (Test-Path -LiteralPath $target.Path -ErrorAction Stop) {
            $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
            try {
                $present = @($key.GetValueNames()) -contains $target.Name
                if ($present) {
                    $kind = [string]$key.GetValueKind($target.Name)
                    $value = $key.GetValue($target.Name)
                    if ($kind -ne 'DWord' -or $value -notin @(0,1)) {
                        $blockers.Add("Unsupported power-menu policy type or value: $($target.Id)")
                    }
                }
            }
            finally { $key.Close() }
        }
        $entries.Add([pscustomobject]@{ Id=$target.Id; Path=$target.Path; Name=$target.Name; Present=$present; Kind=$kind; Value=$value })
    }

    # Do not override an active managed CSP policy or edit PolicyManager defaults.
    $managedStart = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start'
    if (Test-Path -LiteralPath $managedStart -ErrorAction Stop) {
        $key = Get-Item -LiteralPath $managedStart -ErrorAction Stop
        try {
            foreach ($name in @('HidePowerButton','HideShutDown','HideRestart')) {
                if (@($key.GetValueNames()) -contains $name) {
                    if ([string]$key.GetValueKind($name) -ne 'DWord' -or $key.GetValue($name) -ne 0) {
                        $blockers.Add("A managed Start/$name policy is active or unsupported; change its policy source first.")
                    }
                }
            }
        }
        finally { $key.Close() }
    }

    # The observed image uses tattooed registry values, not a Registry.pol entry.
    # Refuse managed variants instead of silently allowing the policy to reappear.
    foreach ($path in @(Get-CTPowerMenuPolicyFiles)) {
        if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { continue }
        if (Test-CTPathHasReparsePoint -Path $path) { throw 'Power-menu policy source contains a reparse point.' }
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.Length -gt 16777216) { throw 'Power-menu policy source is too large to inspect safely.' }
        $text = [Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes($path))
        if ($text -match '(?i)NoClose|HidePowerOptions') {
            $blockers.Add("Local Group Policy contains power-menu entries in $path; adjust that source policy first.")
        }
    }
    [pscustomobject]@{ Entries=$entries.ToArray(); Blockers=$blockers.ToArray(); PolicyWarnings=@() }
}

function Save-CTPowerMenuBackup {
    param([Parameter(Mandatory=$true)][object[]]$Entries)
    $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($commonData)) { throw 'Power-menu backup location is unavailable.' }
    $root = Join-Path $commonData 'CTyunTrim\PowerMenuBackups'
    if (Test-CTPathHasReparsePoint -Path $root) { throw 'Power-menu backup path contains a reparse point.' }
    $missing = New-Object Collections.Generic.List[string]
    $candidate = $root
    while (-not (Test-Path -LiteralPath $candidate)) {
        $missing.Add($candidate)
        $candidate = Split-Path -Parent $candidate
        if ([string]::IsNullOrWhiteSpace($candidate)) { throw 'Power-menu backup path has no existing ancestor.' }
    }
    for ($i=$missing.Count-1; $i -ge 0; $i--) {
        New-Item -ItemType Directory -Path $missing[$i] -ErrorAction Stop | Out-Null
        Set-CTRunDirectoryAcl -Path $missing[$i]
    }
    if (-not (Test-CTSecureSourcePath -Path $root)) { throw 'Power-menu backup directory is not secure.' }
    $directory = Join-Path $root ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
    Set-CTRunDirectoryAcl -Path $directory
    if (-not (Test-CTSecureSourcePath -Path $directory)) { throw 'Power-menu backup directory failed its ACL check.' }
    $path = Join-Path $directory 'before.json'
    $record = [pscustomobject]@{
        SchemaVersion='1.0'; Feature='PowerMenu'; ToolVersion=$script:CTyunTrimVersion
        CreatedAt=(Get-Date).ToString('o'); UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Entries=@($Entries)
    }
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    Set-CTRunFileAcl -Path $path
    if (-not (Test-CTSecureSourcePath -Path $path)) { throw 'Power-menu backup file failed its ACL check.' }
    $saved = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($saved.Feature -ne 'PowerMenu' -or @($saved.Entries).Count -ne $Entries.Count) { throw 'Power-menu backup validation failed.' }
    foreach ($entry in $Entries) {
        $copy = @($saved.Entries | Where-Object { $_.Id -eq $entry.Id })
        if ($copy.Count -ne 1 -or $copy[0].Path -cne $entry.Path -or $copy[0].Name -cne $entry.Name -or
            $copy[0].Kind -ne $entry.Kind -or $copy[0].Value -ne $entry.Value) { throw 'Power-menu backup differs from its source.' }
    }
    return $path
}

function Set-CTPowerMenuValue {
    param([Parameter(Mandatory=$true)][PSObject]$Entry)
    $approved = @(Get-CTPowerMenuTargets | Where-Object { $_.Id -ceq $Entry.Id -and $_.Path -ceq $Entry.Path -and $_.Name -ceq $Entry.Name })
    if ($approved.Count -ne 1 -or -not $Entry.Present -or $Entry.Kind -ne 'DWord' -or $Entry.Value -ne 1) {
        throw 'Power-menu write target is outside the exact repair allowlist.'
    }
    # Hold the same key handle from boundary read through the single-value write.
    $hive = if ($Entry.Path.StartsWith('HKLM:',[StringComparison]::Ordinal)) { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,[Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $baseKey.OpenSubKey($Entry.Path.Substring(6),$true)
        if ($null -eq $key) { throw 'Power-menu registry key disappeared after backup.' }
        if (@($key.GetValueNames()) -notcontains $Entry.Name -or [string]$key.GetValueKind($Entry.Name) -ne 'DWord' -or $key.GetValue($Entry.Name) -ne 1) {
            throw 'Power-menu policy changed after backup; rerun to inspect the new state.'
        }
        $key.SetValue($Entry.Name,[int]0,[Microsoft.Win32.RegistryValueKind]::DWord)
        $key.Flush()
        if ([string]$key.GetValueKind($Entry.Name) -ne 'DWord' -or $key.GetValue($Entry.Name) -ne 0) { throw 'Power-menu value did not retain DWORD zero.' }
    }
    finally { if ($null -ne $key) { $key.Close() }; $baseKey.Close() }
}

function Invoke-CTPowerMenuRestore {
    param([Parameter(Mandatory=$true)][Management.Automation.PSCmdlet]$Caller)
    $state = Get-CTPowerMenuState
    if (@($state.Blockers).Count -gt 0) { throw "Power-menu repair refused: $($state.Blockers -join '; ')" }
    $changes = @($state.Entries | Where-Object { $_.Present -and $_.Kind -eq 'DWord' -and $_.Value -eq 1 })
    if ($changes.Count -eq 0) {
        return [pscustomobject]@{ Passed=$true; ChangedCount=0; BackupPath=$null; RefreshRequired=$false; Warnings=@($state.PolicyWarnings) }
    }
    $approved = $true
    foreach ($entry in $changes) {
        if (-not $Caller.ShouldProcess("$($entry.Path)::$($entry.Name)", 'Back up and restore Start-menu shutdown/restart visibility')) { $approved=$false }
    }
    if (-not $approved) {
        return [pscustomobject]@{ Passed=$false; ChangedCount=0; BackupPath=$null; RefreshRequired=$false; Warnings=@('Power-menu repair was not applied (preview or declined confirmation).') }
    }
    $backup = Save-CTPowerMenuBackup -Entries $changes
    $boundary = Get-CTPowerMenuState
    if (@($boundary.Blockers).Count -gt 0) { throw "Power-menu policy source changed before writing. Backup: $backup" }
    $boundaryChanges = @($boundary.Entries | Where-Object { $_.Present -and $_.Kind -eq 'DWord' -and $_.Value -eq 1 })
    if (($boundaryChanges.Id -join ',') -cne ($changes.Id -join ',')) { throw "Power-menu values changed after backup. Backup: $backup" }
    foreach ($entry in $changes) { Set-CTPowerMenuValue -Entry $entry }
    $after = Get-CTPowerMenuState
    if (@($after.Blockers).Count -gt 0 -or @($after.Entries | Where-Object { $_.Present -and $_.Value -ne 0 }).Count -gt 0) {
        throw "Power-menu repair did not pass read-back verification. Backup: $backup"
    }
    [pscustomobject]@{ Passed=$true; ChangedCount=$changes.Count; BackupPath=$backup; RefreshRequired=$true; Warnings=@($after.PolicyWarnings) }
}

function Restore-CTyunTrimPowerMenu {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
    param([switch]$Force,[switch]$Json)
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or
        $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
        throw 'Power-menu repair requires 64-bit Windows PowerShell 5.1 Desktop Edition.'
    }
    if (-not $WhatIfPreference -and (-not $Force -or -not (Test-CTIsAdministrator))) {
        throw 'Power-menu repair requires an elevated session and explicit -Force.'
    }
    $mutex = New-Object Threading.Mutex($false,'Global\CTyunTrim')
    $locked = $false
    try {
        try { $locked=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
        if (-not $locked) { throw 'Another CTyunTrim operation is already running.' }
        $result = Invoke-CTPowerMenuRestore -Caller $PSCmdlet
        if (-not $WhatIfPreference -and -not $result.Passed) { throw 'Power-menu repair was not applied.' }
        if ($Json) { return ($result | ConvertTo-Json -Depth 6) }
        return $result
    }
    finally { if ($locked) { [void]$mutex.ReleaseMutex() }; $mutex.Dispose() }
}
