#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess) {
    throw 'Task backup tests require Windows PowerShell 5.1 x64.'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('CTyunTrim-TaskBackup-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $testRoot 'tasks') -Force | Out-Null
try {
    $module = Import-Module (Join-Path $repoRoot 'src\CTyunTrim.psd1') -Force -PassThru
    & $module {
        param($FixtureRoot)
        $task = [pscustomobject]@{ TaskName='check_report_img_onstart'; TaskPath='\' }
        $entry = @{ Name=$task.TaskName; TaskPath=$task.TaskPath; ExpectedImage='C:\Program Files\Cloudbase Solutions\Cloudbase-Init\exe\ecloud_img_conf.exe' }
        $manifest = @{ ScheduledTasks=@($entry) }
        $context = [pscustomobject]@{ Root=$FixtureRoot; Operations=(New-Object Collections.ArrayList) }
        $fixture = @{ ExportCount=0; DeleteCount=0; Allow=$true; FailExport=$false }
        function Get-ScheduledTask { [CmdletBinding()]param() return $task }
        function Test-CTScheduledTaskDefinition { param($Task,$Entry) return $true }
        function Confirm-CTRequiredOperation { param($Caller,$Target,$Action) return $fixture.Allow }
        function Save-CTRunContext { param($Context) }
        function Set-CTRunFileAcl { param($Path) }
        function Test-CTSecureSourcePath { param($Path) return $true }
        function Test-CTPathHasReparsePoint { param($Path) return $false }
        function Export-ScheduledTask {
            [CmdletBinding()]param($TaskName,$TaskPath)
            if ($fixture.FailExport) { throw 'A pending operation must not re-export its backup.' }
            $fixture.ExportCount++
            return ('<Task><Version>' + $fixture.ExportCount + '</Version></Task>')
        }
        function Unregister-ScheduledTask { [CmdletBinding(SupportsShouldProcess)]param($TaskName,$TaskPath) $fixture.DeleteCount++ }
        function Invoke-Fixture {
            [CmdletBinding(SupportsShouldProcess)]param()
            Remove-CTScheduledTasks -Context $context -Manifest $manifest -Caller $PSCmdlet
        }

        $legacyPath = Join-Path (Join-Path $FixtureRoot 'tasks') '_check_report_img_onstart.xml'
        '<Task><Version>OriginalPrepare</Version></Task>' | Set-Content -LiteralPath $legacyPath -Encoding Unicode
        $legacyHash = (Get-FileHash -LiteralPath $legacyPath).Hash
        $legacy = [pscustomobject]@{
            Id='original'; Type='ScheduledTask'; Target='\check_report_img_onstart'; Status='Completed'; CompletedAt=$null
            Data=@{ Backup=$legacyPath; BackupSha256=$legacyHash; TaskName=$task.TaskName; TaskPath=$task.TaskPath; ExpectedImage=$entry.ExpectedImage }
        }
        [void]$context.Operations.Add($legacy)
        Invoke-Fixture
        $first = $context.Operations[1]
        Invoke-Fixture
        $second = $context.Operations[2]
        if ($fixture.DeleteCount -ne 2 -or $fixture.ExportCount -ne 2 -or $first.Data.Backup -eq $second.Data.Backup -or
            $first.Data.Backup -eq $legacyPath -or $second.Data.Backup -eq $legacyPath) { throw 'Recreated task did not receive a separate backup.' }
        foreach ($op in $context.Operations) {
            if ((Get-FileHash -LiteralPath $op.Data.Backup).Hash -ne $op.Data.BackupSha256) { throw 'A previous task backup was overwritten.' }
        }

        $second.Status='Pending'
        $fixture.FailExport=$true
        Invoke-Fixture
        if ($fixture.ExportCount -ne 2 -or $fixture.DeleteCount -ne 3 -or $second.Status -ne 'Completed') { throw 'New-format pending task did not resume using its existing backup.' }
        $legacy.Status='Pending'
        Invoke-Fixture
        if ($fixture.ExportCount -ne 2 -or $fixture.DeleteCount -ne 4 -or $legacy.Status -ne 'Completed') { throw 'Legacy pending task backup compatibility failed.' }

        $second.Status='Pending'
        $savedHash=$second.Data.BackupSha256
        $second.Data.BackupSha256='0' * 64
        $blocked=$false
        try { Invoke-Fixture } catch { $blocked=$true }
        if (-not $blocked -or $fixture.DeleteCount -ne 4) { throw 'Tampered pending task backup was accepted.' }
        $second.Data.BackupSha256=$savedHash
        $savedPath=$second.Data.Backup
        $second.Data.Backup=Join-Path $FixtureRoot ([IO.Path]::GetFileName($savedPath))
        $blocked=$false
        try { Invoke-Fixture } catch { $blocked=$true }
        if (-not $blocked -or $fixture.DeleteCount -ne 4) { throw 'Out-of-directory pending task backup was accepted.' }
        $second.Data.Backup=$savedPath
        $fixture.Allow=$false
        Invoke-Fixture
        if ($fixture.ExportCount -ne 2 -or $fixture.DeleteCount -ne 4) { throw 'Declined task operation performed work.' }
    } $testRoot
}
finally {
    $resolvedTestRoot=[IO.Path]::GetFullPath($testRoot).TrimEnd('\')
    $tempPrefix=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedTestRoot.StartsWith($tempPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedTestRoot) -notmatch '^CTyunTrim-TaskBackup-[0-9a-f]{32}$') { throw 'Unsafe fixture cleanup path.' }
    if (Test-Path -LiteralPath $resolvedTestRoot) {
        $items=@(Get-Item -LiteralPath $resolvedTestRoot -Force) + @(Get-ChildItem -LiteralPath $resolvedTestRoot -Recurse -Force)
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) { throw 'Reparse point in fixture cleanup.' }
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}
Write-Host 'Recreated task backup tests passed (unique, immutable, pending resume, legacy, tamper, path, decline).'
