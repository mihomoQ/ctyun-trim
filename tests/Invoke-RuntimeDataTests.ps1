#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition-ne'Desktop'-or$PSVersionTable.PSVersion.Major-ne5){throw 'Use Windows PowerShell 5.1.'}
$root=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('CTyunTrim-RuntimeData-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp|Out-Null
try {
    $module=Import-Module (Join-Path $root 'src\CTyunTrim.psd1') -Force -PassThru
    & $module {
        param($FixtureRoot)
        $empty='C:\Users\Public\Documents\mirror\FileCrypto'
        $log='C:\Users\Public\Documents\mirror\PrinterJobLog'
        $file=Join-Path $FixtureRoot 'printer_jobs.log'
        $normal="`r`n2026-09-05 12:00:00 MonitorPrintJobs start...`r`n2026-09-05 12:00:00 Failed to open registry key, unable to monitor the addition of printer, , errorCode: [0]`r`n2026-09-05 12:00:01 Find [1] printers`r`n2026-09-05 12:00:01 index:[0], printer: [Microsoft Print to PDF]`r`n"
        [IO.File]::WriteAllText($file,$normal,(New-Object Text.UTF8Encoding($false)))
        if(-not(Test-CTPrinterRuntimeLog $file)){throw 'Observed printer startup log was rejected.'}
        foreach($bad in @('powershell.exe -enc AAAA','2026-99-05 12:00:00 MonitorPrintJobs start...',('x'*65537),"2026-09-05 12:00:00 MonitorPrintJobs start...`0")) {
            [IO.File]::WriteAllText($file,$bad)
            if(Test-CTPrinterRuntimeLog $file){throw 'Unknown or oversized printer log passed.'}
        }
        [IO.File]::WriteAllText($file,$normal,(New-Object Text.UTF8Encoding($false)))
        $hold=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try{if(Test-CTPrinterRuntimeLog $file){throw 'An unreadable log passed.'}}finally{$hold.Dispose()}
        $fixture=@{Reparse=$false;Children=@();BackupExists=$true;QueryFails=$false}
        function Test-CTPathHasReparsePoint {param($Path) return $fixture.Reparse}
        function Get-Item {[CmdletBinding()]param($LiteralPath,[switch]$Force) return [pscustomobject]@{PSIsContainer=$true}}
        function Get-ChildItem {[CmdletBinding()]param($LiteralPath,[switch]$Force) if($fixture.QueryFails){throw 'query failed'};return $fixture.Children}
        function Test-Path {param($LiteralPath,$PathType) return $fixture.BackupExists}
        function Assert-CTQuarantinePathPair {param($Context,$Source,$Destination) if($Destination-ne'approved-backup'){throw 'bad pair'}}
        $inv=[pscustomobject]@{RemovalServices=@();RemovalDrivers=@();KnownCertificates=@();LocalUsers=@();CloudbaseProfiles=@()}
        $refs=[pscustomobject]@{Complete=$true;Referenced=@{$empty=$false;$log=$false}}
        $context=[pscustomobject]@{Operations=@([pscustomobject]@{Type='QuarantinePath';Status='Completed';Target=$empty;Data=@{Source=$empty;Destination='approved-backup'}})}
        function Check {param([string]$Path=$empty,[bool]$Healthy=$true) Get-CTKnownRuntimeDataResidue -Path $Path -Context $context -Inventory $inv -CoreHealthy $Healthy -References $refs}
        if($null-eq(Check)){throw 'Verified empty runtime directory was rejected.'}
        if($null-ne(Check -Healthy $false)){throw 'Unhealthy core accepted a runtime exception.'}
        if($null-ne(Check -Path 'C:\Program Files (x86)\ctyun\AppMarketSvc')){throw 'A program directory used the runtime exception.'}
        $refs.Complete=$false;if($null-ne(Check)){throw 'Incomplete reference query was accepted.'};$refs.Complete=$true
        $refs.Referenced[$empty]=$true;if($null-ne(Check)){throw 'An executable reference was ignored.'};$refs.Referenced[$empty]=$false
        $fixture.Reparse=$true;if($null-ne(Check)){throw 'Reparse directory was accepted.'};$fixture.Reparse=$false
        $fixture.QueryFails=$true;if($null-ne(Check)){throw 'Failed directory enumeration was accepted.'};$fixture.QueryFails=$false
        $fixture.BackupExists=$false;if($null-ne(Check)){throw 'Missing backup evidence was accepted.'};$fixture.BackupExists=$true
        $inv.RemovalServices=@([pscustomobject]@{Present=$true});if($null-ne(Check)){throw 'A remaining service was accepted.'};$inv.RemovalServices=@()
        $fixture.Children=@([pscustomobject]@{Name='hidden.exe';PSIsContainer=$false;Attributes=[IO.FileAttributes]::Hidden})
        if($null-ne(Check)){throw 'Nonempty FileCrypto was accepted.'}
        $context.Operations[0].Target=$log;$context.Operations[0].Data.Source=$log
        $fixture.Children=@([pscustomobject]@{Name='printer_jobs.log';FullName=$file;PSIsContainer=$false;Attributes=[IO.FileAttributes]::Normal;Length=[long]266})
        $result=Check -Path $log
        if($null-eq$result-or$result.Kind-ne'PrinterRuntimeLog'){throw 'Known printer log residue was rejected.'}
        $fixture.Children+=@([pscustomobject]@{Name='other.log';PSIsContainer=$false;Attributes=[IO.FileAttributes]::Normal})
        if($null-ne(Check -Path $log)){throw 'An extra log file was accepted.'}
        $fixture.Children=@([pscustomobject]@{Name='printer_jobs.log';FullName=$file;PSIsContainer=$false;Attributes=[IO.FileAttributes]::ReparsePoint;Length=[long]266})
        if($null-ne(Check -Path $log)){throw 'A reparse log was accepted.'}
        $context.Operations=@();if($null-ne(Check -Path $log)){throw 'Missing quarantine record was accepted.'}
    } $temp
} finally {
    $full=[IO.Path]::GetFullPath($temp).TrimEnd('\');$prefix=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not$full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($full)-notmatch '^CTyunTrim-RuntimeData-[0-9a-f]{32}$'){throw 'Unsafe test cleanup path.'}
    $items=@(Get-Item -LiteralPath $full -Force)+@(Get-ChildItem -LiteralPath $full -Recurse -Force)
    if(@($items|Where-Object {$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count){throw 'Reparse point in test cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host 'Runtime data classification tests passed.'
exit 0
