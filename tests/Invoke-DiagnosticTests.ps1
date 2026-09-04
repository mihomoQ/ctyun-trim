#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Diagnostic tests must run under Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) { throw 'Diagnostic tests require a 64-bit process.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($env:GITHUB_ACTIONS -eq 'true') { throw 'GitHub Actions must run Diagnostic integration tests elevated.' }
    Write-Host 'Diagnostic integration tests skipped because the process is not elevated.'
    exit 0
}

$root = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $root 'config\CTyunTrim.psd1'
$modulePath = Join-Path $root 'src\CTyunTrim.psd1'
$entryPath = Join-Path $root 'CTyunTrim.ps1'
$failures = New-Object Collections.Generic.List[string]
$createdOutputs = New-Object Collections.Generic.List[string]

function Assert-CTDiagnostic {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { $script:failures.Add($Message) }
}

function Register-CTDiagnosticOutput {
    param([string]$DisplayPath)
    if ([string]::IsNullOrWhiteSpace($DisplayPath)) { return $null }
    $path = if ($DisplayPath.StartsWith('[CommonApplicationData]\', [StringComparison]::Ordinal)) {
        Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) $DisplayPath.Substring(24)
    }
    else { $DisplayPath }
    $script:createdOutputs.Add($path)
    $script:createdOutputs.Add("$path.sha256")
    return $path
}

function Test-CTDiagnosticArchive {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-CTDiagnostic -Condition (Test-Path -LiteralPath $Path -PathType Leaf) -Message "Diagnostic ZIP is missing: $Path"
    Assert-CTDiagnostic -Condition (Test-Path -LiteralPath "$Path.sha256" -PathType Leaf) -Message 'Diagnostic SHA256 sidecar is missing.'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

    $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $expectedHash = ((Get-Content -LiteralPath "$Path.sha256" -Raw).Trim() -split '\s+')[0]
    Assert-CTDiagnostic -Condition ($actualHash -eq $expectedHash) -Message 'Diagnostic ZIP and sidecar hashes differ.'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $expectedNames = @('environment.json', 'events.jsonl', 'README.txt', 'summary.json')
        $actualNames = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        Assert-CTDiagnostic -Condition (($actualNames -join "`n") -ceq (($expectedNames | Sort-Object) -join "`n")) -Message "Unexpected diagnostic ZIP entries: $($actualNames -join ', ')"
        Assert-CTDiagnostic -Condition (($zip.Entries | Measure-Object -Property Length -Sum).Sum -le 2097152) -Message 'Diagnostic ZIP exceeds the uncompressed size limit.'

        foreach ($entry in $zip.Entries) {
            $stream = $entry.Open()
            $reader = New-Object IO.StreamReader($stream, (New-Object Text.UTF8Encoding($false)))
            try { $content = $reader.ReadToEnd() } finally { $reader.Dispose(); $stream.Dispose() }
            if ($entry.FullName -like '*.json') {
                try { [void]($content | ConvertFrom-Json) } catch { Assert-CTDiagnostic -Condition $false -Message "$($entry.FullName) is invalid JSON." }
            }
            elseif ($entry.FullName -eq 'events.jsonl') {
                foreach ($line in @($content -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
                    try { [void]($line | ConvertFrom-Json) } catch { Assert-CTDiagnostic -Condition $false -Message 'events.jsonl contains invalid JSON.' }
                }
            }

            foreach ($literal in @($env:USERNAME, $env:COMPUTERNAME, [Environment]::GetFolderPath('UserProfile'), 'state.clixml', 'before.json', 'platform-before.json')) {
                if (-not [string]::IsNullOrWhiteSpace($literal)) {
                    Assert-CTDiagnostic -Condition ($content.IndexOf($literal, [StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "$($entry.FullName) leaked a forbidden literal."
                }
            }
            foreach ($pattern in @(
                '(?i)S-1-5-21-(?:[0-9]+-){2,}[0-9]+',
                '(?i)[A-Z]:\\Users\\',
                '(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])',
                '(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}',
                '(?i)(?:password|token|secret|cookie|authorization)\s*[:=]'
            )) {
                Assert-CTDiagnostic -Condition ($content -notmatch $pattern) -Message "$($entry.FullName) failed its forbidden-pattern scan."
            }
        }
    }
    finally { $zip.Dispose() }
}

$trackedFiles = @(
    $entryPath,
    (Join-Path $root 'src\CTyunTrim.psm1'),
    $manifestPath
)
$beforeHashes = @{}
foreach ($file in $trackedFiles) { $beforeHashes[$file] = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash }

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim

try {
    $json = & $entryPath -Mode Audit -Diagnostic -Json
    $envelope = ($json -join "`n") | ConvertFrom-Json
    Assert-CTDiagnostic -Condition $envelope.PrimarySucceeded -Message 'Audit Diagnostic reported primary failure.'
    Assert-CTDiagnostic -Condition $envelope.Diagnostic.Succeeded -Message "Audit Diagnostic export failed: $($envelope.Diagnostic.ErrorCode)"
    Assert-CTDiagnostic -Condition ($envelope.Diagnostic.EntryCount -eq 4) -Message 'Diagnostic envelope reported an unexpected entry count.'
    Assert-CTDiagnostic -Condition ([string]$envelope.Diagnostic.SHA256 -match '^[0-9A-F]{64}$') -Message 'Diagnostic envelope has an invalid SHA256.'
    $successZip = Register-CTDiagnosticOutput -DisplayPath ([string]$envelope.Diagnostic.BundlePath)
    if (-not [string]::IsNullOrWhiteSpace($successZip)) { Test-CTDiagnosticArchive -Path $successZip }

    $canaries = [ordered]@{
        Host = 'CANARY-HOST-9F38'
        UserPath = 'C:\Users\Alice Secret\Documents'
        Sid = 'S-1-5-21-111-222-333-1001'
        IPv4 = '203.0.113.77'
        IPv6 = '2001:db8::dead:beef'
        Mac = '00-11-22-33-44-55'
        Unc = '\\private-server\share'
        Token = 'Bearer CANARY_TOKEN'
        Password = 'password=CANARY_PASSWORD'
        Unicode = 'CANARY-UNICODE-SECRET'
    }
    $safeViewJson = & $module {
        param($ManifestPath, $Canaries)
        $manifest = (Test-CTyunTrimManifest -ManifestPath $ManifestPath).Manifest
        $inventory = Get-CTyunTrimInventory -ManifestPath $ManifestPath
        $inventory.VendorProcesses = @($inventory.VendorProcesses) + @([PSCustomObject]@{ Name = 'canary.exe'; ProcessId = 99; ExecutablePath = $Canaries.UserPath; CommandLine = $Canaries.Token })
        $inventory.LocalUsers = @($inventory.LocalUsers) + @([PSCustomObject]@{ Name = $Canaries.Unicode; SID = $Canaries.Sid })
        $inventory.CertificateCandidates = @($inventory.CertificateCandidates) + @([PSCustomObject]@{ Subject = $Canaries.Password; Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' })
        $inventory.VendorTcpConnections = @($inventory.VendorTcpConnections) + @([PSCustomObject]@{ RemoteAddress = $Canaries.IPv4 })
        $inventory.VendorUdpEndpoints = @($inventory.VendorUdpEndpoints) + @([PSCustomObject]@{ Address = $Canaries.IPv6 })
        Get-CTDiagnosticInventoryView -Inventory $inventory -Manifest $manifest | ConvertTo-Json -Depth 10
    } $manifestPath $canaries
    foreach ($canary in $canaries.Values) {
        Assert-CTDiagnostic -Condition ($safeViewJson.IndexOf([string]$canary, [StringComparison]::OrdinalIgnoreCase) -lt 0) -Message 'Allowlist inventory view leaked a canary value.'
        $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canary))
        Assert-CTDiagnostic -Condition ($safeViewJson.IndexOf($base64, [StringComparison]::Ordinal) -lt 0) -Message 'Allowlist inventory view leaked a base64 canary.'
    }

    $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('CTyunTrim-diagnostic-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    try {
        $stdout = Join-Path $fixtureRoot 'stdout.json'
        $stderr = Join-Path $fixtureRoot 'stderr.txt'
        Push-Location $root
        try {
            $process = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d', '/c', 'Start-CTyunTrim.cmd -Mode Apply -Diagnostic -Json') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
        }
        finally { Pop-Location }
        Assert-CTDiagnostic -Condition ($process.ExitCode -ne 0) -Message 'Apply without Force unexpectedly succeeded in Diagnostic mode.'
        $failureEnvelope = Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json
        Assert-CTDiagnostic -Condition (-not $failureEnvelope.PrimarySucceeded) -Message 'Failure Diagnostic envelope reported primary success.'
        Assert-CTDiagnostic -Condition $failureEnvelope.Diagnostic.Succeeded -Message "Failure Diagnostic did not create a bundle: $($failureEnvelope.Diagnostic.ErrorCode)"
        $failureZip = Register-CTDiagnosticOutput -DisplayPath ([string]$failureEnvelope.Diagnostic.BundlePath)
        if (-not [string]::IsNullOrWhiteSpace($failureZip)) { Test-CTDiagnosticArchive -Path $failureZip }
    }
    finally {
        if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    }

    foreach ($file in $trackedFiles) {
        Assert-CTDiagnostic -Condition ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -eq $beforeHashes[$file]) -Message "Diagnostic execution modified a tracked input: $file"
    }
}
finally {
    foreach ($path in @($createdOutputs)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $commonRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
        $diagnosticRoot = [IO.Path]::GetFullPath((Join-Path $commonRoot 'CTyunTrim\Diagnostics')).TrimEnd('\')
        $fullPath = [IO.Path]::GetFullPath($path)
        if (-not $fullPath.StartsWith($diagnosticRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Diagnostic test cleanup path escaped its fixed root.' }
        $item = Get-Item -LiteralPath $fullPath -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Diagnostic test cleanup refused a reparse point.' }
        Remove-Item -LiteralPath $fullPath -Force
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host 'Diagnostic allowlist, archive, hash, failure, and read-only tests passed.'
exit 0
