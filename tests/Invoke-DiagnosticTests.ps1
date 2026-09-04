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
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

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

function Get-CTDiagnosticArchiveJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$EntryName
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entry = $zip.GetEntry($EntryName)
        if ($null -eq $entry) { throw "Diagnostic archive entry is missing: $EntryName" }
        $stream = $entry.Open()
        $reader = New-Object IO.StreamReader($stream, (New-Object Text.UTF8Encoding($false)))
        try { return ($reader.ReadToEnd() | ConvertFrom-Json) }
        finally { $reader.Dispose(); $stream.Dispose() }
    }
    finally { $zip.Dispose() }
}

function Test-CTDiagnosticProjectionCanaries {
    param(
        [Parameter(Mandatory = $true)][PSModuleInfo]$Module,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

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
        FileHash = 'CANARY-FILE-HASH-62D94B'
        Signer = 'CANARY-SIGNER-IDENTITY-19A3'
        SignerThumbprint = 'CANARY-SIGNER-THUMBPRINT-81E7'
    }
    $safeViewJson = & $Module {
        param($ManifestPath, $Canaries)
        $manifest = (Test-CTyunTrimManifest -ManifestPath $ManifestPath).Manifest
        $inventory = Get-CTyunTrimInventory -ManifestPath $ManifestPath
        $inventory.VendorProcesses = @($inventory.VendorProcesses) + @([PSCustomObject]@{ Name = 'canary.exe'; ProcessId = 99; ExecutablePath = $Canaries.UserPath; CommandLine = $Canaries.Token })
        $inventory.LocalUsers = @($inventory.LocalUsers) + @([PSCustomObject]@{ Name = $Canaries.Unicode; SID = $Canaries.Sid })
        $inventory.CertificateCandidates = @($inventory.CertificateCandidates) + @([PSCustomObject]@{ Subject = $Canaries.Password; Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' })
        $inventory.VendorTcpConnections = @($inventory.VendorTcpConnections) + @([PSCustomObject]@{ RemoteAddress = $Canaries.IPv4 })
        $inventory.VendorUdpEndpoints = @($inventory.VendorUdpEndpoints) + @([PSCustomObject]@{ Address = $Canaries.IPv6 })
        $inventory.CoreServices[0].FileSha256 = $Canaries.FileHash
        $inventory.CoreServices[0].SignerSubject = $Canaries.Signer
        $inventory.CoreServices[0].SignerIssuer = $Canaries.Signer
        $inventory.CoreServices[0].SignerThumbprint = $Canaries.SignerThumbprint
        Get-CTDiagnosticInventoryView -Inventory $inventory -Manifest $manifest | ConvertTo-Json -Depth 10
    } $ManifestPath $canaries
    foreach ($canary in $canaries.Values) {
        Assert-CTDiagnostic -Condition ($safeViewJson.IndexOf([string]$canary, [StringComparison]::OrdinalIgnoreCase) -lt 0) -Message 'Allowlist inventory view leaked a canary value.'
        $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canary))
        Assert-CTDiagnostic -Condition ($safeViewJson.IndexOf($base64, [StringComparison]::Ordinal) -lt 0) -Message 'Allowlist inventory view leaked a base64 canary.'
    }
    Assert-CTDiagnostic -Condition ($safeViewJson -match 'PinnedHashAndSigner') -Message 'Diagnostic inventory omitted the allowlisted pinned trust mode.'
    Assert-CTDiagnostic -Condition ($safeViewJson -match 'TrustSatisfied') -Message 'Diagnostic inventory omitted the trust decision Boolean.'

    $otherViewsJson = & $Module {
        param($ManifestPath, $Canaries)
        $manifest = (Test-CTyunTrimManifest -ManifestPath $ManifestPath).Manifest
        $allCanaries = ($Canaries.Values -join ' ')
        $context = [PSCustomObject]@{
            Status = $Canaries.Host
            RebootNeeded = $Canaries.Token
            Warnings = @($allCanaries)
            Operations = @([PSCustomObject]@{
                Type = 'Service'
                Target = $Canaries.Unc
                Status = $Canaries.Unicode
                Reversible = $Canaries.Password
            })
        }
        $oldEvents = $script:DiagnosticEvents
        try {
            $script:DiagnosticEvents = @([PSCustomObject]@{
                Level = $Canaries.Host
                Stage = $Canaries.Unicode
                Message = $allCanaries
                Data = @{
                    Type = 'Service'
                    Target = $Canaries.UserPath
                    Status = $Canaries.Token
                    ExitCode = $Canaries.IPv4
                    DurationMs = $Canaries.Mac
                    PendingCount = $Canaries.Sid
                    RebootNeeded = $Canaries.Password
                }
            })
            [PSCustomObject]@{
                Context = Get-CTDiagnosticContextView -Context $context -Manifest $manifest
                Events = @(Get-CTDiagnosticEventView -Manifest $manifest)
                PreflightIssues = @(Get-CTDiagnosticIssueView -Messages @($allCanaries) -Manifest $manifest)
            } | ConvertTo-Json -Depth 10
        }
        finally { $script:DiagnosticEvents = $oldEvents }
    } $ManifestPath $canaries
    foreach ($canary in $canaries.Values) {
        Assert-CTDiagnostic -Condition ($otherViewsJson.IndexOf([string]$canary, [StringComparison]::OrdinalIgnoreCase) -lt 0) -Message 'Context, event or preflight projection leaked a canary value.'
    }
    Assert-CTDiagnostic -Condition ($otherViewsJson -match '"Type"\s*:\s*"Service"') -Message 'Context/event projection dropped the allowlisted operation type.'
    Assert-CTDiagnostic -Condition ($otherViewsJson -match '"Status"\s*:\s*"Unknown"') -Message 'Context/event projection did not map an unknown status to a stable value.'

    $unsafeTextResults = & $Module {
        $samples = @(
            'state.clixml',
            'SignerSubject',
            'S-1-5-21-111-222-333-1001',
            'C:\Users\Alice Secret\file.txt',
            '\\private-server\share',
            '203.0.113.77',
            '2001:db8::dead:beef',
            '00-11-22-33-44-55',
            'alice@example.invalid',
            'password=CANARY'
        )
        foreach ($sample in $samples) {
            $rejected = $false
            try { [void](Test-CTDiagnosticTextSafe -Text $sample) }
            catch { $rejected = $_.Exception.Message -eq 'DiagnosticSanitizationFailed' }
            [PSCustomObject]@{ Sample = $sample; Rejected = $rejected }
        }
    }
    Assert-CTDiagnostic -Condition (@($unsafeTextResults | Where-Object { -not $_.Rejected }).Count -eq 0) -Message 'The diagnostic text sanitizer accepted a forbidden literal or pattern.'
}

$rootPrefix = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
$trackedFiles = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File | Where-Object {
    $relative = $_.FullName.Substring($rootPrefix.Length)
    -not ($relative.StartsWith('.git\', [StringComparison]::OrdinalIgnoreCase) -or
        $relative.StartsWith('artifacts\', [StringComparison]::OrdinalIgnoreCase))
})
$beforeHashes = @{}
foreach ($file in $trackedFiles) { $beforeHashes[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }

Import-Module -Name $modulePath -Force
$module = Get-Module CTyunTrim
Test-CTDiagnosticProjectionCanaries -Module $module -ManifestPath $manifestPath

if (-not $isAdministrator) {
    $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('CTyunTrim-nonadmin-diagnostic-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    try {
        $stdout = Join-Path $fixtureRoot 'stdout.json'
        $stderr = Join-Path $fixtureRoot 'stderr.txt'
        Push-Location $root
        try {
            $process = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d', '/c', 'Start-CTyunTrim.cmd -Mode Audit -Diagnostic -Json') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
        }
        finally { Pop-Location }
        Assert-CTDiagnostic -Condition ($process.ExitCode -ne 0) -Message 'Non-elevated Audit reported success after diagnostic export failed.'
        $envelope = Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json
        Assert-CTDiagnostic -Condition $envelope.PrimarySucceeded -Message 'Non-elevated diagnostic failure incorrectly changed the successful Audit status.'
        Assert-CTDiagnostic -Condition (-not $envelope.Diagnostic.Succeeded) -Message 'Non-elevated diagnostic export unexpectedly succeeded.'
        Assert-CTDiagnostic -Condition ([string]$envelope.Diagnostic.ErrorCode -eq 'DiagnosticRequiresElevation') -Message "Non-elevated diagnostic returned the wrong error code: $($envelope.Diagnostic.ErrorCode)"
        Assert-CTDiagnostic -Condition ((Get-Content -LiteralPath $stderr -Raw) -match 'diagnostic export failed: DiagnosticRequiresElevation') -Message 'Non-elevated diagnostic failure was not reported on stderr.'
        if ($env:GITHUB_ACTIONS -eq 'true') {
            Assert-CTDiagnostic -Condition $false -Message 'GitHub Actions must run elevated Diagnostic integration tests.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    }

    foreach ($file in $trackedFiles) {
        Assert-CTDiagnostic -Condition ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -eq $beforeHashes[$file.FullName]) -Message "Non-elevated diagnostic execution modified a tracked input: $($file.FullName)"
    }

    if ($failures.Count -gt 0) {
        $failures | ForEach-Object { Write-Error $_ }
        exit 1
    }
    Write-Host 'Diagnostic sanitizer and non-elevated failure-contract tests passed; elevated archive integration was not available.'
    exit 0
}

try {
    $json = & $entryPath -Mode Audit -Diagnostic -Json
    $envelope = ($json -join "`n") | ConvertFrom-Json
    Assert-CTDiagnostic -Condition $envelope.PrimarySucceeded -Message 'Audit Diagnostic reported primary failure.'
    Assert-CTDiagnostic -Condition $envelope.Diagnostic.Succeeded -Message "Audit Diagnostic export failed: $($envelope.Diagnostic.ErrorCode)"
    Assert-CTDiagnostic -Condition ($envelope.Diagnostic.EntryCount -eq 4) -Message 'Diagnostic envelope reported an unexpected entry count.'
    Assert-CTDiagnostic -Condition ([string]$envelope.Diagnostic.SHA256 -match '^[0-9A-F]{64}$') -Message 'Diagnostic envelope has an invalid SHA256.'
    Assert-CTDiagnostic -Condition (([string]$envelope.Diagnostic.BundlePath).StartsWith('[CommonApplicationData]\CTyunTrim\Diagnostics\', [StringComparison]::Ordinal)) -Message 'Diagnostic envelope returned a path outside the fixed display root.'
    $successZip = Register-CTDiagnosticOutput -DisplayPath ([string]$envelope.Diagnostic.BundlePath)
    if (-not [string]::IsNullOrWhiteSpace($successZip)) {
        Test-CTDiagnosticArchive -Path $successZip
        $successItem = Get-Item -LiteralPath $successZip
        Assert-CTDiagnostic -Condition ([string]$envelope.Diagnostic.SHA256 -eq (Get-FileHash -LiteralPath $successZip -Algorithm SHA256).Hash) -Message 'Diagnostic envelope SHA256 does not match the ZIP.'
        Assert-CTDiagnostic -Condition ([long]$envelope.Diagnostic.Bytes -eq [long]$successItem.Length) -Message 'Diagnostic envelope byte count does not match the ZIP.'
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
        $failureStderr = Get-Content -LiteralPath $stderr -Raw
        Assert-CTDiagnostic -Condition ($failureStderr -match 'requires the explicit -Force switch') -Message 'Apply failure test did not exercise the Force gate.'
        Assert-CTDiagnostic -Condition (-not $failureEnvelope.PrimarySucceeded) -Message 'Failure Diagnostic envelope reported primary success.'
        Assert-CTDiagnostic -Condition $failureEnvelope.Diagnostic.Succeeded -Message "Failure Diagnostic did not create a bundle: $($failureEnvelope.Diagnostic.ErrorCode)"
        $failureZip = Register-CTDiagnosticOutput -DisplayPath ([string]$failureEnvelope.Diagnostic.BundlePath)
        if (-not [string]::IsNullOrWhiteSpace($failureZip)) {
            Test-CTDiagnosticArchive -Path $failureZip
            $failureSummary = Get-CTDiagnosticArchiveJson -Path $failureZip -EntryName 'summary.json'
            Assert-CTDiagnostic -Condition ([string]$failureSummary.FailureCode -eq 'ForceRequired') -Message "Apply Force gate returned the wrong diagnostic code: $($failureSummary.FailureCode)"
        }

        $restartStdout = Join-Path $fixtureRoot 'restart-stdout.json'
        $restartStderr = Join-Path $fixtureRoot 'restart-stderr.txt'
        Push-Location $root
        try {
            $restartProcess = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d', '/c', 'Start-CTyunTrim.cmd -Mode Audit -Restart -Diagnostic -Json') -RedirectStandardOutput $restartStdout -RedirectStandardError $restartStderr -Wait -PassThru
        }
        finally { Pop-Location }
        Assert-CTDiagnostic -Condition ($restartProcess.ExitCode -ne 0) -Message 'Diagnostic unexpectedly accepted -Restart.'
        Assert-CTDiagnostic -Condition ((Get-Content -LiteralPath $restartStderr -Raw) -match 'DiagnosticCannotCombineWithRestart') -Message 'Diagnostic/Restart conflict did not reach the intended guard.'
        $restartEnvelope = Get-Content -LiteralPath $restartStdout -Raw | ConvertFrom-Json
        Assert-CTDiagnostic -Condition (-not $restartEnvelope.PrimarySucceeded) -Message 'Diagnostic/Restart conflict reported primary success.'
        Assert-CTDiagnostic -Condition $restartEnvelope.Diagnostic.Succeeded -Message 'Diagnostic/Restart conflict did not produce a support bundle.'
        $restartZip = Register-CTDiagnosticOutput -DisplayPath ([string]$restartEnvelope.Diagnostic.BundlePath)
        if (-not [string]::IsNullOrWhiteSpace($restartZip)) {
            Test-CTDiagnosticArchive -Path $restartZip
            $restartSummary = Get-CTDiagnosticArchiveJson -Path $restartZip -EntryName 'summary.json'
            Assert-CTDiagnostic -Condition ([string]$restartSummary.FailureCode -eq 'DiagnosticRestartConflict') -Message "Diagnostic/Restart conflict returned the wrong diagnostic code: $($restartSummary.FailureCode)"
        }
    }
    finally {
        if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    }

    $afterTrackedFiles = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File | Where-Object {
        $relative = $_.FullName.Substring($rootPrefix.Length)
        -not ($relative.StartsWith('.git\', [StringComparison]::OrdinalIgnoreCase) -or
            $relative.StartsWith('artifacts\', [StringComparison]::OrdinalIgnoreCase))
    })
    $beforeFileSet = @(($trackedFiles.FullName | Sort-Object)) -join "`n"
    $afterFileSet = @(($afterTrackedFiles.FullName | Sort-Object)) -join "`n"
    Assert-CTDiagnostic -Condition ($afterFileSet -ceq $beforeFileSet) -Message 'Diagnostic execution changed the tracked project file set.'
    foreach ($file in $afterTrackedFiles) {
        Assert-CTDiagnostic -Condition ($beforeHashes.ContainsKey($file.FullName) -and (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -eq $beforeHashes[$file.FullName]) -Message "Diagnostic execution modified a tracked input: $($file.FullName)"
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
