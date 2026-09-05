#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$')]
    [string]$Version = '0.1.5-Diagnostic'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Assert-NoReparsePointInPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $currentPath = [IO.Path]::GetFullPath($Path)
    while ($null -ne $currentPath) {
        if (Test-Path -LiteralPath $currentPath) {
            $item = Get-Item -LiteralPath $currentPath -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Description contains a reparse point and cannot be used safely: $currentPath"
            }
        }

        $parent = [IO.Directory]::GetParent($currentPath)
        if ($null -eq $parent -or
            [string]::Equals($parent.FullName, $currentPath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $currentPath = $parent.FullName
    }
}

function Assert-NoReparsePointInTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Assert-NoReparsePointInPath -Path $Path -Description $Description
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }

    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push([IO.Path]::GetFullPath($Path))
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Description contains a reparse point and cannot be removed recursively: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                $pending.Push($item.FullName)
            }
        }
    }
}

function Get-ReleaseRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release file escaped its expected root: $fullPath"
    }
    return $fullPath.Substring($fullRoot.Length + 1).Replace('\', '/')
}

function Get-ReleaseStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($Stream)).Replace('-', '') }
    finally { $sha256.Dispose() }
}

$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $root 'artifacts')).TrimEnd('\')
$stageRoot = [IO.Path]::GetFullPath((Join-Path $artifactRoot "CTyunTrim-$Version"))
$zipPath = [IO.Path]::GetFullPath((Join-Path $artifactRoot "CTyunTrim-$Version.zip"))
$hashPath = [IO.Path]::GetFullPath("$zipPath.sha256")
$artifactPrefix = $artifactRoot + '\'
if (-not $stageRoot.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $zipPath.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $hashPath.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release output escaped the artifacts directory.'
}

# Recursive cleanup must never cross a junction, symbolic link, or other
# reparse point. Check nonexistent targets too: their existing ancestors are
# still walked and validated before any deletion or directory creation occurs.
Assert-NoReparsePointInPath -Path $artifactRoot -Description 'Release artifacts path'
Assert-NoReparsePointInPath -Path $stageRoot -Description 'Release staging path'
Assert-NoReparsePointInPath -Path $zipPath -Description 'Release archive path'
Assert-NoReparsePointInPath -Path $hashPath -Description 'Release checksum path'

if (Test-Path -LiteralPath $stageRoot) {
    Assert-NoReparsePointInTree -Path $stageRoot -Description 'Release staging path'
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
if (Test-Path -LiteralPath $hashPath) {
    Remove-Item -LiteralPath $hashPath -Force
}

New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
Assert-NoReparsePointInPath -Path $stageRoot -Description 'Release staging path'

$allowedReleaseFiles = @(
    '.github/ISSUE_TEMPLATE/compatibility.yml',
    '.github/ISSUE_TEMPLATE/component-evidence.yml',
    '.github/workflows/powershell.yml',
    '.gitattributes',
    '.gitignore',
    'build/Build-Release.ps1',
    'CHANGELOG.md',
    'config/CTyunTrim.psd1',
    'CONTRIBUTING.md',
    'CTyunTrim.ps1',
    'DISCLAIMER.md',
    'docs/COMPONENTS.md',
    'docs/DIAGNOSTICS.md',
    'docs/RECOVERY.md',
    'docs/REFERENCE-BASELINE.md',
    'docs/REVIOS.md',
    'docs/THREAT-MODEL.md',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'src/CTyunTrim.psd1',
    'src/CTyunTrim.psm1',
    'Start-CTyunTrim.cmd',
    'tests/Invoke-CoreTrustTests.ps1',
    'tests/Invoke-CloudbaseOccupancyTests.ps1',
    'tests/Invoke-CloudbaseQuiesceTests.ps1',
    'tests/Invoke-DiagnosticTests.ps1',
    'tests/Invoke-StaticTests.ps1',
    'tests/Invoke-TaskBackupTests.ps1',
    'tools/Get-CTCloudbaseOccupancy.ps1',
    'tools/README.md'
)

$expectedFiles = @{}
foreach ($relativePath in $allowedReleaseFiles) {
    if ([string]::IsNullOrWhiteSpace($relativePath) -or [IO.Path]::IsPathRooted($relativePath) -or
        $relativePath -match '(^|/|\\)\.\.($|/|\\)') {
        throw "Unsafe release allowlist path: $relativePath"
    }
    $normalizedRelativePath = $relativePath.Replace('\', '/')
    if ($expectedFiles.ContainsKey($normalizedRelativePath)) { throw "Duplicate release source path: $normalizedRelativePath" }
    $source = [IO.Path]::GetFullPath((Join-Path $root ($normalizedRelativePath.Replace('/', '\'))))
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required release source file is missing: $normalizedRelativePath" }
    Assert-NoReparsePointInPath -Path $source -Description "Release source $normalizedRelativePath"
    if ((Get-ReleaseRelativePath -Path $source -Root $root) -cne $normalizedRelativePath) {
        throw "Release source path casing or normalization differs from its allowlist entry: $normalizedRelativePath"
    }
    $expectedFiles[$normalizedRelativePath] = $source

    $destination = Join-Path $stageRoot ($normalizedRelativePath.Replace('/', '\'))
    $destinationParent = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
    }
    Assert-NoReparsePointInPath -Path $destination -Description "Release destination $normalizedRelativePath"
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

$stagedFiles = @(Get-ChildItem -LiteralPath $stageRoot -Recurse -Force -File)
$stagedRelativePaths = @($stagedFiles | ForEach-Object { Get-ReleaseRelativePath -Path $_.FullName -Root $stageRoot } | Sort-Object)
$expectedRelativePaths = @($expectedFiles.Keys | Sort-Object)
if (($stagedRelativePaths -join "`n") -cne ($expectedRelativePaths -join "`n")) {
    throw 'Release staging file set differs from the explicit source allowlist.'
}
foreach ($relativePath in $expectedRelativePaths) {
    $segments = @($relativePath -split '/')
    $extension = [IO.Path]::GetExtension($relativePath)
    if ($segments -contains 'artifacts' -or $segments -contains 'runs' -or $segments -contains 'quarantine' -or
        $extension -in @('.reg', '.cer', '.clixml', '.wfw') -or [IO.Path]::GetFileName($relativePath) -ieq 'LGPO.exe') {
        throw "Forbidden file entered the release staging allowlist: $relativePath"
    }
    $stagedPath = Join-Path $stageRoot ($relativePath.Replace('/', '\'))
    $sourceHash = (Get-FileHash -LiteralPath $expectedFiles[$relativePath] -Algorithm SHA256).Hash
    $stagedHash = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash
    if ($sourceHash -ne $stagedHash) { throw "Staged release file differs from source: $relativePath" }
}

Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $zipPath -CompressionLevel Optimal
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $fileEntries = @($zip.Entries | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })
    $zipRelativePaths = @($fileEntries | ForEach-Object { $_.FullName.Replace('\', '/') } | Sort-Object)
    if (($zipRelativePaths -join "`n") -cne ($expectedRelativePaths -join "`n")) {
        throw 'Release ZIP file set differs from the explicit source allowlist.'
    }
    if (@($zipRelativePaths | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) {
        throw 'Release ZIP contains duplicate file entries.'
    }
    foreach ($entry in $fileEntries) {
        $relativePath = $entry.FullName.Replace('\', '/')
        $stream = $entry.Open()
        try { $entryHash = Get-ReleaseStreamSha256 -Stream $stream }
        finally { $stream.Dispose() }
        $sourceHash = (Get-FileHash -LiteralPath $expectedFiles[$relativePath] -Algorithm SHA256).Hash
        if ($entryHash -ne $sourceHash) { throw "Release ZIP entry differs from source: $relativePath" }
    }
}
finally { $zip.Dispose() }
$hash = Get-FileHash -LiteralPath $zipPath -Algorithm SHA256
$hashLine = "$($hash.Hash)  $([IO.Path]::GetFileName($zipPath))"
$temporaryHashPath = Join-Path $artifactRoot ('.sha256-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    $hashLine | Set-Content -LiteralPath $temporaryHashPath -Encoding ASCII
    Assert-NoReparsePointInPath -Path $hashPath -Description 'Release checksum path'
    Move-Item -LiteralPath $temporaryHashPath -Destination $hashPath -ErrorAction Stop
}
finally {
    if (Test-Path -LiteralPath $temporaryHashPath) { Remove-Item -LiteralPath $temporaryHashPath -Force }
}

[PSCustomObject]@{
    Archive = $zipPath
    SHA256  = $hash.Hash
}
