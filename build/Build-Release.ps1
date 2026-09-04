#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$')]
    [string]$Version = '0.1.0'
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

$include = @(
    '.github',
    'build',
    'config',
    'docs',
    'src',
    'tests',
    'tools',
    '.gitattributes',
    '.gitignore',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'CTyunTrim.ps1',
    'DISCLAIMER.md',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'Start-CTyunTrim.cmd'
)

foreach ($entry in $include) {
    $source = Join-Path $root $entry
    if (Test-Path -LiteralPath $source) {
        Assert-NoReparsePointInPath -Path $source -Description "Release source $entry"
        if (Test-Path -LiteralPath $source -PathType Container) {
            Assert-NoReparsePointInTree -Path $source -Description "Release source $entry"
        }
        Copy-Item -LiteralPath $source -Destination $stageRoot -Recurse -Force
    }
}

Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $zipPath -CompressionLevel Optimal
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
