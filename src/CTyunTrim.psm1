#requires -Version 5.1

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:CTyunTrimVersion = '0.1.4-Diagnostic'
$script:GuardDebugger = "$env:SystemRoot\System32\cmd.exe /d /c exit 0"
$script:GuardOwner = 'CTyunTrim'
$script:VendorPattern = 'ctyun|ecloud|clink|clipa|cloudshare|tianyicloud|chinatelecom|china telecom'
$script:ApprovedManifestSha256 = 'A10C030E27242D10D165EB4F2B2F06654B2346B3057733C8A33D8A7C8CE210D8'
$script:ApprovedCoreProfileVersion = 'ctyun-win11-26100-26200-clipa-2.1.0.0-balloon-1b821f55'
$script:ApprovedPinnedCoreIdentity = @{
    Name                     = 'BalloonService'
    ExpectedImage            = 'C:\Program Files (x86)\ctyun\clink\drivers\Balloon\blnsvr.exe'
    ExpectedSha256           = '1B821F556FFC8F998196CDBFEE6D84846600D39EB1B584D182BFCC5AB6DFCD4E'
    ExpectedSignerThumbprint = '301C73596BAC4FE8EE33487687BD75FCC307FFC6'
    ExpectedSignerSubject    = 'CN=Red Hat Inc., OU=Dev, O=virtio-win'
    ExpectedSignerIssuer     = 'CN=Red Hat Inc., OU=Dev, O=virtio-win'
}
# Microsoft Security Compliance Toolkit LGPO.zip, download id 55319.
# Package SHA256: CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55
$script:ApprovedLgpoSha256 = @('0C97F29543418B30340C4FF5D930D31E6196DD59C2CC74B6B890FA7B90C910C7')
$script:ApprovedLgpoVersion = '3.0.2004.13001'
$script:ApprovedRoots = @{
    CTyun      = 'C:\Program Files (x86)\ctyun'
    PublicData = 'C:\Users\Public\Documents\mirror'
    Cloudbase  = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init'
    Drivers    = 'C:\Windows\System32\drivers'
    PublicDesk = 'C:\Users\Public\Desktop'
}
$script:ApprovedExecutionGuards = @(
    'ExternalLaunch.exe',
    'CloudUpdate.exe',
    'ecloud_img_conf.exe',
    'TaskAgentDetect.exe',
    'TaskLaunch.exe',
    'ecloud_Launch_FullSetup_103010306.exe'
)
$script:DiagnosticEnabled = $false
$script:DiagnosticEvents = New-Object Collections.ArrayList
$script:LastPreflightResult = $null
$script:LastRunId = $null
$script:DiagnosticInvocationId = $null
$script:DiagnosticMode = $null

function Initialize-CTDiagnosticState {
    param(
        [bool]$Enabled,
        [Parameter(Mandatory = $true)][string]$Mode
    )

    $script:DiagnosticEnabled = $Enabled
    $script:DiagnosticEvents = New-Object Collections.ArrayList
    $script:LastPreflightResult = $null
    $script:LastRunId = $null
    $script:DiagnosticInvocationId = [guid]::NewGuid().ToString('N')
    $script:DiagnosticMode = $Mode
    if ($Enabled) {
        Add-CTDiagnosticEvent -Level 'Info' -Stage 'Invocation' -Message "Started $Mode"
    }
}

function Add-CTDiagnosticEvent {
    param(
        [ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info',
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data = @{}
    )

    if (-not $script:DiagnosticEnabled) { return }
    try {
        [void]$script:DiagnosticEvents.Add([PSCustomObject]@{
            Timestamp = (Get-Date).ToString('o')
            Level     = $Level
            Stage     = $Stage
            Message   = $Message
            Data      = $Data
        })
    }
    catch { }
}

function Get-CTNormalizedTextHash {
    param([Parameter(Mandatory = $true)][string]$Path)

    $text = [IO.File]::ReadAllText((ConvertTo-CTFullPath -Path $Path))
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $encoding = New-Object Text.UTF8Encoding($false)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $encoding.GetBytes($text)
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertFrom-CTUtf8Base64 {
    param([Parameter(Mandatory = $true)][string]$Value)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
}

function Get-CTPropertyValue {
    param(
        [PSObject]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-CTEncodedRemovalFiles {
    param([Parameter(Mandatory = $true)][hashtable]$Manifest)
    if (-not $Manifest.ContainsKey('EncodedFiles')) {
        return @()
    }

    return @($Manifest.EncodedFiles | ForEach-Object {
        Join-Path ([string]$_.Parent) (ConvertFrom-CTUtf8Base64 -Value ([string]$_.Utf8NameBase64))
    })
}

function Test-CTCertificateVendorCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Certificate,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest
    )

    $text = "$($Certificate.Subject)`n$($Certificate.Issuer)"
    if ($text -match $Manifest.CertificateAuditPattern) {
        return $true
    }

    if ($Manifest.ContainsKey('CertificateAuditTermsBase64')) {
        foreach ($encodedTerm in $Manifest.CertificateAuditTermsBase64) {
            $term = ConvertFrom-CTUtf8Base64 -Value ([string]$encodedTerm)
            if ($text.IndexOf($term, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
        }
    }

    return $false
}

function ConvertTo-CTFullPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    return [IO.Path]::GetFullPath($expanded).TrimEnd('\')
}

function Test-CTIsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CTOperatingSystem {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($null -eq $os) {
        $version = [Environment]::OSVersion.Version
        return [PSCustomObject]@{
            Caption        = 'Windows'
            Version        = $version.ToString()
            Build          = $version.Build
            Architecture   = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
            LastBootUpTime = $null
            ComputerName   = $env:COMPUTERNAME
        }
    }
    $build = 0
    [void][int]::TryParse([string]$os.BuildNumber, [ref]$build)

    [PSCustomObject]@{
        Caption        = $os.Caption
        Version        = $os.Version
        Build          = $build
        Architecture   = $os.OSArchitecture
        LastBootUpTime = $os.LastBootUpTime
        ComputerName   = $env:COMPUTERNAME
    }
}

function Get-CTManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = ConvertTo-CTFullPath -Path $Path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Manifest not found: $fullPath"
    }

    return Import-PowerShellDataFile -LiteralPath $fullPath
}

function Test-CTPathIsProtected {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Candidate,

        [Parameter(Mandatory = $true)]
        [string[]]$ProtectedPaths
    )

    $candidatePath = ConvertTo-CTFullPath -Path $Candidate
    foreach ($protected in $ProtectedPaths) {
        $protectedPath = ConvertTo-CTFullPath -Path $protected
        if ($candidatePath.Equals($protectedPath, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }

        $candidatePrefix = $candidatePath + '\'
        if ($protectedPath.StartsWith($candidatePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }

        $protectedPrefix = $protectedPath + '\'
        if ($candidatePath.StartsWith($protectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Test-CTPathWithinRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [switch]$AllowEqual
    )

    $fullPath = ConvertTo-CTFullPath -Path $Path
    $fullRoot = ConvertTo-CTFullPath -Path $Root
    if ($AllowEqual -and $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-CTPathHasReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    $current = ConvertTo-CTFullPath -Path $Path
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $true
            }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }
    return $false
}

function Set-CTRunDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $ownerSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($ownerSid)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inheritance, $propagation, $allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-CTRunFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $ownerSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($ownerSid)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-CTyunTrimManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    $errors = New-Object Collections.Generic.List[string]
    $manifestLock = $null
    try {
        $fullManifestPath = ConvertTo-CTFullPath -Path $ManifestPath
        if (Test-CTPathHasReparsePoint -Path $fullManifestPath) {
            throw "Manifest path has a reparse-point ancestor: $fullManifestPath"
        }
        $manifestLock = [IO.File]::Open($fullManifestPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $manifestHash = Get-CTNormalizedTextHash -Path $fullManifestPath
        if ($manifestHash -ne $script:ApprovedManifestSha256) {
            $errors.Add("Manifest content is not the immutable CTyunTrim reference profile. Expected $($script:ApprovedManifestSha256), got $manifestHash.")
        }
        $manifest = Get-CTManifest -Path $fullManifestPath
    }
    catch {
        return [PSCustomObject]@{
            Valid  = $false
            Errors = @("Manifest could not be read safely: $($_.Exception.Message)")
            Manifest = $null
            ManifestHash = $null
        }
    }
    finally {
        if ($null -ne $manifestLock) { $manifestLock.Dispose() }
    }

    $requiredKeys = @(
        'SchemaVersion', 'ProfileName', 'SupportedBuilds', 'Roots', 'CoreFingerprint', 'Preserve',
        'ExecutionGuards', 'ScheduledTasks', 'Processes', 'Services', 'DriverServices',
        'RunValues', 'Directories', 'Files', 'EncodedFiles', 'PublicDataDirectories',
        'PublicDataPreserve', 'WsusPolicy', 'KnownCertificates',
        'CertificateAuditPattern', 'FirewallPrograms', 'DiscoverOnlyPaths'
    )
    foreach ($required in $requiredKeys) {
        if (-not $manifest.ContainsKey($required)) {
            $errors.Add("Missing manifest key: $required")
        }
    }

    if ($errors.Count -eq 0) {
        if ([string]$manifest.SchemaVersion -ne '1.0') {
            $errors.Add("Unsupported manifest schema: $($manifest.SchemaVersion)")
        }
        foreach ($rootName in @('CTyun', 'PublicData', 'Cloudbase', 'Drivers', 'PublicDesk')) {
            if (-not $manifest.Roots.ContainsKey($rootName) -or [string]::IsNullOrWhiteSpace([string]$manifest.Roots[$rootName])) {
                $errors.Add("Missing manifest root: $rootName")
            }
            elseif (-not (ConvertTo-CTFullPath -Path ([string]$manifest.Roots[$rootName])).Equals((ConvertTo-CTFullPath -Path ([string]$script:ApprovedRoots[$rootName])), [StringComparison]::OrdinalIgnoreCase)) {
                $errors.Add("Manifest root differs from the immutable approved root: $rootName / $($manifest.Roots[$rootName])")
            }
        }
        foreach ($preserveName in @('Services', 'Drivers', 'Paths', 'RequiredPaths')) {
            if (-not $manifest.Preserve.ContainsKey($preserveName)) {
                $errors.Add("Missing Preserve key: $preserveName")
            }
        }
    }

    if ($errors.Count -eq 0) {
        $protectedPaths = @($manifest.Preserve.Paths) + @($manifest.PublicDataPreserve) + @('C:\Windows\System32\drivers\FileCrypt.sys')
        $removePaths = @($manifest.Directories) + @($manifest.Files) + @(Get-CTEncodedRemovalFiles -Manifest $manifest) + @($manifest.PublicDataDirectories)

        foreach ($path in $removePaths) {
            if ([string]::IsNullOrWhiteSpace([string]$path)) {
                $errors.Add('Removal path is empty.')
                continue
            }

            if ([WildcardPattern]::ContainsWildcardCharacters([string]$path)) {
                $errors.Add("Removal path contains a wildcard: $path")
                continue
            }

            try {
                $fullPath = ConvertTo-CTFullPath -Path ([string]$path)
                $rootPath = [IO.Path]::GetPathRoot($fullPath).TrimEnd('\')
                if ($fullPath.TrimEnd('\').Equals($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
                    $errors.Add("Removal path resolves to a drive root: $path")
                }

                if (Test-CTPathIsProtected -Candidate $fullPath -ProtectedPaths $protectedPaths) {
                    $errors.Add("Removal path equals or contains a protected path: $path")
                }
            }
            catch {
                $errors.Add("Removal path cannot be normalized: $path ($($_.Exception.Message))")
            }
        }

        foreach ($path in $manifest.Directories) {
            $valid = (Test-CTPathWithinRoot -Path $path -Root $manifest.Roots.CTyun) -or
                (Test-CTPathWithinRoot -Path $path -Root $manifest.Roots.Cloudbase -AllowEqual)
            if (-not $valid) { $errors.Add("Directory removal path is outside approved roots: $path") }
        }
        foreach ($path in $manifest.Files) {
            $valid = (Test-CTPathWithinRoot -Path $path -Root $manifest.Roots.CTyun) -or
                (Test-CTPathWithinRoot -Path $path -Root $manifest.Roots.Drivers)
            if (-not $valid) { $errors.Add("File removal path is outside approved roots: $path") }
        }
        foreach ($path in $manifest.PublicDataDirectories) {
            if (-not (Test-CTPathWithinRoot -Path $path -Root $manifest.Roots.PublicData)) {
                $errors.Add("Public-data removal path is outside its approved root: $path")
            }
        }
        foreach ($path in $manifest.Preserve.Paths) {
            if (-not (Test-CTPathWithinRoot -Path $path -Root $manifest.Roots.CTyun)) {
                $errors.Add("Protected path is outside CTyun root: $path")
            }
        }
        foreach ($path in $manifest.PublicDataPreserve) {
            if (-not (Test-CTPathWithinRoot -Path $path -Root $manifest.Roots.PublicData)) {
                $errors.Add("Protected public-data path is outside its approved root: $path")
            }
        }
        foreach ($encodedFile in $manifest.EncodedFiles) {
            try {
                $decodedName = ConvertFrom-CTUtf8Base64 -Value ([string]$encodedFile.Utf8NameBase64)
                if (-not (ConvertTo-CTFullPath -Path ([string]$encodedFile.Parent)).Equals((ConvertTo-CTFullPath -Path $manifest.Roots.PublicDesk), [StringComparison]::OrdinalIgnoreCase)) {
                    $errors.Add("Encoded file parent is not the approved public desktop: $($encodedFile.Parent)")
                }
                if ([string]::IsNullOrWhiteSpace($decodedName) -or $decodedName -in @('.', '..') -or [IO.Path]::GetFileName($decodedName) -ne $decodedName -or $decodedName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                    $errors.Add('Encoded removal filename is not a single safe leaf name.')
                }
            }
            catch {
                $errors.Add("Invalid encoded removal filename: $($_.Exception.Message)")
            }
        }

        foreach ($service in @($manifest.Services) + @($manifest.DriverServices)) {
            if ([string]::IsNullOrWhiteSpace([string]$service.Name) -or [string]::IsNullOrWhiteSpace([string]$service.ExpectedImage)) {
                $errors.Add('Every service removal entry requires Name and ExpectedImage.')
            }
        }

        if ([string]$manifest.CoreFingerprint.ProfileVersion -ne $script:ApprovedCoreProfileVersion) {
            $errors.Add("Unsupported core fingerprint: $($manifest.CoreFingerprint.ProfileVersion)")
        }
        foreach ($fingerprintKey in @('Services', 'Drivers')) {
            if (-not $manifest.CoreFingerprint.ContainsKey($fingerprintKey)) {
                $errors.Add("Missing CoreFingerprint key: $fingerprintKey")
            }
        }
        $pinnedCoreEntries = New-Object Collections.Generic.List[object]
        $pinFields = @('ExpectedSha256', 'ExpectedSignerThumbprint', 'ExpectedSignerSubject', 'ExpectedSignerIssuer')
        if ($manifest.CoreFingerprint.ContainsKey('Services')) {
            foreach ($service in $manifest.CoreFingerprint.Services) {
                if ([string]::IsNullOrWhiteSpace([string]$service.Name) -or [string]::IsNullOrWhiteSpace([string]$service.ExpectedImage)) {
                    $errors.Add('Every core service fingerprint requires Name and ExpectedImage.')
                }
                elseif (-not (Test-CTPathWithinRoot -Path $service.ExpectedImage -Root $manifest.Roots.CTyun)) {
                    $errors.Add("Core service image is outside the immutable CTyun root: $($service.Name) / $($service.ExpectedImage)")
                }
                $trustMode = [string](Get-CTPropertyValue -InputObject $service -Name 'TrustMode')
                if ($trustMode -eq 'PinnedHashAndSigner') {
                    $pinnedCoreEntries.Add($service)
                    if (-not [string]::Equals([string]$service.Name, [string]$script:ApprovedPinnedCoreIdentity.Name, [StringComparison]::Ordinal) -or
                        -not [string]::Equals([string]$service.ExpectedImage, [string]$script:ApprovedPinnedCoreIdentity.ExpectedImage, [StringComparison]::OrdinalIgnoreCase)) {
                        $errors.Add("PinnedHashAndSigner is approved only for the exact BalloonService image: $($service.Name) / $($service.ExpectedImage)")
                    }
                    if ([string]$service.ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$' -or
                        -not [string]::Equals([string]$service.ExpectedSha256, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
                        $errors.Add("Invalid or unapproved pinned SHA256 for core service: $($service.Name)")
                    }
                    if ([string]$service.ExpectedSignerThumbprint -notmatch '^[0-9A-Fa-f]{40}$' -or
                        -not [string]::Equals([string]$service.ExpectedSignerThumbprint, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSignerThumbprint, [StringComparison]::OrdinalIgnoreCase)) {
                        $errors.Add("Invalid or unapproved pinned signer thumbprint for core service: $($service.Name)")
                    }
                    if (-not [string]::Equals([string]$service.ExpectedSignerSubject, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSignerSubject, [StringComparison]::Ordinal) -or
                        -not [string]::Equals([string]$service.ExpectedSignerIssuer, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSignerIssuer, [StringComparison]::Ordinal)) {
                        $errors.Add("Invalid or unapproved pinned signer identity for core service: $($service.Name)")
                    }
                }
                elseif ($trustMode -eq 'AuthenticodeValidAtBaseline') {
                    foreach ($pinField in $pinFields) {
                        if ($service.ContainsKey($pinField)) {
                            $errors.Add("AuthenticodeValidAtBaseline core service contains a forbidden pin field: $($service.Name) / $pinField")
                        }
                    }
                }
                else {
                    $errors.Add("Unsupported core service trust mode: $($service.Name) / $trustMode")
                }
            }
            $fingerprintNames = @($manifest.CoreFingerprint.Services | ForEach-Object { [string]$_.Name } | Sort-Object)
            $preservedNames = @($manifest.Preserve.Services | ForEach-Object { [string]$_ } | Sort-Object)
            if (($fingerprintNames -join "`n") -cne ($preservedNames -join "`n")) {
                $errors.Add('Core service fingerprint names do not exactly match Preserve.Services.')
            }
            $duplicateNames = @($manifest.CoreFingerprint.Services | ForEach-Object { [string]$_.Name } | Group-Object | Where-Object { $_.Count -gt 1 })
            if ($duplicateNames.Count -gt 0) {
                $errors.Add("Duplicate core service fingerprints: $($duplicateNames.Name -join ', ')")
            }
        }
        if ($manifest.CoreFingerprint.ContainsKey('Drivers')) {
            foreach ($driver in $manifest.CoreFingerprint.Drivers) {
                if ([string]::IsNullOrWhiteSpace([string]$driver.Name) -or [string]::IsNullOrWhiteSpace([string]$driver.ExpectedImage)) {
                    $errors.Add('Every core driver fingerprint requires Name and ExpectedImage.')
                }
                else {
                    $validCoreDriver = (Test-CTPathWithinRoot -Path $driver.ExpectedImage -Root $manifest.Roots.CTyun) -or
                        (Test-CTPathWithinRoot -Path $driver.ExpectedImage -Root $manifest.Roots.Drivers)
                    if (-not $validCoreDriver) {
                        $errors.Add("Core driver image is outside immutable approved roots: $($driver.Name) / $($driver.ExpectedImage)")
                    }
                }
                $trustMode = [string](Get-CTPropertyValue -InputObject $driver -Name 'TrustMode')
                if ($trustMode -ne 'AuthenticodeValidAtBaseline') {
                    $errors.Add("Core drivers must use AuthenticodeValidAtBaseline trust: $($driver.Name) / $trustMode")
                }
                foreach ($pinField in $pinFields) {
                    if ($driver.ContainsKey($pinField)) {
                        $errors.Add("Core driver contains a forbidden pin field: $($driver.Name) / $pinField")
                    }
                }
            }
            $fingerprintNames = @($manifest.CoreFingerprint.Drivers | ForEach-Object { [string]$_.Name } | Sort-Object)
            $preservedNames = @($manifest.Preserve.Drivers | ForEach-Object { [string]$_ } | Sort-Object)
            if (($fingerprintNames -join "`n") -cne ($preservedNames -join "`n")) {
                $errors.Add('Core driver fingerprint names do not exactly match Preserve.Drivers.')
            }
            $duplicateNames = @($manifest.CoreFingerprint.Drivers | ForEach-Object { [string]$_.Name } | Group-Object | Where-Object { $_.Count -gt 1 })
            if ($duplicateNames.Count -gt 0) {
                $errors.Add("Duplicate core driver fingerprints: $($duplicateNames.Name -join ', ')")
            }
        }
        if ($pinnedCoreEntries.Count -ne 1) {
            $errors.Add("Exactly one approved PinnedHashAndSigner core entry is required; found $($pinnedCoreEntries.Count).")
        }

        foreach ($service in $manifest.Services) {
            $validImage = (Test-CTPathWithinRoot -Path $service.ExpectedImage -Root $manifest.Roots.CTyun) -or
                (Test-CTPathWithinRoot -Path $service.ExpectedImage -Root $manifest.Roots.Cloudbase)
            if (-not $validImage) { $errors.Add("Service image is outside approved roots: $($service.Name) / $($service.ExpectedImage)") }
        }
        foreach ($driver in $manifest.DriverServices) {
            $validImage = (Test-CTPathWithinRoot -Path $driver.ExpectedImage -Root $manifest.Roots.CTyun) -or
                (Test-CTPathWithinRoot -Path $driver.ExpectedImage -Root $manifest.Roots.Drivers)
            if (-not $validImage) { $errors.Add("Driver image is outside approved roots: $($driver.Name) / $($driver.ExpectedImage)") }
        }

        $protectedServiceNames = @($manifest.Preserve.Services) + @('RpcSs', 'PlugPlay', 'Dhcp')
        foreach ($service in $manifest.Services) {
            if ($protectedServiceNames -contains [string]$service.Name) { $errors.Add("Protected service appears in removal entries: $($service.Name)") }
        }
        $protectedDriverNames = @($manifest.Preserve.Drivers) + @('FileCrypt', 'FltMgr')
        foreach ($driver in $manifest.DriverServices) {
            if ($protectedDriverNames -contains [string]$driver.Name) { $errors.Add("Protected driver appears in removal entries: $($driver.Name)") }
        }

        foreach ($certificate in @($manifest.KnownCertificates)) {
            if ([string]$certificate.Thumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
                $errors.Add("Invalid certificate thumbprint: $($certificate.Thumbprint)")
            }
        }

        $wsusKeysPresent = $true
        foreach ($required in @('MachineKey', 'Values', 'AuKey', 'AuValues', 'PreserveValues')) {
            if (-not $manifest.WsusPolicy.ContainsKey($required)) {
                $errors.Add("Missing WsusPolicy key: $required")
                $wsusKeysPresent = $false
            }
        }
        if ($wsusKeysPresent) {
            foreach ($entry in @($manifest.WsusPolicy.Values) + @($manifest.WsusPolicy.AuValues)) {
                if ([string]::IsNullOrWhiteSpace([string]$entry.Name) -or [string]$entry.Type -notin @('String', 'DWord') -or -not $entry.ContainsKey('Value')) {
                    $errors.Add('Every WSUS signature entry requires Name, String/DWord Type and Value.')
                }
            }
        }

        foreach ($image in $manifest.ExecutionGuards) {
            if ([IO.Path]::GetFileName([string]$image) -ne [string]$image -or [string]$image -notmatch '(?i)\.exe$') {
                $errors.Add("Execution guard is not a safe EXE basename: $image")
            }
        }
        if ((@($manifest.ExecutionGuards) -join "`n") -cne ($script:ApprovedExecutionGuards -join "`n")) {
            $errors.Add('ExecutionGuards differs from the immutable approved executable list.')
        }
        foreach ($task in $manifest.ScheduledTasks) {
            if ([string]::IsNullOrWhiteSpace([string]$task.Name) -or
                [string]::IsNullOrWhiteSpace([string]$task.TaskPath) -or
                [string]::IsNullOrWhiteSpace([string]$task.ExpectedImage)) {
                $errors.Add('Every scheduled-task entry requires Name, TaskPath and ExpectedImage.')
                continue
            }
            if ([WildcardPattern]::ContainsWildcardCharacters([string]$task.Name) -or
                [string]$task.Name -match '[\\/]' -or
                [IO.Path]::GetFileName([string]$task.Name) -ne [string]$task.Name) {
                $errors.Add("Scheduled task name is not an exact safe leaf name: $($task.Name)")
            }
            if ([string]$task.TaskPath -ne '\') {
                $errors.Add("Scheduled task is outside the approved root TaskPath: $($task.TaskPath)$($task.Name)")
            }
            if ([IO.Path]::GetExtension([string]$task.ExpectedImage) -ine '.exe') {
                $errors.Add("Scheduled task image is not an EXE: $($task.Name) / $($task.ExpectedImage)")
            }
            $validTaskImage = (Test-CTPathWithinRoot -Path $task.ExpectedImage -Root $manifest.Roots.CTyun) -or
                (Test-CTPathWithinRoot -Path $task.ExpectedImage -Root $manifest.Roots.Cloudbase)
            if (-not $validTaskImage) {
                $errors.Add("Scheduled task image is outside immutable approved roots: $($task.Name) / $($task.ExpectedImage)")
            }
        }
        foreach ($program in $manifest.FirewallPrograms) {
            if (-not (Test-CTPathWithinRoot -Path $program -Root $manifest.Roots.CTyun)) {
                $errors.Add("Firewall program is outside CTyun root: $program")
            }
        }

        $duplicateGroups = @(
            @{ Name = 'ExecutionGuards'; Values = @($manifest.ExecutionGuards) },
            @{ Name = 'ScheduledTasks'; Values = @($manifest.ScheduledTasks | ForEach-Object { ("$($_.TaskPath)|$($_.Name)").ToUpperInvariant() }) },
            @{ Name = 'Directories'; Values = @($manifest.Directories) },
            @{ Name = 'Files'; Values = @($manifest.Files) },
            @{ Name = 'PublicDataDirectories'; Values = @($manifest.PublicDataDirectories) }
        )
        foreach ($group in $duplicateGroups) {
            $duplicates = @($group.Values | Group-Object | Where-Object { $_.Count -gt 1 })
            if ($duplicates.Count -gt 0) { $errors.Add("Duplicate entries in $($group.Name): $($duplicates.Name -join ', ')") }
        }
    }

    [PSCustomObject]@{
        Valid        = ($errors.Count -eq 0)
        Errors       = @($errors)
        Manifest     = $manifest
        ManifestHash = $manifestHash
    }
}

function Get-CTServiceByName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Driver
    )

    $className = if ($Driver) { 'Win32_SystemDriver' } else { 'Win32_Service' }
    return Get-CimInstance -ClassName $className -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $Name } |
        Select-Object -First 1
}

function Get-CTRunValue {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Entry,

        [switch]$Strict
    )

    $drive = if ($Entry.Hive -eq 'HKLM') { 'HKLM:' } else { 'HKCU:' }
    $path = Join-Path $drive $Entry.Key
    try {
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        $property = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    }
    catch {
        if ($Strict) { throw }
        return $null
    }
    $valueProperty = $property.PSObject.Properties[[string]$Entry.Name]
    if ($null -eq $valueProperty) { return $null }

    return [PSCustomObject]@{
        Hive  = $Entry.Hive
        Key   = $Entry.Key
        Name  = $Entry.Name
        Value = $valueProperty.Value
    }
}

function Test-CTRunValueOwned {
    param([Parameter(Mandatory = $true)][PSObject]$RunValue)

    return [string]$RunValue.Value -match '(?i)ctyun|ecloud|CloudLaptop'
}

function Get-CTIfEOState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Image
    )

    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$Image"
    $item = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Image    = $Image
        Present  = ($null -ne $item)
        Debugger = Get-CTPropertyValue -InputObject $item -Name 'Debugger'
        Marker   = Get-CTPropertyValue -InputObject $item -Name 'CTyunTrimGuard'
        RunId    = Get-CTPropertyValue -InputObject $item -Name 'CTyunTrimRunId'
    }
}

function Get-CTPolicyValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $path = "HKLM:\$Key"
    $item = Get-ItemProperty -LiteralPath $path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return [PSCustomObject]@{ Key = $Key; Name = $Name; Present = $false; Type = $null; Value = $null }
    }
    $registryKey = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    $kind = if ($null -ne $registryKey) { [string]$registryKey.GetValueKind($Name) } else { $null }
    return [PSCustomObject]@{ Key = $Key; Name = $Name; Present = $true; Type = $kind; Value = $item.($Name) }
}

function Get-CTWsusPolicySignature {
    param([Parameter(Mandatory = $true)][hashtable]$Manifest)

    $states = New-Object Collections.Generic.List[object]
    foreach ($entry in $Manifest.WsusPolicy.Values) {
        $state = Get-CTPolicyValue -Key $Manifest.WsusPolicy.MachineKey -Name $entry.Name
        $states.Add([PSCustomObject]@{ Expected = $entry; Actual = $state })
    }
    foreach ($entry in $Manifest.WsusPolicy.AuValues) {
        $state = Get-CTPolicyValue -Key $Manifest.WsusPolicy.AuKey -Name $entry.Name
        $states.Add([PSCustomObject]@{ Expected = $entry; Actual = $state })
    }

    $presentCount = @($states | Where-Object { $_.Actual.Present }).Count
    if ($presentCount -eq 0) {
        return [PSCustomObject]@{ Classification = 'Absent'; States = $states.ToArray() }
    }

    $matches = $true
    foreach ($state in @($states | Where-Object { $_.Actual.Present })) {
        if ([string]$state.Actual.Type -ne [string]$state.Expected.Type -or
            [string]$state.Actual.Value -ne [string]$state.Expected.Value) {
            $matches = $false
        }
    }

    return [PSCustomObject]@{
        Classification = if (-not $matches) {
            'Conflict'
        }
        elseif ($presentCount -eq $states.Count) {
            'ReferenceCTyunLoopback'
        }
        else {
            'PartialReferenceCTyunLoopback'
        }
        States         = $states.ToArray()
    }
}

function Get-CTStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $Stream.Position = 0
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($Stream)).Replace('-', '')
    }
    finally { $sha256.Dispose() }
}

function Get-CTCoreFileEvidence {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = ConvertTo-CTFullPath -Path $Path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Core binary is missing: $fullPath"
    }
    if (Test-CTPathHasReparsePoint -Path $fullPath) {
        throw "Core binary has a reparse-point ancestor: $fullPath"
    }

    $secureBefore = Test-CTSecureSourcePath -Path $fullPath
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $hashBefore = Get-CTStreamSha256 -Stream $stream
        $signature = Get-AuthenticodeSignature -LiteralPath $fullPath -ErrorAction SilentlyContinue
        $fileVersion = Get-CTNumericFileVersion -Path $fullPath
        $hashAfter = Get-CTStreamSha256 -Stream $stream
        $secureAfter = Test-CTSecureSourcePath -Path $fullPath
        if ($hashBefore -ne $hashAfter) {
            throw "Core binary changed while its identity was being inspected: $fullPath"
        }

        return [PSCustomObject]@{
            FileSha256        = $hashBefore
            FileVersion       = $fileVersion
            SignatureStatus   = if ($null -ne $signature) { [string]$signature.Status } else { $null }
            SignerThumbprint  = if (($null -ne $signature) -and ($null -ne $signature.SignerCertificate)) { [string]$signature.SignerCertificate.Thumbprint } else { $null }
            SignerSubject     = if (($null -ne $signature) -and ($null -ne $signature.SignerCertificate)) { [string]$signature.SignerCertificate.Subject } else { $null }
            SignerIssuer      = if (($null -ne $signature) -and ($null -ne $signature.SignerCertificate)) { [string]$signature.SignerCertificate.Issuer } else { $null }
            SecureSource      = [bool]($secureBefore -and $secureAfter)
        }
    }
    finally { $stream.Dispose() }
}

function Test-CTCoreBinaryTrust {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Entry,
        [Parameter(Mandatory = $true)][PSObject]$Evidence
    )

    $trustMode = [string](Get-CTPropertyValue -InputObject $Entry -Name 'TrustMode')
    $fileSha256 = [string](Get-CTPropertyValue -InputObject $Evidence -Name 'FileSha256')
    $signatureStatus = [string](Get-CTPropertyValue -InputObject $Evidence -Name 'SignatureStatus')
    $signerThumbprint = [string](Get-CTPropertyValue -InputObject $Evidence -Name 'SignerThumbprint')
    $signerSubject = [string](Get-CTPropertyValue -InputObject $Evidence -Name 'SignerSubject')
    $signerIssuer = [string](Get-CTPropertyValue -InputObject $Evidence -Name 'SignerIssuer')
    $secureValue = Get-CTPropertyValue -InputObject $Evidence -Name 'SecureSource'
    $secureSource = ($secureValue -is [bool]) -and ($secureValue -eq $true)
    $signerPresent = -not [string]::IsNullOrWhiteSpace($signerThumbprint) -and
        -not [string]::IsNullOrWhiteSpace($signerSubject) -and
        -not [string]::IsNullOrWhiteSpace($signerIssuer)

    $hashMatches = $null
    $signerMatches = $null
    $signatureStatusAllowed = $false
    $policyApproved = $false
    $failureCode = 'UnsupportedTrustMode'

    if (-not $secureSource) {
        $failureCode = 'UnsafeSource'
    }
    elseif ($trustMode -eq 'AuthenticodeValidAtBaseline') {
        $unexpectedPin = $false
        foreach ($pinField in @('ExpectedSha256', 'ExpectedSignerThumbprint', 'ExpectedSignerSubject', 'ExpectedSignerIssuer')) {
            if ($Entry.ContainsKey($pinField)) { $unexpectedPin = $true }
        }
        $policyApproved = -not $unexpectedPin
        $signerMatches = $signerPresent
        $signatureStatusAllowed = $signatureStatus -eq 'Valid'
        if (-not $policyApproved) { $failureCode = 'UnexpectedPinFields' }
        elseif (-not $signerPresent) { $failureCode = 'SignerMissing' }
        elseif (-not $signatureStatusAllowed) { $failureCode = 'SignatureStatusRejected' }
        else { $failureCode = 'None' }
    }
    elseif ($trustMode -eq 'PinnedHashAndSigner') {
        $policyApproved = [string]::Equals([string]$Entry.Name, [string]$script:ApprovedPinnedCoreIdentity.Name, [StringComparison]::Ordinal) -and
            [string]::Equals([string]$Entry.ExpectedImage, [string]$script:ApprovedPinnedCoreIdentity.ExpectedImage, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$Entry.ExpectedSha256, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSha256, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$Entry.ExpectedSignerThumbprint, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSignerThumbprint, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$Entry.ExpectedSignerSubject, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSignerSubject, [StringComparison]::Ordinal) -and
            [string]::Equals([string]$Entry.ExpectedSignerIssuer, [string]$script:ApprovedPinnedCoreIdentity.ExpectedSignerIssuer, [StringComparison]::Ordinal)
        $hashMatches = [string]::Equals($fileSha256, [string]$Entry.ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)
        $signerMatches = $signerPresent -and
            [string]::Equals($signerThumbprint, [string]$Entry.ExpectedSignerThumbprint, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals($signerSubject, [string]$Entry.ExpectedSignerSubject, [StringComparison]::Ordinal) -and
            [string]::Equals($signerIssuer, [string]$Entry.ExpectedSignerIssuer, [StringComparison]::Ordinal)
        $signatureStatusAllowed = $signatureStatus -in @('Valid', 'UnknownError')
        if (-not $policyApproved) { $failureCode = 'UnapprovedPinnedIdentity' }
        elseif (-not $hashMatches) { $failureCode = 'PinnedHashMismatch' }
        elseif (-not $signerPresent) { $failureCode = 'SignerMissing' }
        elseif (-not $signerMatches) { $failureCode = 'PinnedSignerMismatch' }
        elseif (-not $signatureStatusAllowed) { $failureCode = 'SignatureStatusRejected' }
        else { $failureCode = 'None' }
    }

    return [PSCustomObject]@{
        TrustMode              = $trustMode
        TrustSatisfied         = $failureCode -eq 'None'
        PolicyApproved         = $policyApproved
        SecureSource           = $secureSource
        HashMatches            = $hashMatches
        SignerPresent          = $signerPresent
        SignerMatches          = $signerMatches
        SignatureStatusAllowed = $signatureStatusAllowed
        FailureCode            = $failureCode
    }
}

function Test-CTCoreBaselineContinuity {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Entry,
        [Parameter(Mandatory = $true)][PSObject]$BaselineEntry,
        [Parameter(Mandatory = $true)][PSObject]$CurrentEvidence,
        [switch]$AllowTrustDegradation
    )

    $baselineTrust = Test-CTCoreBinaryTrust -Entry $Entry -Evidence $BaselineEntry
    $currentTrust = Test-CTCoreBinaryTrust -Entry $Entry -Evidence $CurrentEvidence
    $currentContinuity = if ([string]$Entry.TrustMode -eq 'PinnedHashAndSigner') {
        [bool]$currentTrust.TrustSatisfied
    }
    elseif ($AllowTrustDegradation) {
        [bool]$currentTrust.SecureSource -and [bool]$currentTrust.SignerPresent -and
            [string](Get-CTPropertyValue -InputObject $CurrentEvidence -Name 'SignatureStatus') -in @('Valid', 'UnknownError', 'NotTrusted')
    }
    else { [bool]$currentTrust.TrustSatisfied }
    $matches = [bool]$baselineTrust.TrustSatisfied -and $currentContinuity -and
        [string]::Equals([string](Get-CTPropertyValue -InputObject $BaselineEntry -Name 'TrustMode'), [string]$Entry.TrustMode, [StringComparison]::Ordinal) -and
        [string]::Equals([string](Get-CTPropertyValue -InputObject $BaselineEntry -Name 'ExpectedImage'), [string]$Entry.ExpectedImage, [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string](Get-CTPropertyValue -InputObject $BaselineEntry -Name 'FileSha256'), [string](Get-CTPropertyValue -InputObject $CurrentEvidence -Name 'FileSha256'), [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string](Get-CTPropertyValue -InputObject $BaselineEntry -Name 'SignerThumbprint'), [string](Get-CTPropertyValue -InputObject $CurrentEvidence -Name 'SignerThumbprint'), [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string](Get-CTPropertyValue -InputObject $BaselineEntry -Name 'SignerSubject'), [string](Get-CTPropertyValue -InputObject $CurrentEvidence -Name 'SignerSubject'), [StringComparison]::Ordinal) -and
        [string]::Equals([string](Get-CTPropertyValue -InputObject $BaselineEntry -Name 'SignerIssuer'), [string](Get-CTPropertyValue -InputObject $CurrentEvidence -Name 'SignerIssuer'), [StringComparison]::Ordinal)

    return [PSCustomObject]@{
        Matches                = $matches
        BaselineTrustSatisfied = [bool]$baselineTrust.TrustSatisfied
        CurrentTrustSatisfied  = [bool]$currentTrust.TrustSatisfied
        CurrentContinuity      = $currentContinuity
    }
}

function Get-CTyunTrimInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    $validation = Test-CTyunTrimManifest -ManifestPath $ManifestPath
    if (-not $validation.Valid) {
        throw "Manifest validation failed: $($validation.Errors -join '; ')"
    }
    $manifest = $validation.Manifest
    $os = Get-CTOperatingSystem

    $coreServices = foreach ($entry in $manifest.CoreFingerprint.Services) {
        $service = Get-CTServiceByName -Name $entry.Name
        $actualImage = if ($null -ne $service) { Get-CTImageExecutable -PathName ([string]$service.PathName) } else { $null }
        $imageExists = -not [string]::IsNullOrWhiteSpace($actualImage) -and (Test-Path -LiteralPath $actualImage -PathType Leaf)
        $hasReparsePoint = $imageExists -and (Test-CTPathHasReparsePoint -Path $actualImage)
        $evidence = if ($imageExists -and -not $hasReparsePoint) { Get-CTCoreFileEvidence -Path $actualImage } else { $null }
        $trust = if ($null -ne $evidence) { Test-CTCoreBinaryTrust -Entry $entry -Evidence $evidence } else { $null }
        [PSCustomObject]@{
            Name                = $entry.Name
            Present             = ($null -ne $service)
            State               = if ($null -ne $service) { $service.State } else { $null }
            StartMode           = if ($null -ne $service) { $service.StartMode } else { $null }
            PathName            = if ($null -ne $service) { $service.PathName } else { $null }
            ExpectedImage       = $entry.ExpectedImage
            PathExpected        = if ($null -ne $service) { Test-CTExpectedService -Service $service -ExpectedImage $entry.ExpectedImage } else { $false }
            ImageExists         = $imageExists
            HasReparsePoint     = $hasReparsePoint
            FileSha256          = if ($null -ne $evidence) { [string]$evidence.FileSha256 } else { $null }
            SignatureStatus     = if ($null -ne $evidence) { [string]$evidence.SignatureStatus } else { $null }
            SignerThumbprint    = if ($null -ne $evidence) { [string]$evidence.SignerThumbprint } else { $null }
            SignerSubject       = if ($null -ne $evidence) { [string]$evidence.SignerSubject } else { $null }
            SignerIssuer        = if ($null -ne $evidence) { [string]$evidence.SignerIssuer } else { $null }
            TrustMode           = [string]$entry.TrustMode
            SecureSource        = if ($null -ne $trust) { [bool]$trust.SecureSource } else { $false }
            HashMatches         = if ($null -ne $trust) { $trust.HashMatches } else { $null }
            SignerPresent       = if ($null -ne $trust) { [bool]$trust.SignerPresent } else { $false }
            SignerMatches       = if ($null -ne $trust) { $trust.SignerMatches } else { $null }
            TrustSatisfied      = if ($null -ne $trust) { [bool]$trust.TrustSatisfied } else { $false }
            ExpectedFileVersion = if ($entry.ContainsKey('ExpectedFileVersion')) { [string]$entry.ExpectedFileVersion } else { $null }
            FileVersion         = if ($null -ne $evidence) { [string]$evidence.FileVersion } else { $null }
        }
    }

    $removedServices = foreach ($entry in $manifest.Services) {
        $service = Get-CTServiceByName -Name $entry.Name
        [PSCustomObject]@{
            Name         = $entry.Name
            Present      = ($null -ne $service)
            State        = if ($null -ne $service) { $service.State } else { $null }
            StartMode    = if ($null -ne $service) { $service.StartMode } else { $null }
            PathName     = if ($null -ne $service) { $service.PathName } else { $null }
            PathExpected = if ($null -ne $service) { Test-CTExpectedService -Service $service -ExpectedImage $entry.ExpectedImage } else { $true }
        }
    }

    $coreDrivers = foreach ($entry in $manifest.CoreFingerprint.Drivers) {
        $driver = Get-CTServiceByName -Name $entry.Name -Driver
        $actualImage = if ($null -ne $driver) { Get-CTImageExecutable -PathName ([string]$driver.PathName) } else { $null }
        $imageExists = -not [string]::IsNullOrWhiteSpace($actualImage) -and (Test-Path -LiteralPath $actualImage -PathType Leaf)
        $hasReparsePoint = $imageExists -and (Test-CTPathHasReparsePoint -Path $actualImage)
        $evidence = if ($imageExists -and -not $hasReparsePoint) { Get-CTCoreFileEvidence -Path $actualImage } else { $null }
        $trust = if ($null -ne $evidence) { Test-CTCoreBinaryTrust -Entry $entry -Evidence $evidence } else { $null }
        [PSCustomObject]@{
            Name            = $entry.Name
            Present         = ($null -ne $driver)
            State           = if ($null -ne $driver) { $driver.State } else { $null }
            StartMode       = if ($null -ne $driver) { $driver.StartMode } else { $null }
            PathName        = if ($null -ne $driver) { $driver.PathName } else { $null }
            ExpectedImage   = $entry.ExpectedImage
            PathExpected    = if ($null -ne $driver) { Test-CTExpectedService -Service $driver -ExpectedImage $entry.ExpectedImage } else { $false }
            ImageExists     = $imageExists
            HasReparsePoint = $hasReparsePoint
            FileSha256      = if ($null -ne $evidence) { [string]$evidence.FileSha256 } else { $null }
            SignatureStatus = if ($null -ne $evidence) { [string]$evidence.SignatureStatus } else { $null }
            SignerThumbprint = if ($null -ne $evidence) { [string]$evidence.SignerThumbprint } else { $null }
            SignerSubject   = if ($null -ne $evidence) { [string]$evidence.SignerSubject } else { $null }
            SignerIssuer    = if ($null -ne $evidence) { [string]$evidence.SignerIssuer } else { $null }
            TrustMode       = [string]$entry.TrustMode
            SecureSource    = if ($null -ne $trust) { [bool]$trust.SecureSource } else { $false }
            HashMatches     = if ($null -ne $trust) { $trust.HashMatches } else { $null }
            SignerPresent   = if ($null -ne $trust) { [bool]$trust.SignerPresent } else { $false }
            SignerMatches   = if ($null -ne $trust) { $trust.SignerMatches } else { $null }
            TrustSatisfied  = if ($null -ne $trust) { [bool]$trust.TrustSatisfied } else { $false }
        }
    }

    $removedDrivers = foreach ($entry in $manifest.DriverServices) {
        $driver = Get-CTServiceByName -Name $entry.Name -Driver
        [PSCustomObject]@{
            Name         = $entry.Name
            Present      = ($null -ne $driver)
            State        = if ($null -ne $driver) { $driver.State } else { $null }
            StartMode    = if ($null -ne $driver) { $driver.StartMode } else { $null }
            PathName     = if ($null -ne $driver) { $driver.PathName } else { $null }
            PathExpected = if ($null -ne $driver) { Test-CTExpectedService -Service $driver -ExpectedImage $entry.ExpectedImage } else { $true }
        }
    }

    $processes = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Name -match $script:VendorPattern) -or
            ($_.ExecutablePath -match $script:VendorPattern)
        } |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine

    $tasks = foreach ($task in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        foreach ($action in @($task.Actions)) {
            $execute = [string](Get-CTPropertyValue -InputObject $action -Name 'Execute')
            $arguments = [string](Get-CTPropertyValue -InputObject $action -Name 'Arguments')
            if (($task.TaskName -match $script:VendorPattern) -or ($execute -match $script:VendorPattern)) {
                [PSCustomObject]@{
                    TaskName  = $task.TaskName
                    TaskPath  = $task.TaskPath
                    State     = $task.State
                    Execute   = $execute
                    Arguments = $arguments
                }
            }
        }
    }

    $nonMicrosoftTasks = foreach ($task in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        if ($task.TaskPath -like '\Microsoft\*') {
            continue
        }
        foreach ($action in @($task.Actions)) {
            $execute = [string](Get-CTPropertyValue -InputObject $action -Name 'Execute')
            $arguments = [string](Get-CTPropertyValue -InputObject $action -Name 'Arguments')
            [PSCustomObject]@{
                TaskName  = $task.TaskName
                TaskPath  = $task.TaskPath
                State     = $task.State
                Execute   = $execute
                Arguments = $arguments
            }
        }
    }

    $runValues = foreach ($entry in $manifest.RunValues) {
        $value = Get-CTRunValue -Entry $entry
        if ($null -ne $value) { $value }
    }

    $paths = foreach ($path in @($manifest.Directories) + @($manifest.Files) + @(Get-CTEncodedRemovalFiles -Manifest $manifest) + @($manifest.PublicDataDirectories)) {
        [PSCustomObject]@{
            Path   = $path
            Exists = Test-Path -LiteralPath $path
        }
    }

    $protectedPaths = foreach ($path in $manifest.Preserve.Paths) {
        [PSCustomObject]@{
            Path   = $path
            Exists = Test-Path -LiteralPath $path
        }
    }

    $discoverOnlyPaths = foreach ($path in @($manifest.DiscoverOnlyPaths)) {
        [PSCustomObject]@{
            Path   = $path
            Exists = Test-Path -LiteralPath $path
        }
    }

    $guards = foreach ($image in $manifest.ExecutionGuards) {
        Get-CTIfEOState -Image $image
    }

    $policyValues = @()
    foreach ($entry in $manifest.WsusPolicy.Values) {
        $policyValues += Get-CTPolicyValue -Key $manifest.WsusPolicy.MachineKey -Name $entry.Name
    }
    foreach ($entry in $manifest.WsusPolicy.AuValues) {
        $policyValues += Get-CTPolicyValue -Key $manifest.WsusPolicy.AuKey -Name $entry.Name
    }

    $certificateCandidates = foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\TrustedPublisher', 'Cert:\LocalMachine\My')) {
        Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
            Where-Object { Test-CTCertificateVendorCandidate -Certificate $_ -Manifest $manifest } |
            Select-Object @{Name = 'Store'; Expression = { $store } }, Subject, Issuer, Thumbprint, NotAfter
    }

    $knownCertificateState = foreach ($entry in $manifest.KnownCertificates) {
        $certificate = Get-ChildItem -Path $entry.Store -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $entry.Thumbprint } |
            Select-Object -First 1
        [PSCustomObject]@{
            Store      = $entry.Store
            Thumbprint = $entry.Thumbprint
            Present    = ($null -ne $certificate)
            Subject    = if ($null -ne $certificate) { $certificate.Subject } else { $null }
        }
    }

    $firewallPrograms = foreach ($program in $manifest.FirewallPrograms) {
        $filters = Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Program -ieq $program }
        $associatedRules = foreach ($filter in @($filters)) {
            Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $filter -ErrorAction SilentlyContinue |
                Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
        }
        [PSCustomObject]@{
            Program = $program
            Rules   = @($associatedRules).Count
        }
    }

    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, @{Name = 'SID'; Expression = { [string]$_.SID } }, LastLogon
    $cloudbaseInventoryAccount = @($localUsers | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1
    $cloudbaseInventorySid = if ($null -ne $cloudbaseInventoryAccount) { [string]$cloudbaseInventoryAccount.SID } else { $null }

    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $localAdministrators = Get-LocalGroupMember -SID $administratorsSid -ErrorAction SilentlyContinue |
        Select-Object Name, ObjectClass, PrincipalSource, @{Name = 'SID'; Expression = { [string]$_.SID } }

    $cloudbaseProfiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -like '*cloudbase-init*' -or (-not [string]::IsNullOrWhiteSpace($cloudbaseInventorySid) -and [string]$_.SID -eq $cloudbaseInventorySid) } |
        Select-Object LocalPath, SID, Loaded, Special

    $listeners = foreach ($connection in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if (($null -ne $process) -and ($process.Path -match $script:VendorPattern)) {
            [PSCustomObject]@{
                Address = $connection.LocalAddress
                Port    = $connection.LocalPort
                Process = $process.ProcessName
                Path    = $process.Path
            }
        }
    }

    $establishedConnections = foreach ($connection in Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if (($null -ne $process) -and ($process.Path -match $script:VendorPattern)) {
            [PSCustomObject]@{
                Process       = $process.ProcessName
                LocalAddress  = $connection.LocalAddress
                LocalPort     = $connection.LocalPort
                RemoteAddress = $connection.RemoteAddress
                RemotePort    = $connection.RemotePort
                Path          = $process.Path
            }
        }
    }

    $udpEndpoints = foreach ($endpoint in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
        if (($null -ne $process) -and ($process.Path -match $script:VendorPattern)) {
            [PSCustomObject]@{
                Process = $process.ProcessName
                Address = $endpoint.LocalAddress
                Port    = $endpoint.LocalPort
                Path    = $process.Path
            }
        }
    }

    $wmiCommandConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
        Select-Object Name, ExecutablePath, CommandLineTemplate)
    $wmiScriptConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
        Select-Object Name, ScriptingEngine, ScriptText)
    $wmiBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Select-Object @{Name = 'Filter'; Expression = { [string]$_.Filter } }, @{Name = 'Consumer'; Expression = { [string]$_.Consumer } })

    $ifeoDebuggers = foreach ($key in Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue) {
        $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
        $debugger = [string](Get-CTPropertyValue -InputObject $properties -Name 'Debugger')
        if (($null -ne $properties) -and -not [string]::IsNullOrWhiteSpace($debugger)) {
            [PSCustomObject]@{
                Image    = $key.PSChildName
                Debugger = $debugger
                Marker   = [string](Get-CTPropertyValue -InputObject $properties -Name 'CTyunTrimGuard')
            }
        }
    }

    $startupFiles = @(Get-ChildItem -LiteralPath @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    ) -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, Attributes, LastWriteTime)

    [PSCustomObject]@{
        SchemaVersion        = '1.0'
        ToolVersion          = $script:CTyunTrimVersion
        Timestamp            = (Get-Date).ToString('o')
        OperatingSystem      = $os
        CoreServices         = @($coreServices)
        CoreDrivers          = @($coreDrivers)
        RemovalServices      = @($removedServices)
        RemovalDrivers       = @($removedDrivers)
        VendorProcesses      = @($processes)
        VendorTasks          = @($tasks)
        NonMicrosoftTasks    = @($nonMicrosoftTasks)
        VendorRunValues      = @($runValues)
        RemovalPaths         = @($paths)
        ProtectedPaths       = @($protectedPaths)
        DiscoverOnlyPaths    = @($discoverOnlyPaths)
        ExecutionGuards      = @($guards)
        WsusPolicyValues     = @($policyValues)
        CertificateCandidates = @($certificateCandidates)
        KnownCertificates    = @($knownCertificateState)
        FirewallPrograms     = @($firewallPrograms)
        LocalUsers           = @($localUsers)
        LocalAdministrators  = @($localAdministrators)
        CloudbaseProfiles    = @($cloudbaseProfiles)
        VendorTcpListeners   = @($listeners)
        VendorTcpConnections = @($establishedConnections)
        VendorUdpEndpoints   = @($udpEndpoints)
        WmiCommandConsumers  = @($wmiCommandConsumers)
        WmiScriptConsumers   = @($wmiScriptConsumers)
        WmiBindings          = @($wmiBindings)
        IfeoDebuggers        = @($ifeoDebuggers)
        StartupFiles         = @($startupFiles)
    }
}

function Get-CTPlan {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest
    )

    $actions = New-Object Collections.Generic.List[object]
    foreach ($image in $Manifest.ExecutionGuards) {
        $actions.Add([PSCustomObject]@{ Type = 'ExecutionGuard'; Target = $image; Action = 'Ensure IFEO guard' })
    }
    $actions.Add([PSCustomObject]@{ Type = 'LocalPolicy'; Target = 'CTyun fake WSUS'; Action = 'Back up LocalGPO and clear five exact values with Microsoft-signed LGPO.exe' })
    foreach ($task in $Manifest.ScheduledTasks) {
        $actions.Add([PSCustomObject]@{ Type = 'ScheduledTask'; Target = "$($task.TaskPath)$($task.Name)"; Action = "Export and unregister only if its sole action is exactly $($task.ExpectedImage)" })
    }
    foreach ($process in $Manifest.Processes) {
        $actions.Add([PSCustomObject]@{ Type = 'ProcessStop'; Target = $process; Action = 'Stop only when the executable is inside an approved removal directory' })
    }
    foreach ($entry in $Manifest.RunValues) {
        $actions.Add([PSCustomObject]@{ Type = 'RunValue'; Target = "$($entry.Hive)\$($entry.Key)::$($entry.Name)"; Action = 'Export and remove if value is CTyun-owned' })
    }
    $actions.Add([PSCustomObject]@{ Type = 'StartupApproved'; Target = 'Known CTyun and stale WinPE entries'; Action = 'Export and remove exact StartupApproved values' })
    $actions.Add([PSCustomObject]@{ Type = 'Shortcut'; Target = 'Start menus and desktops'; Action = 'Quarantine .lnk files whose resolved target is inside a removal root' })
    foreach ($entry in $Manifest.Services) {
        $actions.Add([PSCustomObject]@{ Type = 'Service'; Target = $entry.Name; Action = 'Validate path, export, disable, stop and delete' })
    }
    foreach ($entry in $Manifest.DriverServices) {
        $actions.Add([PSCustomObject]@{ Type = 'DriverService'; Target = $entry.Name; Action = 'Validate path, export, disable and remove registration' })
    }
    foreach ($path in @($Manifest.Directories) + @($Manifest.Files) + @(Get-CTEncodedRemovalFiles -Manifest $Manifest) + @($Manifest.PublicDataDirectories)) {
        $actions.Add([PSCustomObject]@{ Type = 'Path'; Target = $path; Action = 'Move to run quarantine after protection checks' })
    }
    foreach ($certificate in $Manifest.KnownCertificates) {
        $actions.Add([PSCustomObject]@{ Type = 'Certificate'; Target = $certificate.Thumbprint; Action = 'Verify subject, export and remove exact certificate' })
    }
    foreach ($program in $Manifest.FirewallPrograms) {
        $actions.Add([PSCustomObject]@{ Type = 'Firewall'; Target = $program; Action = 'Export metadata and remove rules for exact dead program path' })
    }

    return $actions.ToArray()
}

function Get-CTDiagnosticCode {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return 'None' }
    if ($Message -match '(?i)Cloudbase profile is loaded only by the approved TaskAgentDetect') { return 'CloudbaseProfileDeferred' }
    if ($Message -match '(?i)Cloudbase.*(?:profile.*(?:loaded|Special)|hive.*mounted|loaded-profile)|loaded Cloudbase identity') { return 'CloudbaseProfileUnsafe' }
    $hasNegativeSignal = $Message -match '(?i)\b(failed|failure|mismatch|missing|unsafe|untrusted|unknown|refused|refusing|cannot|requires|still|appeared)\b|\bcould not\b|\bdoes not\b|\bdid not\b|\bnot\s+(?:running|trusted|found|available|valid|match)|\bloaded or special\b|\bprofile is loaded\b|\bcurrently loaded\b'
    if (-not $hasNegativeSignal -and $Message -match '(?i)\b(started|passed|completed|created|loaded|confirmed|recorded|reused|returned)\b') { return 'Success' }
    switch -Regex ($Message) {
        '(?i)manifest'                              { return 'ManifestValidationFailed' }
        '(?i)unsupported Windows build'             { return 'UnsupportedWindowsBuild' }
        '(?i)installation root|CTyun root'          { return 'InstallationRootMismatch' }
        '(?i)protected service|core service'        { return 'CoreServiceMismatch' }
        '(?i)protected driver|core driver'          { return 'CoreDriverMismatch' }
        '(?i)protected path|core path'              { return 'CorePathMismatch' }
        '(?i)scheduled task|TaskPath'               { return 'ScheduledTaskMismatch' }
        '(?i)Run value|Run-value|StartupApproved'   { return 'StartupEntryMismatch' }
        '(?i)IFEO|execution guard'                  { return 'ExecutionGuardMismatch' }
        '(?i)WSUS|LocalPolicy|LGPO|Group Policy'    { return 'LocalPolicyFailure' }
        '(?i)Cloudbase|cloudbase-init'              { return 'CloudbaseIdentityFailure' }
        '(?i)certificate'                           { return 'CertificateFailure' }
        '(?i)firewall'                              { return 'FirewallFailure' }
        '(?i)registry backup|registry export'       { return 'RegistryBackupFailure' }
        '(?i)reparse|junction|symbolic'              { return 'UnsafeReparsePoint' }
        '(?i)backup root|quarantine'                { return 'BackupOrQuarantineFailure' }
        '(?i)Windows PowerShell|administrator|64-bit' { return 'RuntimeRequirementFailed' }
        '(?i)explicit -Force switch'                { return 'ForceRequired' }
        '(?i)DiagnosticCannotCombineWithRestart'    { return 'DiagnosticRestartConflict' }
        '(?i)declined'                              { return 'OperationDeclined' }
        '(?i)preflight'                             { return 'PreflightFailed' }
        '(?i)reboot'                                { return 'RebootRequired' }
        default                                     { return 'OperationFailed' }
    }
}

function Get-CTDiagnosticIssueView {
    param(
        [object[]]$Messages,
        [Parameter(Mandatory = $true)][hashtable]$Manifest
    )

    $issues = New-Object Collections.Generic.List[object]
    foreach ($message in @($Messages)) {
        $text = [string]$message
        $component = 'Unclassified'
        foreach ($name in @($Manifest.Preserve.Services) + @($Manifest.Preserve.Drivers) +
            @($Manifest.Services | ForEach-Object { $_.Name }) +
            @($Manifest.DriverServices | ForEach-Object { $_.Name }) +
            @($Manifest.ScheduledTasks | ForEach-Object { $_.Name }) +
            @($Manifest.ExecutionGuards)) {
            if ($text -match [regex]::Escape([string]$name)) {
                $component = [string]$name
                break
            }
        }
        $issues.Add([PSCustomObject]@{
            Code      = Get-CTDiagnosticCode -Message $text
            Component = $component
        })
    }
    return $issues.ToArray()
}

function Get-CTDiagnosticTargetId {
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [string]$Target,
        [Parameter(Mandatory = $true)][hashtable]$Manifest
    )

    switch ($Type) {
        'Service' { if (@($Manifest.Services.Name) -contains $Target) { return "Service:$Target" } }
        'DriverService' { if (@($Manifest.DriverServices.Name) -contains $Target) { return "Driver:$Target" } }
        'ExecutionGuard' { if (@($Manifest.ExecutionGuards) -contains $Target) { return "Guard:$Target" } }
        'ScheduledTask' {
            foreach ($task in $Manifest.ScheduledTasks) {
                if ($Target -ieq "$($task.TaskPath)$($task.Name)") { return "Task:$($task.Name)" }
            }
        }
        'ProcessStop' {
            $name = ([string]$Target -split ':')[0]
            if (@($Manifest.Processes) -contains $name) { return "Process:$name" }
        }
        'Certificate' {
            for ($index = 0; $index -lt @($Manifest.KnownCertificates).Count; $index++) {
                if ([string]$Manifest.KnownCertificates[$index].Thumbprint -eq $Target) { return ('Certificate:{0:D2}' -f ($index + 1)) }
            }
        }
        'QuarantinePath' {
            $paths = @($Manifest.Directories) + @($Manifest.Files) + @(Get-CTEncodedRemovalFiles -Manifest $Manifest) + @($Manifest.PublicDataDirectories)
            for ($index = 0; $index -lt $paths.Count; $index++) {
                if ([string]$paths[$index] -ieq $Target) { return ('RemovalPath:{0:D3}' -f ($index + 1)) }
            }
            return 'Shortcut'
        }
        'LocalPolicy' { return 'LocalPolicy:CTyunLoopbackWsus' }
        'LocalUser' { return 'CloudbaseIdentity:Account' }
        'UserProfile' { return 'CloudbaseIdentity:Profile' }
        'CloudbaseIdentityEvidence' { return 'CloudbaseIdentity:Evidence' }
        'Baseline' { return 'Run:Baseline' }
        'FirewallRule' { return 'Firewall:CloudUpdateJre' }
        'NativeCommand' {
            $fileName = [IO.Path]::GetFileName([string]$Target)
            if ($fileName -in @('reg.exe', 'sc.exe', 'gpupdate.exe', 'LGPO.exe', 'cmd.exe')) { return "Command:$fileName" }
            return 'Command:Other'
        }
        'RunValue' {
            for ($index = 0; $index -lt @($Manifest.RunValues).Count; $index++) {
                if ($Target -like "*::$($Manifest.RunValues[$index].Name)") { return ('RunValue:{0:D2}' -f ($index + 1)) }
            }
            return 'StartupMetadata'
        }
    }
    return $Type
}

function Get-CTDiagnosticEnumValue {
    param(
        [string]$Value,
        [Parameter(Mandatory = $true)][string[]]$Allowed,
        [string]$Fallback = 'Unknown'
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Unavailable' }
    foreach ($candidate in $Allowed) {
        if ([string]$Value -eq $candidate) { return $candidate }
    }
    return $Fallback
}

function Get-CTDiagnosticBoundedInteger {
    param(
        [object]$Value,
        [long]$Minimum,
        [long]$Maximum
    )

    if (-not ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64])) { return $null }
    try { $number = [long]$Value } catch { return $null }
    if ($number -lt $Minimum) { return $Minimum }
    if ($number -gt $Maximum) { return $Maximum }
    return $number
}

function Get-CTDiagnosticInventoryView {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Inventory,
        [Parameter(Mandatory = $true)][hashtable]$Manifest
    )

    $coreServices = foreach ($service in @($Inventory.CoreServices)) {
        [PSCustomObject]@{
            Id               = "Service:$($service.Name)"
            Present          = [bool]$service.Present
            State            = Get-CTDiagnosticEnumValue -Value ([string]$service.State) -Allowed @('Running', 'Stopped', 'Paused', 'Start Pending', 'Stop Pending')
            StartMode        = Get-CTDiagnosticEnumValue -Value ([string]$service.StartMode) -Allowed @('Auto', 'Manual', 'Disabled')
            PathExpected     = [bool]$service.PathExpected
            ImageExists      = [bool]$service.ImageExists
            HasReparsePoint  = [bool]$service.HasReparsePoint
            SignatureStatus  = Get-CTDiagnosticEnumValue -Value ([string]$service.SignatureStatus) -Allowed @('Valid', 'UnknownError', 'NotSigned', 'HashMismatch', 'NotTrusted', 'NotSupported', 'Incompatible')
            TrustMode        = Get-CTDiagnosticEnumValue -Value ([string]$service.TrustMode) -Allowed @('AuthenticodeValidAtBaseline', 'PinnedHashAndSigner')
            SecureSource     = [bool]$service.SecureSource
            HashMatches      = if ([string]$service.TrustMode -eq 'PinnedHashAndSigner') { [bool]$service.HashMatches } else { $null }
            SignerPresent    = [bool]$service.SignerPresent
            SignerMatches    = if ([string]$service.TrustMode -eq 'PinnedHashAndSigner') { [bool]$service.SignerMatches } else { $null }
            TrustSatisfied   = [bool]$service.TrustSatisfied
            VersionMatches   = [string]::IsNullOrWhiteSpace([string]$service.ExpectedFileVersion) -or [string]$service.FileVersion -eq [string]$service.ExpectedFileVersion
        }
    }
    $coreDrivers = foreach ($driver in @($Inventory.CoreDrivers)) {
        [PSCustomObject]@{
            Id              = "Driver:$($driver.Name)"
            Present         = [bool]$driver.Present
            State           = Get-CTDiagnosticEnumValue -Value ([string]$driver.State) -Allowed @('Running', 'Stopped', 'Paused', 'Start Pending', 'Stop Pending')
            StartMode       = Get-CTDiagnosticEnumValue -Value ([string]$driver.StartMode) -Allowed @('Auto', 'Manual', 'Disabled')
            PathExpected    = [bool]$driver.PathExpected
            ImageExists     = [bool]$driver.ImageExists
            HasReparsePoint = [bool]$driver.HasReparsePoint
            SignatureStatus = Get-CTDiagnosticEnumValue -Value ([string]$driver.SignatureStatus) -Allowed @('Valid', 'UnknownError', 'NotSigned', 'HashMismatch', 'NotTrusted', 'NotSupported', 'Incompatible')
            TrustMode       = Get-CTDiagnosticEnumValue -Value ([string]$driver.TrustMode) -Allowed @('AuthenticodeValidAtBaseline', 'PinnedHashAndSigner')
            SecureSource    = [bool]$driver.SecureSource
            SignerPresent   = [bool]$driver.SignerPresent
            TrustSatisfied  = [bool]$driver.TrustSatisfied
        }
    }
    $removalServices = foreach ($service in @($Inventory.RemovalServices)) {
        [PSCustomObject]@{ Id = "Service:$($service.Name)"; Present = [bool]$service.Present; State = Get-CTDiagnosticEnumValue -Value ([string]$service.State) -Allowed @('Running', 'Stopped', 'Paused', 'Start Pending', 'Stop Pending'); PathExpected = [bool]$service.PathExpected }
    }
    $removalDrivers = foreach ($driver in @($Inventory.RemovalDrivers)) {
        [PSCustomObject]@{ Id = "Driver:$($driver.Name)"; Present = [bool]$driver.Present; State = Get-CTDiagnosticEnumValue -Value ([string]$driver.State) -Allowed @('Running', 'Stopped', 'Paused', 'Start Pending', 'Stop Pending'); PathExpected = [bool]$driver.PathExpected }
    }
    $tasks = foreach ($task in $Manifest.ScheduledTasks) {
        $matches = @($Inventory.NonMicrosoftTasks | Where-Object { $_.TaskName -ieq $task.Name -and $_.TaskPath -ieq $task.TaskPath })
        [PSCustomObject]@{ Id = "Task:$($task.Name)"; Present = ($matches.Count -gt 0); ActionCount = $matches.Count }
    }
    $paths = @($Inventory.RemovalPaths)
    $pathStates = for ($index = 0; $index -lt $paths.Count; $index++) {
        [PSCustomObject]@{ Id = ('RemovalPath:{0:D3}' -f ($index + 1)); Exists = [bool]$paths[$index].Exists }
    }
    $certificates = for ($index = 0; $index -lt @($Inventory.KnownCertificates).Count; $index++) {
        [PSCustomObject]@{ Id = ('Certificate:{0:D2}' -f ($index + 1)); Present = [bool]$Inventory.KnownCertificates[$index].Present }
    }
    $guards = foreach ($guard in @($Inventory.ExecutionGuards)) {
        [PSCustomObject]@{
            Id              = "Guard:$($guard.Image)"
            Present         = [bool]$guard.Present
            DebuggerMatches = [string]$guard.Debugger -eq $script:GuardDebugger
            MarkerMatches   = [string]$guard.Marker -eq $script:GuardOwner
        }
    }
    $cloudbaseAccount = @($Inventory.LocalUsers | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1
    $exactCloudbaseProfiles = @($Inventory.CloudbaseProfiles | Where-Object { $_.LocalPath -ieq 'C:\Users\cloudbase-init' })
    $cloudbaseProjectionSid = if ($null -ne $cloudbaseAccount) { [string]$cloudbaseAccount.SID } elseif ($exactCloudbaseProfiles.Count -eq 1) { [string]$exactCloudbaseProfiles[0].SID } else { $null }
    $cloudbaseProjectionSidProfiles = @()
    if (-not [string]::IsNullOrWhiteSpace($cloudbaseProjectionSid)) {
        $cloudbaseProjectionSidProfiles = @($Inventory.CloudbaseProfiles | Where-Object { [string]$_.SID -eq $cloudbaseProjectionSid })
    }
    elseif ($exactCloudbaseProfiles.Count -eq 0) {
        $cloudbaseProjectionSidProfiles = @($Inventory.CloudbaseProfiles)
    }
    $unexpectedCloudbaseProfileCount = @($cloudbaseProjectionSidProfiles | Where-Object { $_.LocalPath -ine 'C:\Users\cloudbase-init' }).Count
    $cloudbaseHiveMountedCount = @($exactCloudbaseProfiles | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.SID) -and (Test-Path -LiteralPath ("Registry::HKEY_USERS\$([string]$_.SID)"))
    }).Count
    $accountProfileSidMatches = if ($null -ne $cloudbaseAccount -and $exactCloudbaseProfiles.Count -eq 1) {
        [string]::Equals([string]$cloudbaseAccount.SID, [string]$exactCloudbaseProfiles[0].SID, [StringComparison]::OrdinalIgnoreCase)
    }
    else { $null }
    $currentIdentityMatches = if ($exactCloudbaseProfiles.Count -eq 1) {
        [string]::Equals([string]([Security.Principal.WindowsIdentity]::GetCurrent().User.Value), [string]$exactCloudbaseProfiles[0].SID, [StringComparison]::OrdinalIgnoreCase)
    }
    else { $null }

    return [PSCustomObject]@{
        CoreServices       = @($coreServices)
        CoreDrivers        = @($coreDrivers)
        RemovalServices    = @($removalServices)
        RemovalDrivers     = @($removalDrivers)
        ScheduledTasks     = @($tasks)
        RemovalPaths       = @($pathStates)
        ExecutionGuards    = @($guards)
        KnownCertificates  = @($certificates)
        WsusClassification = [string](Get-CTWsusPolicySignature -Manifest $Manifest).Classification
        CloudbaseAccountPresent = $null -ne $cloudbaseAccount
        CloudbaseProfileCount   = $exactCloudbaseProfiles.Count
        CloudbaseProfileLoadedCount = @($exactCloudbaseProfiles | Where-Object { [bool]$_.Loaded }).Count
        CloudbaseProfileSpecialCount = @($exactCloudbaseProfiles | Where-Object { [bool]$_.Special }).Count
        CloudbaseProfileHiveMountedCount = $cloudbaseHiveMountedCount
        CloudbaseUnexpectedProfileCount = $unexpectedCloudbaseProfileCount
        CloudbaseAccountProfileIdentityMatches = $accountProfileSidMatches
        CloudbaseCurrentIdentityMatches = $currentIdentityMatches
        VendorProcessCount      = @($Inventory.VendorProcesses).Count
        VendorTaskCount         = @($Inventory.VendorTasks).Count
        UnknownCertificateCandidateCount = @($Inventory.CertificateCandidates | Where-Object {
            @($Manifest.KnownCertificates.Thumbprint) -notcontains [string]$_.Thumbprint
        }).Count
        FirewallAllowRuleCount  = (@($Inventory.FirewallPrograms | ForEach-Object { [int]$_.Rules }) | Measure-Object -Sum).Sum
        VendorTcpListenerCount  = @($Inventory.VendorTcpListeners).Count
        VendorTcpConnectionCount = @($Inventory.VendorTcpConnections).Count
        VendorUdpEndpointCount  = @($Inventory.VendorUdpEndpoints).Count
        WmiCommandConsumerCount = @($Inventory.WmiCommandConsumers).Count
        WmiScriptConsumerCount  = @($Inventory.WmiScriptConsumers).Count
        WmiBindingCount         = @($Inventory.WmiBindings).Count
        NonMicrosoftTaskCount   = @($Inventory.NonMicrosoftTasks).Count
        StartupFileCount        = @($Inventory.StartupFiles).Count
    }
}

function Get-CTDiagnosticContextView {
    param(
        [PSObject]$Context,
        [Parameter(Mandatory = $true)][hashtable]$Manifest
    )

    if ($null -eq $Context) {
        return [PSCustomObject]@{ Bound = $false; Status = 'Stateless'; RebootNeeded = $false; OperationCount = 0; PendingCount = 0; Operations = @(); Issues = @() }
    }
    $operations = New-Object Collections.Generic.List[object]
    $allowedTypes = @('Baseline', 'ExecutionGuard', 'ScheduledTask', 'RunValue', 'ProcessStop', 'Service', 'DriverService', 'LocalPolicy', 'QuarantinePath', 'LocalUser', 'UserProfile', 'Certificate', 'FirewallRule', 'CloudbaseIdentityEvidence')
    $index = 0
    foreach ($operation in @($Context.Operations) | Select-Object -First 1000) {
        $index++
        $safeType = Get-CTDiagnosticEnumValue -Value ([string]$operation.Type) -Allowed $allowedTypes
        $operations.Add([PSCustomObject]@{
            Sequence    = $index
            Type        = $safeType
            Component   = Get-CTDiagnosticTargetId -Type $safeType -Target ([string]$operation.Target) -Manifest $Manifest
            Status      = Get-CTDiagnosticEnumValue -Value ([string]$operation.Status) -Allowed @('Pending', 'Completed')
            Reversible  = [bool]$operation.Reversible
        })
    }
    return [PSCustomObject]@{
        Bound          = $true
        Status         = Get-CTDiagnosticEnumValue -Value ([string]$Context.Status) -Allowed @('Running', 'Prepared', 'PendingReboot', 'Applied', 'Failed')
        RebootNeeded   = [bool]$Context.RebootNeeded
        OperationCount = @($Context.Operations).Count
        PendingCount   = @($Context.Operations | Where-Object { $_.Status -eq 'Pending' }).Count
        Operations     = $operations.ToArray()
        Issues         = @(Get-CTDiagnosticIssueView -Messages @($Context.Warnings) -Manifest $Manifest)
    }
}

function Get-CTDiagnosticResultView {
    param([object]$Result)

    if ($null -eq $Result) { return [PSCustomObject]@{ Available = $false } }
    $items = @($Result)
    if ($items.Count -ne 1) { return [PSCustomObject]@{ Available = $true; ItemCount = $items.Count } }
    $item = $items[0]
    $passed = Get-CTPropertyValue -InputObject $item -Name 'Passed'
    $rebootNeeded = Get-CTPropertyValue -InputObject $item -Name 'RebootNeeded'
    $warningCount = Get-CTPropertyValue -InputObject $item -Name 'WarningCount'
    return [PSCustomObject]@{
        Available     = $true
        ItemCount     = 1
        Status        = Get-CTDiagnosticEnumValue -Value ([string](Get-CTPropertyValue -InputObject $item -Name 'Status')) -Allowed @('Running', 'Prepared', 'PendingReboot', 'Applied', 'Failed')
        Passed        = if ($passed -is [bool]) { [bool]$passed } else { $null }
        RebootNeeded  = if ($rebootNeeded -is [bool]) { [bool]$rebootNeeded } else { $null }
        WarningCount  = Get-CTDiagnosticBoundedInteger -Value $warningCount -Minimum 0 -Maximum 100000
    }
}

function Get-CTDiagnosticEventView {
    param([Parameter(Mandatory = $true)][hashtable]$Manifest)

    $events = New-Object Collections.Generic.List[object]
    $allowedStages = @('Invocation', 'Manifest', 'RunContext', 'Operation', 'Confirmation', 'Preflight', 'NativeCommand', 'Apply', 'Prepare', 'Verification', 'Journal')
    $allowedTypes = @('Baseline', 'ExecutionGuard', 'ScheduledTask', 'RunValue', 'ProcessStop', 'Service', 'DriverService', 'LocalPolicy', 'QuarantinePath', 'LocalUser', 'UserProfile', 'Certificate', 'FirewallRule', 'CloudbaseIdentityEvidence', 'NativeCommand')
    $index = 0
    foreach ($event in @($script:DiagnosticEvents) | Select-Object -First 2000) {
        $index++
        $type = Get-CTDiagnosticEnumValue -Value ([string](Get-CTPropertyValue -InputObject $event.Data -Name 'Type')) -Allowed $allowedTypes
        if ($type -eq 'Unavailable') { $type = $null }
        $target = [string](Get-CTPropertyValue -InputObject $event.Data -Name 'Target')
        $exitCode = Get-CTPropertyValue -InputObject $event.Data -Name 'ExitCode'
        $durationMs = Get-CTPropertyValue -InputObject $event.Data -Name 'DurationMs'
        $pendingCount = Get-CTPropertyValue -InputObject $event.Data -Name 'PendingCount'
        $rebootNeeded = Get-CTPropertyValue -InputObject $event.Data -Name 'RebootNeeded'
        $events.Add([PSCustomObject]@{
            Sequence  = $index
            Level     = Get-CTDiagnosticEnumValue -Value ([string]$event.Level) -Allowed @('Info', 'Warning', 'Error')
            Stage     = Get-CTDiagnosticEnumValue -Value ([string]$event.Stage) -Allowed $allowedStages
            Code      = Get-CTDiagnosticCode -Message ([string]$event.Message)
            Type      = $type
            Component = if ([string]::IsNullOrWhiteSpace($type)) { 'Unclassified' } else { Get-CTDiagnosticTargetId -Type $type -Target $target -Manifest $Manifest }
            ExitCode  = Get-CTDiagnosticBoundedInteger -Value $exitCode -Minimum -1 -Maximum 65535
            DurationMs = Get-CTDiagnosticBoundedInteger -Value $durationMs -Minimum 0 -Maximum ([int]::MaxValue)
            Status     = Get-CTDiagnosticEnumValue -Value ([string](Get-CTPropertyValue -InputObject $event.Data -Name 'Status')) -Allowed @('Pending', 'Completed', 'Running', 'Prepared', 'PendingReboot', 'Applied', 'Failed')
            RebootNeeded = if ($rebootNeeded -is [bool]) { [bool]$rebootNeeded } else { $null }
            PendingCount = Get-CTDiagnosticBoundedInteger -Value $pendingCount -Minimum 0 -Maximum 100000
        })
    }
    return $events.ToArray()
}

function Write-CTNewUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
        [Parameter(Mandatory = $true)][bool]$MachineScope
    )

    $encoding = New-Object Text.UTF8Encoding($false)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $writer = New-Object IO.StreamWriter($stream, $encoding)
        try {
            $writer.Write($Content)
            $writer.Flush()
        }
        finally { $writer.Dispose() }
    }
    finally { $stream.Dispose() }
    Set-CTDiagnosticFileAcl -Path $Path -MachineScope $MachineScope
}

function Test-CTDiagnosticTextSafe {
    param([Parameter(Mandatory = $true)][string]$Text)

    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 2097152) { throw 'DiagnosticSizeLimitExceeded' }
    $forbiddenLiterals = @(
        'state.clixml', 'before.json', 'after.json', 'platform-before.json',
        '.reg', '.cer', '.wfw', 'quarantine\', 'CommandLine', 'ScriptText',
        'SignerSubject', 'Thumbprint', 'RemoteAddress', 'LocalAddress', 'MacAddress',
        'ServerAddresses', 'ProfilePath', 'MachineSid', 'AccountSid', 'ProfileSid'
    )
    foreach ($literal in $forbiddenLiterals) {
        if ($Text.IndexOf($literal, [StringComparison]::OrdinalIgnoreCase) -ge 0) { throw 'DiagnosticSanitizationFailed' }
    }
    foreach ($literal in @([string]$env:USERNAME, [string]$env:COMPUTERNAME, [string]([Environment]::GetFolderPath('UserProfile')))) {
        if (-not [string]::IsNullOrWhiteSpace($literal) -and $literal.Length -ge 3 -and
            $Text.IndexOf($literal, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'DiagnosticSanitizationFailed'
        }
    }
    foreach ($pattern in @(
        '(?i)S-1-5-21-(?:[0-9]+-){2,}[0-9]+',
        '(?i)[A-Z]:\\Users\\',
        '(?i)\\\\[^\\\s]+\\',
        '(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])',
        '(?i)(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]{1,}',
        '(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}',
        '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}',
        '(?i)(?:password|passwd|pwd|token|secret|cookie|authorization)\s*[:=]'
    )) {
        if ($Text -match $pattern) { throw 'DiagnosticSanitizationFailed' }
    }
    return $true
}

function Set-CTDiagnosticDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$MachineScope
    )

    if (-not $MachineScope) { throw 'UnsafeDiagnosticOutputPath' }
    Set-CTRunDirectoryAcl -Path $Path
}

function Set-CTDiagnosticFileAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$MachineScope
    )

    if (-not $MachineScope) { throw 'UnsafeDiagnosticOutputPath' }
    Set-CTRunFileAcl -Path $Path
}

function Initialize-CTDiagnosticOutputRoot {
    param([Parameter(Mandatory = $true)][string]$Mode)

    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or
        $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
        throw 'DiagnosticRequiresWindowsPowerShell51x64'
    }

    if (-not (Test-CTIsAdministrator)) { throw 'DiagnosticRequiresElevation' }
    $machineScope = $true
    $knownFolderBase = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $expectedBase = Join-Path ([IO.Path]::GetPathRoot([Environment]::SystemDirectory)) 'ProgramData'
    if ([string]::IsNullOrWhiteSpace($knownFolderBase) -or
        -not (ConvertTo-CTFullPath -Path $knownFolderBase).Equals((ConvertTo-CTFullPath -Path $expectedBase), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'UnsafeDiagnosticOutputPath'
    }
    $base = $knownFolderBase
    if ([string]::IsNullOrWhiteSpace($base)) { throw 'UnsafeDiagnosticOutputPath' }
    $base = ConvertTo-CTFullPath -Path $base
    $root = ConvertTo-CTFullPath -Path (Join-Path $base 'CTyunTrim\Diagnostics')
    if ($root -notmatch '^[A-Za-z]:\\' -or [WildcardPattern]::ContainsWildcardCharacters($root) -or
        $root.StartsWith('\\', [StringComparison]::Ordinal) -or $root.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        throw 'UnsafeDiagnosticOutputPath'
    }
    if (Test-CTPathHasReparsePoint -Path $root) { throw 'UnsafeDiagnosticOutputPath' }

    if (-not (Test-Path -LiteralPath $root)) {
        $missingDirectories = New-Object Collections.Generic.List[string]
        $candidate = $root
        while (-not (Test-Path -LiteralPath $candidate)) {
            $missingDirectories.Add($candidate)
            $candidate = Split-Path -Parent $candidate
            if ([string]::IsNullOrWhiteSpace($candidate)) { throw 'UnsafeDiagnosticOutputPath' }
        }
        for ($index = $missingDirectories.Count - 1; $index -ge 0; $index--) {
            New-Item -ItemType Directory -Path $missingDirectories[$index] -ErrorAction Stop | Out-Null
            Set-CTDiagnosticDirectoryAcl -Path $missingDirectories[$index] -MachineScope $machineScope
        }
    }
    elseif (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'UnsafeDiagnosticOutputPath'
    }
    if (-not (Test-CTSecureSourcePath -Path $root)) { throw 'UnsafeDiagnosticOutputPath' }
    return [PSCustomObject]@{
        Root         = $root
        MachineScope = $machineScope
        DisplayRoot  = '[CommonApplicationData]\CTyunTrim\Diagnostics'
    }
}

function Test-CTDiagnosticArchiveSafe {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Test-CTPathHasReparsePoint -Path $Path)) { throw 'DiagnosticArchiveValidationFailed' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $expectedNames = @('environment.json', 'events.jsonl', 'README.txt', 'summary.json')
        $actualNames = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        if (($actualNames -join "`n") -cne (($expectedNames | Sort-Object) -join "`n") -or
            @($zip.Entries | Group-Object { $_.FullName.ToUpperInvariant() } | Where-Object { $_.Count -gt 1 }).Count -gt 0 -or
            ($zip.Entries | Measure-Object -Property Length -Sum).Sum -gt 2097152) {
            throw 'DiagnosticArchiveValidationFailed'
        }
        $allText = New-Object Text.StringBuilder
        foreach ($entry in $zip.Entries) {
            if ($entry.Length -gt 1048576) { throw 'DiagnosticArchiveValidationFailed' }
            $stream = $entry.Open()
            $reader = New-Object IO.StreamReader($stream, (New-Object Text.UTF8Encoding($false)))
            try { $content = $reader.ReadToEnd() } finally { $reader.Dispose(); $stream.Dispose() }
            [void]$allText.AppendLine($content)
            if ($entry.FullName -in @('summary.json', 'environment.json')) {
                try { [void]($content | ConvertFrom-Json -ErrorAction Stop) } catch { throw 'DiagnosticArchiveValidationFailed' }
            }
            elseif ($entry.FullName -eq 'events.jsonl') {
                foreach ($line in @($content -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
                    try { [void]($line | ConvertFrom-Json -ErrorAction Stop) } catch { throw 'DiagnosticArchiveValidationFailed' }
                }
            }
        }
        [void](Test-CTDiagnosticTextSafe -Text $allText.ToString())
    }
    finally { $zip.Dispose() }
    return $true
}

function New-CTyunTrimDiagnosticBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Audit', 'Plan', 'Prepare', 'Apply', 'Verify')][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [string]$RunId,
        [object]$Result,
        [bool]$PrimarySucceeded = $true,
        [string]$FailureMessage
    )

    $output = Initialize-CTDiagnosticOutputRoot -Mode $Mode
    $outputRoot = [string]$output.Root
    $machineScope = [bool]$output.MachineScope
    $backupRootFull = ConvertTo-CTFullPath -Path $BackupRoot
    if ($outputRoot.Equals($backupRootFull, [StringComparison]::OrdinalIgnoreCase) -or
        $outputRoot.StartsWith($backupRootFull + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $backupRootFull.StartsWith($outputRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'UnsafeDiagnosticOutputPath'
    }
    foreach ($protectedRoot in $script:ApprovedRoots.Values) {
        $protectedRootFull = ConvertTo-CTFullPath -Path ([string]$protectedRoot)
        if ($outputRoot.Equals($protectedRootFull, [StringComparison]::OrdinalIgnoreCase) -or
            $outputRoot.StartsWith($protectedRootFull + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $protectedRootFull.StartsWith($outputRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'UnsafeDiagnosticOutputPath'
        }
    }
    $suffix = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 12))
    $stagingRoot = ConvertTo-CTFullPath -Path (Join-Path $outputRoot ('.staging-' + $suffix))
    $archivePath = ConvertTo-CTFullPath -Path (Join-Path $outputRoot ("CTyunTrim-Diagnostic-$suffix.zip"))
    $temporaryArchive = ConvertTo-CTFullPath -Path (Join-Path $outputRoot ('.diagnostic-' + $suffix + '.tmp.zip'))
    $checksumPath = "$archivePath.sha256"
    if (-not (Test-CTPathWithinRoot -Path $stagingRoot -Root $outputRoot) -or
        -not (Test-CTPathWithinRoot -Path $archivePath -Root $outputRoot) -or
        -not (Test-CTPathWithinRoot -Path $temporaryArchive -Root $outputRoot) -or
        -not (Test-CTPathWithinRoot -Path $checksumPath -Root $outputRoot)) {
        throw 'UnsafeDiagnosticOutputPath'
    }
    foreach ($path in @($stagingRoot, $archivePath, $temporaryArchive, $checksumPath)) {
        if (Test-Path -LiteralPath $path) { throw 'DiagnosticOutputCollision' }
        if (Test-CTPathHasReparsePoint -Path $path) { throw 'UnsafeDiagnosticOutputPath' }
    }

    $createdStaging = $false
    $completed = $false
    try {
        New-Item -ItemType Directory -Path $stagingRoot -ErrorAction Stop | Out-Null
        $createdStaging = $true
        Set-CTDiagnosticDirectoryAcl -Path $stagingRoot -MachineScope $machineScope

        $validation = Test-CTyunTrimManifest -ManifestPath $ManifestPath
        $manifest = if ($validation.Valid) { $validation.Manifest } else { $null }
        $context = $null
        $contextState = 'Stateless'
        $effectiveRunId = if (-not [string]::IsNullOrWhiteSpace($RunId)) { $RunId } else { [string]$script:LastRunId }
        if ($validation.Valid -and -not [string]::IsNullOrWhiteSpace($effectiveRunId)) {
            try {
                $context = Get-CTRunContext -BackupRoot $BackupRoot -RunId $effectiveRunId
                $contextState = 'Bound'
            }
            catch { $contextState = 'Untrusted' }
        }

        $inventoryView = $null
        $inventoryStatus = 'Unavailable'
        $planCounts = @()
        if ($validation.Valid) {
            try {
                $inventory = Get-CTyunTrimInventory -ManifestPath $ManifestPath
                $inventoryView = Get-CTDiagnosticInventoryView -Inventory $inventory -Manifest $manifest
                $inventoryStatus = 'Available'
            }
            catch { $inventoryStatus = 'QueryFailed' }
            $plan = @(Get-CTPlan -Manifest $manifest)
            $planCounts = @($plan | Group-Object -Property Type | ForEach-Object {
                [PSCustomObject]@{ Type = [string]$_.Name; Count = [int]$_.Count }
            })
        }

        $preflightView = if ($null -ne $script:LastPreflightResult -and $validation.Valid) {
            [PSCustomObject]@{
                Ran          = $true
                Passed       = [bool]$script:LastPreflightResult.Passed
                ErrorCount   = @($script:LastPreflightResult.Errors).Count
                WarningCount = @($script:LastPreflightResult.Warnings).Count
                Errors       = @(Get-CTDiagnosticIssueView -Messages @($script:LastPreflightResult.Errors) -Manifest $manifest)
                Warnings     = @(Get-CTDiagnosticIssueView -Messages @($script:LastPreflightResult.Warnings) -Manifest $manifest)
            }
        }
        else { [PSCustomObject]@{ Ran = $false; Passed = $null; ErrorCount = 0; WarningCount = 0; Errors = @(); Warnings = @() } }

        $contextView = if ($validation.Valid) { Get-CTDiagnosticContextView -Context $context -Manifest $manifest } else { [PSCustomObject]@{ Bound = $false; Status = 'Stateless'; RebootNeeded = $false; OperationCount = 0; PendingCount = 0; Operations = @(); Issues = @() } }
        $eventView = if ($validation.Valid) { @(Get-CTDiagnosticEventView -Manifest $manifest) } else { @() }
        $primaryFailureCode = if ($PrimarySucceeded) { 'None' } else { Get-CTDiagnosticCode -Message $FailureMessage }
        if (-not $PrimarySucceeded -and $primaryFailureCode -in @('None', 'Success')) { $primaryFailureCode = 'OperationFailed' }
        $summary = [ordered]@{
            SchemaVersion    = '1.0'
            ToolVersion      = $script:CTyunTrimVersion
            InvocationId     = if ([string]$script:DiagnosticInvocationId -match '^[0-9a-f]{32}$') { [string]$script:DiagnosticInvocationId } else { 'Unavailable' }
            Mode             = $Mode
            PrimarySucceeded = $PrimarySucceeded
            FailureCode      = $primaryFailureCode
            ManifestValid    = [bool]$validation.Valid
            ManifestHashMatches = [bool]($validation.Valid -and [string]$validation.ManifestHash -eq $script:ApprovedManifestSha256)
            InventoryStatus  = $inventoryStatus
            ContextState     = $contextState
            Result           = Get-CTDiagnosticResultView -Result $Result
            Preflight        = $preflightView
            Run              = $contextView
            Components       = $inventoryView
            PlanCounts       = @($planCounts)
            EventCount       = @($eventView).Count
        }
        $os = Get-CTOperatingSystem
        $environment = [ordered]@{
            SchemaVersion      = '1.0'
            ToolVersion        = $script:CTyunTrimVersion
            PowerShellMajor    = [int]$PSVersionTable.PSVersion.Major
            PowerShellMinor    = [int]$PSVersionTable.PSVersion.Minor
            PowerShellBuild    = [int]$PSVersionTable.PSVersion.Build
            PowerShellRevision = [int]$PSVersionTable.PSVersion.Revision
            PowerShellEdition  = [string]$PSVersionTable.PSEdition
            Process64Bit       = [bool][Environment]::Is64BitProcess
            OperatingSystemVersion = if ([string]$os.Version -match '^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$') { [string]$os.Version } else { 'Unknown' }
            OperatingSystemBuild   = [int]$os.Build
            OperatingSystemArchitecture = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
            SupportedBuild     = if ($validation.Valid) { @($manifest.SupportedBuilds) -contains [int]$os.Build } else { $false }
        }
        $readme = @'
CTyunTrim sanitized diagnostic bundle

This archive is generated only when -Diagnostic is explicitly requested.
It contains allowlisted component states, counts, stable reason codes, and no raw run backups.
It intentionally excludes command lines, registry values, task arguments, scripts, usernames,
SIDs, network addresses, certificate identities, quarantine contents, and credentials.
Review the JSON before sharing it.
'@

        $summaryText = $summary | ConvertTo-Json -Depth 12
        $environmentText = $environment | ConvertTo-Json -Depth 6
        $eventLines = @($eventView | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 })
        $eventsText = $eventLines -join "`n"
        $combinedText = "$summaryText`n$environmentText`n$eventsText`n$readme"
        [void](Test-CTDiagnosticTextSafe -Text $combinedText)

        $summaryPath = Join-Path $stagingRoot 'summary.json'
        $environmentPath = Join-Path $stagingRoot 'environment.json'
        $eventsPath = Join-Path $stagingRoot 'events.jsonl'
        $readmePath = Join-Path $stagingRoot 'README.txt'
        Write-CTNewUtf8File -Path $summaryPath -Content $summaryText -MachineScope $machineScope
        Write-CTNewUtf8File -Path $environmentPath -Content $environmentText -MachineScope $machineScope
        Write-CTNewUtf8File -Path $eventsPath -Content $eventsText -MachineScope $machineScope
        Write-CTNewUtf8File -Path $readmePath -Content $readme -MachineScope $machineScope

        Compress-Archive -LiteralPath @($summaryPath, $environmentPath, $eventsPath, $readmePath) -DestinationPath $temporaryArchive -CompressionLevel Optimal -ErrorAction Stop
        Set-CTDiagnosticFileAcl -Path $temporaryArchive -MachineScope $machineScope
        [void](Test-CTDiagnosticArchiveSafe -Path $temporaryArchive)

        Move-Item -LiteralPath $temporaryArchive -Destination $archivePath -ErrorAction Stop
        [void](Test-CTDiagnosticArchiveSafe -Path $archivePath)
        $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        Write-CTNewUtf8File -Path $checksumPath -Content "$archiveHash  $([IO.Path]::GetFileName($archivePath))`r`n" -MachineScope $machineScope
        $completed = $true
        return [PSCustomObject]@{
            Succeeded       = $true
            BundlePath      = (Join-Path ([string]$output.DisplayRoot) ([IO.Path]::GetFileName($archivePath)))
            SHA256          = $archiveHash
            Bytes           = (Get-Item -LiteralPath $archivePath).Length
            EntryCount      = 4
            RunBound        = ($null -ne $context)
            SanitizerSchema = '1.0'
        }
    }
    finally {
        if ($createdStaging -and (Test-Path -LiteralPath $stagingRoot) -and
            (Test-CTPathWithinRoot -Path $stagingRoot -Root $outputRoot) -and
            -not (Test-CTPathHasReparsePoint -Path $stagingRoot)) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        foreach ($temporary in @($temporaryArchive)) {
            if ((Test-Path -LiteralPath $temporary) -and (Test-CTPathWithinRoot -Path $temporary -Root $outputRoot) -and
                -not (Test-CTPathHasReparsePoint -Path $temporary)) {
                Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
            }
        }
        if (-not $completed) {
            foreach ($finalOutput in @($checksumPath, $archivePath)) {
                if ((Test-Path -LiteralPath $finalOutput) -and (Test-CTPathWithinRoot -Path $finalOutput -Root $outputRoot) -and
                    -not (Test-CTPathHasReparsePoint -Path $finalOutput)) {
                    Remove-Item -LiteralPath $finalOutput -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Start-CTyunTrimDiagnosticCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Audit', 'Plan', 'Prepare', 'Apply', 'Verify')][string]$Mode)

    Initialize-CTDiagnosticState -Enabled $true -Mode $Mode
    return [PSCustomObject]@{
        InvocationId = [string]$script:DiagnosticInvocationId
        Mode         = $Mode
        Enabled      = $true
    }
}

function Stop-CTyunTrimDiagnosticCapture {
    [CmdletBinding()]
    param()

    $script:DiagnosticEnabled = $false
    $script:DiagnosticEvents = New-Object Collections.ArrayList
    $script:LastPreflightResult = $null
    $script:LastRunId = $null
    $script:DiagnosticInvocationId = $null
    $script:DiagnosticMode = $null
}

function Invoke-CTNativeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [int[]]$SuccessExitCodes = @(0),

        [switch]$IgnoreFailure
    )

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $exitCode = -1
    $output = @()
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
        $stopwatch.Stop()
    }
    Add-CTDiagnosticEvent -Level $(if ($SuccessExitCodes -contains $exitCode) { 'Info' } else { 'Error' }) -Stage 'NativeCommand' -Message $(if ($SuccessExitCodes -contains $exitCode) { 'Native command completed.' } else { 'Native command failed.' }) -Data @{
        Type = 'NativeCommand'; Target = [IO.Path]::GetFileName($FilePath); ExitCode = [int]$exitCode; DurationMs = [int][Math]::Min([long]$stopwatch.ElapsedMilliseconds, [long][int]::MaxValue)
    }
    if (($SuccessExitCodes -notcontains $exitCode) -and -not $IgnoreFailure) {
        throw "$FilePath exited with code $exitCode. $($output -join [Environment]::NewLine)"
    }

    [PSCustomObject]@{
        ExitCode = $exitCode
        Output   = @($output)
    }
}

function New-CTRunContext {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupRoot,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    $backupRootFull = ConvertTo-CTFullPath -Path $BackupRoot
    if (Test-CTPathHasReparsePoint -Path $backupRootFull) {
        throw "Backup root has a reparse-point ancestor: $backupRootFull"
    }
    if (-not (Test-Path -LiteralPath $backupRootFull)) {
        $missingDirectories = New-Object Collections.Generic.List[string]
        $candidateDirectory = $backupRootFull
        while (-not (Test-Path -LiteralPath $candidateDirectory)) {
            $missingDirectories.Add($candidateDirectory)
            $candidateDirectory = Split-Path -Parent $candidateDirectory
            if ([string]::IsNullOrWhiteSpace($candidateDirectory)) { throw 'Backup root has no existing filesystem ancestor.' }
        }
        for ($index = $missingDirectories.Count - 1; $index -ge 0; $index--) {
            New-Item -ItemType Directory -Path $missingDirectories[$index] -ErrorAction Stop | Out-Null
            Set-CTRunDirectoryAcl -Path $missingDirectories[$index]
        }
    }

    elseif (-not (Test-Path -LiteralPath $backupRootFull -PathType Container)) {
        throw "Backup root is not a directory: $backupRootFull"
    }
    if (-not (Test-CTSecureSourcePath -Path $backupRootFull)) {
        throw "Backup root or one of its parents is not securely owned: $backupRootFull"
    }

    $runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $root = Join-Path $backupRootFull $runId
    if (Test-Path -LiteralPath $root) {
        throw "Run directory already exists: $root"
    }
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    Set-CTRunDirectoryAcl -Path $root
    if (-not (Test-CTSecureSourcePath -Path $root)) {
        throw "Run directory or one of its parents is writable by an untrusted principal: $root"
    }

    $directories = @(
        (Join-Path $root 'registry'),
        (Join-Path $root 'tasks'),
        (Join-Path $root 'certificates'),
        (Join-Path $root 'firewall'),
        (Join-Path $root 'policy'),
        (Join-Path $root 'tools'),
        (Join-Path $root 'quarantine'),
        (Join-Path $root 'reports')
    )

    foreach ($directory in $directories) {
        New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
        Set-CTRunDirectoryAcl -Path $directory
    }

    $archivedManifest = Join-Path $root 'manifest.psd1'
    Copy-Item -LiteralPath (ConvertTo-CTFullPath -Path $ManifestPath) -Destination $archivedManifest -Force
    Set-CTRunFileAcl -Path $archivedManifest
    if ((Get-CTNormalizedTextHash -Path $archivedManifest) -ne $script:ApprovedManifestSha256) {
        throw 'The manifest changed while the run was being created. The run was not trusted.'
    }

    $context = [PSCustomObject]@{
        SchemaVersion = '1.0'
        ToolVersion   = $script:CTyunTrimVersion
        RunId         = $runId
        Root          = $root
        ManifestPath  = $archivedManifest
        MachineSid    = Get-CTMachineSid
        ManifestHash  = (Get-CTNormalizedTextHash -Path $archivedManifest)
        ArchivedManifestFileHash = (Get-FileHash -LiteralPath $archivedManifest -Algorithm SHA256).Hash
        StartedAt     = (Get-Date).ToString('o')
        LastBootUpTime = [string](Get-CTOperatingSystem).LastBootUpTime
        CompletedAt   = $null
        Status        = 'Running'
        RebootNeeded  = $false
        Operations    = New-Object Collections.ArrayList
        Warnings      = New-Object Collections.ArrayList
    }

    if ([string]::IsNullOrWhiteSpace([string]$context.MachineSid)) {
        throw 'Could not determine the local machine SID; no run state was accepted.'
    }
    Save-CTRunContext -Context $context
    $script:LastRunId = $runId
    Add-CTDiagnosticEvent -Stage 'RunContext' -Message 'Created protected run context.' -Data @{ RunId = $runId }
    return $context
}

function Get-CTRunContext {
    param(
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    if ($RunId -notmatch '^[0-9]{8}-[0-9]{6}-[0-9a-fA-F]{8}$') {
        throw 'RunId has an invalid format.'
    }
    $backupRootFull = ConvertTo-CTFullPath -Path $BackupRoot
    $root = ConvertTo-CTFullPath -Path (Join-Path $backupRootFull $RunId)
    if (-not (Test-CTPathWithinRoot -Path $root -Root $backupRootFull)) {
        throw 'RunId escaped the configured backup root.'
    }
    if (Test-CTPathHasReparsePoint -Path $root) {
        throw 'Run directory or one of its ancestors is a reparse point.'
    }
    $runAcl = Get-Acl -LiteralPath $root -ErrorAction Stop
    if (-not $runAcl.AreAccessRulesProtected -or (Test-CTPathWritableByStandardUsers -Path $root)) {
        throw 'Run directory ACL is not restricted to trusted administrative principals.'
    }
    if (-not (Test-CTSecureSourcePath -Path $root)) {
        throw 'Run directory or an ancestor can be replaced by an untrusted principal.'
    }
    $statePath = Join-Path $root 'state.clixml'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "Run state not found: $statePath"
    }
    if (-not (Test-CTSecureSourcePath -Path $statePath)) {
        throw 'Run state file ACL or ownership is not trusted.'
    }

    $context = Import-Clixml -LiteralPath $statePath
    $currentMachineSid = Get-CTMachineSid
    if ([string]$context.SchemaVersion -ne '1.0') {
        throw "Unsupported run-state schema: $($context.SchemaVersion)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$context.MachineSid) -or [string]::IsNullOrWhiteSpace($currentMachineSid) -or $context.MachineSid -ne $currentMachineSid) {
        throw 'Run state belongs to a different Windows installation.'
    }
    if (-not (ConvertTo-CTFullPath -Path ([string]$context.Root)).Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Run state contains an unexpected root path.'
    }
    $archivedManifest = Join-Path $root 'manifest.psd1'
    $archivedFileHash = [string](Get-CTPropertyValue -InputObject $context -Name 'ArchivedManifestFileHash')
    if (-not (Test-Path -LiteralPath $archivedManifest -PathType Leaf) -or
        [string]::IsNullOrWhiteSpace($archivedFileHash) -or
        (Get-FileHash -LiteralPath $archivedManifest -Algorithm SHA256).Hash -ne $archivedFileHash) {
        throw 'Archived manifest is missing or its integrity check failed.'
    }
    if (-not (Test-CTSecureSourcePath -Path $archivedManifest)) {
        throw 'Archived manifest ACL or ownership is not trusted.'
    }
    if ((Get-CTNormalizedTextHash -Path $archivedManifest) -ne [string]$context.ManifestHash -or
        [string]$context.ManifestHash -ne $script:ApprovedManifestSha256) {
        throw 'Archived manifest is not the immutable approved CTyunTrim profile.'
    }

    $operations = New-Object Collections.ArrayList
    foreach ($operation in @($context.Operations)) { [void]$operations.Add($operation) }
    $warnings = New-Object Collections.ArrayList
    foreach ($warning in @($context.Warnings)) { [void]$warnings.Add([string]$warning) }
    $context.Operations = $operations
    $context.Warnings = $warnings
    $script:LastRunId = [string]$context.RunId
    Add-CTDiagnosticEvent -Stage 'RunContext' -Message 'Loaded protected run context.' -Data @{ RunId = [string]$context.RunId; Status = [string]$context.Status }
    return $context
}

function Get-CTMachineSid {
    $administrator = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $administrator -or [string]::IsNullOrWhiteSpace([string]$administrator.SID)) {
        return $null
    }

    return ([string]$administrator.SID -replace '-500$', '')
}

function Save-CTRunContext {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context
    )

    $destination = Join-Path $Context.Root 'state.clixml'
    $temporary = "$destination.tmp"
    $Context | Export-Clixml -LiteralPath $temporary -Depth 8 -Force
    Set-CTRunFileAcl -Path $temporary
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    Set-CTRunFileAcl -Path $destination
}

function Add-CTOperation {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Target,

        [hashtable]$Data = @{},

        [bool]$Reversible = $true
    )

    $operation = [PSCustomObject]@{
        Id          = [guid]::NewGuid().ToString('N')
        Timestamp   = (Get-Date).ToString('o')
        CompletedAt = (Get-Date).ToString('o')
        Status      = 'Completed'
        Type        = $Type
        Target      = $Target
        Data        = $Data
        Reversible  = $Reversible
    }
    [void]$Context.Operations.Add($operation)
    Save-CTRunContext -Context $Context
    Add-CTDiagnosticEvent -Stage 'Operation' -Message 'Recorded completed operation.' -Data @{ Type = $Type; Target = $Target; Status = 'Completed' }
}

function Get-CTPendingOperation {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Context,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Target
    )

    $pending = @($Context.Operations | Where-Object {
        $_.Status -eq 'Pending' -and $_.Type -eq $Type -and $_.Target -eq $Target
    })
    if ($pending.Count -gt 1) {
        throw "Multiple pending journal entries exist for $Type / $Target. Manual review is required."
    }
    if ($pending.Count -eq 1) { return $pending[0] }
    return $null
}

function Start-CTOperation {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Context,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Target,
        [hashtable]$Data = @{},
        [bool]$Reversible = $true
    )

    $existingPending = Get-CTPendingOperation -Context $Context -Type $Type -Target $Target
    if ($null -ne $existingPending) {
        foreach ($propertyName in @('Backup', 'BackupSha256', 'ExpectedImage', 'RunId', 'SID', 'Source', 'Destination', 'Store', 'Program', 'TaskName', 'TaskPath', 'StartTimeUtcTicks')) {
            $recordedValue = Get-CTPropertyValue -InputObject $existingPending.Data -Name $propertyName
            $currentValue = Get-CTPropertyValue -InputObject $Data -Name $propertyName
            if ($null -ne $recordedValue -and $null -ne $currentValue -and [string]$recordedValue -ne [string]$currentValue) {
                throw "Pending journal data changed for $Type / $Target / $propertyName."
            }
        }
        Add-CTDiagnosticEvent -Stage 'Operation' -Message 'Reused pending write-ahead operation.' -Data @{ Type = $Type; Target = $Target; Status = 'Pending' }
        return [string]$existingPending.Id
    }

    $id = [guid]::NewGuid().ToString('N')
    $operation = [PSCustomObject]@{
        Id          = $id
        Timestamp   = (Get-Date).ToString('o')
        CompletedAt = $null
        Status      = 'Pending'
        Type        = $Type
        Target      = $Target
        Data        = $Data
        Reversible  = $Reversible
    }
    [void]$Context.Operations.Add($operation)
    Save-CTRunContext -Context $Context
    Add-CTDiagnosticEvent -Stage 'Operation' -Message 'Started write-ahead operation.' -Data @{ Type = $Type; Target = $Target; Status = 'Pending' }
    return $id
}

function Complete-CTOperation {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Context,
        [Parameter(Mandatory = $true)][string]$Id
    )

    $operation = @($Context.Operations | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
    if ($null -eq $operation) { throw "Journal operation not found: $Id" }
    $operation.Status = 'Completed'
    $operation.CompletedAt = (Get-Date).ToString('o')
    Save-CTRunContext -Context $Context
    Add-CTDiagnosticEvent -Stage 'Operation' -Message 'Completed write-ahead operation.' -Data @{ Type = [string]$operation.Type; Target = [string]$operation.Target; Status = 'Completed' }
}

function Resolve-CTPendingOperations {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Context,
        [Parameter(Mandatory = $true)][hashtable]$Manifest
    )

    $pendingOperations = @($Context.Operations | Where-Object { $_.Status -eq 'Pending' })
    Add-CTDiagnosticEvent -Stage 'Journal' -Message 'Started pending-operation reconciliation.' -Data @{ PendingCount = $pendingOperations.Count }
    $taskSnapshot = if (@($pendingOperations | Where-Object { $_.Type -eq 'ScheduledTask' }).Count -gt 0) {
        @(Get-ScheduledTask -ErrorAction Stop)
    }
    else { @() }
    $localUserSnapshot = if (@($pendingOperations | Where-Object { $_.Type -eq 'LocalUser' }).Count -gt 0) {
        @(Get-LocalUser -ErrorAction Stop)
    }
    else { @() }
    $userProfileSnapshot = if (@($pendingOperations | Where-Object { $_.Type -eq 'UserProfile' }).Count -gt 0) {
        @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)
    }
    else { @() }
    $firewallSnapshot = if (@($pendingOperations | Where-Object { $_.Type -eq 'FirewallRule' }).Count -gt 0) {
        @(Get-NetFirewallRule -ErrorAction Stop)
    }
    else { @() }
    foreach ($operation in $pendingOperations) {
        $completed = $false
        switch ($operation.Type) {
            'ExecutionGuard' {
                $state = Get-CTIfEOState -Image ([string]$operation.Target)
                $completed = $state.Present -and $state.Debugger -eq $script:GuardDebugger -and $state.Marker -eq $script:GuardOwner -and $state.RunId -eq $Context.RunId
            }
            'ScheduledTask' {
                $taskName = [string](Get-CTPropertyValue -InputObject $operation.Data -Name 'TaskName')
                $taskPath = [string](Get-CTPropertyValue -InputObject $operation.Data -Name 'TaskPath')
                $completed = @($taskSnapshot | Where-Object {
                    ([string]$_.TaskName).Equals($taskName, [StringComparison]::OrdinalIgnoreCase) -and
                    ([string]$_.TaskPath).Equals($taskPath, [StringComparison]::OrdinalIgnoreCase)
                }).Count -eq 0
            }
            'RunValue' {
                $parts = [string]$operation.Target -split '::', 2
                if ($parts.Count -eq 2) {
                    $providerPath = $parts[0] -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\'
                    $value = Get-ItemProperty -LiteralPath $providerPath -Name $parts[1] -ErrorAction SilentlyContinue
                    $completed = $null -eq $value
                }
            }
            'ProcessStop' {
                $pidText = ([string]$operation.Target -split ':')[-1]
                $processId = 0
                if ([int]::TryParse($pidText, [ref]$processId)) {
                    $currentProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    if ($null -eq $currentProcess) {
                        $completed = $true
                    }
                    else {
                        $recordedName = ([string]$operation.Target -split ':')[0]
                        $recordedPath = [string](Get-CTPropertyValue -InputObject $operation.Data -Name 'Path')
                        $recordedStartTicks = [string](Get-CTPropertyValue -InputObject $operation.Data -Name 'StartTimeUtcTicks')
                        $currentPath = $null
                        $currentStartTicks = $null
                        try { $currentPath = [string]$currentProcess.Path } catch { }
                        try { $currentStartTicks = [string]$currentProcess.StartTime.ToUniversalTime().Ticks } catch { }
                        $completed = -not ([string]$currentProcess.ProcessName -eq $recordedName -and
                            $currentPath -eq $recordedPath -and
                            -not [string]::IsNullOrWhiteSpace($recordedStartTicks) -and
                            $currentStartTicks -eq $recordedStartTicks)
                    }
                }
            }
            'Service' {
                $completed = $null -eq (Get-CTServiceByName -Name ([string]$operation.Target))
            }
            'DriverService' {
                $completed = $null -eq (Get-CTServiceByName -Name ([string]$operation.Target) -Driver)
            }
            'LocalPolicy' {
                $completed = (Get-CTWsusPolicySignature -Manifest $Manifest).Classification -eq 'Absent'
            }
            'QuarantinePath' {
                $completed = -not (Test-Path -LiteralPath ([string]$operation.Data.Source)) -and (Test-Path -LiteralPath ([string]$operation.Data.Destination))
            }
            'LocalUser' {
                $expectedSid = [string](Get-CTPropertyValue -InputObject $operation.Data -Name 'SID')
                $completed = @($localUserSnapshot | Where-Object { [string]$_.SID -eq $expectedSid }).Count -eq 0
            }
            'UserProfile' {
                $expectedSid = [string](Get-CTPropertyValue -InputObject $operation.Data -Name 'SID')
                $completed = @($userProfileSnapshot | Where-Object { [string]$_.SID -eq $expectedSid }).Count -eq 0
            }
            'Certificate' {
                $store = [string](Get-CTPropertyValue -InputObject $operation.Data -Name 'Store')
                $completed = $null -eq (Get-ChildItem -Path $store -ErrorAction Stop | Where-Object { $_.Thumbprint -eq [string]$operation.Target } | Select-Object -First 1)
            }
            'FirewallRule' {
                $completed = @($firewallSnapshot | Where-Object { $_.Name -eq [string]$operation.Target }).Count -eq 0
            }
        }

        if ($completed) {
            Complete-CTOperation -Context $Context -Id ([string]$operation.Id)
        }
    }
    Add-CTDiagnosticEvent -Stage 'Journal' -Message 'Completed pending-operation reconciliation.' -Data @{
        PendingCount = @($Context.Operations | Where-Object { $_.Status -eq 'Pending' }).Count
    }
}

function Add-CTWarning {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    [void]$Context.Warnings.Add($Message)
    Save-CTRunContext -Context $Context
    Add-CTDiagnosticEvent -Level 'Warning' -Stage 'Operation' -Message $Message
    Write-Warning $Message
}

function Save-CTFailedRunContextSafe {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Context,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    try {
        $Context.Status = 'Failed'
        $Context.CompletedAt = (Get-Date).ToString('o')
        [void]$Context.Warnings.Add($FailureMessage)
        Save-CTRunContext -Context $Context
    }
    catch {
        Add-CTDiagnosticEvent -Level 'Error' -Stage 'RunContext' -Message 'Failed to persist failure state.'
    }
}

function Confirm-CTRequiredOperation {
    param(
        [Parameter(Mandatory = $true)][Management.Automation.PSCmdlet]$Caller,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Action
    )

    if (-not $Caller.ShouldProcess($Target, $Action)) {
        Add-CTDiagnosticEvent -Level 'Error' -Stage 'Confirmation' -Message 'Required operation was declined.' -Data @{ Action = $Action; Target = $Target }
        throw (New-Object System.OperationCanceledException("Required operation was declined; the transaction stopped before dependent changes: $Action / $Target"))
    }
    Add-CTDiagnosticEvent -Stage 'Confirmation' -Message 'Required operation was confirmed.' -Data @{ Action = $Action; Target = $Target }
    return $true
}

function Test-CTRegistryExportFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$NativeKey
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Test-CTPathHasReparsePoint -Path $Path)) { return $false }
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -le 0) { return $false }
    $header = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
    if ([string]$header -ne 'Windows Registry Editor Version 5.00') { return $false }

    $registryPath = if ($NativeKey -match '^(?i)HKLM\\(?<rest>.+)$') {
        "HKEY_LOCAL_MACHINE\$($matches.rest)"
    }
    elseif ($NativeKey -match '^(?i)HKCU\\(?<rest>.+)$') {
        "HKEY_CURRENT_USER\$($matches.rest)"
    }
    else { return $false }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    return $content -match ('(?im)^\[' + [regex]::Escape($registryPath) + '\]\s*$')
}

function Export-CTRegistryKey {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$NativeKey,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$AllowMissing
    )

    $providerPath = if ($NativeKey -match '^(?i)HKLM\\(?<rest>.+)$') {
        "HKLM:\$($matches.rest)"
    }
    elseif ($NativeKey -match '^(?i)HKCU\\(?<rest>.+)$') {
        "HKCU:\$($matches.rest)"
    }
    else {
        throw "Unsupported native registry root: $NativeKey"
    }

    if (-not (Test-Path -LiteralPath $providerPath)) {
        if ($AllowMissing) { return $null }
        throw "Registry backup source does not exist: $NativeKey"
    }

    $destination = Join-Path (Join-Path $Context.Root 'registry') "$Name.reg"
    if (Test-Path -LiteralPath $destination) {
        if (-not (Test-CTRegistryExportFile -Path $destination -NativeKey $NativeKey) -or
            -not (Test-CTSecureSourcePath -Path $destination)) {
            throw "Existing registry backup is not a valid export of the expected key: $NativeKey / $destination"
        }
        $existingFile = Get-Item -LiteralPath $destination -ErrorAction Stop
        return [PSCustomObject]@{
            Path   = $destination
            SHA256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
            Length = $existingFile.Length
        }
    }

    $temporary = Join-Path (Join-Path $Context.Root 'registry') ('.reg-export-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [void](Invoke-CTNativeCommand -FilePath "$env:SystemRoot\System32\reg.exe" -Arguments @('export', $NativeKey, $temporary, '/y'))
        if (-not (Test-CTRegistryExportFile -Path $temporary -NativeKey $NativeKey)) {
            throw "Registry export did not produce a valid backup of the expected key: $NativeKey"
        }
        Move-Item -LiteralPath $temporary -Destination $destination -ErrorAction Stop
        Set-CTRunFileAcl -Path $destination
        return [PSCustomObject]@{
            Path   = $destination
            SHA256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
            Length = (Get-Item -LiteralPath $destination).Length
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Export-CTBaseline {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest
    )

    $inventory = Get-CTyunTrimInventory -ManifestPath $Context.ManifestPath
    $inventoryPath = Join-Path $Context.Root 'reports\before.json'
    $platformPath = Join-Path $Context.Root 'reports\platform-before.json'
    $inventory | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $inventoryPath -Encoding UTF8
    Set-CTRunFileAcl -Path $inventoryPath

    foreach ($nativeKey in @(
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    )) {
        $safeName = ($nativeKey -replace '[^A-Za-z0-9_-]', '_')
        [void](Export-CTRegistryKey -Context $Context -NativeKey $nativeKey -Name $safeName -AllowMissing)
    }

    $network = [ordered]@{
        Adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, MacAddress, InterfaceGuid, LinkSpeed)
        IP       = @(Get-NetIPConfiguration -All -ErrorAction SilentlyContinue)
        MTU      = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, NlMtu, ConnectionState, Dhcp)
        DNS      = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses)
        Routes   = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, PolicyStore)
        Disks    = @(Get-Disk -ErrorAction SilentlyContinue | Select-Object Number, FriendlyName, PartitionStyle, OperationalStatus, Size)
        Volumes  = @(Get-Volume -ErrorAction SilentlyContinue | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, Size, SizeRemaining)
    }
    $network | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $platformPath -Encoding UTF8
    Set-CTRunFileAcl -Path $platformPath

    Add-CTOperation -Context $Context -Type 'Baseline' -Target $Context.Root -Data @{
        Inventory       = 'reports\before.json'
        InventorySha256 = (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash
        Platform        = 'reports\platform-before.json'
        PlatformSha256  = (Get-FileHash -LiteralPath $platformPath -Algorithm SHA256).Hash
    }
}

function Get-CTImageExecutable {
    param([Parameter(Mandatory = $true)][string]$PathName)

    $text = [Environment]::ExpandEnvironmentVariables($PathName.Trim())
    if ($text.StartsWith('\??\', [StringComparison]::Ordinal)) {
        $text = $text.Substring(4)
    }

    $image = $null
    if ($text -match '^\s*"(?<image>[^"]+\.(?:exe|sys))"') {
        $image = $matches.image
    }
    elseif ($text -match '^\s*(?<image>.+?\.(?:exe|sys))(?=\s|$)') {
        $image = $matches.image
    }
    if ([string]::IsNullOrWhiteSpace($image)) {
        return $null
    }

    if ($image -match '(?i)^\\SystemRoot\\') {
        $image = Join-Path $env:SystemRoot $image.Substring(12)
    }
    elseif ($image -match '(?i)^system32\\') {
        $image = Join-Path $env:SystemRoot $image
    }

    try { return ConvertTo-CTFullPath -Path $image } catch { return $null }
}

function Test-CTExpectedService {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Service,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedImage
    )

    if ([string]::IsNullOrWhiteSpace([string]$Service.PathName)) {
        return $false
    }
    $actualImage = Get-CTImageExecutable -PathName ([string]$Service.PathName)
    if ([string]::IsNullOrWhiteSpace($actualImage)) { return $false }
    return $actualImage.Equals((ConvertTo-CTFullPath -Path $ExpectedImage), [StringComparison]::OrdinalIgnoreCase)
}

function Get-CTNumericFileVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo((ConvertTo-CTFullPath -Path $Path))
    return '{0}.{1}.{2}.{3}' -f $version.FileMajorPart, $version.FileMinorPart, $version.FileBuildPart, $version.FilePrivatePart
}

function Get-CTBaselineCoreInventory {
    param([Parameter(Mandatory = $true)][PSObject]$Context)

    $baselineOperations = @($Context.Operations | Where-Object { $_.Type -eq 'Baseline' -and $_.Status -eq 'Completed' })
    if ($baselineOperations.Count -ne 1) {
        throw 'Exactly one completed baseline operation is required for core integrity comparison.'
    }
    $relativePath = [string](Get-CTPropertyValue -InputObject $baselineOperations[0].Data -Name 'Inventory')
    $expectedHash = [string](Get-CTPropertyValue -InputObject $baselineOperations[0].Data -Name 'InventorySha256')
    $inventoryPath = ConvertTo-CTFullPath -Path (Join-Path $Context.Root $relativePath)
    if ([string]::IsNullOrWhiteSpace($relativePath) -or [string]::IsNullOrWhiteSpace($expectedHash) -or
        -not (Test-CTPathWithinRoot -Path $inventoryPath -Root (Join-Path $Context.Root 'reports')) -or
        -not (Test-Path -LiteralPath $inventoryPath -PathType Leaf) -or
        (Test-CTPathHasReparsePoint -Path $inventoryPath) -or
        -not (Test-CTSecureSourcePath -Path $inventoryPath) -or
        (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash -ne $expectedHash) {
        throw 'The archived baseline inventory is missing, unsafe or has changed.'
    }
    return Get-Content -LiteralPath $inventoryPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}

function Test-CTCoreHealth {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [switch]$RequireRunning,

        [PSObject]$Context
    )

    $failures = New-Object Collections.Generic.List[string]
    $baselineInventory = $null
    if ($null -ne $Context) {
        try { $baselineInventory = Get-CTBaselineCoreInventory -Context $Context }
        catch { $failures.Add("Core integrity baseline failed validation: $($_.Exception.Message)") }
    }
    $contextOperations = if ($null -ne $Context) { @(Get-CTPropertyValue -InputObject $Context -Name 'Operations') } else { @() }
    $knownCertificateTargets = @($Manifest.KnownCertificates | ForEach-Object { [string]$_.Thumbprint })
    $allowTrustDegradation = @($contextOperations | Where-Object {
        [string](Get-CTPropertyValue -InputObject $_ -Name 'Type') -eq 'Certificate' -and
        [string](Get-CTPropertyValue -InputObject $_ -Name 'Status') -eq 'Completed' -and
        $knownCertificateTargets -contains [string](Get-CTPropertyValue -InputObject $_ -Name 'Target')
    }).Count -gt 0

    foreach ($kind in @('Service', 'Driver')) {
        $entries = if ($kind -eq 'Service') { @($Manifest.CoreFingerprint.Services) } else { @($Manifest.CoreFingerprint.Drivers) }
        foreach ($entry in $entries) {
            $component = if ($kind -eq 'Service') {
                Get-CTServiceByName -Name $entry.Name
            }
            else {
                Get-CTServiceByName -Name $entry.Name -Driver
            }
            $kindLower = $kind.ToLowerInvariant()
            if ($null -eq $component) {
                $failures.Add("Protected $kindLower is missing: $($entry.Name)")
                continue
            }

            if ($RequireRunning -and $component.State -ne 'Running') {
                $failures.Add("Protected $kindLower is not running: $($entry.Name) ($($component.State))")
            }
            if (-not (Test-CTExpectedService -Service $component -ExpectedImage $entry.ExpectedImage)) {
                $failures.Add("Protected $kindLower ImagePath mismatch: $($entry.Name) / $($component.PathName)")
                continue
            }

            $image = Get-CTImageExecutable -PathName ([string]$component.PathName)
            if ([string]::IsNullOrWhiteSpace($image) -or -not (Test-Path -LiteralPath $image -PathType Leaf)) {
                $failures.Add("Protected $kindLower image is missing: $($entry.Name) / $($entry.ExpectedImage)")
                continue
            }
            if (Test-CTPathHasReparsePoint -Path $image) {
                $failures.Add("Protected $kindLower image has a reparse-point ancestor: $($entry.Name) / $image")
                continue
            }

            try { $evidence = Get-CTCoreFileEvidence -Path $image }
            catch {
                $failures.Add("Protected $kindLower image identity could not be inspected safely: $($entry.Name) / $image / $($_.Exception.Message)")
                continue
            }
            $currentTrust = Test-CTCoreBinaryTrust -Entry $entry -Evidence $evidence

            if ($null -ne $Context) {
                $baselineEntries = @(if ($null -eq $baselineInventory) {
                    @()
                }
                elseif ($kind -eq 'Service') {
                    @($baselineInventory.CoreServices | Where-Object { $_.Name -eq $entry.Name })
                }
                else {
                    @($baselineInventory.CoreDrivers | Where-Object { $_.Name -eq $entry.Name })
                })
                $baselineMatch = $false
                if ($baselineEntries.Count -eq 1) {
                    $baselineEntry = $baselineEntries[0]
                    $baselineMatch = [bool](Test-CTCoreBaselineContinuity -Entry $entry -BaselineEntry $baselineEntry -CurrentEvidence $evidence -AllowTrustDegradation:$allowTrustDegradation).Matches
                }
                if (-not $baselineMatch) {
                    $failures.Add("Protected $kindLower image differs from the trusted pre-cleanup baseline: $($entry.Name) / $image")
                }
            }
            else {
                if (-not $currentTrust.TrustSatisfied) {
                    $failures.Add("Protected $kindLower image failed its $($entry.TrustMode) trust policy: $($entry.Name) / $image / $($currentTrust.FailureCode)")
                }
            }

            if ($kind -eq 'Service' -and $entry.ContainsKey('ExpectedFileVersion')) {
                if ([string]$evidence.FileVersion -ne [string]$entry.ExpectedFileVersion) {
                    $failures.Add("Protected service version mismatch: $($entry.Name) / expected $($entry.ExpectedFileVersion), actual $($evidence.FileVersion)")
                }
            }
        }
    }

    $requiredPaths = if ($Manifest.Preserve.ContainsKey('RequiredPaths')) { @($Manifest.Preserve.RequiredPaths) } else { @($Manifest.Preserve.Paths) }
    foreach ($path in $requiredPaths) {
        if (-not (Test-Path -LiteralPath $path)) {
            $failures.Add("Protected path is missing: $path")
        }
    }

    [PSCustomObject]@{
        Healthy  = ($failures.Count -eq 0)
        Failures = @($failures)
    }
}

function Add-CTExecutionGuards {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($image in $Manifest.ExecutionGuards) {
        $path = Join-Path $base $image
        $existing = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        $pending = @($Context.Operations | Where-Object {
            $_.Status -eq 'Pending' -and $_.Type -eq 'ExecutionGuard' -and $_.Target -eq $image
        })
        if ($pending.Count -gt 1) {
            throw "Multiple pending execution-guard operations exist for $image."
        }

        if ($null -ne $existing) {
            $existingDebugger = [string](Get-CTPropertyValue -InputObject $existing -Name 'Debugger')
            $existingMarker = [string](Get-CTPropertyValue -InputObject $existing -Name 'CTyunTrimGuard')
            $existingRunId = [string](Get-CTPropertyValue -InputObject $existing -Name 'CTyunTrimRunId')
            if (($existingDebugger -eq $script:GuardDebugger) -and ($existingMarker -eq $script:GuardOwner) -and ($existingRunId -eq $Context.RunId)) {
                if ($pending.Count -eq 1) { Complete-CTOperation -Context $Context -Id ([string]$pending[0].Id) }
                continue
            }
            $pendingRunId = if ($pending.Count -eq 1) { [string](Get-CTPropertyValue -InputObject $pending[0].Data -Name 'RunId') } else { $null }
            $partialOwned = ($pending.Count -eq 1) -and ($pendingRunId -eq $Context.RunId) -and
                ([string]::IsNullOrWhiteSpace($existingDebugger) -or $existingDebugger -eq $script:GuardDebugger) -and
                ([string]::IsNullOrWhiteSpace($existingMarker) -or $existingMarker -eq $script:GuardOwner) -and
                ([string]::IsNullOrWhiteSpace($existingRunId) -or $existingRunId -eq $Context.RunId)
            if (-not $partialOwned) {
                throw "Refusing to modify an existing IFEO key not owned by this CTyunTrim run: $image / $existingDebugger"
            }
        }

        if (Confirm-CTRequiredOperation -Caller $Caller -Target $image -Action 'Create CTyunTrim IFEO execution guard') {
            if ($pending.Count -eq 1) {
                $operationId = [string]$pending[0].Id
            }
            else {
                $nativeKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$image"
                $safeName = 'ifeo-' + ($image -replace '[^A-Za-z0-9_.-]', '_')
                $backup = Export-CTRegistryKey -Context $Context -NativeKey $nativeKey -Name $safeName -AllowMissing

                $operationId = Start-CTOperation -Context $Context -Type 'ExecutionGuard' -Target $image -Data @{
                    RegistryPath = $path
                    Debugger     = $script:GuardDebugger
                    Backup       = if ($null -ne $backup) { [string]$backup.Path } else { $null }
                    BackupSha256 = if ($null -ne $backup) { [string]$backup.SHA256 } else { $null }
                    KeyExisted   = ($null -ne $existing)
                    RunId        = $Context.RunId
                }
            }

            if (-not (Test-Path -LiteralPath $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            New-ItemProperty -LiteralPath $path -Name 'Debugger' -PropertyType String -Value $script:GuardDebugger -Force | Out-Null
            New-ItemProperty -LiteralPath $path -Name 'CTyunTrimGuard' -PropertyType String -Value $script:GuardOwner -Force | Out-Null
            New-ItemProperty -LiteralPath $path -Name 'CTyunTrimRunId' -PropertyType String -Value $Context.RunId -Force | Out-Null
            Complete-CTOperation -Context $Context -Id $operationId
        }
    }
}

function Get-CTStrictTaskActionImage {
    param([Parameter(Mandatory = $true)][string]$Execute)

    $text = [Environment]::ExpandEnvironmentVariables($Execute).Trim()
    $image = $null
    if ($text -match '^\s*"(?<image>[^"\r\n]+\.exe)"\s*$') {
        $image = $matches.image
    }
    elseif ($text -match '^\s*(?<image>[^"\r\n]+\.exe)\s*$') {
        $image = $matches.image.Trim()
    }
    if ([string]::IsNullOrWhiteSpace($image)) {
        return $null
    }

    try { return ConvertTo-CTFullPath -Path $image } catch { return $null }
}

function Test-CTScheduledTaskDefinition {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Task,
        [Parameter(Mandatory = $true)][hashtable]$Entry
    )

    if (-not ([string]$Task.TaskName).Equals([string]$Entry.Name, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$Task.TaskPath).Equals([string]$Entry.TaskPath, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$actions[0].Execute)) {
        return $false
    }
    $cimClass = Get-CTPropertyValue -InputObject $actions[0] -Name 'CimClass'
    $cimClassName = [string](Get-CTPropertyValue -InputObject $cimClass -Name 'CimClassName')
    if ($cimClassName -ne 'MSFT_TaskExecAction') {
        return $false
    }

    $actualImage = Get-CTStrictTaskActionImage -Execute ([string]$actions[0].Execute)
    if ([string]::IsNullOrWhiteSpace($actualImage)) {
        return $false
    }
    return $actualImage.Equals((ConvertTo-CTFullPath -Path ([string]$Entry.ExpectedImage)), [StringComparison]::OrdinalIgnoreCase)
}

function Remove-CTScheduledTasks {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $taskSnapshot = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($entry in $Manifest.ScheduledTasks) {
        $tasks = @($taskSnapshot | Where-Object {
            ([string]$_.TaskName).Equals([string]$entry.Name, [StringComparison]::OrdinalIgnoreCase) -and
            ([string]$_.TaskPath).Equals([string]$entry.TaskPath, [StringComparison]::OrdinalIgnoreCase)
        })
        foreach ($task in $tasks) {
            if (-not (Test-CTScheduledTaskDefinition -Task $task -Entry $entry)) {
                Add-CTWarning -Context $Context -Message "Task $($task.TaskPath)$($task.TaskName) exists but its complete definition does not match the approved image $($entry.ExpectedImage); it was not removed."
                continue
            }

            $target = "$($task.TaskPath)$($task.TaskName)"
            if (Confirm-CTRequiredOperation -Caller $Caller -Target $target -Action 'Export and unregister scheduled task') {
                $fileName = (($task.TaskPath + $task.TaskName) -replace '[^A-Za-z0-9_.-]', '_') + '.xml'
                $backupPath = Join-Path (Join-Path $Context.Root 'tasks') $fileName
                $pending = Get-CTPendingOperation -Context $Context -Type 'ScheduledTask' -Target $target
                if ($null -ne $pending) {
                    $recordedBackup = [string](Get-CTPropertyValue -InputObject $pending.Data -Name 'Backup')
                    $recordedHash = [string](Get-CTPropertyValue -InputObject $pending.Data -Name 'BackupSha256')
                    if (-not $recordedBackup.Equals($backupPath, [StringComparison]::OrdinalIgnoreCase) -or
                        -not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or
                        (Test-CTPathHasReparsePoint -Path $backupPath) -or
                        -not (Test-CTSecureSourcePath -Path $backupPath) -or
                        (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ne $recordedHash) {
                        throw "Scheduled task backup no longer matches its pending journal entry: $target"
                    }
                    $operationId = [string]$pending.Id
                }
                else {
                    Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | Set-Content -LiteralPath $backupPath -Encoding Unicode
                    Set-CTRunFileAcl -Path $backupPath
                    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or
                        (Get-Item -LiteralPath $backupPath).Length -le 0 -or
                        (Test-CTPathHasReparsePoint -Path $backupPath)) {
                        throw "Scheduled task export did not produce a usable backup: $target"
                    }
                    try { [void][xml](Get-Content -LiteralPath $backupPath -Raw -ErrorAction Stop) } catch { throw "Scheduled task export is not valid XML: $target" }
                    $operationId = Start-CTOperation -Context $Context -Type 'ScheduledTask' -Target $target -Data @{
                        Backup         = $backupPath
                        BackupSha256   = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash
                        TaskName       = $task.TaskName
                        TaskPath       = $task.TaskPath
                        ExpectedImage  = [string]$entry.ExpectedImage
                    }
                }
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
                Complete-CTOperation -Context $Context -Id $operationId
            }
        }
    }
}

function Remove-CTRunValues {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $backedUpKeys = @{}
    foreach ($entry in $Manifest.RunValues) {
        $current = Get-CTRunValue -Entry $entry -Strict
        if ($null -eq $current) {
            continue
        }

        if (-not (Test-CTRunValueOwned -RunValue $current)) {
            Add-CTWarning -Context $Context -Message "Run value $($current.Name) did not point to a CTyun path and was not removed: $($current.Value)"
            continue
        }

        $drive = if ($entry.Hive -eq 'HKLM') { 'HKLM:' } else { 'HKCU:' }
        $providerPath = Join-Path $drive $entry.Key
        $nativeKey = "$($entry.Hive)\$($entry.Key)"
        if (-not $backedUpKeys.ContainsKey($nativeKey)) {
            $safeName = 'run-' + ($nativeKey -replace '[^A-Za-z0-9_.-]', '_')
            $backedUpKeys[$nativeKey] = Export-CTRegistryKey -Context $Context -NativeKey $nativeKey -Name $safeName
        }

        if (Confirm-CTRequiredOperation -Caller $Caller -Target "$nativeKey::$($entry.Name)" -Action 'Remove vendor Run value') {
            $operationId = Start-CTOperation -Context $Context -Type 'RunValue' -Target "$nativeKey::$($entry.Name)" -Data @{
                Backup = [string]$backedUpKeys[$nativeKey].Path
                BackupSha256 = [string]$backedUpKeys[$nativeKey].SHA256
                Value  = [string]$current.Value
            }
            Remove-ItemProperty -LiteralPath $providerPath -Name $entry.Name -ErrorAction Stop
            Complete-CTOperation -Context $Context -Id $operationId
        }
    }

    foreach ($hive in @('HKLM', 'HKCU')) {
        $drive = if ($hive -eq 'HKLM') { 'HKLM:' } else { 'HKCU:' }
        $key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        $providerPath = Join-Path $drive $key
        if (-not (Test-Path -LiteralPath $providerPath)) {
            continue
        }

        $properties = Get-ItemProperty -LiteralPath $providerPath -ErrorAction SilentlyContinue
        foreach ($property in $properties.PSObject.Properties) {
            if (($property.Name -like 'Unattend0000000001*') -and ([string]$property.Value -match '(?i)^\s*["'']?X:\\Windows\\1\.cmd')) {
                $nativeKey = "$hive\$key"
                if (-not $backedUpKeys.ContainsKey($nativeKey)) {
                    $safeName = 'run-' + ($nativeKey -replace '[^A-Za-z0-9_.-]', '_')
                    $backedUpKeys[$nativeKey] = Export-CTRegistryKey -Context $Context -NativeKey $nativeKey -Name $safeName
                }
                if (Confirm-CTRequiredOperation -Caller $Caller -Target "$nativeKey::$($property.Name)" -Action 'Remove stale WinPE unattend Run value') {
                    $operationId = Start-CTOperation -Context $Context -Type 'RunValue' -Target "$nativeKey::$($property.Name)" -Data @{
                        Backup = [string]$backedUpKeys[$nativeKey].Path
                        BackupSha256 = [string]$backedUpKeys[$nativeKey].SHA256
                        Value  = [string]$property.Value
                    }
                    Remove-ItemProperty -LiteralPath $providerPath -Name $property.Name -ErrorAction Stop
                    Complete-CTOperation -Context $Context -Id $operationId
                }
            }
        }
    }
}

function Stop-CTOptionalProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $names = @($Manifest.Processes)
    foreach ($process in Get-Process -ErrorAction SilentlyContinue) {
        if ($names -notcontains $process.ProcessName) {
            continue
        }

        $path = $null
        try { $path = $process.Path } catch {}
        if ([string]::IsNullOrWhiteSpace([string]$path) -or
            -not (Test-CTPathUnderAnyRoot -Path $path -Roots @($Manifest.Directories)) -or
            (Test-CTPathHasReparsePoint -Path $path)) {
            Add-CTWarning -Context $Context -Message "Process $($process.ProcessName) did not run from an exact approved removal directory, or its path was unsafe; it was not stopped: $path"
            continue
        }

        if (Confirm-CTRequiredOperation -Caller $Caller -Target "$($process.ProcessName) PID=$($process.Id)" -Action 'Stop optional vendor process') {
            $startTimeUtcTicks = $null
            try { $startTimeUtcTicks = [string]$process.StartTime.ToUniversalTime().Ticks } catch { }
            if ([string]::IsNullOrWhiteSpace($startTimeUtcTicks)) {
                throw "Could not bind the process stop to a start time: $($process.ProcessName) PID=$($process.Id)"
            }
            $operationId = Start-CTOperation -Context $Context -Type 'ProcessStop' -Target "$($process.ProcessName):$($process.Id)" -Data @{
                Path              = $path
                StartTimeUtcTicks = $startTimeUtcTicks
            } -Reversible $false
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $process.Id -Timeout 5 -ErrorAction SilentlyContinue
            if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
                $Context.RebootNeeded = $true
                Add-CTWarning -Context $Context -Message "Optional process is still running and prevents a complete Apply: $($process.ProcessName) PID=$($process.Id)"
            }
            else {
                Complete-CTOperation -Context $Context -Id $operationId
            }
        }
    }
}

function Remove-CTServiceEntry {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Entry,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller,

        [switch]$Driver
    )

    $service = Get-CTServiceByName -Name $Entry.Name -Driver:$Driver
    if ($null -eq $service) {
        return
    }

    if (-not (Test-CTExpectedService -Service $service -ExpectedImage $Entry.ExpectedImage)) {
        throw "Refusing to modify $($Entry.Name): executable path does not exactly match $($Entry.ExpectedImage). Actual: $($service.PathName)"
    }

    $typeName = if ($Driver) { 'driver service' } else { 'service' }
    if (Confirm-CTRequiredOperation -Caller $Caller -Target $Entry.Name -Action "Disable, stop and delete $typeName registration") {
        $nativeKey = "HKLM\SYSTEM\CurrentControlSet\Services\$($Entry.Name)"
        $safeName = 'service-' + ($Entry.Name -replace '[^A-Za-z0-9_.-]', '_')
        $backup = Export-CTRegistryKey -Context $Context -NativeKey $nativeKey -Name $safeName

        $operationId = Start-CTOperation -Context $Context -Type $(if ($Driver) { 'DriverService' } else { 'Service' }) -Target $Entry.Name -Data @{
            Backup        = [string]$backup.Path
            BackupSha256  = [string]$backup.SHA256
            PathName      = [string]$service.PathName
            ExpectedImage = [string]$Entry.ExpectedImage
            State         = [string]$service.State
            StartMode     = [string]$service.StartMode
            StartName     = [string]$service.StartName
        }

        [void](Invoke-CTNativeCommand -FilePath "$env:SystemRoot\System32\sc.exe" -Arguments @('config', $Entry.Name, 'start=', 'disabled'))
        [void](Invoke-CTNativeCommand -FilePath "$env:SystemRoot\System32\sc.exe" -Arguments @('stop', $Entry.Name) -SuccessExitCodes @(0, 1052, 1061, 1062))
        [void](Invoke-CTNativeCommand -FilePath "$env:SystemRoot\System32\sc.exe" -Arguments @('delete', $Entry.Name) -SuccessExitCodes @(0, 1072))

        $remaining = Get-CTServiceByName -Name $Entry.Name -Driver:$Driver
        if ($Driver -or $service.State -eq 'Running' -or $null -ne $remaining) {
            $Context.RebootNeeded = $true
        }
        Complete-CTOperation -Context $Context -Id $operationId
    }
}

function Remove-CTServices {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    foreach ($entry in $Manifest.Services) {
        Remove-CTServiceEntry -Context $Context -Entry $entry -Caller $Caller
    }
    foreach ($entry in $Manifest.DriverServices) {
        Remove-CTServiceEntry -Context $Context -Entry $entry -Caller $Caller -Driver
    }
}

function Test-CTPathWritableByStandardUsers {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$DeleteOnly
    )

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trustedSids = New-Object Collections.Generic.List[string]
    foreach ($sid in @(
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )) { $trustedSids.Add($sid) }
    try {
        $ownerSid = (New-Object Security.Principal.NTAccount([string]$acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch { return $true }
    if (-not $trustedSids.Contains($ownerSid)) {
        return $true
    }

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $dangerous = [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    if (-not $DeleteOnly) {
        $dangerous = $dangerous -bor [Security.AccessControl.FileSystemRights]::Write
    }
    foreach ($entry in $acl.Access) {
        if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($entry.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if (($entry.FileSystemRights -band $dangerous) -eq 0) { continue }
        try {
            $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        }
        catch { return $true }
        if (-not $trustedSids.Contains($sid)) {
            return $true
        }
    }
    return $false
}

function Test-CTSecureSourcePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $target = ConvertTo-CTFullPath -Path $Path
    $current = $target
    $volumeRoot = [IO.Path]::GetPathRoot($current).TrimEnd('\')
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if ($current.TrimEnd('\').Equals($volumeRoot, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            $isExactTarget = $current.Equals($target, [StringComparison]::OrdinalIgnoreCase)
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Test-CTPathWritableByStandardUsers -Path $current -DeleteOnly:(-not $isExactTarget))) {
                return $false
            }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) { break }
        $current = $parent
    }
    return $true
}

function Test-CTLgpoBinary {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowStagingName
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $fullPath = ConvertTo-CTFullPath -Path $Path
    if ((-not $AllowStagingName -and [IO.Path]::GetFileName($fullPath) -ine 'LGPO.exe') -or (Test-CTPathHasReparsePoint -Path $fullPath)) { return $false }
    $fileHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
    if ($script:ApprovedLgpoSha256 -notcontains $fileHash) { return $false }
    if ((Get-CTNumericFileVersion -Path $fullPath) -ne $script:ApprovedLgpoVersion) { return $false }

    $signature = Get-AuthenticodeSignature -LiteralPath $fullPath -ErrorAction SilentlyContinue
    $version = (Get-Item -LiteralPath $fullPath -ErrorAction Stop).VersionInfo
    if ($null -eq $signature -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) { return $false }
    if ([string]$signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { return $false }
    if ([string]$version.OriginalFilename -ine 'LGPO.exe') { return $false }
    return ("$($version.FileDescription) $($version.ProductName)" -match '(?i)Local Group Policy|LGPO')
}

function Find-CTLgpo {
    param(
        [string]$RequestedPath,
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [string]$TrustedRunRoot
    )

    $candidates = New-Object Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($TrustedRunRoot)) {
        $candidates.Add((Join-Path $TrustedRunRoot 'tools\LGPO.exe'))
    }
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates.Add($RequestedPath)
    }
    $candidates.Add((Join-Path $Manifest.Roots.CTyun 'clink\Mirror\ScriptConfig\LGPO.exe'))
    $candidates.Add('C:\ProgramData\LGPO\LGPO.exe')

    foreach ($candidate in $candidates) {
        try {
            if ((Test-CTLgpoBinary -Path $candidate) -and (Test-CTSecureSourcePath -Path $candidate)) {
                return (ConvertTo-CTFullPath -Path $candidate)
            }
        }
        catch { continue }
    }
    return $null
}

function Copy-CTTrustedLgpo {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Context,
        [Parameter(Mandatory = $true)][string]$SourcePath
    )

    $toolsRoot = Join-Path $Context.Root 'tools'
    if (-not (Test-Path -LiteralPath $toolsRoot)) {
        New-Item -ItemType Directory -Path $toolsRoot -ErrorAction Stop | Out-Null
    }
    if (-not (Test-CTSecureSourcePath -Path $toolsRoot)) {
        throw "Hardened run tools directory is not secure: $toolsRoot"
    }

    $destination = Join-Path $toolsRoot 'LGPO.exe'
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        if (-not (Test-CTLgpoBinary -Path $destination)) {
            throw "Existing staged LGPO.exe failed identity or signature validation: $destination"
        }
        $existingSignature = Get-AuthenticodeSignature -LiteralPath $destination
        return [PSCustomObject]@{
            SourcePath       = $destination
            Path             = $destination
            SHA256           = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
            SignerThumbprint = [string]$existingSignature.SignerCertificate.Thumbprint
        }
    }

    if (-not (Test-CTLgpoBinary -Path $SourcePath) -or -not (Test-CTSecureSourcePath -Path $SourcePath)) {
        throw "LGPO source failed identity, signature or ACL validation: $SourcePath"
    }
    $sourceHash = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash
    $temporary = Join-Path $toolsRoot ('.LGPO-' + [guid]::NewGuid().ToString('N') + '.tmp.exe')
    try {
        Copy-Item -LiteralPath $SourcePath -Destination $temporary -ErrorAction Stop
        Set-CTRunFileAcl -Path $temporary
        $copiedHash = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash
        $sourceHashAfter = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash
        if ($copiedHash -ne $sourceHash -or $sourceHashAfter -ne $sourceHash) {
            throw 'LGPO source changed while it was being staged.'
        }
        if (-not (Test-CTLgpoBinary -Path $temporary -AllowStagingName)) {
            throw 'The staged LGPO copy failed independent signature or identity validation.'
        }
        Move-Item -LiteralPath $temporary -Destination $destination -ErrorAction Stop
        Set-CTRunFileAcl -Path $destination
        $signature = Get-AuthenticodeSignature -LiteralPath $destination
        return [PSCustomObject]@{
            SourcePath       = (ConvertTo-CTFullPath -Path $SourcePath)
            Path             = $destination
            SHA256           = $copiedHash
            SignerThumbprint = [string]$signature.SignerCertificate.Thumbprint
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
}

function Backup-CTLocalPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context
    )

    $policyDirectory = Join-Path $Context.Root 'policy'
    $files = @(
        "$env:SystemRoot\System32\GroupPolicy\Machine\Registry.pol",
        "$env:SystemRoot\System32\GroupPolicy\User\Registry.pol",
        "$env:SystemRoot\System32\GroupPolicy\GPT.INI"
    )

    $backups = @{}
    foreach ($file in $files) {
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            $destination = Join-Path $policyDirectory (($file -replace '^[A-Za-z]:\\', '') -replace '[\\:]', '_')
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
                Copy-Item -LiteralPath $file -Destination $destination -ErrorAction Stop
                Set-CTRunFileAcl -Path $destination
            }
            if ((Get-Item -LiteralPath $destination -ErrorAction Stop).Length -le 0 -or (Test-CTPathHasReparsePoint -Path $destination)) {
                throw "Local policy backup is missing, empty or unsafe: $destination"
            }
            $backups[$file] = [PSCustomObject]@{
                Path   = $destination
                SHA256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
            }
        }
    }

    return $backups
}

function Get-CTPendingLocalPolicyOperation {
    param([Parameter(Mandatory = $true)][PSObject]$Context)

    $pending = @($Context.Operations | Where-Object { $_.Status -eq 'Pending' -and $_.Type -eq 'LocalPolicy' })
    if ($pending.Count -eq 0) { return $null }
    if ($pending.Count -ne 1 -or [string]$pending[0].Target -ne 'CTyun fake WSUS') {
        throw 'The run contains ambiguous pending LocalPolicy journal entries.'
    }

    $inputPath = [string](Get-CTPropertyValue -InputObject $pending[0].Data -Name 'Input')
    $inputHash = [string](Get-CTPropertyValue -InputObject $pending[0].Data -Name 'InputSha256')
    $lgpoPath = [string](Get-CTPropertyValue -InputObject $pending[0].Data -Name 'LgpoPath')
    $lgpoHash = [string](Get-CTPropertyValue -InputObject $pending[0].Data -Name 'LgpoSha256')
    $signerThumbprint = [string](Get-CTPropertyValue -InputObject $pending[0].Data -Name 'SignerThumbprint')
    if ([string]::IsNullOrWhiteSpace($inputPath) -or [string]::IsNullOrWhiteSpace($inputHash) -or
        [string]::IsNullOrWhiteSpace($lgpoPath) -or [string]::IsNullOrWhiteSpace($lgpoHash) -or [string]::IsNullOrWhiteSpace($signerThumbprint) -or
        -not (Test-CTPathWithinRoot -Path $inputPath -Root (Join-Path $Context.Root 'policy')) -or
        -not (Test-CTPathWithinRoot -Path $lgpoPath -Root (Join-Path $Context.Root 'tools'))) {
        throw 'The pending LocalPolicy journal entry does not reference the hardened run paths.'
    }
    return $pending[0]
}

function Clear-CTFakeWsusPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [string]$LgpoPath,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $pendingOperation = Get-CTPendingLocalPolicyOperation -Context $Context
    $policySignature = Get-CTWsusPolicySignature -Manifest $Manifest
    if ($policySignature.Classification -eq 'Absent') {
        if ($null -ne $pendingOperation) {
            Complete-CTOperation -Context $Context -Id ([string]$pendingOperation.Id)
        }
        return
    }
    if ($policySignature.Classification -eq 'Conflict' -or
        ($policySignature.Classification -eq 'PartialReferenceCTyunLoopback' -and $null -eq $pendingOperation)) {
        throw 'Windows Update policy does not exactly match the five-value CTyun loopback signature. It was preserved and Apply stopped.'
    }

    if ($null -ne $pendingOperation) {
        $trustedLgpo = [string](Get-CTPropertyValue -InputObject $pendingOperation.Data -Name 'LgpoPath')
        $expectedLgpoHash = [string](Get-CTPropertyValue -InputObject $pendingOperation.Data -Name 'LgpoSha256')
        $expectedSigner = [string](Get-CTPropertyValue -InputObject $pendingOperation.Data -Name 'SignerThumbprint')
        $currentLgpoSignature = Get-AuthenticodeSignature -LiteralPath $trustedLgpo -ErrorAction SilentlyContinue
        if (-not (Test-CTLgpoBinary -Path $trustedLgpo) -or
            -not (Test-CTSecureSourcePath -Path $trustedLgpo) -or
            (Get-FileHash -LiteralPath $trustedLgpo -Algorithm SHA256).Hash -ne $expectedLgpoHash -or
            [string]$currentLgpoSignature.SignerCertificate.Thumbprint -ne $expectedSigner) {
            throw 'The staged LGPO.exe no longer matches the pending LocalPolicy journal entry.'
        }
        $policyBackups = Get-CTPropertyValue -InputObject $pendingOperation.Data -Name 'Backups'
        if ($null -ne $policyBackups) {
            foreach ($backupEntry in $policyBackups.GetEnumerator()) {
                $backupPath = [string](Get-CTPropertyValue -InputObject $backupEntry.Value -Name 'Path')
                $backupHash = [string](Get-CTPropertyValue -InputObject $backupEntry.Value -Name 'SHA256')
                if ([string]::IsNullOrWhiteSpace($backupPath) -or [string]::IsNullOrWhiteSpace($backupHash) -or
                    -not (Test-CTPathWithinRoot -Path $backupPath -Root (Join-Path $Context.Root 'policy')) -or
                    -not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or
                    -not (Test-CTSecureSourcePath -Path $backupPath) -or
                    (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ne $backupHash) {
                    throw 'A LocalPolicy backup no longer matches the pending journal entry.'
                }
            }
        }
    }
    else {
        $lgpoSource = Find-CTLgpo -RequestedPath $LgpoPath -Manifest $Manifest -TrustedRunRoot $Context.Root
        if ([string]::IsNullOrWhiteSpace($lgpoSource)) {
            throw 'Fake WSUS policy values are active, but no securely located Microsoft-signed LGPO.exe was found. Supply -LgpoPath or place LGPO.exe in C:\ProgramData\LGPO. No policy was changed.'
        }
        $stagedLgpo = Copy-CTTrustedLgpo -Context $Context -SourcePath $lgpoSource
        $trustedLgpo = [string]$stagedLgpo.Path
    }

    [void](Confirm-CTRequiredOperation -Caller $Caller -Target 'Local computer policy' -Action 'Clear five CTyun fake WSUS entries with Microsoft LGPO.exe')

    if ($null -ne $pendingOperation) {
        $operationId = [string]$pendingOperation.Id
        $inputPath = [string](Get-CTPropertyValue -InputObject $pendingOperation.Data -Name 'Input')
        $expectedInputHash = [string](Get-CTPropertyValue -InputObject $pendingOperation.Data -Name 'InputSha256')
        if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf) -or
            -not (Test-CTSecureSourcePath -Path $inputPath) -or
            (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash -ne $expectedInputHash) {
            throw 'The LocalPolicy input no longer matches the pending journal entry.'
        }
    }
    else {
        $policyBackups = Backup-CTLocalPolicy -Context $Context
        $lines = New-Object Collections.Generic.List[string]
        foreach ($entry in $Manifest.WsusPolicy.Values) {
            $lines.Add('Computer')
            $lines.Add([string]$Manifest.WsusPolicy.MachineKey)
            $lines.Add([string]$entry.Name)
            $lines.Add('CLEAR')
            $lines.Add('')
        }
        foreach ($entry in $Manifest.WsusPolicy.AuValues) {
            $lines.Add('Computer')
            $lines.Add([string]$Manifest.WsusPolicy.AuKey)
            $lines.Add([string]$entry.Name)
            $lines.Add('CLEAR')
            $lines.Add('')
        }

        $inputPath = Join-Path $Context.Root 'policy\clear-ctyun-wsus.txt'
        $lines | Set-Content -LiteralPath $inputPath -Encoding ASCII
        Set-CTRunFileAcl -Path $inputPath
        $inputHash = (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash
        $signature = Get-AuthenticodeSignature -LiteralPath $trustedLgpo
        $operationId = Start-CTOperation -Context $Context -Type 'LocalPolicy' -Target 'CTyun fake WSUS' -Data @{
            SourcePath         = [string]$stagedLgpo.SourcePath
            LgpoPath           = $trustedLgpo
            LgpoSha256         = [string]$stagedLgpo.SHA256
            SignerThumbprint   = [string]$signature.SignerCertificate.Thumbprint
            Backups            = $policyBackups
            Input              = $inputPath
            InputSha256        = $inputHash
        }
    }
    [void](Invoke-CTNativeCommand -FilePath $trustedLgpo -Arguments @('/t', $inputPath))

    foreach ($entry in $Manifest.WsusPolicy.Values) {
        $providerPath = "HKLM:\$($Manifest.WsusPolicy.MachineKey)"
        Remove-ItemProperty -LiteralPath $providerPath -Name $entry.Name -ErrorAction SilentlyContinue
    }
    foreach ($entry in $Manifest.WsusPolicy.AuValues) {
        $providerPath = "HKLM:\$($Manifest.WsusPolicy.AuKey)"
        Remove-ItemProperty -LiteralPath $providerPath -Name $entry.Name -ErrorAction SilentlyContinue
    }

    [void](Invoke-CTNativeCommand -FilePath "$env:SystemRoot\System32\gpupdate.exe" -Arguments @('/target:computer', '/force'))

    $remainingSignature = Get-CTWsusPolicySignature -Manifest $Manifest
    if ($remainingSignature.Classification -ne 'Absent') {
        throw 'LGPO completed, but one or more fake WSUS values returned after gpupdate. The script stopped before deleting Mirror.'
    }

    Complete-CTOperation -Context $Context -Id $operationId
}

function Get-CTQuarantineDestination {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = ConvertTo-CTFullPath -Path $Path
    $root = [IO.Path]::GetPathRoot($fullPath)
    $driveName = $root.TrimEnd('\').Replace(':', '')
    $relative = $fullPath.Substring($root.Length).TrimStart('\')
    return Join-Path (Join-Path $Context.Root 'quarantine') (Join-Path $driveName $relative)
}

function Move-CTPathToQuarantine {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$ProtectedPaths,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $source = ConvertTo-CTFullPath -Path $Path
    if (Test-CTPathIsProtected -Candidate $source -ProtectedPaths $ProtectedPaths) {
        throw "Refusing to quarantine a protected path or its parent: $source"
    }

    if (Test-CTPathHasReparsePoint -Path $source) {
        throw "Refusing to quarantine a path with a reparse-point ancestor: $source"
    }

    $destination = Get-CTQuarantineDestination -Context $Context -Path $source
    $quarantineRoot = ConvertTo-CTFullPath -Path (Join-Path $Context.Root 'quarantine')
    if (-not (Test-CTPathWithinRoot -Path $destination -Root $quarantineRoot)) {
        throw "Quarantine destination escaped the run directory: $destination"
    }
    if (-not ([IO.Path]::GetPathRoot($source).Equals([IO.Path]::GetPathRoot($destination), [StringComparison]::OrdinalIgnoreCase))) {
        throw "Quarantine must be on the same volume as the source: $source -> $destination"
    }

    if (Test-Path -LiteralPath $destination) {
        throw "Quarantine destination already exists: $destination"
    }

    if (Confirm-CTRequiredOperation -Caller $Caller -Target $source -Action "Move to quarantine: $destination") {
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        $operationId = Start-CTOperation -Context $Context -Type 'QuarantinePath' -Target $source -Data @{
            Source      = $source
            Destination = $destination
        }
        try {
            if ((Test-CTPathHasReparsePoint -Path $source) -or (Test-CTPathHasReparsePoint -Path $parent)) {
                throw 'A reparse point appeared after preflight.'
            }
            Move-Item -LiteralPath $source -Destination $destination -Force -ErrorAction Stop
            Complete-CTOperation -Context $Context -Id $operationId
        }
        catch {
            $Context.RebootNeeded = $true
            Add-CTWarning -Context $Context -Message "Could not quarantine $source, usually because it is still loaded. Reboot and run Apply again. $($_.Exception.Message)"
        }
    }
}

function Move-CTRemovalPaths {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $allPaths = @($Manifest.Directories) + @($Manifest.Files) + @(Get-CTEncodedRemovalFiles -Manifest $Manifest) + @($Manifest.PublicDataDirectories)
    foreach ($path in $allPaths) {
        Move-CTPathToQuarantine -Context $Context -Path $path -ProtectedPaths (@($Manifest.Preserve.Paths) + @($Manifest.PublicDataPreserve) + @('C:\Windows\System32\drivers\FileCrypt.sys')) -Caller $Caller
    }
}

function Test-CTPathUnderAnyRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Roots
    )

    try { $fullPath = ConvertTo-CTFullPath -Path $Path } catch { return $false }
    foreach ($root in $Roots) {
        try { $fullRoot = ConvertTo-CTFullPath -Path $root } catch { continue }
        if ($fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Move-CTDeadShortcuts {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $searchRoots = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
        "$env:PUBLIC\Desktop",
        [Environment]::GetFolderPath('Desktop')
    ) | Select-Object -Unique
    $removalRoots = @($Manifest.Directories)
    $shell = New-Object -ComObject WScript.Shell

    foreach ($searchRoot in $searchRoots) {
        if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) { continue }
        foreach ($shortcutFile in Get-ChildItem -LiteralPath $searchRoot -Filter '*.lnk' -File -Recurse -Force -ErrorAction SilentlyContinue) {
            try {
                $shortcut = $shell.CreateShortcut($shortcutFile.FullName)
                $targetPath = [string]$shortcut.TargetPath
                if ([string]::IsNullOrWhiteSpace($targetPath)) { continue }
                if (-not (Test-CTPathUnderAnyRoot -Path $targetPath -Roots $removalRoots)) { continue }

                Move-CTPathToQuarantine -Context $Context -Path $shortcutFile.FullName -ProtectedPaths (@($Manifest.Preserve.Paths) + @($Manifest.PublicDataPreserve) + @('C:\Windows\System32\drivers\FileCrypt.sys')) -Caller $Caller
            }
            catch {
                if ($_.Exception -is [OperationCanceledException]) { throw }
                Add-CTWarning -Context $Context -Message "Could not inspect shortcut $($shortcutFile.FullName): $($_.Exception.Message)"
            }
        }
    }
}

function Test-CTRegistryValueExistsInView {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Registry32', 'Registry64')][string]$View
    )

    $registryHive = if ($Hive -eq 'HKLM') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $registryView = if ($View -eq 'Registry32') { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($registryHive, $registryView)
    try {
        $registryKey = $baseKey.OpenSubKey($Key, $false)
        if ($null -eq $registryKey) { return $false }
        try { return @($registryKey.GetValueNames()) -contains $Name }
        finally { $registryKey.Dispose() }
    }
    finally { $baseKey.Dispose() }
}

function Remove-CTStartupApprovedEntries {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    $locations = @(
        @{ Hive = 'HKLM'; View = 'Registry64'; Provider = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Native = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' },
        @{ Hive = 'HKLM'; View = 'Registry32'; Provider = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; Native = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' },
        @{ Hive = 'HKCU'; View = 'Registry64'; Provider = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Native = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' },
        @{ Hive = 'HKCU'; View = 'Registry32'; Provider = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; Native = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
    )

    foreach ($location in $locations) {
        if (-not (Test-Path -LiteralPath $location.Provider)) { continue }
        $properties = Get-ItemProperty -LiteralPath $location.Provider -ErrorAction SilentlyContinue
        $backup = $null
        foreach ($property in $properties.PSObject.Properties) {
            $manifestNames = @($Manifest.RunValues | Where-Object { $_.Hive -eq $location.Hive } | ForEach-Object { [string]$_.Name })
            $matches = ($manifestNames -contains $property.Name) -or ($property.Name -like 'Unattend0000000001*')
            if (-not $matches) { continue }

            $underlyingRunValueExists = Test-CTRegistryValueExistsInView -Hive $location.Hive -Key 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $property.Name -View $location.View
            if ($underlyingRunValueExists) {
                Add-CTWarning -Context $Context -Message "StartupApproved entry was preserved because its underlying Run value still exists: $($location.Hive) / $($property.Name)"
                continue
            }

            if ($null -eq $backup) {
                $safeName = 'startup-approved-' + ($location.Native -replace '[^A-Za-z0-9_.-]', '_')
                $backup = Export-CTRegistryKey -Context $Context -NativeKey $location.Native -Name $safeName
            }
            if (Confirm-CTRequiredOperation -Caller $Caller -Target "$($location.Native)::$($property.Name)" -Action 'Remove stale StartupApproved entry') {
                $operationId = Start-CTOperation -Context $Context -Type 'RunValue' -Target "$($location.Native)::$($property.Name)" -Data @{ Backup = [string]$backup.Path; BackupSha256 = [string]$backup.SHA256; Value = '<binary StartupApproved state>' }
                Remove-ItemProperty -LiteralPath $location.Provider -Name $property.Name -ErrorAction SilentlyContinue
                Complete-CTOperation -Context $Context -Id $operationId
            }
        }
    }
}

function Test-CTSafeCloudbaseSid {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][string]$MachineSid
    )

    if (-not $Sid.StartsWith($MachineSid + '-', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Sid -notmatch '-(?<rid>[0-9]+)$') { return $false }
    $rid = [uint64]$matches.rid
    return $rid -ge 1000
}

function Test-CTCloudbasePrepareProcessEvidence {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Evidence,
        [Parameter(Mandatory = $true)][string]$ExpectedSid,
        [Parameter(Mandatory = $true)][string]$ExpectedImage
    )

    $failures = New-Object Collections.Generic.List[string]
    $expectedPath = ConvertTo-CTFullPath -Path $ExpectedImage
    $expectedName = [IO.Path]::GetFileNameWithoutExtension($expectedPath)
    $expectedFileName = [IO.Path]::GetFileName($expectedPath)
    $processId = Get-CTPropertyValue -InputObject $Evidence -Name 'ProcessId'
    $sessionId = Get-CTPropertyValue -InputObject $Evidence -Name 'SessionId'
    $stable = Get-CTPropertyValue -InputObject $Evidence -Name 'Stable'
    $hasReparsePoint = Get-CTPropertyValue -InputObject $Evidence -Name 'HasReparsePoint'
    $secureSource = Get-CTPropertyValue -InputObject $Evidence -Name 'SecureSource'
    if ([string](Get-CTPropertyValue -InputObject $Evidence -Name 'ProcessName') -cne $expectedName -or
        [string](Get-CTPropertyValue -InputObject $Evidence -Name 'CimName') -cne $expectedFileName) {
        $failures.Add('ProcessNameMismatch')
    }
    if (-not [string]::Equals([string](Get-CTPropertyValue -InputObject $Evidence -Name 'Path'), $expectedPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string](Get-CTPropertyValue -InputObject $Evidence -Name 'CimPath'), $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        $failures.Add('ProcessPathMismatch')
    }
    if (-not [string]::Equals([string](Get-CTPropertyValue -InputObject $Evidence -Name 'OwnerSid'), $ExpectedSid, [StringComparison]::OrdinalIgnoreCase)) {
        $failures.Add('ProcessOwnerMismatch')
    }
    if ($processId -isnot [int] -or [int]$processId -le 0 -or
        [string](Get-CTPropertyValue -InputObject $Evidence -Name 'StartTimeUtcTicks') -notmatch '^[0-9]{10,20}$' -or
        $stable -isnot [bool] -or $stable -ne $true) {
        $failures.Add('ProcessIdentityUnstable')
    }
    if ($sessionId -isnot [uint32] -and $sessionId -isnot [int]) {
        $failures.Add('ProcessSessionUnknown')
    }
    elseif ([uint32]$sessionId -ne 0) {
        $failures.Add('InteractiveSessionDetected')
    }
    if ([string](Get-CTPropertyValue -InputObject $Evidence -Name 'SignatureStatus') -ne 'Valid' -or
        [string](Get-CTPropertyValue -InputObject $Evidence -Name 'FileSha256') -notmatch '^[0-9A-F]{64}$') {
        $failures.Add('ProcessSignatureInvalid')
    }
    if ($hasReparsePoint -isnot [bool] -or $hasReparsePoint -ne $false -or
        $secureSource -isnot [bool] -or $secureSource -ne $true) {
        $failures.Add('ProcessPathUnsafe')
    }

    [PSCustomObject]@{
        Passed   = $failures.Count -eq 0
        Failures = $failures.ToArray()
    }
}

function Get-CTProcessesByOwnerSid {
    param(
        [Parameter(Mandatory = $true)][string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) { throw 'A nonempty owner SID is required for process inventory.' }
    try { $processSnapshot = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop) }
    catch { throw "Process owner SID inventory failed: $($_.Exception.Message)" }

    $owned = New-Object Collections.Generic.List[object]
    $unresolved = New-Object Collections.Generic.List[uint32]
    foreach ($cimProcess in $processSnapshot) {
        $processId = [uint32]$cimProcess.ProcessId
        if ($processId -in @(0, 4)) { continue }
        $candidate = $cimProcess
        $owner = $null
        try {
            $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid -ErrorAction Stop
        }
        catch { $owner = $null }
        if ($null -eq $owner -or [uint32]$owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$owner.Sid)) {
            try { $retry = @(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = $processId") -ErrorAction Stop) }
            catch { $unresolved.Add($processId); continue }
            if ($retry.Count -eq 0) { continue }
            if ($retry.Count -ne 1) { $unresolved.Add($processId); continue }
            $candidate = $retry[0]
            try { $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid -ErrorAction Stop }
            catch { $owner = $null }
            if ($null -eq $owner -or [uint32]$owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$owner.Sid)) {
                $unresolved.Add($processId)
                continue
            }
        }
        if (-not [string]::Equals([string]$owner.Sid, $Sid, [StringComparison]::OrdinalIgnoreCase)) { continue }

        $process = Get-Process -Id ([int]$processId) -ErrorAction SilentlyContinue
        if ($null -eq $process) {
            try { $stillLive = @(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = $processId") -ErrorAction Stop) }
            catch { throw "Targeted process liveness query failed after Get-Process failed for PID $processId." }
            if ($stillLive.Count -eq 0) { continue }
            if ($stillLive.Count -ne 1) { throw "A target-SID process remained live with ambiguous identity for PID $processId." }
            try { $stillOwner = Invoke-CimMethod -InputObject $stillLive[0] -MethodName GetOwnerSid -ErrorAction Stop }
            catch { $stillOwner = $null }
            if ($null -eq $stillOwner -or [uint32]$stillOwner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$stillOwner.Sid)) {
                throw "A live process could not be revalidated after Get-Process failed for PID $processId."
            }
            if ([string]::Equals([string]$stillOwner.Sid, $Sid, [StringComparison]::OrdinalIgnoreCase)) {
                throw "A live target-SID process could not be inspected safely for PID $processId."
            }
            continue
        }
        $path = $null
        $startTimeUtcTicks = $null
        try { $path = ConvertTo-CTFullPath -Path ([string]$process.Path) } catch { }
        try { $startTimeUtcTicks = [string]$process.StartTime.ToUniversalTime().Ticks } catch { }

        try { $freshCim = @(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = $processId") -ErrorAction Stop) }
        catch { $freshCim = @() }
        $freshOwner = $null
        if ($freshCim.Count -eq 1) {
            try { $freshOwner = Invoke-CimMethod -InputObject $freshCim[0] -MethodName GetOwnerSid -ErrorAction Stop }
            catch { $freshOwner = $null }
        }
        $stable = $freshCim.Count -eq 1 -and $null -ne $freshOwner -and [uint32]$freshOwner.ReturnValue -eq 0 -and
            [string]::Equals([string]$freshOwner.Sid, $Sid, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$candidate.Name, [string]$freshCim[0].Name, [StringComparison]::Ordinal) -and
            [string]::Equals([string]$candidate.CreationDate, [string]$freshCim[0].CreationDate, [StringComparison]::Ordinal)
        $owned.Add([PSCustomObject]@{
            ProcessId         = [int]$processId
            ProcessName       = [string]$process.ProcessName
            CimName           = [string]$candidate.Name
            Path              = $path
            CimPath           = [string]$candidate.ExecutablePath
            OwnerSid          = [string]$owner.Sid
            SessionId         = $candidate.SessionId
            StartTimeUtcTicks = $startTimeUtcTicks
            Stable            = $stable
        })
    }
    if ($unresolved.Count -gt 0) {
        throw "Process owner SID inventory remained unresolved for $($unresolved.Count) live processes."
    }
    return $owned.ToArray()
}

function Get-CTCloudbaseOwnedProcessEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][hashtable]$Manifest
    )

    $taskEntries = @($Manifest.ScheduledTasks | Where-Object { $_.Name -eq 'ecloud_update_agent_detect' })
    if ($taskEntries.Count -ne 1) { throw 'The immutable TaskAgentDetect scheduled-task identity is missing or ambiguous.' }
    $expectedImage = ConvertTo-CTFullPath -Path ([string]$taskEntries[0].ExpectedImage)
    if ([IO.Path]::GetFileName($expectedImage) -cne 'TaskAgentDetect.exe') { throw 'The immutable TaskAgentDetect image name is unexpected.' }

    $evidence = New-Object Collections.Generic.List[object]
    foreach ($item in @(Get-CTProcessesByOwnerSid -Sid $Sid)) {
        try {
            $fileEvidence = Get-CTCoreFileEvidence -Path ([string]$item.Path)
            $item | Add-Member -NotePropertyName SignatureStatus -NotePropertyValue ([string]$fileEvidence.SignatureStatus)
            $item | Add-Member -NotePropertyName FileSha256 -NotePropertyValue ([string]$fileEvidence.FileSha256)
            $item | Add-Member -NotePropertyName HasReparsePoint -NotePropertyValue (Test-CTPathHasReparsePoint -Path ([string]$item.Path))
            $item | Add-Member -NotePropertyName SecureSource -NotePropertyValue ([bool]$fileEvidence.SecureSource)
        }
        catch {
            $item | Add-Member -NotePropertyName SignatureStatus -NotePropertyValue 'Unavailable'
            $item | Add-Member -NotePropertyName FileSha256 -NotePropertyValue $null
            $item | Add-Member -NotePropertyName HasReparsePoint -NotePropertyValue $true
            $item | Add-Member -NotePropertyName SecureSource -NotePropertyValue $false
        }
        $validation = Test-CTCloudbasePrepareProcessEvidence -Evidence $item -ExpectedSid $Sid -ExpectedImage $expectedImage
        $item | Add-Member -NotePropertyName Approved -NotePropertyValue ([bool]$validation.Passed)
        $item | Add-Member -NotePropertyName Failures -NotePropertyValue @($validation.Failures)
        $evidence.Add($item)
    }
    return $evidence.ToArray()
}

function Get-CTCloudbaseIdentityAnchors {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [object[]]$TaskSnapshot
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) { return @() }
    $anchors = New-Object Collections.Generic.List[string]
    foreach ($entry in @($Manifest.Services | Where-Object { $_.Name -in @('cloudbase-init', 'cloudbase-init-unattend') })) {
        $service = Get-CTServiceByName -Name $entry.Name
        if ($null -eq $service -or -not (Test-CTExpectedService -Service $service -ExpectedImage $entry.ExpectedImage)) { continue }
        $serviceSid = Resolve-CTAccountSid -Identity ([string]$service.StartName)
        if ([string]::Equals($serviceSid, $Sid, [StringComparison]::OrdinalIgnoreCase)) {
            $anchors.Add("service:$($entry.Name)")
        }
    }

    $tasks = if ($null -ne $TaskSnapshot) { @($TaskSnapshot) } else { @(Get-ScheduledTask -ErrorAction Stop) }
    $tasks = @($tasks)
    foreach ($entry in $Manifest.ScheduledTasks) {
        foreach ($task in @($tasks | Where-Object {
            ([string]$_.TaskName).Equals([string]$entry.Name, [StringComparison]::OrdinalIgnoreCase) -and
            ([string]$_.TaskPath).Equals([string]$entry.TaskPath, [StringComparison]::OrdinalIgnoreCase)
        })) {
            if (-not (Test-CTScheduledTaskDefinition -Task $task -Entry $entry)) { continue }
            $principal = Get-CTPropertyValue -InputObject $task -Name 'Principal'
            $principalSid = Resolve-CTAccountSid -Identity ([string](Get-CTPropertyValue -InputObject $principal -Name 'UserId'))
            if ([string]::Equals($principalSid, $Sid, [StringComparison]::OrdinalIgnoreCase)) {
                $anchors.Add("task:$($entry.TaskPath)$($entry.Name)")
            }
        }
    }
    return @($anchors.ToArray() | Sort-Object -Unique)
}

function Save-CTCloudbaseIdentityEvidence {
    param(
        [Parameter(Mandatory = $true)][PSObject]$Context,
        [Parameter(Mandatory = $true)][hashtable]$Manifest
    )

    $existing = @($Context.Operations | Where-Object { $_.Type -eq 'CloudbaseIdentityEvidence' -and $_.Status -eq 'Completed' })
    if ($existing.Count -gt 1) { throw 'Multiple Cloudbase identity evidence entries exist in this run.' }
    if ($existing.Count -eq 1) {
        $recordedRoot = [string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'CloudbaseRoot')
        $recordedMachineSid = [string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'MachineSid')
        $recordedState = [string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'State')
        $recordedServices = @(Get-CTPropertyValue -InputObject $existing[0].Data -Name 'Services')
        $recordedAnchors = @(Get-CTPropertyValue -InputObject $existing[0].Data -Name 'IdentityAnchors')
        if (-not $recordedRoot.Equals((ConvertTo-CTFullPath -Path $Manifest.Roots.Cloudbase), [StringComparison]::OrdinalIgnoreCase) -or
            $recordedMachineSid -ne [string]$Context.MachineSid) {
            throw 'Archived Cloudbase identity evidence does not belong to this manifest or machine.'
        }
        if ($recordedState -eq 'AbsentAtBaseline') {
            if ($recordedServices.Count -ne 0 -or $recordedAnchors.Count -ne 0 -or
                -not [string]::IsNullOrWhiteSpace([string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'AccountSid')) -or
                -not [string]::IsNullOrWhiteSpace([string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'ProfileSid'))) {
                throw 'Archived absent-at-baseline Cloudbase evidence is internally inconsistent.'
            }
            return $existing[0]
        }
        if ($recordedState -eq 'ServicePresentIdentityAbsent') {
            if ($recordedServices.Count -eq 0 -or $recordedAnchors.Count -ne 0 -or
                -not [string]::IsNullOrWhiteSpace([string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'AccountSid')) -or
                -not [string]::IsNullOrWhiteSpace([string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'ProfileSid'))) {
                throw 'Archived service-present/identity-absent Cloudbase evidence is internally inconsistent.'
            }
        }
        elseif ($recordedState -ne 'PresentAtBaseline' -or $recordedServices.Count -eq 0 -or $recordedAnchors.Count -eq 0) {
            throw 'Archived Cloudbase identity evidence has no exact service record.'
        }
        $allowedAnchors = @('service:cloudbase-init', 'service:cloudbase-init-unattend') + @($Manifest.ScheduledTasks | ForEach-Object { "task:$($_.TaskPath)$($_.Name)" })
        if (@($recordedAnchors | Where-Object { $_ -notin $allowedAnchors }).Count -gt 0) {
            throw 'Archived Cloudbase identity evidence contains an unexpected principal anchor.'
        }
        $recordedSid = [string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'AccountSid')
        if ([string]::IsNullOrWhiteSpace($recordedSid)) { $recordedSid = [string](Get-CTPropertyValue -InputObject $existing[0].Data -Name 'ProfileSid') }
        if (-not [string]::IsNullOrWhiteSpace($recordedSid) -and -not (Test-CTSafeCloudbaseSid -Sid $recordedSid -MachineSid ([string]$Context.MachineSid))) {
            throw 'Archived Cloudbase identity evidence contains a built-in, foreign or otherwise unsafe SID.'
        }
        foreach ($recordedService in $recordedServices) {
            $recordedName = [string](Get-CTPropertyValue -InputObject $recordedService -Name 'Name')
            $recordedImage = [string](Get-CTPropertyValue -InputObject $recordedService -Name 'ResolvedImage')
            $expectedEntry = @($Manifest.Services | Where-Object { $_.Name -eq $recordedName -and $_.Name -in @('cloudbase-init', 'cloudbase-init-unattend') }) | Select-Object -First 1
            if ($null -eq $expectedEntry -or
                -not $recordedImage.Equals((ConvertTo-CTFullPath -Path $expectedEntry.ExpectedImage), [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Archived Cloudbase identity evidence contains an unexpected service identity.'
            }
        }
        return $existing[0]
    }

    $account = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1
    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -ieq 'C:\Users\cloudbase-init' })
    if ($profiles.Count -gt 1) { throw 'Multiple exact cloudbase-init profile records were found.' }
    if ($null -ne $account -and $profiles.Count -eq 1 -and [string]$profiles[0].SID -ne [string]$account.SID) {
        throw 'The cloudbase-init account SID does not match its exact profile SID.'
    }
    $observedSid = if ($null -ne $account) { [string]$account.SID } elseif ($profiles.Count -eq 1) { [string]$profiles[0].SID } else { $null }
    if (-not [string]::IsNullOrWhiteSpace($observedSid) -and -not (Test-CTSafeCloudbaseSid -Sid $observedSid -MachineSid ([string]$Context.MachineSid))) {
        throw 'The cloudbase-init identity uses a built-in, foreign or otherwise unsafe SID.'
    }
    if (-not [string]::IsNullOrWhiteSpace($observedSid)) {
        $sidProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { [string]$_.SID -eq $observedSid })
        if (@($sidProfiles | Where-Object { $_.LocalPath -ine 'C:\Users\cloudbase-init' }).Count -gt 0 -or $sidProfiles.Count -gt 1) {
            throw 'The cloudbase-init SID has an unexpected or additional Profile path; baseline evidence was refused.'
        }
    }

    $serviceEvidence = New-Object Collections.Generic.List[object]
    foreach ($entry in @($Manifest.Services | Where-Object { $_.Name -in @('cloudbase-init', 'cloudbase-init-unattend') })) {
        $service = Get-CTServiceByName -Name $entry.Name
        if ($null -eq $service) { continue }
        if (-not (Test-CTExpectedService -Service $service -ExpectedImage $entry.ExpectedImage)) {
            throw "Cloudbase service ImagePath does not match the immutable reference: $($entry.Name) / $($service.PathName)"
        }
        $resolvedImage = Get-CTImageExecutable -PathName ([string]$service.PathName)
        if (-not (Test-CTPathWithinRoot -Path $resolvedImage -Root $Manifest.Roots.Cloudbase)) {
            throw "Cloudbase service image is outside the immutable Cloudbase root: $($entry.Name) / $resolvedImage"
        }
        $serviceEvidence.Add([PSCustomObject]@{
            Name          = [string]$entry.Name
            PathName      = [string]$service.PathName
            ResolvedImage = $resolvedImage
            ExpectedImage = [string]$entry.ExpectedImage
            StartName     = [string]$service.StartName
        })
    }

    if (($null -ne $account -or $profiles.Count -gt 0) -and $serviceEvidence.Count -eq 0) {
        throw 'A cloudbase-init account/profile exists, but no exact Cloudbase service establishes ownership. Identity deletion was refused.'
    }
    $identityAnchors = if (-not [string]::IsNullOrWhiteSpace($observedSid)) {
        @(Get-CTCloudbaseIdentityAnchors -Sid $observedSid -Manifest $Manifest)
    }
    else { @() }
    $identityAnchors = @($identityAnchors)
    if (-not [string]::IsNullOrWhiteSpace($observedSid) -and $identityAnchors.Count -eq 0) {
        throw 'The cloudbase-init account/Profile is not bound to an exact Cloudbase service or scheduled-task principal SID.'
    }
    Add-CTOperation -Context $Context -Type 'CloudbaseIdentityEvidence' -Target (ConvertTo-CTFullPath -Path $Manifest.Roots.Cloudbase) -Data @{
        State         = if ($serviceEvidence.Count -eq 0) { 'AbsentAtBaseline' } elseif ([string]::IsNullOrWhiteSpace($observedSid)) { 'ServicePresentIdentityAbsent' } else { 'PresentAtBaseline' }
        MachineSid    = [string]$Context.MachineSid
        CloudbaseRoot = (ConvertTo-CTFullPath -Path $Manifest.Roots.Cloudbase)
        AccountSid    = if ($null -ne $account) { [string]$account.SID } else { $null }
        ProfilePath   = if ($profiles.Count -eq 1) { [string]$profiles[0].LocalPath } else { $null }
        ProfileSid    = if ($profiles.Count -eq 1) { [string]$profiles[0].SID } else { $null }
        Services      = $serviceEvidence.ToArray()
        IdentityAnchors = @($identityAnchors)
    }
    return @($Context.Operations | Where-Object { $_.Type -eq 'CloudbaseIdentityEvidence' -and $_.Status -eq 'Completed' }) | Select-Object -First 1
}

function Resolve-CTAccountSid {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    $text = $Identity.Trim()
    if ($text -match '^S-1-[0-9-]+$') { return $text }
    if ($text.StartsWith('.\', [StringComparison]::Ordinal)) {
        $text = "$env:COMPUTERNAME\$($text.Substring(2))"
    }
    elseif ($text.IndexOf('\') -lt 0) {
        $text = "$env:COMPUTERNAME\$text"
    }
    try {
        return (New-Object Security.Principal.NTAccount($text)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch { return $null }
}

function Get-CTCloudbaseIdentityReferences {
    param([Parameter(Mandatory = $true)][string]$Sid)

    $references = New-Object Collections.Generic.List[string]
    $namePattern = '(?i)(^|\\)cloudbase-init$'
    $sidPattern = [regex]::Escape($Sid)
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        $serviceStartSid = Resolve-CTAccountSid -Identity ([string]$service.StartName)
        if ([string]$service.Name -in @('cloudbase-init', 'cloudbase-init-unattend') -or
            $serviceStartSid -eq $Sid -or [string]$service.StartName -match $namePattern -or [string]$service.StartName -match $sidPattern -or
            [string]$service.PathName -match '(?i)C:\\Users\\cloudbase-init(?:\\|$)') {
            $references.Add("service:$($service.Name)")
        }
    }
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
        $principal = Get-CTPropertyValue -InputObject $task -Name 'Principal'
        $principalUser = [string](Get-CTPropertyValue -InputObject $principal -Name 'UserId')
        $principalGroup = [string](Get-CTPropertyValue -InputObject $principal -Name 'GroupId')
        $principalText = "$principalUser`n$principalGroup"
        $principalUserSid = Resolve-CTAccountSid -Identity $principalUser
        $principalGroupSid = Resolve-CTAccountSid -Identity $principalGroup
        $actionText = @($task.Actions | ForEach-Object {
            "$(Get-CTPropertyValue -InputObject $_ -Name 'Execute')`n$(Get-CTPropertyValue -InputObject $_ -Name 'Arguments')`n$(Get-CTPropertyValue -InputObject $_ -Name 'WorkingDirectory')"
        }) -join "`n"
        if ([string]$task.TaskName -in @('check_report_img_onstart', 'check_report_img_daily', 'check_report_img_random') -or
            $principalUserSid -eq $Sid -or $principalGroupSid -eq $Sid -or
            $principalText -match $namePattern -or $principalText -match $sidPattern -or
            $actionText -match '(?i)C:\\Users\\cloudbase-init(?:\\|$)' -or $actionText -match $sidPattern) {
            $references.Add("task:$($task.TaskPath)$($task.TaskName)")
        }
    }
    return $references.ToArray()
}

function Remove-CTCloudbaseIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    if (-not [Environment]::Is64BitProcess) {
        throw 'Cloudbase account cleanup requires 64-bit Windows PowerShell.'
    }

    $namedAccount = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1
    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -ieq 'C:\Users\cloudbase-init' })
    $existingEvidence = @($Context.Operations | Where-Object { $_.Type -eq 'CloudbaseIdentityEvidence' -and $_.Status -eq 'Completed' })
    if ($null -eq $namedAccount -and $profiles.Count -eq 0 -and $existingEvidence.Count -eq 0) { return }

    $evidence = Save-CTCloudbaseIdentityEvidence -Context $Context -Manifest $Manifest
    if ($null -eq $evidence) { throw 'No archived Cloudbase ownership evidence is available for identity deletion.' }
    $evidenceState = [string](Get-CTPropertyValue -InputObject $evidence.Data -Name 'State')
    if ($evidenceState -in @('AbsentAtBaseline', 'ServicePresentIdentityAbsent')) {
        if ($null -ne $namedAccount -or $profiles.Count -gt 0) {
            throw 'Cloudbase identity appeared after the baseline recorded it absent. Automatic deletion was refused.'
        }
        return [PSCustomObject]@{ Deferred = $false; References = @() }
    }
    if ($evidenceState -ne 'PresentAtBaseline') { throw 'Cloudbase identity evidence state is invalid.' }
    $expectedSid = [string](Get-CTPropertyValue -InputObject $evidence.Data -Name 'AccountSid')
    if ([string]::IsNullOrWhiteSpace($expectedSid)) {
        $expectedSid = [string](Get-CTPropertyValue -InputObject $evidence.Data -Name 'ProfileSid')
    }
    if ([string]::IsNullOrWhiteSpace($expectedSid) -or -not (Test-CTSafeCloudbaseSid -Sid $expectedSid -MachineSid ([string]$Context.MachineSid))) {
        throw 'Archived Cloudbase evidence does not contain a valid local account SID.'
    }
    if ($null -ne $namedAccount -and [string]$namedAccount.SID -ne $expectedSid) {
        throw 'The current cloudbase-init account SID differs from the archived ownership evidence.'
    }
    $sidAccounts = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
    if ($sidAccounts.Count -gt 1) { throw 'Multiple local accounts unexpectedly resolved to the archived Cloudbase SID.' }
    $account = if ($sidAccounts.Count -eq 1) { $sidAccounts[0] } else { $null }
    if ($null -ne $account -and [string]$account.Name -ne 'cloudbase-init') {
        throw "The archived Cloudbase SID now belongs to a renamed account. Manual review is required: $($account.Name) / $expectedSid"
    }
    $allProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)
    $sidProfiles = @($allProfiles | Where-Object { [string]$_.SID -eq $expectedSid })
    $unexpectedSidProfiles = @($sidProfiles | Where-Object { $_.LocalPath -ine 'C:\Users\cloudbase-init' })
    if ($unexpectedSidProfiles.Count -gt 0 -or $sidProfiles.Count -gt 1) {
        throw 'The archived Cloudbase SID is associated with an unexpected or additional user Profile path.'
    }
    $profiles = @($sidProfiles | Where-Object { $_.LocalPath -ieq 'C:\Users\cloudbase-init' })

    $currentIdentitySid = [string]([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    if ($currentIdentitySid -eq $expectedSid) {
        throw 'Refusing to remove the account that is running CTyunTrim.'
    }
    $ownedProcesses = @(Get-CTProcessesByOwnerSid -Sid $expectedSid)
    if ($ownedProcesses.Count -gt 0) {
        throw 'Refusing Cloudbase identity removal while a process still runs under the archived SID.'
    }
    if (Test-Path -LiteralPath ("Registry::HKEY_USERS\$expectedSid")) {
        throw 'Refusing Cloudbase identity removal while its user hive remains mounted.'
    }
    $references = @(Get-CTCloudbaseIdentityReferences -Sid $expectedSid)
    if ($references.Count -gt 0) {
        $expectedDeferred = @($references | Where-Object {
            $_ -in @(
                'service:cloudbase-init',
                'service:cloudbase-init-unattend',
                'task:\check_report_img_onstart',
                'task:\check_report_img_daily',
                'task:\check_report_img_random'
            )
        })
        if ($expectedDeferred.Count -ne $references.Count) {
            throw "An unrelated service or task still references the Cloudbase identity. Manual review is required: $($references -join ', ')"
        }
        $Context.RebootNeeded = $true
        Add-CTWarning -Context $Context -Message "Cloudbase identity cleanup is deferred until marked service/task registrations disappear after reboot: $($references -join ', ')"
        return [PSCustomObject]@{ Deferred = $true; References = $references }
    }

    $allProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)
    $sidProfiles = @($allProfiles | Where-Object { [string]$_.SID -eq $expectedSid })
    $unexpectedSidProfiles = @($sidProfiles | Where-Object { $_.LocalPath -ine 'C:\Users\cloudbase-init' })
    if ($unexpectedSidProfiles.Count -gt 0 -or $sidProfiles.Count -gt 1) {
        throw 'The Cloudbase SID acquired an unexpected or additional Profile before identity removal.'
    }
    $profiles = @($sidProfiles | Where-Object { $_.LocalPath -ieq 'C:\Users\cloudbase-init' })
    foreach ($profile in $profiles) {
        if ($profile.Loaded -or $profile.Special -or (Test-Path -LiteralPath ("Registry::HKEY_USERS\$expectedSid")) -or
            (Test-CTPathHasReparsePoint -Path ([string]$profile.LocalPath))) {
            throw "Refusing to remove a loaded, special or unsafe cloudbase-init Profile: $($profile.LocalPath)"
        }
    }

    $accountOperationId = $null
    if ($null -ne $account) {
        if (Confirm-CTRequiredOperation -Caller $Caller -Target "cloudbase-init ($expectedSid)" -Action 'Disable and remove exact local service account SID') {
            $finalAccounts = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
            $finalOwnedProcesses = @(Get-CTProcessesByOwnerSid -Sid $expectedSid)
            $finalSidProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
            if ($finalAccounts.Count -ne 1 -or [string]$finalAccounts[0].Name -ne 'cloudbase-init' -or
                $finalOwnedProcesses.Count -gt 0 -or $finalSidProfiles.Count -gt 1 -or @($finalSidProfiles | Where-Object { $_.LocalPath -ine 'C:\Users\cloudbase-init' }).Count -gt 0 -or
                @($finalSidProfiles | Where-Object { [bool]$_.Loaded -or [bool]$_.Special }).Count -gt 0 -or
                (Test-Path -LiteralPath ("Registry::HKEY_USERS\$expectedSid"))) {
                throw 'Cloudbase identity state changed before account disable; no identity object was removed.'
            }
            $account = $finalAccounts[0]
            $pendingAccount = Get-CTPendingOperation -Context $Context -Type 'LocalUser' -Target 'cloudbase-init'
            if ($null -ne $pendingAccount) {
                if ([string](Get-CTPropertyValue -InputObject $pendingAccount.Data -Name 'SID') -ne $expectedSid) {
                    throw 'Pending Cloudbase account operation has a different SID.'
                }
                $accountOperationId = [string]$pendingAccount.Id
            }
            else {
                $accountOperationId = Start-CTOperation -Context $Context -Type 'LocalUser' -Target 'cloudbase-init' -Data @{
                    SID     = [string]$account.SID
                    Enabled = [bool]$account.Enabled
                } -Reversible $false
            }
            Disable-LocalUser -SID $account.SID -ErrorAction Stop
            $postDisableAccounts = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
            $postDisableProcesses = @(Get-CTProcessesByOwnerSid -Sid $expectedSid)
            $postDisableProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
            if ($postDisableAccounts.Count -ne 1 -or [string]$postDisableAccounts[0].Name -ne 'cloudbase-init' -or [bool]$postDisableAccounts[0].Enabled -or
                $postDisableProcesses.Count -gt 0 -or $postDisableProfiles.Count -gt 1 -or @($postDisableProfiles | Where-Object { $_.LocalPath -ine 'C:\Users\cloudbase-init' }).Count -gt 0 -or
                @($postDisableProfiles | Where-Object { [bool]$_.Loaded -or [bool]$_.Special }).Count -gt 0 -or
                (Test-Path -LiteralPath ("Registry::HKEY_USERS\$expectedSid"))) {
                throw 'Cloudbase identity could not be proven inactive after account disable; deletion was deferred with its journal entry pending.'
            }
            $account = $postDisableAccounts[0]
            $profiles = @($postDisableProfiles)
        }
    }
    if ($null -ne $account -and [string]::IsNullOrWhiteSpace($accountOperationId)) {
        throw 'Cloudbase account operation was not confirmed; no Profile or account was removed.'
    }

    foreach ($profile in $profiles) {
        if (Confirm-CTRequiredOperation -Caller $Caller -Target $profile.LocalPath -Action 'Remove orphaned cloudbase-init user profile') {
            $boundaryProcesses = @(Get-CTProcessesByOwnerSid -Sid $expectedSid)
            $finalProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
            if ($boundaryProcesses.Count -gt 0 -or $finalProfiles.Count -ne 1 -or $finalProfiles[0].LocalPath -ine 'C:\Users\cloudbase-init' -or
                [bool]$finalProfiles[0].Loaded -or [bool]$finalProfiles[0].Special -or
                (Test-Path -LiteralPath ("Registry::HKEY_USERS\$expectedSid")) -or
                (Test-CTPathHasReparsePoint -Path ([string]$finalProfiles[0].LocalPath))) {
                throw 'Cloudbase Profile state changed at the deletion boundary; no Profile was removed.'
            }
            $profile = $finalProfiles[0]
            $pendingProfile = Get-CTPendingOperation -Context $Context -Type 'UserProfile' -Target ([string]$profile.LocalPath)
            if ($null -ne $pendingProfile) {
                if ([string](Get-CTPropertyValue -InputObject $pendingProfile.Data -Name 'SID') -ne $expectedSid) {
                    throw 'Pending Cloudbase Profile operation has a different SID.'
                }
                $profileOperationId = [string]$pendingProfile.Id
            }
            else {
                $profileOperationId = Start-CTOperation -Context $Context -Type 'UserProfile' -Target $profile.LocalPath -Data @{ SID = [string]$profile.SID } -Reversible $false
            }
            $profile | Remove-CimInstance -ErrorAction Stop
            Complete-CTOperation -Context $Context -Id $profileOperationId
        }
    }

    if ($null -ne $account) {
        $finalOwnedProcesses = @(Get-CTProcessesByOwnerSid -Sid $expectedSid)
        $finalSidProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
        $finalAccounts = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -eq $expectedSid })
        if ($finalOwnedProcesses.Count -gt 0 -or $finalSidProfiles.Count -gt 0 -or
            (Test-Path -LiteralPath ("Registry::HKEY_USERS\$expectedSid")) -or
            $finalAccounts.Count -ne 1 -or [string]$finalAccounts[0].Name -ne 'cloudbase-init' -or [bool]$finalAccounts[0].Enabled) {
            throw 'Cloudbase identity changed before final account removal; the disabled account was preserved with its journal entry pending.'
        }
        $account = $finalAccounts[0]
        $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        Remove-LocalGroupMember -SID $administratorsSid -Member $account -ErrorAction SilentlyContinue
        Remove-LocalUser -SID $account.SID -ErrorAction Stop
        Complete-CTOperation -Context $Context -Id $accountOperationId
    }
    return [PSCustomObject]@{ Deferred = $false; References = @() }
}

function Remove-CTKnownCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    foreach ($entry in $Manifest.KnownCertificates) {
        $certificate = Get-ChildItem -Path $entry.Store -ErrorAction Stop |
            Where-Object { $_.Thumbprint -eq $entry.Thumbprint } |
            Select-Object -First 1
        if ($null -eq $certificate) {
            continue
        }

        $subjectFragment = if ($entry.ContainsKey('SubjectContainsBase64')) {
            ConvertFrom-CTUtf8Base64 -Value ([string]$entry.SubjectContainsBase64)
        }
        else {
            [string]$entry.SubjectContains
        }
        if ([string]$certificate.Subject -notmatch [regex]::Escape($subjectFragment)) {
            throw "Certificate thumbprint matched but subject did not. Refusing removal: $($entry.Thumbprint) / $($certificate.Subject)"
        }

        if (Confirm-CTRequiredOperation -Caller $Caller -Target "$($entry.Store)\$($entry.Thumbprint)" -Action 'Export and remove exact known certificate') {
            $backup = Join-Path (Join-Path $Context.Root 'certificates') "$($entry.Thumbprint).cer"
            $pending = Get-CTPendingOperation -Context $Context -Type 'Certificate' -Target $entry.Thumbprint
            if ($null -ne $pending) {
                $recordedBackup = [string](Get-CTPropertyValue -InputObject $pending.Data -Name 'Backup')
                $recordedHash = [string](Get-CTPropertyValue -InputObject $pending.Data -Name 'BackupSha256')
                if (-not $recordedBackup.Equals($backup, [StringComparison]::OrdinalIgnoreCase) -or
                    -not (Test-Path -LiteralPath $backup -PathType Leaf) -or
                    (Test-CTPathHasReparsePoint -Path $backup) -or
                    -not (Test-CTSecureSourcePath -Path $backup) -or
                    (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $recordedHash) {
                    throw "Certificate backup no longer matches its pending journal entry: $($entry.Thumbprint)"
                }
                $operationId = [string]$pending.Id
            }
            else {
                Export-Certificate -Cert $certificate -FilePath $backup -Force | Out-Null
                Set-CTRunFileAcl -Path $backup
                if (-not (Test-Path -LiteralPath $backup -PathType Leaf) -or
                    (Get-Item -LiteralPath $backup -ErrorAction Stop).Length -le 0 -or
                    (Test-CTPathHasReparsePoint -Path $backup)) {
                    throw "Certificate export did not produce a usable backup: $($entry.Thumbprint)"
                }
                $operationId = Start-CTOperation -Context $Context -Type 'Certificate' -Target $entry.Thumbprint -Data @{
                    Store          = [string]$entry.Store
                    Backup         = $backup
                    BackupSha256   = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
                    Subject        = [string]$certificate.Subject
                }
            }
            Remove-Item -LiteralPath $certificate.PSPath -Force
            Complete-CTOperation -Context $Context -Id $operationId
        }
    }
}

function Remove-CTFirewallRules {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    foreach ($program in $Manifest.FirewallPrograms) {
        $filters = @(Get-NetFirewallApplicationFilter -ErrorAction Stop |
            Where-Object { $_.Program -ieq $program })
        foreach ($filter in $filters) {
            $rules = @(Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $filter -ErrorAction Stop)
            foreach ($rule in $rules) {
                if ($rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow') {
                    Add-CTWarning -Context $Context -Message "Firewall rule for $program was not an inbound Allow rule and was preserved: $($rule.Name) / $($rule.Direction) / $($rule.Action)"
                    continue
                }

                if (Confirm-CTRequiredOperation -Caller $Caller -Target $rule.Name -Action "Remove firewall rule for exact dead program path $program") {
                    $backup = Join-Path (Join-Path $Context.Root 'firewall') (($rule.Name -replace '[^A-Za-z0-9_.-]', '_') + '.json')
                    $pending = Get-CTPendingOperation -Context $Context -Type 'FirewallRule' -Target $rule.Name
                    if ($null -ne $pending) {
                        $recordedBackup = [string](Get-CTPropertyValue -InputObject $pending.Data -Name 'Backup')
                        $recordedHash = [string](Get-CTPropertyValue -InputObject $pending.Data -Name 'BackupSha256')
                        if (-not $recordedBackup.Equals($backup, [StringComparison]::OrdinalIgnoreCase) -or
                            -not (Test-Path -LiteralPath $backup -PathType Leaf) -or
                            (Test-CTPathHasReparsePoint -Path $backup) -or
                            -not (Test-CTSecureSourcePath -Path $backup) -or
                            (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $recordedHash) {
                            throw "Firewall backup no longer matches its pending journal entry: $($rule.Name)"
                        }
                        $operationId = [string]$pending.Id
                    }
                    else {
                        [PSCustomObject]@{
                            Name        = $rule.Name
                            DisplayName = $rule.DisplayName
                            Enabled     = $rule.Enabled
                            Direction   = $rule.Direction
                            Action      = $rule.Action
                            Profile     = $rule.Profile
                            Program     = $program
                        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backup -Encoding UTF8
                        Set-CTRunFileAcl -Path $backup
                        if (-not (Test-Path -LiteralPath $backup -PathType Leaf) -or
                            (Get-Item -LiteralPath $backup).Length -le 0 -or
                            (Test-CTPathHasReparsePoint -Path $backup)) {
                            throw "Firewall metadata backup is unusable: $($rule.Name)"
                        }
                        try { [void](Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json) } catch { throw "Firewall metadata backup is not valid JSON: $($rule.Name)" }
                        $operationId = Start-CTOperation -Context $Context -Type 'FirewallRule' -Target $rule.Name -Data @{
                            Backup       = $backup
                            BackupSha256 = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
                            Program      = $program
                        } -Reversible $false
                    }
                    $rule | Remove-NetFirewallRule
                    Complete-CTOperation -Context $Context -Id $operationId
                }
            }
        }
    }
}

function Get-CTVerification {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [PSObject]$Context
    )

    $inventory = Get-CTyunTrimInventory -ManifestPath $ManifestPath
    $failures = New-Object Collections.Generic.List[string]
    $warnings = New-Object Collections.Generic.List[string]
    try { $taskSnapshot = @(Get-ScheduledTask -ErrorAction Stop) }
    catch { $taskSnapshot = @(); $failures.Add("Scheduled Task verification inventory failed: $($_.Exception.Message)") }
    try { $localUserSnapshot = @(Get-LocalUser -ErrorAction Stop) }
    catch { $localUserSnapshot = @(); $failures.Add("Local-user verification inventory failed: $($_.Exception.Message)") }
    try { $userProfileSnapshot = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop) }
    catch { $userProfileSnapshot = @(); $failures.Add("User-profile verification inventory failed: $($_.Exception.Message)") }
    $coreHealth = Test-CTCoreHealth -Manifest $Manifest -RequireRunning -Context $Context
    foreach ($failure in $coreHealth.Failures) { $failures.Add($failure) }

    foreach ($service in $inventory.CoreServices) {
        if ($service.Present -and $service.StartMode -ne 'Auto') {
            $warnings.Add("Core service is not Automatic: $($service.Name) ($($service.StartMode))")
        }
        $expectedPinnedTrust = [string]$service.TrustMode -eq 'PinnedHashAndSigner' -and [bool]$service.TrustSatisfied
        if ($service.Present -and -not $expectedPinnedTrust -and -not [string]::IsNullOrWhiteSpace([string]$service.SignerSubject) -and $service.SignatureStatus -ne 'Valid') {
            $warnings.Add("Core service retains a cryptographic signer but is no longer trusted after certificate cleanup: $($service.Name) ($($service.SignatureStatus))")
        }
    }

    foreach ($driver in $inventory.CoreDrivers) {
        if ($driver.Present -and $driver.State -ne 'Running') {
            $warnings.Add("Core driver is not currently running: $($driver.Name) ($($driver.State))")
        }
        if ($driver.Present -and -not [string]::IsNullOrWhiteSpace([string]$driver.SignerSubject) -and $driver.SignatureStatus -ne 'Valid') {
            $warnings.Add("Core driver retains a cryptographic signer but is no longer trusted after certificate cleanup: $($driver.Name) ($($driver.SignatureStatus))")
        }
    }

    foreach ($service in $inventory.RemovalServices) {
        if ($service.Present) {
            $failures.Add("Removal service still exists: $($service.Name)")
        }
    }

    foreach ($driver in $inventory.RemovalDrivers) {
        if ($driver.Present) {
            $failures.Add("Removal driver service still exists: $($driver.Name)")
        }
    }

    foreach ($path in $inventory.RemovalPaths) {
        if ($path.Exists) {
            $failures.Add("Removal path still exists: $($path.Path)")
        }
    }

    foreach ($path in $inventory.DiscoverOnlyPaths) {
        if ($path.Exists) {
            $warnings.Add("Unclassified vendor path remains and was intentionally preserved: $($path.Path)")
        }
    }

    foreach ($task in $Manifest.ScheduledTasks) {
        $remainingTask = @($taskSnapshot | Where-Object {
            ([string]$_.TaskName).Equals([string]$task.Name, [StringComparison]::OrdinalIgnoreCase) -and
            ([string]$_.TaskPath).Equals([string]$task.TaskPath, [StringComparison]::OrdinalIgnoreCase)
        })
        if ($remainingTask.Count -gt 0) {
            $failures.Add("Removal scheduled task still exists: $($task.TaskPath)$($task.Name)")
        }
    }

    foreach ($entry in $Manifest.RunValues) {
        $remainingRunValue = Get-CTRunValue -Entry $entry -Strict
        if ($null -ne $remainingRunValue) {
            if (Test-CTRunValueOwned -RunValue $remainingRunValue) {
                $failures.Add("Removal Run value still exists: $($entry.Hive)\$($entry.Key)::$($entry.Name)")
            }
            else {
                $warnings.Add("Same-name non-CTyun Run value was preserved: $($entry.Hive)\$($entry.Key)::$($entry.Name) / $($remainingRunValue.Value)")
            }
        }
    }

    $policySignature = Get-CTWsusPolicySignature -Manifest $Manifest
    if ($policySignature.Classification -in @('ReferenceCTyunLoopback', 'PartialReferenceCTyunLoopback')) {
        $failures.Add('The CTyun loopback WSUS policy is fully or partially active.')
    }
    elseif ($policySignature.Classification -eq 'Conflict') {
        $warnings.Add('Windows Update policy values are present but do not match the CTyun loopback signature; they were not classified or modified.')
    }

    foreach ($guard in $inventory.ExecutionGuards) {
        if (-not $guard.Present -or $guard.Debugger -ne $script:GuardDebugger -or $guard.Marker -ne $script:GuardOwner -or
            ($null -ne $Context -and [string]$guard.RunId -ne [string]$Context.RunId)) {
            $failures.Add("Execution guard missing or changed: $($guard.Image)")
        }
    }

    foreach ($entry in $Manifest.KnownCertificates) {
        try {
            $certificate = Get-ChildItem -Path $entry.Store -ErrorAction Stop |
                Where-Object { $_.Thumbprint -eq $entry.Thumbprint } |
                Select-Object -First 1
            if ($null -ne $certificate) { $failures.Add("Known vendor certificate remains: $($entry.Thumbprint)") }
        }
        catch { $failures.Add("Certificate verification inventory failed for $($entry.Store): $($_.Exception.Message)") }
    }

    $knownThumbprints = @($Manifest.KnownCertificates | ForEach-Object { [string]$_.Thumbprint })
    foreach ($candidate in $inventory.CertificateCandidates) {
        if ($knownThumbprints -notcontains [string]$candidate.Thumbprint) {
            $warnings.Add("Unrecognized vendor certificate candidate was preserved for review: $($candidate.Store) / $($candidate.Thumbprint) / $($candidate.Subject)")
        }
    }

    foreach ($program in $Manifest.FirewallPrograms) {
        try {
            $allowRules = foreach ($filter in @(Get-NetFirewallApplicationFilter -ErrorAction Stop | Where-Object { $_.Program -ieq $program })) {
                Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $filter -ErrorAction Stop |
                    Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
            }
            if (@($allowRules).Count -gt 0) { $failures.Add("Dead inbound Allow firewall rule remains for: $program") }
        }
        catch { $failures.Add("Firewall verification inventory failed for $program`: $($_.Exception.Message)") }
    }

    $cloudbaseAccount = @($localUserSnapshot | Where-Object { $_.Name -eq 'cloudbase-init' })
    if ($cloudbaseAccount.Count -gt 0) {
        $failures.Add('cloudbase-init local account remains.')
    }
    if (@($userProfileSnapshot | Where-Object { $_.LocalPath -ieq 'C:\Users\cloudbase-init' }).Count -gt 0) {
        $failures.Add('cloudbase-init user profile remains.')
    }
    if ($null -eq $Context) {
        $failures.Add('A trusted RunId is required to prove that the archived Cloudbase SID was removed, including rename cases.')
    }
    else {
        $evidence = @($Context.Operations | Where-Object { $_.Type -eq 'CloudbaseIdentityEvidence' -and $_.Status -eq 'Completed' })
        if ($evidence.Count -ne 1) {
            $failures.Add('Exactly one trusted Cloudbase identity evidence record is required for verification.')
        }
        else {
            try { [void](Save-CTCloudbaseIdentityEvidence -Context $Context -Manifest $Manifest) }
            catch { $failures.Add("Archived Cloudbase identity evidence failed validation: $($_.Exception.Message)") }
            $expectedSid = [string](Get-CTPropertyValue -InputObject $evidence[0].Data -Name 'AccountSid')
            if ([string]::IsNullOrWhiteSpace($expectedSid)) {
                $expectedSid = [string](Get-CTPropertyValue -InputObject $evidence[0].Data -Name 'ProfileSid')
            }
            if ([string]::IsNullOrWhiteSpace($expectedSid)) {
                $warnings.Add('The reference run recorded no Cloudbase account/profile SID to verify.')
            }
            else {
                $remainingSidAccounts = @($localUserSnapshot | Where-Object { [string]$_.SID -eq $expectedSid })
                if ($remainingSidAccounts.Count -gt 0) {
                    $failures.Add("The archived Cloudbase SID still belongs to a local account: $($remainingSidAccounts.Name -join ', ') / $expectedSid")
                }
                $remainingSidProfiles = @($userProfileSnapshot | Where-Object { [string]$_.SID -eq $expectedSid })
                if ($remainingSidProfiles.Count -gt 0) {
                    $failures.Add("The archived Cloudbase SID still has a user profile: $($remainingSidProfiles.LocalPath -join ', ') / $expectedSid")
                }
            }
        }
    }

    $fileCrypt = Get-CTServiceByName -Name 'FileCrypt' -Driver
    if ($null -eq $fileCrypt) {
        $warnings.Add('Windows FileCrypt driver was not found. CTyunTrim never removes it; investigate separately.')
    }

    [PSCustomObject]@{
        Passed       = ($failures.Count -eq 0)
        Timestamp    = (Get-Date).ToString('o')
        Failures     = @($failures)
        Warnings     = @($warnings)
        ManualChecks = @(
            'Disconnect and reconnect with the official CTyun client.',
            'Verify keyboard and mouse input.',
            'Verify dynamic display/resolution behavior.',
            'Verify bidirectional text clipboard.',
            'Transfer ordinary TXT, ZIP, image and medium-size binary files in both directions.',
            'Do not use a .lnk shortcut as the only file-transfer test; it is a known cloudshare edge case.',
            'Verify audio and any device redirection you intend to keep.',
            'Verify network, DNS and Windows Update.',
            'Reboot at least twice and run Verify again.'
        )
        Inventory = $inventory
    }
}

function Test-CTApplyPreflight {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$BackupRoot,

        [string]$LgpoPath,

        [string]$RunId,

        [PSObject]$Context,

        [ValidateSet('Prepare', 'Apply')]
        [string]$Phase = 'Apply'
    )

    $errors = New-Object Collections.Generic.List[string]
    $warnings = New-Object Collections.Generic.List[string]
    try { $taskSnapshot = @(Get-ScheduledTask -ErrorAction Stop) }
    catch { $taskSnapshot = @(); $errors.Add("Scheduled Task inventory failed: $($_.Exception.Message)") }
    $health = Test-CTCoreHealth -Manifest $Manifest -RequireRunning -Context $Context
    foreach ($failure in $health.Failures) { $errors.Add($failure) }

    $backupRootFull = ConvertTo-CTFullPath -Path $BackupRoot
    $backupVolume = [IO.Path]::GetPathRoot($backupRootFull)
    if (Test-CTPathHasReparsePoint -Path (Split-Path -Parent $backupRootFull)) {
        $errors.Add("Backup root has a reparse-point ancestor: $backupRootFull")
    }
    try {
        if (-not (Test-CTSecureSourcePath -Path $backupRootFull)) {
            $errors.Add("Backup root or an existing parent is writable by an untrusted principal: $backupRootFull")
        }
    }
    catch {
        $errors.Add("Backup root ACL validation failed: $($_.Exception.Message)")
    }
    $removalPaths = @($Manifest.Directories) + @($Manifest.Files) + @(Get-CTEncodedRemovalFiles -Manifest $Manifest) + @($Manifest.PublicDataDirectories)
    foreach ($path in $removalPaths) {
        try {
            $fullPath = ConvertTo-CTFullPath -Path $path
            if ($backupRootFull.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase) -or
                $backupRootFull.StartsWith($fullPath + '\', [StringComparison]::OrdinalIgnoreCase) -or
                $fullPath.StartsWith($backupRootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
                $errors.Add("Backup root overlaps a removal path: $backupRootFull / $fullPath")
            }
            if (-not [IO.Path]::GetPathRoot($fullPath).Equals($backupVolume, [StringComparison]::OrdinalIgnoreCase)) {
                $errors.Add("Removal path and quarantine are on different volumes: $fullPath / $BackupRoot")
            }
            if (Test-CTPathHasReparsePoint -Path $fullPath) {
                $errors.Add("Removal path has a reparse-point ancestor: $fullPath")
            }
        }
        catch {
            $errors.Add("Removal path preflight failed for $path`: $($_.Exception.Message)")
        }
    }

    foreach ($entry in $Manifest.Services) {
        $service = Get-CTServiceByName -Name $entry.Name
        if (($null -ne $service) -and -not (Test-CTExpectedService -Service $service -ExpectedImage $entry.ExpectedImage)) {
            $errors.Add("Service ImagePath mismatch for $($entry.Name): $($service.PathName)")
        }
        elseif ($null -ne $service) {
            $image = Get-CTImageExecutable -PathName ([string]$service.PathName)
            if ([string]::IsNullOrWhiteSpace($image) -or -not (Test-Path -LiteralPath $image -PathType Leaf)) {
                $errors.Add("Service image is missing; ownership cannot be authenticated: $($entry.Name) / $image")
            }
            elseif ((Get-AuthenticodeSignature -LiteralPath $image).Status -ne 'Valid') {
                $errors.Add("Service image does not have a valid Authenticode signature: $($entry.Name) / $image")
            }
        }
    }
    foreach ($entry in $Manifest.DriverServices) {
        $driver = Get-CTServiceByName -Name $entry.Name -Driver
        if (($null -ne $driver) -and -not (Test-CTExpectedService -Service $driver -ExpectedImage $entry.ExpectedImage)) {
            $errors.Add("Driver ImagePath mismatch for $($entry.Name): $($driver.PathName)")
        }
        elseif (($null -ne $driver) -and ($driver.State -eq 'Running')) {
            $warnings.Add("Driver is currently loaded and its file may require a reboot before quarantine: $($entry.Name)")
        }
        if ($null -ne $driver) {
            $image = Get-CTImageExecutable -PathName ([string]$driver.PathName)
            if ([string]::IsNullOrWhiteSpace($image) -or -not (Test-Path -LiteralPath $image -PathType Leaf)) {
                $errors.Add("Driver image is missing; ownership cannot be authenticated: $($entry.Name) / $image")
            }
            elseif ((Get-AuthenticodeSignature -LiteralPath $image).Status -ne 'Valid') {
                $errors.Add("Driver image does not have a valid Authenticode signature: $($entry.Name) / $image")
            }
        }
    }

    foreach ($image in $Manifest.ExecutionGuards) {
        $guard = Get-CTIfEOState -Image $image
        if ($guard.Present) {
            $requestedRunId = if ($null -ne $Context) { [string]$Context.RunId } else { [string]$RunId }
            $pending = @()
            if ($null -ne $Context) {
                $pending = @($Context.Operations | Where-Object { $_.Status -eq 'Pending' -and $_.Type -eq 'ExecutionGuard' -and $_.Target -eq $image })
            }
            $fullOwned = ($guard.Debugger -eq $script:GuardDebugger) -and ($guard.Marker -eq $script:GuardOwner) -and ([string]$guard.RunId -eq $requestedRunId)
            $pendingRunId = if ($pending.Count -eq 1) { [string](Get-CTPropertyValue -InputObject $pending[0].Data -Name 'RunId') } else { $null }
            $partialOwned = ($pending.Count -eq 1) -and ($pendingRunId -eq $requestedRunId) -and
                ([string]::IsNullOrWhiteSpace([string]$guard.Debugger) -or $guard.Debugger -eq $script:GuardDebugger) -and
                ([string]::IsNullOrWhiteSpace([string]$guard.Marker) -or $guard.Marker -eq $script:GuardOwner) -and
                ([string]::IsNullOrWhiteSpace([string]$guard.RunId) -or [string]$guard.RunId -eq $requestedRunId)
            if (-not $fullOwned -and -not $partialOwned) {
                $errors.Add("Existing unknown or differently owned IFEO debugger for $image`: $($guard.Debugger)")
            }
            elseif ([string]::IsNullOrWhiteSpace($requestedRunId)) {
                $errors.Add("CTyunTrim guard $image already belongs to run $($guard.RunId). Resume with that RunId instead of starting a new run.")
            }
            elseif (-not $fullOwned -and -not $partialOwned) {
                $errors.Add("CTyunTrim guard $image does not belong to requested run $requestedRunId.")
            }
        }
    }

    foreach ($entry in $Manifest.ScheduledTasks) {
        foreach ($task in @($taskSnapshot | Where-Object { ([string]$_.TaskName).Equals([string]$entry.Name, [StringComparison]::OrdinalIgnoreCase) })) {
            if (-not ([string]$task.TaskPath).Equals([string]$entry.TaskPath, [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-CTScheduledTaskDefinition -Task $task -Entry $entry)) {
                $errors.Add("Scheduled task definition mismatch for $($task.TaskPath)$($task.TaskName)")
            }
        }
    }

    foreach ($entry in $Manifest.RunValues) {
        try { $runValue = Get-CTRunValue -Entry $entry -Strict }
        catch { $runValue = $null; $errors.Add("Run-value preflight inventory failed for $($entry.Hive)\$($entry.Key)::$($entry.Name): $($_.Exception.Message)") }
        if ($null -ne $runValue -and -not (Test-CTRunValueOwned -RunValue $runValue)) {
            $errors.Add("Same-name non-CTyun Run value conflicts with the removal profile: $($entry.Hive)\$($entry.Key)::$($entry.Name) / $($runValue.Value)")
        }
    }

    $pendingPolicy = $null
    if ($null -ne $Context) {
        try { $pendingPolicy = Get-CTPendingLocalPolicyOperation -Context $Context } catch { $errors.Add($_.Exception.Message) }
    }
    $policySignature = Get-CTWsusPolicySignature -Manifest $Manifest
    if ($policySignature.Classification -eq 'Conflict' -or
        ($policySignature.Classification -eq 'PartialReferenceCTyunLoopback' -and $null -eq $pendingPolicy)) {
        $errors.Add('Windows Update policy is mixed or non-reference. CTyun ownership cannot be established.')
    }
    elseif ($policySignature.Classification -in @('ReferenceCTyunLoopback', 'PartialReferenceCTyunLoopback')) {
        if ($null -ne $pendingPolicy) {
            $journalLgpo = [string](Get-CTPropertyValue -InputObject $pendingPolicy.Data -Name 'LgpoPath')
            $journalHash = [string](Get-CTPropertyValue -InputObject $pendingPolicy.Data -Name 'LgpoSha256')
            if (-not (Test-CTLgpoBinary -Path $journalLgpo) -or
                (Get-FileHash -LiteralPath $journalLgpo -Algorithm SHA256).Hash -ne $journalHash) {
                $errors.Add('The pending policy operation no longer has its verified staged LGPO.exe.')
            }
        }
        elseif ([string]::IsNullOrWhiteSpace((Find-CTLgpo -RequestedPath $LgpoPath -Manifest $Manifest -TrustedRunRoot $(if ($null -ne $Context) { $Context.Root } else { $null })))) {
            $errors.Add('Fake WSUS values are active and no securely located Microsoft-signed LGPO.exe is available.')
        }
    }

    foreach ($entry in $Manifest.KnownCertificates) {
        $certificate = Get-ChildItem -Path $entry.Store -ErrorAction Stop |
            Where-Object { $_.Thumbprint -eq $entry.Thumbprint } |
            Select-Object -First 1
        if ($null -eq $certificate) { continue }
        $subjectFragment = if ($entry.ContainsKey('SubjectContainsBase64')) {
            ConvertFrom-CTUtf8Base64 -Value ([string]$entry.SubjectContainsBase64)
        }
        else { [string]$entry.SubjectContains }
        if ([string]$certificate.Subject -notmatch [regex]::Escape($subjectFragment)) {
            $errors.Add("Known certificate thumbprint has an unexpected subject: $($entry.Thumbprint)")
        }
    }

    try { $cloudbaseUsers = @(Get-LocalUser -ErrorAction Stop) }
    catch { $cloudbaseUsers = @(); $errors.Add("Cloudbase local-user preflight inventory failed: $($_.Exception.Message)") }
    try { $allUserProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop) }
    catch { $allUserProfiles = @(); $errors.Add("Cloudbase user-profile preflight inventory failed: $($_.Exception.Message)") }
    $cloudbaseAccount = @($cloudbaseUsers | Where-Object { $_.Name -eq 'cloudbase-init' }) | Select-Object -First 1
    $cloudbaseProfiles = @($allUserProfiles | Where-Object { $_.LocalPath -ieq 'C:\Users\cloudbase-init' })
    $archivedEvidence = @()
    if ($null -ne $Context) {
        $archivedEvidence = @($Context.Operations | Where-Object { $_.Type -eq 'CloudbaseIdentityEvidence' -and $_.Status -eq 'Completed' })
    }
    if ($archivedEvidence.Count -gt 1) {
        $errors.Add('Multiple archived Cloudbase identity evidence records were found.')
    }
    $archivedIdentitySid = $null
    if ($archivedEvidence.Count -eq 1 -and
        [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'State') -eq 'PresentAtBaseline') {
        $archivedAccountSid = [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'AccountSid')
        $archivedProfileSid = [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'ProfileSid')
        $archivedAnchors = @(Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'IdentityAnchors')
        if (-not [string]::IsNullOrWhiteSpace($archivedAccountSid) -and -not [string]::IsNullOrWhiteSpace($archivedProfileSid) -and
            -not [string]::Equals($archivedAccountSid, $archivedProfileSid, [StringComparison]::OrdinalIgnoreCase)) {
            $errors.Add('Archived Cloudbase account and Profile SIDs do not match.')
        }
        $archivedIdentitySid = if (-not [string]::IsNullOrWhiteSpace($archivedAccountSid)) { $archivedAccountSid } else { $archivedProfileSid }
        if ([string]::IsNullOrWhiteSpace($archivedIdentitySid)) {
            $errors.Add('Archived present-at-baseline Cloudbase evidence has no identity SID.')
        }
        $allowedArchivedAnchors = @('service:cloudbase-init', 'service:cloudbase-init-unattend') + @($Manifest.ScheduledTasks | ForEach-Object { "task:$($_.TaskPath)$($_.Name)" })
        if ($archivedAnchors.Count -eq 0 -or @($archivedAnchors | Where-Object { $_ -notin $allowedArchivedAnchors }).Count -gt 0) {
            $errors.Add('Archived present-at-baseline Cloudbase evidence has no valid principal SID anchor.')
        }
    }
    if ($cloudbaseProfiles.Count -gt 1) {
        $errors.Add('Multiple exact cloudbase-init profile records were found.')
    }
    if ($null -ne $cloudbaseAccount -and $cloudbaseProfiles.Count -eq 1 -and [string]$cloudbaseAccount.SID -ne [string]$cloudbaseProfiles[0].SID) {
        $errors.Add('cloudbase-init account and profile SIDs do not match.')
    }
    $cloudbaseIdentitySid = if ($null -ne $cloudbaseAccount) {
        [string]$cloudbaseAccount.SID
    }
    elseif ($cloudbaseProfiles.Count -eq 1) { [string]$cloudbaseProfiles[0].SID }
    elseif (-not [string]::IsNullOrWhiteSpace($archivedIdentitySid)) { $archivedIdentitySid }
    else { $null }
    $cloudbaseSidProfiles = @()
    if (-not [string]::IsNullOrWhiteSpace($cloudbaseIdentitySid)) {
        $cloudbaseSidProfiles = @($allUserProfiles | Where-Object { [string]$_.SID -eq $cloudbaseIdentitySid })
    }
    $unexpectedCloudbaseProfiles = @($cloudbaseSidProfiles | Where-Object { $_.LocalPath -ine 'C:\Users\cloudbase-init' })
    if ($unexpectedCloudbaseProfiles.Count -gt 0 -or $cloudbaseSidProfiles.Count -ne $cloudbaseProfiles.Count) {
        $errors.Add('Cloudbase identity SID is associated with an unexpected or additional user Profile path.')
    }
    if (-not [string]::IsNullOrWhiteSpace($cloudbaseIdentitySid) -and
        (Test-Path -LiteralPath ("Registry::HKEY_USERS\$cloudbaseIdentitySid")) -and
        $cloudbaseProfiles.Count -eq 0) {
        $errors.Add('Cloudbase identity user hive is mounted without its one exact Profile record.')
    }
    if (($null -ne $cloudbaseAccount -or $cloudbaseProfiles.Count -gt 0) -and $archivedEvidence.Count -eq 0 -and
        -not [string]::IsNullOrWhiteSpace($cloudbaseIdentitySid)) {
        try {
            $currentIdentityAnchors = @(Get-CTCloudbaseIdentityAnchors -Sid $cloudbaseIdentitySid -Manifest $Manifest -TaskSnapshot $taskSnapshot)
            if ($currentIdentityAnchors.Count -eq 0) {
                $errors.Add('Cloudbase account/Profile has no exact service or scheduled-task principal SID anchor.')
            }
        }
        catch { $errors.Add("Cloudbase principal SID anchor validation failed: $($_.Exception.Message)") }
    }
    $validCloudbaseServices = @($Manifest.Services | Where-Object { $_.Name -in @('cloudbase-init', 'cloudbase-init-unattend') } | ForEach-Object {
        $service = Get-CTServiceByName -Name $_.Name
        if ($null -ne $service -and (Test-CTExpectedService -Service $service -ExpectedImage $_.ExpectedImage)) { $service }
    })
    foreach ($profile in $cloudbaseProfiles) {
        $profileSid = [string]$profile.SID
        $hiveMounted = -not [string]::IsNullOrWhiteSpace($profileSid) -and
            (Test-Path -LiteralPath ("Registry::HKEY_USERS\$profileSid"))
        if ([bool]$profile.Special) {
            $errors.Add("Cloudbase profile is marked Special and cannot be handled automatically: $($profile.LocalPath)")
            continue
        }
        if ([bool]$profile.Loaded -or $hiveMounted) {
            if ($Phase -ne 'Prepare') {
                $errors.Add("Cloudbase profile is loaded or its user hive is mounted; Apply requires an unloaded profile: $($profile.LocalPath)")
                continue
            }

            $loadedErrorCount = $errors.Count
            if ($cloudbaseProfiles.Count -ne 1 -or $cloudbaseSidProfiles.Count -ne 1 -or $null -eq $cloudbaseAccount -or
                -not [string]::Equals([string]$cloudbaseAccount.SID, $profileSid, [StringComparison]::OrdinalIgnoreCase)) {
                $errors.Add('Cloudbase loaded-profile Prepare exception requires one matching account and profile SID.')
            }
            $machineSid = Get-CTMachineSid
            if ([string]::IsNullOrWhiteSpace($machineSid) -or -not (Test-CTSafeCloudbaseSid -Sid $profileSid -MachineSid $machineSid)) {
                $errors.Add('Cloudbase loaded-profile SID is not a safe local non-built-in account SID.')
            }
            if ([string]([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -eq $profileSid) {
                $errors.Add('CTyunTrim is running as the loaded Cloudbase identity.')
            }
            if (Test-CTPathHasReparsePoint -Path ([string]$profile.LocalPath)) {
                $errors.Add('Cloudbase loaded-profile path has a reparse-point ancestor.')
            }
            if ($validCloudbaseServices.Count -ne 1) {
                $errors.Add('Cloudbase loaded-profile Prepare exception requires exactly one current reference service.')
            }

            try {
                $ownedProcesses = @(Get-CTCloudbaseOwnedProcessEvidence -Sid $profileSid -Manifest $Manifest)
                if ($ownedProcesses.Count -ne 1) {
                    $errors.Add("Cloudbase loaded-profile Prepare exception requires exactly one owned process; found $($ownedProcesses.Count).")
                }
                elseif (-not [bool]$ownedProcesses[0].Approved) {
                    $errors.Add("Cloudbase loaded-profile process failed identity validation: $(@($ownedProcesses[0].Failures) -join ', ')")
                }
            }
            catch { $errors.Add("Cloudbase loaded-profile process validation failed: $($_.Exception.Message)") }

            try {
                $references = @(Get-CTCloudbaseIdentityReferences -Sid $profileSid)
                $allowedReferences = @('service:cloudbase-init', 'service:cloudbase-init-unattend') + @($Manifest.ScheduledTasks | ForEach-Object { "task:$($_.TaskPath)$($_.Name)" })
                $unexpectedReferences = @($references | Where-Object { $_ -notin $allowedReferences })
                if ($unexpectedReferences.Count -gt 0) {
                    $errors.Add("Cloudbase loaded-profile identity has unrelated service or task references: $($unexpectedReferences -join ', ')")
                }
            }
            catch { $errors.Add("Cloudbase loaded-profile reference validation failed: $($_.Exception.Message)") }

            if ($errors.Count -eq $loadedErrorCount) {
                $warnings.Add('Cloudbase profile is loaded only by the approved TaskAgentDetect process; Prepare may neutralize it, but Apply still requires an unloaded profile after reboot.')
            }
        }
    }
    if ($null -ne $cloudbaseAccount -or $cloudbaseProfiles.Count -gt 0 -or $archivedEvidence.Count -gt 0) {
        if ($archivedEvidence.Count -eq 1) {
            $evidenceState = [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'State')
            $evidenceMachineSid = [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'MachineSid')
            $evidenceRoot = [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'CloudbaseRoot')
            $evidenceAccountSid = [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'AccountSid')
            $evidenceProfileSid = [string](Get-CTPropertyValue -InputObject $archivedEvidence[0].Data -Name 'ProfileSid')
            if ($evidenceMachineSid -ne [string]$Context.MachineSid -or
                -not $evidenceRoot.Equals((ConvertTo-CTFullPath -Path $Manifest.Roots.Cloudbase), [StringComparison]::OrdinalIgnoreCase)) {
                $errors.Add('Archived Cloudbase identity evidence does not match this machine or immutable root.')
            }
            if ($evidenceState -in @('AbsentAtBaseline', 'ServicePresentIdentityAbsent') -and ($null -ne $cloudbaseAccount -or $cloudbaseProfiles.Count -gt 0)) {
                $errors.Add('Cloudbase identity appeared after it was recorded absent at baseline.')
            }
            elseif ($evidenceState -notin @('AbsentAtBaseline', 'ServicePresentIdentityAbsent', 'PresentAtBaseline')) {
                $errors.Add('Archived Cloudbase identity evidence has an invalid state.')
            }
            if ($null -ne $cloudbaseAccount -and -not [string]::IsNullOrWhiteSpace($evidenceAccountSid) -and [string]$cloudbaseAccount.SID -ne $evidenceAccountSid) {
                $errors.Add('Current cloudbase-init account SID differs from archived ownership evidence.')
            }
            if ($cloudbaseProfiles.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($evidenceProfileSid) -and [string]$cloudbaseProfiles[0].SID -ne $evidenceProfileSid) {
                $errors.Add('Current cloudbase-init profile SID differs from archived ownership evidence.')
            }
            $evidenceSid = if (-not [string]::IsNullOrWhiteSpace($evidenceAccountSid)) { $evidenceAccountSid } else { $evidenceProfileSid }
            if (-not [string]::IsNullOrWhiteSpace($evidenceSid)) {
                $evidenceSidAccounts = @($cloudbaseUsers | Where-Object { [string]$_.SID -eq $evidenceSid })
                foreach ($sidAccount in $evidenceSidAccounts) {
                    if ([string]$sidAccount.Name -ne 'cloudbase-init') {
                        $errors.Add("Archived Cloudbase SID belongs to a renamed account: $($sidAccount.Name) / $evidenceSid")
                    }
                }
            }
        }
        if ($validCloudbaseServices.Count -eq 0 -and $archivedEvidence.Count -ne 1) {
            $errors.Add('cloudbase-init identity exists without one exact current service or one archived ownership evidence record.')
        }
    }

    $result = [PSCustomObject]@{
        Passed   = ($errors.Count -eq 0)
        Errors   = $errors.ToArray()
        Warnings = $warnings.ToArray()
    }
    $script:LastPreflightResult = $result
    Add-CTDiagnosticEvent -Level $(if ($result.Passed) { 'Info' } else { 'Error' }) -Stage 'Preflight' -Message $(if ($result.Passed) { 'Preflight passed.' } else { 'Preflight failed.' }) -Data @{
        Passed       = [bool]$result.Passed
        ErrorCount   = @($result.Errors).Count
        WarningCount = @($result.Warnings).Count
    }
    return $result
}

function Invoke-CTApply {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupRoot,

        [string]$LgpoPath,

        [string]$RunId,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    Add-CTDiagnosticEvent -Stage 'Apply' -Message 'Apply started.'
    $os = Get-CTOperatingSystem
    if ($Manifest.SupportedBuilds -notcontains $os.Build) {
        throw "Unsupported Windows build $($os.Build). Supported builds: $($Manifest.SupportedBuilds -join ', '). Apply refused."
    }

    if (-not (Test-Path -LiteralPath $Manifest.Roots.CTyun -PathType Container)) {
        throw "CTyun installation root was not found: $($Manifest.Roots.CTyun)"
    }

    $resuming = -not [string]::IsNullOrWhiteSpace($RunId)
    if ($resuming) {
        $context = Get-CTRunContext -BackupRoot $BackupRoot -RunId $RunId
        if ((Get-CTNormalizedTextHash -Path (ConvertTo-CTFullPath -Path $ManifestPath)) -ne [string]$context.ManifestHash) {
            throw 'Current manifest differs from the manifest that created this run. Resume refused.'
        }
        if ([string]$context.Status -eq 'Applied') {
            throw 'This run is already Applied. Use Verify instead of replaying destructive steps.'
        }
        if ([string]$context.Status -notin @('Prepared', 'PendingReboot', 'Failed', 'Running')) {
            throw "Run status cannot be resumed safely: $($context.Status)"
        }
    }
    else {
        $preflight = Test-CTApplyPreflight -Manifest $Manifest -BackupRoot $BackupRoot -LgpoPath $LgpoPath -Phase Apply
        if (-not $preflight.Passed) {
            throw "Apply preflight failed: $($preflight.Errors -join '; ')"
        }
        $context = New-CTRunContext -BackupRoot $BackupRoot -ManifestPath $ManifestPath
    }

    try {
        $currentBoot = [string]$os.LastBootUpTime
        $recordedBoot = [string](Get-CTPropertyValue -InputObject $context -Name 'LastBootUpTime')
        if ($resuming -and -not [string]::IsNullOrWhiteSpace($recordedBoot) -and $recordedBoot -ne $currentBoot) {
            $context.RebootNeeded = $false
        }
        if (-not $resuming) { $context.RebootNeeded = $false }
        if ($null -eq $context.PSObject.Properties['LastBootUpTime']) {
            $context | Add-Member -NotePropertyName LastBootUpTime -NotePropertyValue $currentBoot
        }
        else { $context.LastBootUpTime = $currentBoot }
        $context.Status = 'Running'
        $context.CompletedAt = $null
        Save-CTRunContext -Context $context
        if ($resuming) {
            Resolve-CTPendingOperations -Context $context -Manifest $Manifest
            $preflight = Test-CTApplyPreflight -Manifest $Manifest -BackupRoot $BackupRoot -LgpoPath $LgpoPath -RunId $context.RunId -Context $context -Phase Apply
            if (-not $preflight.Passed) {
                throw "Apply resume preflight failed: $($preflight.Errors -join '; ')"
            }
        }
        if (@($context.Operations | Where-Object { $_.Type -eq 'Baseline' }).Count -eq 0) {
            Export-CTBaseline -Context $context -Manifest $Manifest
        }
        $baselineHealth = Test-CTCoreHealth -Manifest $Manifest -RequireRunning -Context $context
        if (-not $baselineHealth.Healthy) {
            throw "Core baseline continuity failed before Apply changes: $($baselineHealth.Failures -join '; ')"
        }
        $identityEvidence = Save-CTCloudbaseIdentityEvidence -Context $context -Manifest $Manifest
        $preChangePreflight = Test-CTApplyPreflight -Manifest $Manifest -BackupRoot $BackupRoot -LgpoPath $LgpoPath -RunId $context.RunId -Context $context -Phase Apply
        if (-not $preChangePreflight.Passed) {
            throw "Apply mutation-boundary preflight failed: $($preChangePreflight.Errors -join '; ')"
        }
        foreach ($warning in @(@($preflight.Warnings) + @($preChangePreflight.Warnings) | Sort-Object -Unique)) {
            Add-CTWarning -Context $context -Message $warning
        }
        Add-CTExecutionGuards -Context $context -Manifest $Manifest -Caller $Caller
        Stop-CTOptionalProcesses -Context $context -Manifest $Manifest -Caller $Caller
        Remove-CTScheduledTasks -Context $context -Manifest $Manifest -Caller $Caller
        Stop-CTOptionalProcesses -Context $context -Manifest $Manifest -Caller $Caller
        if ($null -ne $identityEvidence) {
            $preparedIdentitySid = [string](Get-CTPropertyValue -InputObject $identityEvidence.Data -Name 'AccountSid')
            if ([string]::IsNullOrWhiteSpace($preparedIdentitySid)) {
                $preparedIdentitySid = [string](Get-CTPropertyValue -InputObject $identityEvidence.Data -Name 'ProfileSid')
            }
            if (-not [string]::IsNullOrWhiteSpace($preparedIdentitySid) -and @(Get-CTProcessesByOwnerSid -Sid $preparedIdentitySid).Count -gt 0) {
                throw 'A process still runs under the Cloudbase identity after Apply guards and task removal.'
            }
        }
        Clear-CTFakeWsusPolicy -Context $context -Manifest $Manifest -LgpoPath $LgpoPath -Caller $Caller
        Remove-CTRunValues -Context $context -Manifest $Manifest -Caller $Caller
        Remove-CTStartupApprovedEntries -Context $context -Manifest $Manifest -Caller $Caller
        Remove-CTServices -Context $context -Manifest $Manifest -Caller $Caller
        $identityResult = Remove-CTCloudbaseIdentity -Context $context -Manifest $Manifest -Caller $Caller
        if ($null -ne $identityResult -and $identityResult.Deferred) {
            $context.Status = 'PendingReboot'
            $context.CompletedAt = (Get-Date).ToString('o')
            Save-CTRunContext -Context $context
            Add-CTDiagnosticEvent -Level 'Warning' -Stage 'Apply' -Message 'Apply requires reboot.' -Data @{ Status = 'PendingReboot' }
            return [PSCustomObject]@{
                RunId        = $context.RunId
                Status       = $context.Status
                BackupPath   = $context.Root
                RebootNeeded = $true
                WarningCount = $context.Warnings.Count
                Warnings     = @($context.Warnings)
                NextCommand  = ".\CTyunTrim.ps1 -Mode Apply -RunId $($context.RunId) -Force"
            }
        }
        Move-CTDeadShortcuts -Context $context -Manifest $Manifest -Caller $Caller
        Move-CTRemovalPaths -Context $context -Manifest $Manifest -Caller $Caller
        if ($context.RebootNeeded) {
            $after = Get-CTyunTrimInventory -ManifestPath $context.ManifestPath
            $afterPath = Join-Path $context.Root 'reports\after.json'
            $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $afterPath -Encoding UTF8
            Set-CTRunFileAcl -Path $afterPath
            $health = Test-CTCoreHealth -Manifest $Manifest -RequireRunning -Context $context
            if (-not $health.Healthy) {
                throw "Core health check failed before the reboot checkpoint: $($health.Failures -join '; ')"
            }
            $context.Status = 'PendingReboot'
            $context.CompletedAt = (Get-Date).ToString('o')
            Save-CTRunContext -Context $context
            Add-CTDiagnosticEvent -Level 'Warning' -Stage 'Apply' -Message 'Apply requires reboot.' -Data @{ Status = 'PendingReboot' }
            return [PSCustomObject]@{
                RunId        = $context.RunId
                Status       = $context.Status
                BackupPath   = $context.Root
                RebootNeeded = $true
                WarningCount = $context.Warnings.Count
                Warnings     = @($context.Warnings)
                NextCommand  = ".\CTyunTrim.ps1 -Mode Apply -RunId $($context.RunId) -Force"
            }
        }
        Remove-CTKnownCertificates -Context $context -Manifest $Manifest -Caller $Caller
        Remove-CTFirewallRules -Context $context -Manifest $Manifest -Caller $Caller

        $after = Get-CTyunTrimInventory -ManifestPath $context.ManifestPath
        $afterPath = Join-Path $context.Root 'reports\after.json'
        $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $afterPath -Encoding UTF8
        Set-CTRunFileAcl -Path $afterPath

        $health = Test-CTCoreHealth -Manifest $Manifest -RequireRunning -Context $context
        if (-not $health.Healthy) {
            throw "Core health check failed after Apply: $($health.Failures -join '; ')"
        }

        $pendingOperations = @($context.Operations | Where-Object { $_.Status -eq 'Pending' })
        if ($context.RebootNeeded) {
            $context.Status = 'PendingReboot'
        }
        elseif ($pendingOperations.Count -gt 0) {
            throw "Apply has unresolved write-ahead journal entries: $($pendingOperations.Target -join '; ')"
        }
        else {
            $verification = Get-CTVerification -Manifest $Manifest -ManifestPath $context.ManifestPath -Context $context
            if (-not $verification.Passed) {
                throw "Apply is incomplete: $($verification.Failures -join '; ')"
            }
            $context.Status = 'Applied'
        }
        $context.CompletedAt = (Get-Date).ToString('o')
        Save-CTRunContext -Context $context
        Add-CTDiagnosticEvent -Stage 'Apply' -Message 'Apply completed.' -Data @{ Status = [string]$context.Status; RebootNeeded = [bool]$context.RebootNeeded }

        return [PSCustomObject]@{
            RunId         = $context.RunId
            Status        = $context.Status
            BackupPath    = $context.Root
            RebootNeeded  = $context.RebootNeeded
            WarningCount  = $context.Warnings.Count
            Warnings      = @($context.Warnings)
            NextCommand   = if ($context.RebootNeeded) { ".\CTyunTrim.ps1 -Mode Apply -RunId $($context.RunId) -Force" } else { ".\CTyunTrim.ps1 -Mode Verify -RunId $($context.RunId)" }
        }
    }
    catch {
        Save-CTFailedRunContextSafe -Context $context -FailureMessage $_.Exception.Message
        Add-CTDiagnosticEvent -Level 'Error' -Stage 'Apply' -Message 'Apply failed.'
        throw
    }
}

function Invoke-CTPrepare {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupRoot,

        [string]$LgpoPath,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCmdlet]$Caller
    )

    Add-CTDiagnosticEvent -Stage 'Prepare' -Message 'Prepare started.'
    $os = Get-CTOperatingSystem
    if ($Manifest.SupportedBuilds -notcontains $os.Build) {
        throw "Unsupported Windows build $($os.Build). Supported builds: $($Manifest.SupportedBuilds -join ', '). Prepare refused."
    }
    if (-not (Test-Path -LiteralPath $Manifest.Roots.CTyun -PathType Container)) {
        throw "CTyun installation root was not found: $($Manifest.Roots.CTyun)"
    }

    $preflight = Test-CTApplyPreflight -Manifest $Manifest -BackupRoot $BackupRoot -LgpoPath $LgpoPath -Phase Prepare
    if (-not $preflight.Passed) {
        throw "Prepare preflight failed: $($preflight.Errors -join '; ')"
    }

    $context = New-CTRunContext -BackupRoot $BackupRoot -ManifestPath $ManifestPath
    try {
        Export-CTBaseline -Context $context -Manifest $Manifest
        $baselineHealth = Test-CTCoreHealth -Manifest $Manifest -RequireRunning -Context $context
        if (-not $baselineHealth.Healthy) {
            throw "Core baseline continuity failed before Prepare changes: $($baselineHealth.Failures -join '; ')"
        }
        $identityEvidence = Save-CTCloudbaseIdentityEvidence -Context $context -Manifest $Manifest
        $preChangePreflight = Test-CTApplyPreflight -Manifest $Manifest -BackupRoot $BackupRoot -LgpoPath $LgpoPath -RunId $context.RunId -Context $context -Phase Prepare
        if (-not $preChangePreflight.Passed) {
            throw "Prepare mutation-boundary preflight failed: $($preChangePreflight.Errors -join '; ')"
        }
        foreach ($warning in @(@($preflight.Warnings) + @($preChangePreflight.Warnings) | Sort-Object -Unique)) {
            Add-CTWarning -Context $context -Message $warning
        }
        Add-CTExecutionGuards -Context $context -Manifest $Manifest -Caller $Caller
        Stop-CTOptionalProcesses -Context $context -Manifest $Manifest -Caller $Caller
        Remove-CTScheduledTasks -Context $context -Manifest $Manifest -Caller $Caller
        Stop-CTOptionalProcesses -Context $context -Manifest $Manifest -Caller $Caller
        if ($null -ne $identityEvidence) {
            $preparedIdentitySid = [string](Get-CTPropertyValue -InputObject $identityEvidence.Data -Name 'AccountSid')
            if ([string]::IsNullOrWhiteSpace($preparedIdentitySid)) {
                $preparedIdentitySid = [string](Get-CTPropertyValue -InputObject $identityEvidence.Data -Name 'ProfileSid')
            }
            if (-not [string]::IsNullOrWhiteSpace($preparedIdentitySid) -and @(Get-CTProcessesByOwnerSid -Sid $preparedIdentitySid).Count -gt 0) {
                throw 'A process still runs under the Cloudbase identity after Prepare guards and task removal.'
            }
        }
        Clear-CTFakeWsusPolicy -Context $context -Manifest $Manifest -LgpoPath $LgpoPath -Caller $Caller

        $after = Get-CTyunTrimInventory -ManifestPath $context.ManifestPath
        $afterPreparePath = Join-Path $context.Root 'reports\after-prepare.json'
        $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $afterPreparePath -Encoding UTF8
        Set-CTRunFileAcl -Path $afterPreparePath
        $context.Status = 'Prepared'
        $context.CompletedAt = (Get-Date).ToString('o')
        Save-CTRunContext -Context $context
        Add-CTDiagnosticEvent -Stage 'Prepare' -Message 'Prepare completed.' -Data @{ Status = 'Prepared' }

        return [PSCustomObject]@{
            RunId       = $context.RunId
            Status      = $context.Status
            BackupPath  = $context.Root
            NextCommand = "Run Windows Update, apply the official ReviOS Playbook, reboot, then run .\CTyunTrim.ps1 -Mode Apply -RunId $($context.RunId) -Force"
        }
    }
    catch {
        Save-CTFailedRunContextSafe -Context $context -FailureMessage $_.Exception.Message
        Add-CTDiagnosticEvent -Level 'Error' -Stage 'Prepare' -Message 'Prepare failed.'
        throw
    }
}

function Invoke-CTyunTrim {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [ValidateSet('Audit', 'Plan', 'Prepare', 'Apply', 'Verify')]
        [string]$Mode = 'Audit',

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [string]$BackupRoot = "$env:ProgramData\CTyunTrim\Runs",

        [string]$RunId,

        [string]$LgpoPath,

        [switch]$Force,

        [switch]$Restart,

        [switch]$Json
    )

    if (-not $script:DiagnosticEnabled) { Initialize-CTDiagnosticState -Enabled $false -Mode $Mode }
    $manifestValidation = Test-CTyunTrimManifest -ManifestPath $ManifestPath
    if (-not $manifestValidation.Valid) {
        Add-CTDiagnosticEvent -Level 'Error' -Stage 'Manifest' -Message 'Manifest validation failed.' -Data @{ ErrorCount = @($manifestValidation.Errors).Count }
        throw "Manifest validation failed: $($manifestValidation.Errors -join '; ')"
    }
    $manifest = $manifestValidation.Manifest
    Add-CTDiagnosticEvent -Stage 'Manifest' -Message 'Manifest validation passed.'

    if ($Mode -eq 'Audit') {
        $result = Get-CTyunTrimInventory -ManifestPath $ManifestPath
        Add-CTDiagnosticEvent -Stage 'Invocation' -Message 'Audit completed.'
        if ($Json) { return ($result | ConvertTo-Json -Depth 10) }
        return $result
    }

    if ($Mode -eq 'Plan' -or ($Mode -eq 'Apply' -and $WhatIfPreference)) {
        $result = Get-CTPlan -Manifest $manifest
        Add-CTDiagnosticEvent -Stage 'Invocation' -Message 'Plan completed.' -Data @{ ActionCount = @($result).Count }
        if ($Json) { return ($result | ConvertTo-Json -Depth 6) }
        return $result
    }

    if ($Mode -eq 'Prepare' -and $WhatIfPreference) {
        $result = @(Get-CTPlan -Manifest $manifest | Where-Object { $_.Type -in @('ExecutionGuard', 'ScheduledTask', 'ProcessStop', 'LocalPolicy') })
        Add-CTDiagnosticEvent -Stage 'Invocation' -Message 'Prepare preview completed.' -Data @{ ActionCount = @($result).Count }
        if ($Json) { return ($result | ConvertTo-Json -Depth 6) }
        return $result
    }

    if ($Mode -eq 'Verify') {
        $verificationContext = $null
        $verificationManifestPath = $ManifestPath
        if (-not [string]::IsNullOrWhiteSpace($RunId)) {
            $verificationContext = Get-CTRunContext -BackupRoot $BackupRoot -RunId $RunId
            if ((Get-CTNormalizedTextHash -Path (ConvertTo-CTFullPath -Path $ManifestPath)) -ne [string]$verificationContext.ManifestHash) {
                throw 'Current manifest differs from the manifest that created this verification run.'
            }
            $verificationManifestPath = [string]$verificationContext.ManifestPath
        }
        $result = Get-CTVerification -Manifest $manifest -ManifestPath $verificationManifestPath -Context $verificationContext
        Add-CTDiagnosticEvent -Level $(if ($result.Passed) { 'Info' } else { 'Error' }) -Stage 'Verification' -Message $(if ($result.Passed) { 'Verification passed.' } else { 'Verification failed.' }) -Data @{
            Passed = [bool]$result.Passed; FailureCount = @($result.Failures).Count; WarningCount = @($result.Warnings).Count
        }
        if ($Json) { return ($result | ConvertTo-Json -Depth 12) }
        return $result
    }

    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
        throw "$Mode requires 64-bit Windows PowerShell 5.1 Desktop Edition. Use Start-CTyunTrim.cmd."
    }
    if (-not (Test-CTIsAdministrator)) {
        throw "$Mode requires a 64-bit elevated Windows PowerShell session."
    }
    if (-not [Environment]::Is64BitProcess) {
        throw "$Mode requires 64-bit Windows PowerShell. Use Start-CTyunTrim.cmd."
    }
    if (-not $Force) {
        throw "$Mode is destructive and requires the explicit -Force switch after reviewing Audit and Plan output."
    }

    $mutex = New-Object Threading.Mutex($false, 'Global\CTyunTrim')
    $lockTaken = $false
    try {
        $lockTaken = $mutex.WaitOne(0)
        if (-not $lockTaken) {
            throw 'Another CTyunTrim Prepare or Apply operation is already running.'
        }

        if ($Mode -eq 'Prepare') {
            $result = Invoke-CTPrepare -Manifest $manifest -ManifestPath $ManifestPath -BackupRoot $BackupRoot -LgpoPath $LgpoPath -Caller $PSCmdlet
        }
        elseif ($Mode -eq 'Apply') {
            $result = Invoke-CTApply -Manifest $manifest -ManifestPath $ManifestPath -BackupRoot $BackupRoot -LgpoPath $LgpoPath -RunId $RunId -Caller $PSCmdlet
        }
        if ($Restart) {
            Restart-Computer -Force
        }

        Add-CTDiagnosticEvent -Stage 'Invocation' -Message 'Destructive workflow returned.' -Data @{ Status = [string](Get-CTPropertyValue -InputObject $result -Name 'Status') }
        if ($Json) { return ($result | ConvertTo-Json -Depth 10) }
        return $result
    }
    finally {
        if ($lockTaken) {
            [void]$mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}

Export-ModuleMember -Function Get-CTyunTrimInventory, Test-CTyunTrimManifest, Invoke-CTyunTrim, Start-CTyunTrimDiagnosticCapture, Stop-CTyunTrimDiagnosticCapture, New-CTyunTrimDiagnosticBundle
