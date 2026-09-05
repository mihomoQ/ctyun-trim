#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Quarantine resume tests must run under Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) { throw 'Quarantine resume tests require a 64-bit process.' }

$root = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'src\CTyunTrim.psd1'
$sourcePath = Join-Path $root 'src\CTyunTrim.psm1'
$failures = New-Object Collections.Generic.List[string]
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("CTyunTrim-QuarantineTests-{0}" -f [guid]::NewGuid().ToString('N'))

function Assert-CTQuarantine {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { $script:failures.Add($Message) }
}

try {
    New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null

    Import-Module -Name $modulePath -Force
    $module = Get-Module CTyunTrim
    $results = & $module {
        param($FixtureRoot)

        $script:QuarantineReparsePath = $null
        $script:QuarantineCrossVolume = $false
        $script:QuarantineSaveCalls = 0
        $script:QuarantineWarningCalls = 0
        $originalReparseTest = ${function:Test-CTPathHasReparsePoint}
        $originalDestination = ${function:Get-CTQuarantineDestination}

        function Test-CTPathHasReparsePoint {
            param([string]$Path)
            $full = $null
            try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { }
            if (-not [string]::IsNullOrWhiteSpace([string]$script:QuarantineReparsePath) -and
                [string]::Equals($full, [IO.Path]::GetFullPath($script:QuarantineReparsePath).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
            return & $originalReparseTest -Path $Path
        }
        function Get-CTQuarantineDestination {
            param([PSObject]$Context, [string]$Path)
            if ($script:QuarantineCrossVolume) { return 'Z:\CTyunTrim-Test-Do-Not-Create\collision' }
            return & $originalDestination -Context $Context -Path $Path
        }
        function Save-CTRunContext { param([PSObject]$Context) $script:QuarantineSaveCalls++ }
        function Add-CTDiagnosticEvent { param([string]$Level,[string]$Stage,[string]$Message,[hashtable]$Data) }
        function Add-CTWarning {
            param([PSObject]$Context,[string]$Message)
            $script:QuarantineWarningCalls++
            [void]$Context.Warnings.Add($Message)
        }
        function Invoke-QuarantineFixture {
            [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
            param([PSObject]$Context,[string]$Path,[string[]]$ProtectedPaths)
            Move-CTPathToQuarantine -Context $Context -Path $Path -ProtectedPaths $ProtectedPaths -Caller $PSCmdlet
        }
        function New-QuarantineContext {
            param([string]$Name)
            $runRoot = Join-Path $FixtureRoot (Join-Path 'runs' $Name)
            New-Item -ItemType Directory -Path $runRoot -Force -ErrorAction Stop | Out-Null
            [PSCustomObject]@{
                RunId=$Name;Root=[IO.Path]::GetFullPath($runRoot);RebootNeeded=$false
                Operations=(New-Object Collections.ArrayList);Warnings=(New-Object Collections.ArrayList)
            }
        }
        function New-FixtureDirectory {
            param([string]$Path,[string]$FileName,[string]$Content)
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
            [IO.File]::WriteAllText((Join-Path $Path $FileName),$Content,(New-Object Text.UTF8Encoding($false)))
        }
        function Get-QuarantineOperations {
            param([PSObject]$Context,[string]$Source)
            return @($Context.Operations | Where-Object { $_.Type -eq 'QuarantinePath' -and [string]$_.Target -eq [IO.Path]::GetFullPath($Source).TrimEnd('\') })
        }

        $sourceArea = Join-Path $FixtureRoot 'source-area'
        New-Item -ItemType Directory -Path $sourceArea -Force -ErrorAction Stop | Out-Null
        $unrelatedProtected = Join-Path $FixtureRoot 'protected-canary'
        New-Item -ItemType Directory -Path $unrelatedProtected -Force -ErrorAction Stop | Out-Null

        # Original plus two consecutive recreations of the exact source path.
        $generationContext = New-QuarantineContext -Name 'generations'
        $generationSource = Join-Path $sourceArea 'FileCrypto'
        New-FixtureDirectory -Path $generationSource -FileName 'original.txt' -Content 'ORIGINAL-BACKUP-CANARY'
        Invoke-QuarantineFixture -Context $generationContext -Path $generationSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false
        $firstOperations = @(Get-QuarantineOperations -Context $generationContext -Source $generationSource)
        $firstDestination = [string]$firstOperations[0].Data.Destination
        $firstHashBefore = (Get-FileHash -LiteralPath (Join-Path $firstDestination 'original.txt') -Algorithm SHA256).Hash

        New-FixtureDirectory -Path $generationSource -FileName 'second.txt' -Content 'SECOND-GENERATION-CANARY'
        Invoke-QuarantineFixture -Context $generationContext -Path $generationSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false
        $secondOperations = @(Get-QuarantineOperations -Context $generationContext -Source $generationSource)
        $secondDestination = [string]$secondOperations[1].Data.Destination
        $secondHashBefore = (Get-FileHash -LiteralPath (Join-Path $secondDestination 'second.txt') -Algorithm SHA256).Hash

        New-FixtureDirectory -Path $generationSource -FileName 'third.txt' -Content 'THIRD-GENERATION-CANARY'
        Invoke-QuarantineFixture -Context $generationContext -Path $generationSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false
        $generationOperations = @(Get-QuarantineOperations -Context $generationContext -Source $generationSource)
        $thirdDestination = [string]$generationOperations[2].Data.Destination
        $generationResult = [PSCustomObject]@{
            Count = @($generationOperations).Count
            Statuses = @($generationOperations | ForEach-Object { [string]$_.Status })
            Generations = @($generationOperations | ForEach-Object { [string]$_.Data.Generation })
            FirstPrevious = [string]$generationOperations[0].Data.PreviousOperationId
            SecondPrevious = [string]$generationOperations[1].Data.PreviousOperationId
            ThirdPrevious = [string]$generationOperations[2].Data.PreviousOperationId
            FirstId = [string]$generationOperations[0].Id
            SecondId = [string]$generationOperations[1].Id
            FirstDestination = $firstDestination
            SecondDestination = $secondDestination
            ThirdDestination = $thirdDestination
            DestinationsDistinct = @($firstDestination,$secondDestination,$thirdDestination | Select-Object -Unique).Count -eq 3
            FirstHashUnchanged = (Get-FileHash -LiteralPath (Join-Path $firstDestination 'original.txt') -Algorithm SHA256).Hash -eq $firstHashBefore
            SecondHashUnchanged = (Get-FileHash -LiteralPath (Join-Path $secondDestination 'second.txt') -Algorithm SHA256).Hash -eq $secondHashBefore
            FirstNoMerge = -not (Test-Path -LiteralPath (Join-Path $firstDestination 'second.txt')) -and -not (Test-Path -LiteralPath (Join-Path $firstDestination 'third.txt'))
            SecondNoMerge = -not (Test-Path -LiteralPath (Join-Path $secondDestination 'original.txt')) -and -not (Test-Path -LiteralPath (Join-Path $secondDestination 'third.txt'))
            ThirdExact = (Test-Path -LiteralPath (Join-Path $thirdDestination 'third.txt')) -and -not (Test-Path -LiteralPath (Join-Path $thirdDestination 'original.txt'))
            SourceAbsent = -not (Test-Path -LiteralPath $generationSource)
            Nested = $secondDestination.StartsWith($firstDestination+'\',[StringComparison]::OrdinalIgnoreCase) -or
                $thirdDestination.StartsWith($firstDestination+'\',[StringComparison]::OrdinalIgnoreCase) -or
                $thirdDestination.StartsWith($secondDestination+'\',[StringComparison]::OrdinalIgnoreCase)
        }

        # A genuine Windows sharing violation leaves one Pending operation; the
        # retry must use that exact destination after the handle is released.
        $pendingContext = New-QuarantineContext -Name 'pending-retry'
        $pendingSource = Join-Path $sourceArea 'pending-file.bin'
        [IO.File]::WriteAllBytes($pendingSource,[byte[]](1,2,3,4,5,6,7,8))
        $lock = [IO.File]::Open($pendingSource,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try { Invoke-QuarantineFixture -Context $pendingContext -Path $pendingSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false }
        finally { $lock.Dispose() }
        $pendingAfterFailure = @(Get-QuarantineOperations -Context $pendingContext -Source $pendingSource)
        $pendingDestination = [string]$pendingAfterFailure[0].Data.Destination
        $failureState = [PSCustomObject]@{
            Count=@($pendingAfterFailure).Count;Status=[string]$pendingAfterFailure[0].Status
            SourceExists=Test-Path -LiteralPath $pendingSource;DestinationExists=Test-Path -LiteralPath $pendingDestination
            RebootNeeded=[bool]$pendingContext.RebootNeeded
        }
        Invoke-QuarantineFixture -Context $pendingContext -Path $pendingSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false
        $pendingAfterRetry = @(Get-QuarantineOperations -Context $pendingContext -Source $pendingSource)
        $pendingResult = [PSCustomObject]@{
            Failure=$failureState;Count=@($pendingAfterRetry).Count;Status=[string]$pendingAfterRetry[0].Status
            SameDestination=[string]$pendingAfterRetry[0].Data.Destination -eq $pendingDestination
            SourceAbsent=-not(Test-Path -LiteralPath $pendingSource);DestinationExists=Test-Path -LiteralPath $pendingDestination
        }

        # An unjournaled destination collision must preserve both trees.
        $collisionContext = New-QuarantineContext -Name 'unknown-collision'
        $collisionSource = Join-Path $sourceArea 'collision-source'
        New-FixtureDirectory -Path $collisionSource -FileName 'source.txt' -Content 'SOURCE-COLLISION-CANARY'
        $collisionDestination = & $originalDestination -Context $collisionContext -Path $collisionSource
        New-FixtureDirectory -Path $collisionDestination -FileName 'destination.txt' -Content 'DESTINATION-COLLISION-CANARY'
        $unknownCollisionBlocked = $false
        try { Invoke-QuarantineFixture -Context $collisionContext -Path $collisionSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false }
        catch { $unknownCollisionBlocked = $_.Exception.Message -match 'Unknown quarantine destination collision' }
        $unknownCollision = [PSCustomObject]@{
            Blocked=$unknownCollisionBlocked;OperationCount=@($collisionContext.Operations).Count
            SourceUnchanged=[IO.File]::ReadAllText((Join-Path $collisionSource 'source.txt')) -eq 'SOURCE-COLLISION-CANARY'
            DestinationUnchanged=[IO.File]::ReadAllText((Join-Path $collisionDestination 'destination.txt')) -eq 'DESTINATION-COLLISION-CANARY'
        }

        # Even a journal-owned Pending destination must not be merged when both
        # sides exist.
        $bothContext = New-QuarantineContext -Name 'both-exist'
        $bothSource = Join-Path $sourceArea 'both-source'
        [IO.File]::WriteAllText($bothSource,'SOURCE-BOTH-CANARY')
        $bothDestination = & $originalDestination -Context $bothContext -Path $bothSource
        New-Item -ItemType Directory -Path (Split-Path -Parent $bothDestination) -Force -ErrorAction Stop | Out-Null
        [IO.File]::WriteAllText($bothDestination,'DESTINATION-BOTH-CANARY')
        [void]$bothContext.Operations.Add([PSCustomObject]@{
            Id='pending-both';Type='QuarantinePath';Target=[IO.Path]::GetFullPath($bothSource);Status='Pending';CompletedAt=$null;Reversible=$true
            Data=@{Source=[IO.Path]::GetFullPath($bothSource);Destination=[IO.Path]::GetFullPath($bothDestination);Generation='Original';PreviousOperationId=$null}
        })
        $bothBlocked = $false
        try { Invoke-QuarantineFixture -Context $bothContext -Path $bothSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false }
        catch { $bothBlocked = $_.Exception.Message -match 'source and destination both exist' }
        $bothExist = [PSCustomObject]@{
            Blocked=$bothBlocked;Status=[string]$bothContext.Operations[0].Status
            SourceUnchanged=[IO.File]::ReadAllText($bothSource) -eq 'SOURCE-BOTH-CANARY'
            DestinationUnchanged=[IO.File]::ReadAllText($bothDestination) -eq 'DESTINATION-BOTH-CANARY'
        }

        $reparseContext = New-QuarantineContext -Name 'reparse'
        $reparseSource = Join-Path $sourceArea 'reparse-source'
        New-FixtureDirectory -Path $reparseSource -FileName 'keep.txt' -Content 'REPARSE-KEEP-CANARY'
        $script:QuarantineReparsePath = $reparseSource
        $reparseBlocked = $false
        try { Invoke-QuarantineFixture -Context $reparseContext -Path $reparseSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false }
        catch { $reparseBlocked = $_.Exception.Message -match 'reparse-point' }
        $script:QuarantineReparsePath = $null

        $protectedContext = New-QuarantineContext -Name 'protected'
        $protectedSource = Join-Path $sourceArea 'protected-source'
        New-FixtureDirectory -Path $protectedSource -FileName 'keep.txt' -Content 'PROTECTED-KEEP-CANARY'
        $protectedBlocked = $false
        try { Invoke-QuarantineFixture -Context $protectedContext -Path $protectedSource -ProtectedPaths @($protectedSource) -Confirm:$false }
        catch { $protectedBlocked = $_.Exception.Message -match 'protected path' }

        $volumeContext = New-QuarantineContext -Name 'cross-volume'
        $volumeSource = Join-Path $sourceArea 'volume-source'
        New-FixtureDirectory -Path $volumeSource -FileName 'keep.txt' -Content 'VOLUME-KEEP-CANARY'
        $script:QuarantineCrossVolume = $true
        $volumeBlocked = $false
        try { Invoke-QuarantineFixture -Context $volumeContext -Path $volumeSource -ProtectedPaths @($unrelatedProtected) -Confirm:$false }
        catch { $volumeBlocked = $_.Exception.Message -match 'same-volume run boundary' }
        $script:QuarantineCrossVolume = $false

        $rootContext = New-QuarantineContext -Name 'root-source'
        $volumeRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($FixtureRoot))
        $rootDestination = Join-Path $rootContext.Root 'quarantine\root-entry'
        $rootBlocked = $false
        try { Assert-CTQuarantinePathPair -Context $rootContext -Source $volumeRoot -Destination $rootDestination }
        catch { $rootBlocked = $true }

        [PSCustomObject]@{
            Generations=$generationResult;Pending=$pendingResult;UnknownCollision=$unknownCollision;BothExist=$bothExist
            Reparse=[PSCustomObject]@{Blocked=$reparseBlocked;SourceExists=Test-Path -LiteralPath $reparseSource;OperationCount=@($reparseContext.Operations).Count}
            Protected=[PSCustomObject]@{Blocked=$protectedBlocked;SourceExists=Test-Path -LiteralPath $protectedSource;OperationCount=@($protectedContext.Operations).Count}
            CrossVolume=[PSCustomObject]@{Blocked=$volumeBlocked;SourceExists=Test-Path -LiteralPath $volumeSource;OperationCount=@($volumeContext.Operations).Count}
            Root=[PSCustomObject]@{Blocked=$rootBlocked}
        }
    } $testRoot

    Assert-CTQuarantine -Condition ($results.Generations.Count -eq 3 -and @($results.Generations.Statuses | Where-Object { $_ -eq 'Completed' }).Count -eq 3) -Message 'Original plus two recreated generations were not completed independently.'
    Assert-CTQuarantine -Condition ($results.Generations.Generations[0] -eq 'Original' -and $results.Generations.Generations[1] -match '^Recreated:[0-9a-f]{32}$' -and $results.Generations.Generations[2] -match '^Recreated:[0-9a-f]{32}$') -Message 'Quarantine generation labels are invalid.'
    Assert-CTQuarantine -Condition ([string]::IsNullOrWhiteSpace($results.Generations.FirstPrevious) -and $results.Generations.SecondPrevious -eq $results.Generations.FirstId -and $results.Generations.ThirdPrevious -eq $results.Generations.SecondId) -Message 'Recreated quarantine generation ancestry is wrong.'
    Assert-CTQuarantine -Condition ($results.Generations.DestinationsDistinct -and -not $results.Generations.Nested) -Message 'Recreated destinations collided with or nested inside an older backup.'
    Assert-CTQuarantine -Condition ($results.Generations.FirstHashUnchanged -and $results.Generations.SecondHashUnchanged -and $results.Generations.FirstNoMerge -and $results.Generations.SecondNoMerge -and $results.Generations.ThirdExact -and $results.Generations.SourceAbsent) -Message 'A recreated move overwrote, merged, or modified an earlier quarantine backup.'

    Assert-CTQuarantine -Condition ($results.Pending.Failure.Count -eq 1 -and $results.Pending.Failure.Status -eq 'Pending' -and $results.Pending.Failure.SourceExists -and -not $results.Pending.Failure.DestinationExists -and $results.Pending.Failure.RebootNeeded) -Message 'Sharing-violation failure did not leave one safe Pending operation.'
    Assert-CTQuarantine -Condition ($results.Pending.Count -eq 1 -and $results.Pending.Status -eq 'Completed' -and $results.Pending.SameDestination -and $results.Pending.SourceAbsent -and $results.Pending.DestinationExists) -Message 'Pending quarantine retry did not reuse and complete its exact destination.'

    Assert-CTQuarantine -Condition ($results.UnknownCollision.Blocked -and $results.UnknownCollision.OperationCount -eq 0 -and $results.UnknownCollision.SourceUnchanged -and $results.UnknownCollision.DestinationUnchanged) -Message 'Unknown destination collision overwrote or merged data.'
    Assert-CTQuarantine -Condition ($results.BothExist.Blocked -and $results.BothExist.Status -eq 'Pending' -and $results.BothExist.SourceUnchanged -and $results.BothExist.DestinationUnchanged) -Message 'Pending source+destination coexistence was merged or modified.'
    Assert-CTQuarantine -Condition ($results.Reparse.Blocked -and $results.Reparse.SourceExists -and $results.Reparse.OperationCount -eq 0) -Message 'Reparse-point source reached quarantine mutation.'
    Assert-CTQuarantine -Condition ($results.Protected.Blocked -and $results.Protected.SourceExists -and $results.Protected.OperationCount -eq 0) -Message 'Protected source reached quarantine mutation.'
    Assert-CTQuarantine -Condition ($results.CrossVolume.Blocked -and $results.CrossVolume.SourceExists -and $results.CrossVolume.OperationCount -eq 0) -Message 'Cross-volume destination reached quarantine mutation.'
    Assert-CTQuarantine -Condition $results.Root.Blocked -Message 'A volume root was accepted as a quarantine source.'

    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$parseErrors)
    $moveFunction=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Move-CTPathToQuarantine'},$true))
    Assert-CTQuarantine -Condition (@($parseErrors).Count -eq 0 -and @($moveFunction).Count -eq 1) -Message 'Could not inspect the quarantine function AST.'
    if (@($moveFunction).Count -eq 1) {
        $moveText=[string]$moveFunction[0].Extent.Text
        Assert-CTQuarantine -Condition ($moveText -notmatch '(?i)\bMove-Item\b') -Message 'Quarantine still invokes Move-Item and can accidentally regain overwrite semantics.'
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        $fullTestRoot=[IO.Path]::GetFullPath($testRoot).TrimEnd('\')
        $fullTempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
        $leaf=[IO.Path]::GetFileName($fullTestRoot)
        $item=Get-Item -LiteralPath $fullTestRoot -Force -ErrorAction Stop
        $safe=$fullTestRoot.StartsWith($fullTempRoot,[StringComparison]::OrdinalIgnoreCase) -and
            $leaf -match '^CTyunTrim-QuarantineTests-[0-9a-f]{32}$' -and
            -not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
        if(-not $safe){throw "Refusing unsafe quarantine test cleanup path: $fullTestRoot"}
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failures.Count -gt 0) {
    throw "Quarantine resume tests failed:`n - $($failures -join "`n - ")"
}

Write-Host 'Quarantine resume tests passed.'
exit 0
