@{
    RootModule        = 'CTyunTrim.psm1'
    ModuleVersion     = '0.1.4'
    GUID              = '767c6b7c-b751-4fd3-8a2a-242df21c92df'
    Author            = 'CTyunTrim contributors'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 CTyunTrim contributors. MIT License.'
    Description       = 'Audit-first CTyun Windows guest minimization while preserving selected interoperability components.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-CTyunTrimInventory',
        'Test-CTyunTrimManifest',
        'Invoke-CTyunTrim',
        'Start-CTyunTrimDiagnosticCapture',
        'Stop-CTyunTrimDiagnosticCapture',
        'New-CTyunTrimDiagnosticBundle'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Windows', 'CTyun', 'Debloat', 'Audit', 'PowerShell')
            Prerelease = 'Diagnostic'
            LicenseUri = 'https://opensource.org/license/mit'
            ProjectUri = 'https://github.com/mihomoQ/ctyun-trim'
        }
    }
}
