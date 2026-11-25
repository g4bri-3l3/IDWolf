#
# Module manifest for IDWolf.
#
# ModuleVersion must match $script:IDWolfVersion in IDWolf.ps1; the regression
# suite asserts it. Bump both together, and the tag with them.
#
@{
    RootModule           = 'IDWolf.psm1'
    ModuleVersion        = '1.16'
    GUID                 = 'db8efb60-d602-43d0-8b35-fb7c51d5c458'
    Author               = 'Gabriele Piccini'
    CompanyName          = 'Gabriele Piccini'
    Copyright            = '(c) 2026 Gabriele Piccini. MIT licensed.'

    Description          = @'
IDWolf is a pure-PowerShell Active Directory and Microsoft Entra ID hygiene auditor.

Collect once, analyze anywhere. The collectors are strictly read-only and use only
native cmdlets (RSAT ActiveDirectory, Microsoft Graph SDK); they write one JSON
snapshot and never touch the directory. The analyzer needs no AD module, no Graph
and no network, so the snapshot can be reviewed on any machine, including Linux
PowerShell 7.

It writes an HTML report, a findings CSV and JSON Lines for a SIEM, maps every
finding to MITRE ATT&CK and to NIS2 / ISO 27001 / DORA / GDPR controls, scores the
domain, and renders attack-path and trust maps as server-side SVG with no external
libraries or CDN. A collection gap is listed as "not evaluated" rather than
reported clean. Ages are measured at snapshot time, so the same snapshot always
gives the same findings.

Optional extras: a hashless password-quality report (DSInternals), a BloodHound CE
export, unattended scheduled runs, and an AI summary (Gemini) that is sent only
after every identifier has been pseudonymized and re-scanned for leaks.

Runs on Windows PowerShell 5.1 and PowerShell 7.
'@

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport    = @(
        'Start-IDWolf',
        'Invoke-IDWolf',
        'Export-IDWolfADSnapshot',
        'Export-IDWolfEntraSnapshot',
        'Export-IDWolfPasswordQuality',
        'Export-IDWolfBloodHound',
        'Invoke-IDWolfScheduled',
        'Test-IDWolfSafety',
        'Get-IDWolfPath'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    # The ActiveDirectory, Microsoft.Graph and DSInternals modules are needed only
    # by the collectors, on the machine that collects. They are deliberately not
    # RequiredModules: the analyzer must install and run without them.
    RequiredModules      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @(
                'ActiveDirectory', 'AD', 'EntraID', 'AzureAD', 'Security', 'Audit', 'Hygiene',
                'Hardening', 'MITRE', 'ATTACK', 'Compliance', 'NIS2', 'ISO27001', 'DORA', 'GDPR',
                'BloodHound', 'Reporting', 'SIEM', 'ReadOnly', 'Offline',
                'Windows', 'PSEdition_Desktop', 'PSEdition_Core'
            )
            LicenseUri   = 'https://github.com/g4bri-3l3/IDWolf/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/g4bri-3l3/IDWolf'
            ReleaseNotes = 'https://github.com/g4bri-3l3/IDWolf/blob/main/CHANGELOG.md'
        }
    }
}
