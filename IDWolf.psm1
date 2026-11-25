<#
    IDWolf module surface.

    The tool is a set of scripts that dot-source lib\ and are meant to be run by
    path. This file adds nothing but names: each function invokes the matching
    script next to it and forwards every argument unchanged, so there is one
    implementation and one parameter list to keep right.

    Because the arguments are forwarded, the parameters are the script's own:
    Get-Help on the script file (Get-IDWolfPath tells you where it is) lists
    them, as does the README.

    Nothing here runs at import time: importing the module collects nothing,
    reads no snapshot and contacts nothing.
#>

function Get-IDWolfPath {
    <#
    .SYNOPSIS
        The folder the IDWolf scripts live in.
    .DESCRIPTION
        Installed from the PowerShell Gallery the scripts are not on your PATH.
        This is where they are, so you can run one directly or read its help.
    .EXAMPLE
        Get-Help (Join-Path (Get-IDWolfPath) 'IDWolf.ps1') -Full
    .EXAMPLE
        & (Join-Path (Get-IDWolfPath) 'Start-IDWolf.ps1')
    #>
    [CmdletBinding()]
    Param()
    $PSScriptRoot
}

function Start-IDWolf {
    <#
    .SYNOPSIS
        IDWolf launcher: one guided entry point for collection and analysis.
    .DESCRIPTION
        Runs Start-IDWolf.ps1. Arguments are passed through unchanged; see
        Get-Help (Join-Path (Get-IDWolfPath) 'Start-IDWolf.ps1') -Full.
    .EXAMPLE
        Start-IDWolf
    .EXAMPLE
        Start-IDWolf -Server dc07.corp.local -Credential (Get-Credential)
    #>
    & (Join-Path $PSScriptRoot 'Start-IDWolf.ps1') @args
}

function Invoke-IDWolf {
    <#
    .SYNOPSIS
        Analyze an AD or Entra snapshot and write the report. No AD, no Graph,
        no network.
    .DESCRIPTION
        Runs IDWolf.ps1. Arguments are passed through unchanged; see
        Get-Help (Join-Path (Get-IDWolfPath) 'IDWolf.ps1') -Full.

        Without -Snapshot it starts the interactive wizard. Always pass -SkipLLM
        in an unattended run.
    .EXAMPLE
        Invoke-IDWolf -Snapshot .\adsnap.json -SkipLLM
    .EXAMPLE
        Invoke-IDWolf -Snapshot .\snap.json -OutJson .\findings.jsonl -CompareTo .\report_prev.csv -SkipLLM
    #>
    & (Join-Path $PSScriptRoot 'IDWolf.ps1') @args
}

function Export-IDWolfADSnapshot {
    <#
    .SYNOPSIS
        Read-only Active Directory snapshot, native ActiveDirectory module
        (RSAT) only.
    .DESCRIPTION
        Runs Collect-ADSnapshot.ps1. Arguments are passed through unchanged; see
        Get-Help (Join-Path (Get-IDWolfPath) 'Collect-ADSnapshot.ps1') -Full.
    .EXAMPLE
        Export-IDWolfADSnapshot -OutFile .\adsnap.json
    #>
    & (Join-Path $PSScriptRoot 'Collect-ADSnapshot.ps1') @args
}

function Export-IDWolfEntraSnapshot {
    <#
    .SYNOPSIS
        Read-only Microsoft Entra ID tenant snapshot through Microsoft Graph.
    .DESCRIPTION
        Runs Collect-EntraSnapshot.ps1. Arguments are passed through unchanged;
        see Get-Help (Join-Path (Get-IDWolfPath) 'Collect-EntraSnapshot.ps1') -Full.
    .EXAMPLE
        Export-IDWolfEntraSnapshot -OutFile .\entra.json
    #>
    & (Join-Path $PSScriptRoot 'Collect-EntraSnapshot.ps1') @args
}

function Export-IDWolfPasswordQuality {
    <#
    .SYNOPSIS
        Password-quality report without hashes, for Invoke-IDWolf
        -PasswordQualityFile.
    .DESCRIPTION
        Runs Export-PasswordQuality.ps1 (needs DSInternals and replication
        rights). Arguments are passed through unchanged; see
        Get-Help (Join-Path (Get-IDWolfPath) 'Export-PasswordQuality.ps1') -Full.
    .EXAMPLE
        Export-IDWolfPasswordQuality -OutFile .\pwq.json
    #>
    & (Join-Path $PSScriptRoot 'Export-PasswordQuality.ps1') @args
}

function Export-IDWolfBloodHound {
    <#
    .SYNOPSIS
        Convert an IDWolf snapshot to BloodHound CE JSON in a zip (beta).
    .DESCRIPTION
        Runs Export-BloodHound.ps1. Arguments are passed through unchanged; see
        Get-Help (Join-Path (Get-IDWolfPath) 'Export-BloodHound.ps1') -Full.
    .EXAMPLE
        Export-IDWolfBloodHound -Snapshot .\adsnap.json
    #>
    & (Join-Path $PSScriptRoot 'Export-BloodHound.ps1') @args
}

function Invoke-IDWolfScheduled {
    <#
    .SYNOPSIS
        Unattended run for a scheduled task: collect, analyze, feed a SIEM.
    .DESCRIPTION
        Runs Invoke-IDWolfScheduled.ps1. It never registers the task itself.
        Arguments are passed through unchanged; see
        Get-Help (Join-Path (Get-IDWolfPath) 'Invoke-IDWolfScheduled.ps1') -Full.
    .EXAMPLE
        Invoke-IDWolfScheduled -RunRoot D:\IDWolfRuns -KeepRuns 30
    #>
    & (Join-Path $PSScriptRoot 'Invoke-IDWolfScheduled.ps1') @args
}

function Test-IDWolfSafety {
    <#
    .SYNOPSIS
        Read the installed IDWolf scripts without running them and show
        everything they can do.
    .DESCRIPTION
        Runs Test-IDWolfSafety.ps1 over this module folder: every external
        command called, every place written, every address contacted. Defaults
        to the installed copy, so you can verify what you got from the gallery;
        -Path points it somewhere else.
    .EXAMPLE
        Test-IDWolfSafety
    #>
    & (Join-Path $PSScriptRoot 'Test-IDWolfSafety.ps1') @args
}

# No Export-ModuleMember here on purpose: FunctionsToExport in IDWolf.psd1 is the
# only list of what the module offers, so there is nothing to keep in step.
