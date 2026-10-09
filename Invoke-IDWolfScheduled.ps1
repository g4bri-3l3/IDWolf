<#
.SYNOPSIS
    Unattended IDWolf run, for a scheduled task: collect, analyze, feed a SIEM.

.DESCRIPTION
    Runs the collector and the analyzer with no prompts and keeps one folder
    per run:

      <OutputDir>\ad_20261006_020000\
          snapshot.json  report.html  findings.csv  findings.jsonl  run.log

    Each run is compared with the previous one, so the JSON Lines say which
    findings are new and which were resolved. They are also appended to one
    file (<OutputDir>\idwolf.jsonl unless -SiemFile says otherwise) for a
    forwarder to follow: Splunk Universal Forwarder, Azure Monitor Agent,
    Filebeat, Wazuh...

    Gemini is never called. The script doesn't create the scheduled task
    either: that's your decision, see "Scheduled runs" in the README.

    The snapshot describes your whole directory: give OutputDir an ACL that
    only the service account and the admins can read.

.PARAMETER Target
    AD (default) or Entra. One scheduled task per target.
.PARAMETER OutputDir
    Folder for the run folders and the SIEM file. Created if missing.
.PARAMETER Server
    AD only: domain controller to query.
.PARAMETER Deep
    AD only: full ACL sweep (needs a privileged account, see the README).
.PARAMETER TenantId
    Entra only, with -ClientId and -CertificateThumbprint (app-only sign-in).
.PARAMETER ClientId
    Entra only: app registration with read-only application permissions.
.PARAMETER CertificateThumbprint
    Entra only: the app's certificate, in the run account's store.
.PARAMETER ExceptionsFile
    Accepted risks, as for IDWolf.ps1.
.PARAMETER SiemFile
    File the JSON Lines of every run are appended to. Default
    <OutputDir>\idwolf.jsonl. Rotation is up to the forwarder or you.
.PARAMETER KeepRuns
    Run folders to keep per target (default 30, 0 = keep all). Older ones are
    deleted; the SIEM file is left alone.

.EXAMPLE
    .\Invoke-IDWolfScheduled.ps1 -OutputDir D:\IDWolf
.EXAMPLE
    .\Invoke-IDWolfScheduled.ps1 -Target Entra -OutputDir D:\IDWolf -TenantId contoso.onmicrosoft.com -ClientId <app id> -CertificateThumbprint <thumbprint>
#>

[CmdletBinding()]
Param(
    [ValidateSet('AD', 'Entra')]
    [string]$Target = 'AD',
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,
    [string]$Server = "",
    [switch]$Deep,
    [string]$TenantId = "",
    [string]$ClientId = "",
    [string]$CertificateThumbprint = "",
    [string]$ExceptionsFile = "",
    [string]$SiemFile = "",
    [int]$KeepRuns = 30
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)

if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$prefix = $Target.ToLower()
$runPattern = "^${prefix}_\d{8}_\d{6}$"
$runDir = Join-Path $OutputDir ("{0}_{1}" -f $prefix, (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$log = Join-Path $runDir 'run.log'

function Write-Log {
    param([string]$Text)
    $line = "{0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Text
    [System.IO.File]::AppendAllText($log, $line + [Environment]::NewLine, $utf8)
    Write-Host $line
}

# Previous run of the same target, for new / resolved.
$previous = @(Get-ChildItem -LiteralPath $OutputDir -Directory |
    Where-Object { $_.Name -match $runPattern -and $_.FullName -ne $runDir -and (Test-Path -LiteralPath (Join-Path $_.FullName 'findings.csv')) } |
    Sort-Object Name -Descending | Select-Object -First 1)

Write-Log "IDWolf scheduled run, target $Target, folder $runDir"

# ---------------------------------------------------------------- collect
$snapFile = Join-Path $runDir 'snapshot.json'
$cp = @{ OutFile = $snapFile }
if ($Target -eq 'AD') {
    $collector = Join-Path $PSScriptRoot 'Collect-ADSnapshot.ps1'
    if ($Server) { $cp['Server'] = $Server }
    if ($Deep) { $cp['Deep'] = $true }
}
else {
    $collector = Join-Path $PSScriptRoot 'Collect-EntraSnapshot.ps1'
    # Nobody is there to sign in: only the app-only path works.
    if (-not ($TenantId -and $ClientId -and $CertificateThumbprint)) {
        Write-Log 'ERROR: Entra needs -TenantId, -ClientId and -CertificateThumbprint when unattended.'
        exit 1
    }
    $cp['TenantId'] = $TenantId; $cp['ClientId'] = $ClientId; $cp['CertificateThumbprint'] = $CertificateThumbprint
}
try { & $collector @cp *>&1 | ForEach-Object { Write-Log "  $_" } }
catch { Write-Log "ERROR: collection failed: $($_.Exception.Message)"; exit 1 }
if (-not (Test-Path -LiteralPath $snapFile)) { Write-Log 'ERROR: the collector wrote no snapshot.'; exit 1 }

# ---------------------------------------------------------------- analyze
$jsonl = Join-Path $runDir 'findings.jsonl'
$ip = @{
    Snapshot = $snapFile
    OutHtml  = (Join-Path $runDir 'report.html')
    OutCsv   = (Join-Path $runDir 'findings.csv')
    OutJson  = $jsonl
    SkipLLM  = $true
}
if ($previous.Count) { $ip['CompareTo'] = Join-Path $previous[0].FullName 'findings.csv'; Write-Log "Comparing with $($previous[0].Name)" }
if ($ExceptionsFile) { $ip['ExceptionsFile'] = $ExceptionsFile }
try { & (Join-Path $PSScriptRoot 'IDWolf.ps1') @ip *>&1 | ForEach-Object { Write-Log "  $_" } }
catch { Write-Log "ERROR: analysis failed: $($_.Exception.Message)"; exit 1 }
if (-not (Test-Path -LiteralPath $jsonl)) { Write-Log 'ERROR: the analyzer wrote no JSON Lines.'; exit 1 }

# ---------------------------------------------------------------- SIEM feed
if (-not $SiemFile) { $SiemFile = Join-Path $OutputDir 'idwolf.jsonl' }
[System.IO.File]::AppendAllText($SiemFile, [System.IO.File]::ReadAllText($jsonl), $utf8)
Write-Log "JSON Lines appended to $SiemFile"

# ---------------------------------------------------------------- retention
if ($KeepRuns -gt 0) {
    $old = @(Get-ChildItem -LiteralPath $OutputDir -Directory | Where-Object { $_.Name -match $runPattern } |
        Sort-Object Name -Descending | Select-Object -Skip $KeepRuns)
    foreach ($d in $old) { Remove-Item -LiteralPath $d.FullName -Recurse -Force; Write-Log "Removed old run $($d.Name)" }
}

Write-Log 'Done.'
exit 0
