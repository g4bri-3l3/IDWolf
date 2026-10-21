<#
.SYNOPSIS
    IDWolf: offline analyzer for Active Directory and Entra ID snapshots.

.DESCRIPTION
    Reads a snapshot from Collect-ADSnapshot.ps1 or Collect-EntraSnapshot.ps1
    and writes an HTML report, a findings CSV and, if asked, JSON Lines for a
    SIEM. No AD module, no Graph, no network: run it wherever you like.

    Ages are measured at snapshot time, not today, so the same snapshot always
    gives the same result.

    Needs the lib\ folder next to it. Checks live in lib\Checks.ps1,
    lib\ChecksHost.ps1 (GPO, password quality) and lib\ChecksEntra.ps1.

.PARAMETER Snapshot
    Snapshot JSON (AD or Entra, detected automatically), or a zip made by Start-IDWolf.ps1 (option 7) on the
    collecting machine. A zip may carry the password-quality report too; it's
    used unless -PasswordQualityFile says otherwise.
.PARAMETER OutHtml
    HTML report path (default output\report_<domain>_<timestamp>.html).
.PARAMETER OutCsv
    Findings CSV path (default: same base name as OutHtml).
.PARAMETER OutJson
    Optional JSON Lines export, one finding per line (Splunk: sourcetype _json).
.PARAMETER CompareTo
    Findings CSV from a previous run: adds a New / Resolved / Still present section.
.PARAMETER ExceptionsFile
    JSON file of accepted risks (see README). Matching findings move to the
    "Accepted risks" section; expired exceptions are ignored and listed.
.PARAMETER SkipLLM
    Never prompt for or send anything to Gemini. Deterministic report only.
.PARAMETER SendToAI
    Send to Gemini without the interactive confirmation (unattended runs).
    Pseudonymization and the leak check still apply. Whether or not it asks,
    the exact prompt is saved as <report>_ai_prompt.txt before sending and
    the reply as <report>_ai_response.json, both still pseudonymized.
.PARAMETER AiDryRun
    Path: write the exact pseudonymized prompt that would be sent, send
    nothing. Useful for a privacy review before enabling the AI step.
.PARAMETER ApiKey
    Gemini API key. Defaults to $env:GEMINI_API_KEY.
.PARAMETER Model
    Gemini model name. Defaults to gemini-3.8-flash.
.PARAMETER AiMaxAttempts
    How many times to try Gemini on a timeout or a busy server (429/5xx).
    Default 3; 0 keeps trying until it works (Ctrl+C to stop).
.PARAMETER KrbtgtMaxAgeDays
    krbtgt password age above which a finding is raised (default 180).
.PARAMETER KrbtgtCriticalDays
    krbtgt password age above which the finding becomes Critical (default 365).
.PARAMETER PrivInactiveDays
    Enabled privileged account without logon for more than this (default 90).
.PARAMETER InactiveDays
    Enabled standard user without logon for more than this (default 180).
.PARAMETER NeverLoggedOnGraceDays
    Never-used accounts younger than this are not flagged (default 90).
.PARAMETER StaleComputerDays
    Enabled computer without logon for more than this (default 90).
.PARAMETER PasswordMaxAgeDays
    Password age threshold for privileged and SPN accounts (default 365).
.PARAMETER MinPasswordLength
    Baseline minimum password length for domain policy and FGPP (default 12).
.PARAMETER MaxDomainAdmins
    Enabled effective Domain Admins above which a finding is raised (default 5).
.PARAMETER LapsOverdueDays
    LAPS expiration this many days in the past = not rotating (default 30).

.EXAMPLE
    .\IDWolf.ps1 -Snapshot .\adsnapshot_corp.local_20260928.json
.EXAMPLE
    .\IDWolf.ps1 -Snapshot .\snap.json -OutJson .\findings.jsonl -CompareTo .\report_prev.csv -ExceptionsFile .\exceptions.json
#>

[CmdletBinding()]
Param(
    [string]$Snapshot = "",
    [string]$OutHtml = "",
    [string]$OutCsv = "",
    [string]$OutJson = "",
    [string]$CompareTo = "",
    [string]$ExceptionsFile = "",
    [int]$KrbtgtMaxAgeDays = 180,
    [int]$KrbtgtCriticalDays = 365,
    [int]$PrivInactiveDays = 90,
    [int]$InactiveDays = 180,
    [int]$NeverLoggedOnGraceDays = 90,
    [int]$StaleComputerDays = 90,
    [int]$PasswordMaxAgeDays = 365,
    [int]$MinPasswordLength = 12,
    [int]$MaxDomainAdmins = 5,
    [int]$LapsOverdueDays = 30,
    [int]$BuiltinAdminRecentDays = 30,
    [int]$DcPasswordMaxAgeDays = 90,
    [string]$PasswordQualityFile = "",
    [System.Security.SecureString]$BundlePassword = $null,
    [switch]$SkipLLM,
    [switch]$SendToAI,
    [string]$AiDryRun = "",
    [string]$ApiKey = $env:GEMINI_API_KEY,
    [string]$Model = "gemini-3.8-flash",
    [int]$AiMaxAttempts = 3
)

$ErrorActionPreference = 'Stop'
$script:IDWolfVersion = "1.6"

$libDir = Join-Path $PSScriptRoot 'lib'
foreach ($f in @('Common.ps1', 'Checks.ps1', 'ChecksHost.ps1', 'Reporting.ps1', 'Graph.ps1', 'AI.ps1', 'ChecksEntra.ps1', 'Compliance.ps1', 'Bundle.ps1', 'Wizard.ps1')) {
    $p = Join-Path $libDir $f
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing $p. Keep the lib\ folder next to IDWolf.ps1." }
    . $p
}

function Show-IDWolfBanner {
    $b = @'
######################################################################
#                      .
#                     / V\
#                   / `  /
#                  <<   |                I D W o l f
#                  /    |                AD / Entra hygiene
#                /      |
#              /        |
#            /    \  \ /
#           (      ) | |
#   ________|   _/_  | |
# <__________\______)\__)
#
#                https://github.com/g4bri-3l3/IDWolf
######################################################################
'@
    # Close the box on the right: pad every inner line to the border width.
    $b = (($b -split "`r?`n") | ForEach-Object { if ($_ -match '^#' -and $_ -notmatch '^#{10,}$') { $_.PadRight(69) + '#' } else { $_ } }) -join "`n"
    Write-Host $b -ForegroundColor DarkYellow
    Write-Host "  v$script:IDWolfVersion  offline analyzer (no AD module needed)" -ForegroundColor DarkYellow
}

# Read-Host with a default shown in brackets; empty input keeps the default.
function Read-Default {
    param([string]$Prompt, [string]$Default = "")
    $shown = if ($Default) { " [$Default]" } else { "" }
    $v = Read-Host "$Prompt$shown"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}
function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $d = if ($Default) { 'Y/n' } else { 'y/N' }
    $v = Read-Host "$Prompt ($d)"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return ($v -match '^[YySs]')
}

# Path prompt with Tab completion; plain Read-Host when input is redirected.
function Read-Path {
    param([string]$Prompt, [string]$Default = "")
    $label = "$Prompt" + $(if ($Default) { " [$Default]" } else { "" })
    $redirected = $true
    try { $redirected = [Console]::IsInputRedirected } catch { $redirected = $true }
    if ($redirected) {
        $v = Read-Host $label
        if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
        return $v.Trim()
    }
    Write-Host -NoNewline "${label}: "
    $buf = ''; $tabMatches = @(); $ti = 0
    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq 'Enter') { Write-Host ''; if ([string]::IsNullOrWhiteSpace($buf)) { return $Default } return $buf.Trim() }
        elseif ($key.Key -eq 'Backspace') { if ($buf.Length -gt 0) { $buf = $buf.Substring(0, $buf.Length - 1); Write-Host -NoNewline "`b `b" }; $tabMatches = @() }
        elseif ($key.Key -eq 'Tab') {
            if ($tabMatches.Count -eq 0) {
                $hasDir = $buf -match '[\\/]'
                $dir = if ($hasDir) { Split-Path $buf -Parent } else { '.' }
                $leaf = if ($buf) { Split-Path $buf -Leaf } else { '' }
                try {
                    $items = @(Get-ChildItem -LiteralPath $dir -Filter ($leaf + '*') -ErrorAction SilentlyContinue)
                    $tabMatches = @($items | ForEach-Object {
                            $n = if ($_.PSIsContainer) { $_.Name + [IO.Path]::DirectorySeparatorChar } else { $_.Name }
                            if ($hasDir) { (Join-Path $dir $n) } else { $n }
                        })
                }
                catch { $tabMatches = @() }
                $ti = 0
            }
            if ($tabMatches.Count -gt 0) {
                $comp = $tabMatches[$ti % $tabMatches.Count]; $ti++
                if ($buf.Length -gt 0) { Write-Host -NoNewline (("`b" * $buf.Length) + (" " * $buf.Length) + ("`b" * $buf.Length)) }
                $buf = $comp; Write-Host -NoNewline $buf
            }
        }
        elseif ($key.KeyChar -and -not [char]::IsControl($key.KeyChar)) { $buf += $key.KeyChar; Write-Host -NoNewline $key.KeyChar; $tabMatches = @() }
    }
}

# Last step of a run started from the wizard: remember the report (the next wizard offers to
# compare against it) and offer to open it. Runs with -Snapshot never get here with WizardMode set.
$script:WizardMode = $false
function Complete-WizardRun {
    param([string]$Html)
    if (-not $script:WizardMode) { return }
    if ($Html -and (Test-Path -LiteralPath $Html)) { Save-IDWolfState -Section analyzer -Values @{ LastReport = (Resolve-Path -LiteralPath $Html).ProviderPath } }
    [void](Request-OpenReport -Path $Html -Since $start)
    Stop-IDWolfLog $script:SessionLog; $script:SessionLog = ''
}
# The wizard's session log (lib\Wizard.ps1) is closed even when the analysis stops with an error.
$script:SessionLog = ''
trap { Stop-IDWolfLog $script:SessionLog; $script:SessionLog = ''; break }

# Guided setup when there's no -Snapshot: a few questions, then a short
# review menu before running.
function Invoke-AnalyzerSetup {
    Show-IDWolfBanner
    Write-Host ""
    Write-Host "Interactive setup. Press Enter to accept the [default]." -ForegroundColor Cyan
    # An elevated window starts in C:\Windows\System32: work from the IDWolf folder instead.
    if ($env:windir -and (Get-Location).Path.TrimEnd('\').StartsWith($env:windir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        Set-Location -LiteralPath $PSScriptRoot
        Write-Host "Working folder: $PSScriptRoot (started in the Windows folder, as an elevated window does)." -ForegroundColor DarkGray
    }
    # Choices and console output to output\idwolf_analysis_<ts>.log; started from the launcher,
    # everything already goes to the launcher's log.
    $script:SessionLog = Start-IDWolfLog 'idwolf_analysis'
    # The default paths below are under .\output.
    $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }

    # Choices of the last wizard run are the defaults (lib\Wizard.ps1); each answer is saved
    # as soon as it is given, so a Ctrl+C half way keeps what was already answered.
    $script:WizardMode = $true
    $wizState = Read-IDWolfState
    $mem = $wizState.analyzer
    $dflt = $wizState.defaults; $useDefaults = $false
    $remember = { param([string]$Key, $Value) Save-IDWolfState -Section analyzer -Values @{ $Key = $Value } }
    $lastCsv = ''
    if ($mem.LastReport) { $c = [System.IO.Path]::ChangeExtension($mem.LastReport, '.csv'); if (Test-Path -LiteralPath $c) { $lastCsv = $c } }

    # The snapshots found in this folder and in .\output.
    $candFiles = @(Get-ChildItem -Path '.', 'output' -Filter *.json -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)snapshot|adsnap|entra' })
    if ($candFiles.Count -eq 0) { $candFiles = @(Get-ChildItem -Path '.', 'output' -Filter *.json -File -ErrorAction SilentlyContinue) }
    $candFiles = @($candFiles) + @(Get-ChildItem -Path '.', 'output' -Filter *.zip -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)idwolf|snap|entra' })
    $candFiles = @($candFiles) + @(Get-ChildItem -Path '.', 'output' -Filter *.idwolf -File -ErrorAction SilentlyContinue)
    # Newest first: the one just collected is [1].
    $candFiles = @($candFiles | Sort-Object @{ Expression = 'LastWriteTimeUtc'; Descending = $true }, @{ Expression = 'FullName'; Descending = $false })
    $cands = @($candFiles | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })

    # The last analysis, if its snapshot is still there: same settings, straight to the review below.
    # A snapshot collected since then (option 3 of the launcher, say) is offered in its place.
    $snap = ""; $reuse = $false
    if ($mem.Snapshot -and (Test-Path -LiteralPath $mem.Snapshot)) {
        $lastFull = (Resolve-Path -LiteralPath $mem.Snapshot).ProviderPath
        $lastTime = [System.IO.File]::GetLastWriteTimeUtc($lastFull)
        # Only files named like a snapshot or a package: any other JSON here is not a candidate.
        $newer = @($candFiles | Where-Object { $_.Name -match '(?i)snapshot|adsnap|entra|idwolf' -and $_.FullName -ne $lastFull -and $_.LastWriteTimeUtc -gt $lastTime } | Sort-Object LastWriteTimeUtc, FullName -Descending | Select-Object -First 1)
        Write-Host "`nLast analysis: $($mem.Snapshot) (AI step: $(if ($mem.AiMode) { $mem.AiMode } else { 'skip' }))" -ForegroundColor Cyan
        if ($newer.Count -gt 0) {
            $newerRel = Resolve-Path -Relative -LiteralPath $newer[0].FullName
            Write-Host "A newer snapshot is here: $newerRel ($($newer[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm')))." -ForegroundColor Cyan
            if (Read-YesNo "Analyze $newerRel with the same settings?" $true) { $snap = $newerRel; $reuse = $true }
        }
        elseif (Read-YesNo "Same settings again?" $true) { $snap = $mem.Snapshot; $reuse = $true }
    }

    if (-not $snap) {
        $lastSnap = if ($mem.Snapshot -and (Test-Path -LiteralPath $mem.Snapshot)) { $mem.Snapshot } else { '' }
        if ($cands.Count -gt 0) {
            Write-Host "`nSnapshot files found here:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $cands.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $cands[$i]) }
            $pick = Read-Host ("Pick a number, or type a path (Tab completes)" + $(if ($lastSnap) { " [Enter = $lastSnap]" } else { '' }))
            if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $cands.Count) { $snap = $cands[[int]$pick - 1] }
            elseif ($pick) { $snap = $pick.Trim() }
            elseif ($lastSnap) { $snap = $lastSnap }
            else { $snap = Read-Path "Snapshot JSON or zip path" }
        }
        else { $snap = Read-Path "Snapshot JSON or zip path (from the collectors, or a zip from Start-IDWolf.ps1)" $lastSnap }
    }
    if (-not $snap -or -not (Test-Path -LiteralPath $snap)) { throw "Snapshot not found: $snap" }
    & $remember 'Snapshot' $snap

    # AD or Entra decides which questions make sense.
    $kind = 'ad'; $zipHasPq = $false; $snapDomain = ''
    try {
        if (Test-IDWolfBundleFile $snap) {
            if ((Test-IDWolfEncryptedBundle $snap) -and -not $BundlePassword) { $BundlePassword = Read-Host 'Bundle password (hidden)' -AsSecureString }
            $b = Expand-IDWolfBundle -Path $snap -Password $BundlePassword
            try { $peek = [System.IO.File]::ReadAllText($b.Snapshot) | ConvertFrom-Json; $zipHasPq = [bool]$b.PasswordQuality }
            finally { Remove-IDWolfBundle $b }
        }
        else { $peek = Get-Content -Raw -LiteralPath $snap | ConvertFrom-Json }
        if ("$($peek.meta.kind)" -eq 'entra') { $kind = 'entra' }
        $snapDomain = "$($peek.domain.dnsRoot)"
        $peek = $null
    }
    catch { }
    Write-Host ("Detected snapshot type: {0}" -f $(if ($kind -eq 'entra') { 'Microsoft Entra ID' } else { 'on-prem Active Directory' })) -ForegroundColor Green

    $defaultHtml = "output\report{0}_{1}.html" -f $(if ($kind -eq 'entra') { '_entra' } else { '' }), (Get-Date -Format 'yyyyMMdd_HHmmss')
    $cfg = [ordered]@{
        Snapshot            = $snap
        OutHtml             = $defaultHtml
        OutJson             = ""
        ExceptionsFile      = ""
        CompareTo           = ""
        PasswordQualityFile = ""
        AiMode              = 'skip'
    }
    $usePq = ($kind -eq 'ad' -and -not $zipHasPq)
    if ($kind -eq 'ad' -and $zipHasPq) { Write-Host "The zip carries a password-quality report: it will be used." -ForegroundColor Green }
    # Only reports of this snapshot's domain, newest first.
    $pqFound = @(if ($usePq) { Get-PasswordQualityCandidates -Domain $snapDomain })
    if ($reuse) {
        # Same choices; a comparison goes against the report of that last run, and a password-quality
        # report is the newest one of this snapshot's domain.
        $cfg.OutJson = "$($mem.OutJson)"
        $cfg.ExceptionsFile = "$($mem.ExceptionsFile)"
        $cfg.CompareTo = if ($mem.CompareTo -and $lastCsv) { $lastCsv } else { "$($mem.CompareTo)" }
        if ($usePq -and $mem.PasswordQualityFile) {
            if ($pqFound.Count -gt 0) { $cfg.PasswordQualityFile = $pqFound[0] }
            else { Write-Host "No password-quality report of $snapDomain here: running without one." -ForegroundColor Yellow }
        }
        if (@('skip', 'dryrun', 'send') -contains $mem.AiMode) { $cfg.AiMode = $mem.AiMode }
    }
    else {
        $cfg.OutHtml = Read-Path "HTML report path" $defaultHtml
        if (Read-YesNo "Also write JSON Lines for a SIEM (Splunk)?" ([bool]$mem.OutJson)) { $cfg.OutJson = Read-Path "  JSON Lines path" $(if ($mem.OutJson) { $mem.OutJson } else { "output\findings.jsonl" }) }
        & $remember 'OutJson' $cfg.OutJson
        if (Read-YesNo "Use an exceptions file (accepted risks)?" ([bool]$mem.ExceptionsFile)) { $cfg.ExceptionsFile = Read-Path "  Exceptions JSON path" $(if ($mem.ExceptionsFile) { $mem.ExceptionsFile } else { "exceptions.json" }) }
        & $remember 'ExceptionsFile' $cfg.ExceptionsFile
        $cmpDefault = if ($lastCsv) { $lastCsv } elseif ($mem.CompareTo) { $mem.CompareTo } else { "report_previous.csv" }
        $cmpPrompt = if ($lastCsv) { "Compare against the previous findings CSV ($lastCsv)?" } else { "Compare against a previous findings CSV?" }
        if (Read-YesNo $cmpPrompt ([bool]$mem.CompareTo)) { $cfg.CompareTo = Read-Path "  Previous report CSV path" $cmpDefault }
        & $remember 'CompareTo' $cfg.CompareTo
        if ($usePq) {
            # The newest report of this snapshot's domain becomes the default.
            $pqDefault = if ($pqFound.Count -gt 0) { $pqFound[0] } else { 'pwq.json' }
            $pqPrompt = if ($pqFound.Count -gt 0) { "Add the hashless password-quality report of $snapDomain ($pqDefault)?" } else { "Add a hashless password-quality report (from Export-PasswordQuality.ps1)?" }
            if (Read-YesNo $pqPrompt ($pqFound.Count -gt 0)) {
                $cfg.PasswordQualityFile = Read-Path "  Password-quality JSON path" $pqDefault
            }
            & $remember 'PasswordQualityFile' $cfg.PasswordQualityFile
        }
        # The launcher's default settings ([S]) carry an AI step: offered first. Taken, they are
        # not remembered as this wizard's answers.
        if ($dflt.Ai) {
            $dMode = switch ("$($dflt.Ai)") { 'A' { 'send' } 'D' { 'dryrun' } default { 'skip' } }
            $dDesc = switch ($dMode) { 'send' { "send to Gemini after you confirm ($(if ($dflt.Model) { $dflt.Model } else { $script:Model }))" } 'dryrun' { 'dry-run, write the prompt only' } default { 'skip' } }
            Write-Host "`nDefault settings: AI step $dDesc." -ForegroundColor Cyan
            if (Read-YesNo "Use the default settings?" $true) { $cfg.AiMode = $dMode; $useDefaults = $true }
        }
        if (-not $useDefaults) {
            $aiLetter = switch ("$($mem.AiMode)") { 'send' { 'G' } 'dryrun' { 'D' } default { 'S' } }
            Write-Host "`nAI step (Gemini): [S]kip, [D]ry-run (write prompt, send nothing), [G] send (you see the prompt and confirm first)" -ForegroundColor Cyan
            $aiPick = Read-Host "Choice [$aiLetter]"
            if ([string]::IsNullOrWhiteSpace($aiPick)) { $aiPick = $aiLetter }
            switch ($aiPick.Trim().ToUpper()) {
                'G' { $cfg.AiMode = 'send' }
                'D' { $cfg.AiMode = 'dryrun' }
                default { $cfg.AiMode = 'skip' }
            }
            & $remember 'AiMode' $cfg.AiMode
        }
    }
    $cfg.Model = if ($mem.Model) { $mem.Model } else { $script:Model }
    $cfg.AiAttempts = if ($mem.AiAttempts -match '^\d+$') { $mem.AiAttempts } else { "$script:AiMaxAttempts" }
    if ($useDefaults) {
        if ($dflt.Model) { $cfg.Model = "$($dflt.Model)" }
        if ($dflt.AiAttempts -match '^\d+$') { $cfg.AiAttempts = "$($dflt.AiAttempts)" }
    }
    # Model, key and attempts for the AI step: asked after the AI choice, and again when the review
    # below switches AiMode to send. Ask = $false (same settings as last time) takes them as they are.
    $askAi = {
        param([bool]$Ask)
        if ($cfg.AiMode -eq 'skip') { return }
        if ($Ask) { $cfg.Model = Read-Default "Gemini model" $cfg.Model; & $remember 'Model' $cfg.Model }
        # The key is never remembered: asked again on every run that sends.
        if ($cfg.AiMode -eq 'send' -and -not $script:ApiKey) {
            # Hidden, so the key is neither on screen nor in the session log.
            # Piped input can't be read hidden (Read-Host -AsSecureString would wait for a console).
            $redirected = $true; try { $redirected = [Console]::IsInputRedirected } catch { }
            if ($redirected) { $k = "$(Read-Host "GEMINI_API_KEY not set. Paste key now, or Enter to switch to dry-run")".Trim() }
            else {
                $sk = Read-Host "GEMINI_API_KEY not set. Paste key now (hidden), or Enter to switch to dry-run" -AsSecureString
                $k = if ($sk -and $sk.Length) { (New-Object System.Net.NetworkCredential('', $sk)).Password.Trim() } else { '' }
            }
            if ($k) { $script:ApiKey = $k } else { $cfg.AiMode = 'dryrun' }
        }
        if ($cfg.AiMode -eq 'send' -and $Ask) {
            $a = Read-Default "Gemini attempts on timeout / busy server (0 = keep trying)" $cfg.AiAttempts
            $cfg.AiAttempts = if ("$a" -match '^\d+$') { "$a" } else { "$script:AiMaxAttempts" }
            & $remember 'AiAttempts' $cfg.AiAttempts
        }
    }
    & $askAi (-not $reuse -and -not $useDefaults)

    # Last look before running.
    while ($true) {
        Write-Host "`nSettings:" -ForegroundColor Cyan
        # Model only with an AI step, attempts only when sending.
        $keys = @($cfg.Keys | Where-Object { -not (($_ -eq 'Model' -and $cfg.AiMode -eq 'skip') -or ($_ -eq 'AiAttempts' -and $cfg.AiMode -ne 'send')) })
        for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host ("  [{0}] {1,-20} {2}" -f ($i + 1), $keys[$i], $(if ($cfg[$keys[$i]]) { $cfg[$keys[$i]] } else { '(none)' })) }
        $edit = Read-Host "Enter a number to change, or press Enter to run"
        if ([string]::IsNullOrWhiteSpace($edit)) { break }
        if ($edit -match '^\d+$' -and [int]$edit -ge 1 -and [int]$edit -le $keys.Count) {
            $k = $keys[[int]$edit - 1]
            if ($k -eq 'AiMode') {
                $was = $cfg.AiMode
                $v = "$(Read-Default "  AiMode (skip/dryrun/send)" $cfg[$k])".Trim().ToLower()
                if (@('skip', 'dryrun', 'send') -notcontains $v) { Write-Host "  Use skip, dryrun or send." -ForegroundColor Yellow; continue }
                $cfg.AiMode = $v
                # Switching the AI step on: its model, key and attempts are asked now.
                if ($v -ne $was -and $v -ne 'skip') { & $askAi $true }
            }
            elseif ($k -eq 'AiAttempts') { $a = Read-Default "  AiAttempts (0 = keep trying)" $cfg[$k]; if ("$a" -match '^\d+$') { $cfg[$k] = "$a" } else { Write-Host "  A number, please." -ForegroundColor Yellow } }
            else { $cfg[$k] = Read-Default "  $k" $cfg[$k] }
        }
    }
    # What runs is what the next wizard offers, edits in the review included. The output path is
    # not kept (each run gets a new one); an Entra run leaves the password-quality default alone.
    # An AI step from the default settings stays theirs: this wizard's own answers are left as they were.
    $keep = @{}
    $keepKeys = @('Snapshot', 'OutJson', 'ExceptionsFile', 'CompareTo') + $(if (-not $useDefaults) { @('AiMode', 'Model', 'AiAttempts') })
    foreach ($k in $keepKeys) { if ($cfg.Contains($k)) { $keep[$k] = "$($cfg[$k])" } }
    if ($usePq) { $keep['PasswordQualityFile'] = "$($cfg.PasswordQualityFile)" }
    Save-IDWolfState -Section analyzer -Values $keep

    # Back into the script parameters.
    $script:Snapshot = $cfg.Snapshot
    $script:OutHtml = $cfg.OutHtml
    $script:OutJson = $cfg.OutJson
    $script:ExceptionsFile = $cfg.ExceptionsFile
    $script:CompareTo = $cfg.CompareTo
    $script:PasswordQualityFile = $cfg.PasswordQualityFile
    if ($cfg.Model) { $script:Model = $cfg.Model }
    if ($cfg.Contains('AiAttempts') -and "$($cfg.AiAttempts)" -match '^\d+$') { $script:AiMaxAttempts = [int]$cfg.AiAttempts }
    switch ($cfg.AiMode) {
        # Not -SendToAI: after the report the analyzer writes the prompt file, shows its path
        # and asks before sending, so the text can be checked first.
        'send' { }
        'dryrun' { $script:AiDryRun = Read-Path "Dry-run output file" "output\ai_prompt.txt" }
        default { $script:SkipLLM = $true }
    }
    Write-Host ""
}

if (-not $Snapshot) {
    if ([Environment]::UserInteractive) { Invoke-AnalyzerSetup }
    else { throw "No -Snapshot given and no interactive console. Pass -Snapshot <file>." }
}

$rule = '#' * 70
Write-Host $rule -ForegroundColor DarkYellow
# Padded so the closing # lines up whatever the version string.
Write-Host (("#  IDWolf v$script:IDWolfVersion    Active Directory Hygiene Analyzer (offline)").PadRight(69) + '#') -ForegroundColor DarkYellow
Write-Host $rule -ForegroundColor DarkYellow

$start = Get-Date
# A zip from another machine: read what's inside, then delete the extracted copy.
$bundlePqText = $null
if ($Snapshot -and (Test-IDWolfBundleFile $Snapshot)) {
    if ((Test-IDWolfEncryptedBundle $Snapshot) -and -not $BundlePassword) {
        # Non-interactive runs must pass -BundlePassword (a SecureString); never a plain string.
        $BundlePassword = Read-Host "Password for the encrypted bundle $([System.IO.Path]::GetFileName($Snapshot)) (hidden)" -AsSecureString
    }
    $bundle = Expand-IDWolfBundle -Path $Snapshot -Password $BundlePassword
    try {
        $snap = Import-ADSnapshot -Path $bundle.Snapshot
        if ($bundle.PasswordQuality) { $bundlePqText = [System.IO.File]::ReadAllText($bundle.PasswordQuality) }
    }
    finally { Remove-IDWolfBundle $bundle }
    Write-Host "Bundle $Snapshot$(if ($bundle.Manifest) { ", hashes verified" })$(if ($bundlePqText) { ', password quality included' })."
}
else { $snap = Import-ADSnapshot -Path $Snapshot }
$script:RefDate = ConvertTo-UtcDate $snap.meta.collectedAtUtc
if ($null -eq $script:RefDate) { throw "Snapshot has no valid meta.collectedAtUtc." }

# ==========================================================================
# Entra snapshots take their own, shorter path.
# ==========================================================================
if ("$($snap.meta.kind)" -eq 'entra') {
    $entraConfig = @{ MaxGlobalAdmins = 4; StaleGuestDays = 90; SecretExpiringDays = 30; MaxStandingAdmins = 2; MaxSecretLifetimeDays = 180; AdminInactiveDays = 90; MaxDevicesPerUser = 10 }
    Write-Host "Entra tenant: $(if ($snap.org) { $snap.org.displayName } else { $snap.meta.tenantId })  snapshot: $($script:RefDate.ToString('yyyy-MM-dd HH:mm')) UTC"
    $eFindings = @(Invoke-EntraChecks -Snapshot $snap -Config $entraConfig)
    $eNotEval = @(Get-EntraNotEvaluated -Snapshot $snap)
    $eExceptions = Import-Exceptions -Path $ExceptionsFile
    $eSplit = Split-FindingsByException -Findings $eFindings -Exceptions $eExceptions
    $eActive = @($eSplit.Active)
    $eScore = Get-HygieneScore -Findings $eActive -NotEvaluated $eNotEval.Count -Total $script:EntraCheckCatalog.Count

    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not $OutHtml) {
        $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }
        $OutHtml = Join-Path $od ("report_entra_{0}_{1}.html" -f $(if ($snap.org) { ($snap.org.displayName -replace '[^\w\-]', '_') } else { $snap.meta.tenantId }), $ts)
    }
    if (-not $OutCsv) { $OutCsv = [System.IO.Path]::ChangeExtension($OutHtml, '.csv') }
    $elapsedText = "{0:N1}s" -f ((Get-Date) - $start).TotalSeconds
    $htmlFull = if ([System.IO.Path]::IsPathRooted($OutHtml)) { $OutHtml } else { Join-Path (Get-Location).Path $OutHtml }

    $eAi = $null
    if (-not $SkipLLM -and $eActive.Count -gt 0) {
        $pz = New-EntraPseudonymizer -Snapshot $snap
        $prompt = New-EntraAiPrompt -Findings $eActive -Pz $pz -Snapshot $snap -Score $eScore -NotEvaluated $eNotEval
        $leaks = @(Test-EntraLeak -Pz $pz -Text $prompt)
        if ($leaks.Count -gt 0) { Write-Host "AI step aborted: identifiers still present after pseudonymization: $($leaks -join ', '). Nothing sent." -ForegroundColor Red }
        elseif ($AiDryRun) {
            Write-AiPromptFile -Path $AiDryRun -UserPrompt $prompt
            Write-Host "AI dry run: prompt written to $AiDryRun ($($pz.Reverse.Count) identifiers pseudonymized). Nothing sent." -ForegroundColor Cyan
        }
        else {
            $promptFile = Get-AiSidecarPath $htmlFull '_ai_prompt.txt'
            Write-AiPromptFile -Path $promptFile -UserPrompt $prompt
            $go = $SendToAI
            if (-not $go) {
                Write-Host "Exactly what would be sent to Gemini: $promptFile" -ForegroundColor Cyan
                Write-Host "The file is self-contained: to use another model instead, paste it whole into that model's chat; the answer is the same JSON."
                $go = ((Read-Host "Open that file if you want, then: send $($eActive.Count) findings to Gemini (identifiers pseudonymized)? (y/N)") -match '^[Yy]')
            }
            else { Write-Host "AI prompt kept at $promptFile" }
            if ($go -and -not $ApiKey) { $ApiKey = Request-GeminiApiKey }
            if ($go -and $ApiKey) {
                $aiSw = [System.Diagnostics.Stopwatch]::StartNew()
                $call = Invoke-AiAnalysisWithFallback -UserPrompt $prompt -ApiKey $ApiKey -Model $Model -MaxAttempts $AiMaxAttempts -ReportPath $htmlFull
                $aiSw.Stop()
                $raw = $call.Raw
                if ($raw) {
                    $responseFile = Get-AiSidecarPath $htmlFull '_ai_response.json'
                    Write-AiResponseFile -Path $responseFile -Raw $raw
                    Write-Host "Gemini reply (still pseudonymized) kept at $responseFile"
                    $eAi = ConvertFrom-AiResponse -Raw $raw -Pz $pz -Findings $eActive -Model $Model -Variant $call.Variant
                    $eAi | Add-Member -NotePropertyName AiElapsedText -NotePropertyValue ("{0:N1}s" -f $aiSw.Elapsed.TotalSeconds) -Force
                }
            }
            elseif ($go) { Write-Host 'No API key given (-ApiKey / GEMINI_API_KEY), nothing sent; skipping AI.' -ForegroundColor Yellow }
        }
    }

    $html = ConvertTo-EntraReportHtml -Snapshot $snap -Findings $eActive -Score $eScore -NotEvaluated $eNotEval -ToolVersion $script:IDWolfVersion -ElapsedText $elapsedText -AiResult $eAi
    [System.IO.File]::WriteAllText($htmlFull, $html, (New-Object System.Text.UTF8Encoding($false)))
    Export-FindingsCsv -Findings $eActive -Path $OutCsv
    if ($OutJson) {
        # The report has no comparison section for Entra yet; the SIEM feed does.
        $eComparison = if ($CompareTo) { Get-FindingsComparison -Findings $eActive -PreviousCsv $CompareTo } else { $null }
        Export-FindingsJsonl -Findings $eActive -Snapshot $snap -Path $OutJson -ToolVersion $script:IDWolfVersion `
            -Score $eScore -Comparison $eComparison -NotEvaluated $eNotEval -AcceptedCount @($eSplit.Accepted).Count
    }

    Write-Host "Entra report written to $OutHtml" -ForegroundColor Green
    $sevs = @('Critical', 'High', 'Medium', 'Low') | ForEach-Object { $s = $_; "{0}: {1}" -f $s, @($eActive | Where-Object { $_.Severity -eq $s }).Count }
    if ($eScore.Reliable) { Write-Host ("Findings: {0} ({1})  score: {2}/100 (grade {3})" -f $eActive.Count, ($sevs -join ', '), $eScore.Score, $eScore.Grade) }
    else { Write-Host ("Findings: {0} ({1})  score: n/a, only {2}% of the checks could be evaluated" -f $eActive.Count, ($sevs -join ', '), $eScore.Coverage) -ForegroundColor Yellow }
    if ($eNotEval.Count -gt 0) { Write-Host "$($eNotEval.Count) check(s) not evaluated (collection gaps): see report." -ForegroundColor Yellow }
    Complete-WizardRun $htmlFull
    return
}

$config = @{
    KrbtgtMaxAgeDays       = $KrbtgtMaxAgeDays
    KrbtgtCriticalDays     = $KrbtgtCriticalDays
    PrivInactiveDays       = $PrivInactiveDays
    InactiveDays           = $InactiveDays
    NeverLoggedOnGraceDays = $NeverLoggedOnGraceDays
    StaleComputerDays      = $StaleComputerDays
    PasswordMaxAgeDays     = $PasswordMaxAgeDays
    MinPasswordLength      = $MinPasswordLength
    MaxDomainAdmins        = $MaxDomainAdmins
    LapsOverdueDays        = $LapsOverdueDays
    BuiltinAdminRecentDays = $BuiltinAdminRecentDays
    DcPasswordMaxAgeDays   = $DcPasswordMaxAgeDays
}

Write-Host "Domain: $($snap.domain.dnsRoot)  snapshot: $($script:RefDate.ToString('yyyy-MM-dd HH:mm')) UTC"
# Optional password-quality report, hooked onto the snapshot so its checks run.
$pqText = $null
if ($PasswordQualityFile) {
    if (-not (Test-Path -LiteralPath $PasswordQualityFile)) { throw "Password-quality file not found: $PasswordQualityFile" }
    $pqText = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $PasswordQualityFile).Path)
}
elseif ($bundlePqText) { $pqText = $bundlePqText }
if ($pqText) {
    # Old PS 5.1 reports hold {} for empty lists: read them as null.
    $pqRaw = [regex]::Replace($pqText, '(?<=[^\\]"):\s*\{\s*\}', ': null') | ConvertFrom-Json
    # A report of another domain would put its accounts in this report. 'domain' is what
    # Export-PasswordQuality.ps1 writes when it could not tell (-FromDatabase on a machine that
    # can't reach the domain): allowed, with a warning.
    $pqDomain = "$($pqRaw.domain)"; $snapDomain = "$($snap.domain.dnsRoot)"
    if ($pqDomain -and $pqDomain -ne 'domain' -and $snapDomain -and $pqDomain -ne $snapDomain) {
        throw "The password-quality report is for $pqDomain, the snapshot for $snapDomain. Use the report of $snapDomain, or run without one."
    }
    if (-not $pqDomain -or $pqDomain -eq 'domain') { Write-Warning "The password-quality report does not say its domain: make sure it is the one of $snapDomain." }
    $snap | Add-Member -NotePropertyName passwordQuality -NotePropertyValue $pqRaw -Force
    Write-Host "Password-quality report loaded (hashless)."
}
$index = New-SnapshotIndex -Snapshot $snap
$privMap = Get-PrivilegedMap -Index $index
$findings = @(Invoke-ADHygieneChecks -Snapshot $snap -Index $index -PrivMap $privMap -Config $config)
$notEvaluated = @(Get-NotEvaluatedChecks -Index $index -Snapshot $snap)
$exceptions = Import-Exceptions -Path $ExceptionsFile
$split = Split-FindingsByException -Findings $findings -Exceptions $exceptions
$active = @($split.Active)
$score = Get-HygieneScore -Findings $active -NotEvaluated $notEvaluated.Count -Total $script:CheckCatalog.Count

$comparison = $null
if ($CompareTo) { $comparison = Get-FindingsComparison -Findings $active -PreviousCsv $CompareTo }

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutHtml) {
    # Unnamed reports go to .\output, not next to everything else.
    $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }
    $OutHtml = Join-Path $od ("report_{0}_{1}.html" -f $snap.domain.dnsRoot, $ts)
}
if (-not $OutCsv) { $OutCsv = [System.IO.Path]::ChangeExtension($OutHtml, '.csv') }

$elapsed = (Get-Date) - $start
$elapsedText = "{0:N1}s" -f $elapsed.TotalSeconds

$html = ConvertTo-ReportHtml -Snapshot $snap -Index $index -PrivMap $privMap -Split $split -Score $score `
    -NotEvaluated $notEvaluated -Comparison $comparison -Config $config -ToolVersion $script:IDWolfVersion -ElapsedText $elapsedText
$htmlFull = if ([System.IO.Path]::IsPathRooted($OutHtml)) { $OutHtml } else { Join-Path (Get-Location).Path $OutHtml }
[System.IO.File]::WriteAllText($htmlFull, $html, (New-Object System.Text.UTF8Encoding($false)))
Export-FindingsCsv -Findings $active -Path $OutCsv
if ($OutJson) {
    Export-FindingsJsonl -Findings $active -Snapshot $snap -Path $OutJson -ToolVersion $script:IDWolfVersion `
        -Score $score -Comparison $comparison -NotEvaluated $notEvaluated -AcceptedCount @($split.Accepted).Count
}

Write-Host "Report written to $OutHtml" -ForegroundColor Green
Write-Host "Findings CSV: $OutCsv"
if ($OutJson) { Write-Host "JSON Lines: $OutJson" }
$sevs = @('Critical', 'High', 'Medium', 'Low') | ForEach-Object { $s = $_; "{0}: {1}" -f $s, @($active | Where-Object { $_.Severity -eq $s }).Count }
Write-Host ("Findings: {0} ({1})  accepted: {2}" -f $active.Count, ($sevs -join ', '), @($split.Accepted).Count)
if ($score.Reliable) { Write-Host ("Hygiene score: {0}/100 (grade {1})  Tier 0 principals: {2}" -f $score.Score, $score.Grade, $privMap.Principals.Count) }
else { Write-Host ("Hygiene score: n/a, only {0}% of the checks could be evaluated  Tier 0 principals: {1}" -f $score.Coverage, $privMap.Principals.Count) -ForegroundColor Yellow }
if ($notEvaluated.Count -gt 0) { Write-Host "$($notEvaluated.Count) check(s) not evaluated because of collection gaps: see report." -ForegroundColor Yellow }
Write-Host "Processing time: $elapsedText"

# --------------------------------------------------------------------------
# Optional AI step. The report is already on disk by now.
# --------------------------------------------------------------------------
# A function, so that each early return (skipped, declined, no key, failed) still reaches the
# end-of-run step below.
function Invoke-AdAiStep {
    if ($SkipLLM) { return }
    if ($active.Count -eq 0) { Write-Host 'No findings: AI step skipped (nothing to ground a summary on).'; return }

    $pz = New-Pseudonymizer -Snapshot $snap -Index $index
    $userPrompt = New-AiPrompt -Findings $active -Pz $pz -Snapshot $snap -Score $score -Comparison $comparison -NotEvaluated $notEvaluated
    $leaks = @(Test-AiLeak -Pz $pz -Text $userPrompt)
    if ($leaks.Count -gt 0) {
        Write-Host "AI step aborted: identifiers still present after pseudonymization: $($leaks -join ', '). Nothing was sent. Please report this as a bug." -ForegroundColor Red
        return
    }

    if ($AiDryRun) {
        Write-AiPromptFile -Path $AiDryRun -UserPrompt $userPrompt
        Write-Host "AI dry run: prompt written to $AiDryRun ($($userPrompt.Length) chars, $($pz.Reverse.Count) identifiers pseudonymized). Nothing sent." -ForegroundColor Cyan
        return
    }

    # Written before asking, so it can be read before saying yes.
    $promptFile = Get-AiSidecarPath $htmlFull '_ai_prompt.txt'
    Write-AiPromptFile -Path $promptFile -UserPrompt $userPrompt
    if (-not $SendToAI) {
        Write-Host ''
        Write-Host "Optional AI step (Gemini, model $Model):" -ForegroundColor Cyan
        Write-Host "  Sent: $($active.Count) findings grouped by check (max 12 objects per check), score, counts, the checks not evaluated, comparison if any."
        Write-Host "  Pseudonymized: $($pz.Reverse.Count) identifiers (accounts, hosts, groups, DNs, SIDs, domain/trust names, paths). The map never leaves this machine."
        Write-Host "  Not sent: the snapshot, ACL dumps, descriptions, group memberships beyond what the finding text states."
        Write-Host "  Exactly what would be sent: $promptFile" -ForegroundColor Cyan
        Write-Host "  The file is self-contained: to use another model instead, paste it whole into that model's chat; the answer is the same JSON."
        $answer = Read-Host 'Open that file if you want, then: send to Gemini for an executive summary and remediation plan? (y/N)'
        if ($answer -notmatch '^[Yy]') { Write-Host "Nothing sent. Deterministic report saved to $OutHtml."; return }
    }
    else { Write-Host "AI prompt kept at $promptFile" }
    if (-not $ApiKey) { $ApiKey = Request-GeminiApiKey }
    if (-not $ApiKey) { Write-Host 'No API key given (-ApiKey or GEMINI_API_KEY), nothing sent. Deterministic report kept as is.' -ForegroundColor Yellow; return }

    # Total Gemini wall time, retries and defensive fallback included: shown in the report header.
    $aiSw = [System.Diagnostics.Stopwatch]::StartNew()
    $call = Invoke-AiAnalysisWithFallback -UserPrompt $userPrompt -ApiKey $ApiKey -Model $Model -MaxAttempts $AiMaxAttempts -ReportPath $htmlFull
    $aiSw.Stop()
    $raw = $call.Raw
    if (-not $raw) { Write-Host "AI step failed; deterministic report kept at $OutHtml." -ForegroundColor Yellow; return }
    $responseFile = Get-AiSidecarPath $htmlFull '_ai_response.json'
    Write-AiResponseFile -Path $responseFile -Raw $raw
    Write-Host "Gemini reply (still pseudonymized) kept at $responseFile"
    $aiResult = ConvertFrom-AiResponse -Raw $raw -Pz $pz -Findings $active -Model $Model -Variant $call.Variant
    $aiResult | Add-Member -NotePropertyName AiElapsedText -NotePropertyValue ("{0:N1}s" -f $aiSw.Elapsed.TotalSeconds) -Force

    $html = ConvertTo-ReportHtml -Snapshot $snap -Index $index -PrivMap $privMap -Split $split -Score $score `
        -NotEvaluated $notEvaluated -Comparison $comparison -Config $config -ToolVersion $script:IDWolfVersion -ElapsedText $elapsedText -AiResult $aiResult
    [System.IO.File]::WriteAllText($htmlFull, $html, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "AI section added to $OutHtml ($(@($aiResult.RemediationPlan).Count) remediation items)." -ForegroundColor Green
}
Invoke-AdAiStep
Complete-WizardRun $htmlFull
