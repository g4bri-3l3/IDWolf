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
$script:IDWolfVersion = "1.3"

$libDir = Join-Path $PSScriptRoot 'lib'
foreach ($f in @('Common.ps1', 'Checks.ps1', 'ChecksHost.ps1', 'Reporting.ps1', 'Graph.ps1', 'AI.ps1', 'ChecksEntra.ps1', 'Compliance.ps1', 'Bundle.ps1')) {
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

# Guided setup when there's no -Snapshot: a few questions, then a short
# review menu before running.
function Invoke-AnalyzerSetup {
    Show-IDWolfBanner
    Write-Host ""
    Write-Host "Interactive setup. Press Enter to accept the [default]." -ForegroundColor Cyan
    # The default paths below are under .\output.
    $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }

    # Offer the snapshots found in this folder and in .\output.
    $cands = @(Get-ChildItem -Path '.', 'output' -Filter *.json -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)snapshot|adsnap|entra' } | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
    if ($cands.Count -eq 0) { $cands = @(Get-ChildItem -Path '.', 'output' -Filter *.json -ErrorAction SilentlyContinue | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName }) }
    $cands = @($cands) + @(Get-ChildItem -Path '.', 'output' -Filter *.zip -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)idwolf|snap|entra' } | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
    $cands = @($cands) + @(Get-ChildItem -Path '.', 'output' -Filter *.idwolf -ErrorAction SilentlyContinue | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
    $snap = ""
    if ($cands.Count -gt 0) {
        Write-Host "`nSnapshot files found here:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $cands.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $cands[$i]) }
        $pick = Read-Host "Pick a number, or type a path (Tab completes)"
        if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $cands.Count) { $snap = $cands[[int]$pick - 1] }
        elseif ($pick) { $snap = $pick }
        else { $snap = Read-Path "Snapshot JSON or zip path" }
    }
    else { $snap = Read-Path "Snapshot JSON or zip path (from the collectors, or a zip from Start-IDWolf.ps1)" }
    if (-not $snap -or -not (Test-Path -LiteralPath $snap)) { throw "Snapshot not found: $snap" }

    # AD or Entra decides which questions make sense.
    $kind = 'ad'; $zipHasPq = $false
    try {
        if (Test-IDWolfBundleFile $snap) {
            if ((Test-IDWolfEncryptedBundle $snap) -and -not $BundlePassword) { $BundlePassword = Read-Host 'Bundle password (hidden)' -AsSecureString }
            $b = Expand-IDWolfBundle -Path $snap -Password $BundlePassword
            try { $peek = ([System.IO.File]::ReadAllText($b.Snapshot) | ConvertFrom-Json).meta; $zipHasPq = [bool]$b.PasswordQuality }
            finally { Remove-IDWolfBundle $b }
        }
        else { $peek = (Get-Content -Raw -LiteralPath $snap | ConvertFrom-Json).meta }
        if ("$($peek.kind)" -eq 'entra') { $kind = 'entra' }
    }
    catch { }
    Write-Host ("Detected snapshot type: {0}" -f $(if ($kind -eq 'entra') { 'Microsoft Entra ID' } else { 'on-prem Active Directory' })) -ForegroundColor Green

    $cfg = [ordered]@{
        Snapshot            = $snap
        OutHtml             = (Read-Path "HTML report path" ("output\report{0}_{1}.html" -f $(if ($kind -eq 'entra') { '_entra' } else { '' }), (Get-Date -Format 'yyyyMMdd_HHmmss')))
        OutJson             = ""
        ExceptionsFile      = ""
        CompareTo           = ""
        PasswordQualityFile = ""
        AiMode              = 'skip'
    }
    if (Read-YesNo "Also write JSON Lines for a SIEM (Splunk)?" $false) { $cfg.OutJson = Read-Path "  JSON Lines path" "output\findings.jsonl" }
    if (Read-YesNo "Use an exceptions file (accepted risks)?" $false) { $cfg.ExceptionsFile = Read-Path "  Exceptions JSON path" "exceptions.json" }
    if (Read-YesNo "Compare against a previous findings CSV?" $false) { $cfg.CompareTo = Read-Path "  Previous report CSV path" "report_previous.csv" }
    if ($kind -eq 'ad' -and $zipHasPq) { Write-Host "The zip carries a password-quality report: it will be used." -ForegroundColor Green }
    elseif ($kind -eq 'ad') {
        # A password-quality report in the folder becomes the default.
        $pqFound = @(Get-ChildItem -Path '.', 'output' -Filter '*.json' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)pwq|passwordquality' } | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
        $pqDefault = if ($pqFound.Count -gt 0) { $pqFound[0] } else { 'pwq.json' }
        $pqPrompt = if ($pqFound.Count -gt 0) { "Add the hashless password-quality report ($($pqFound[0]) found)?" } else { "Add a hashless password-quality report (from Export-PasswordQuality.ps1)?" }
        if (Read-YesNo $pqPrompt ($pqFound.Count -gt 0)) {
            $cfg.PasswordQualityFile = Read-Path "  Password-quality JSON path" $pqDefault
        }
    }
    Write-Host "`nAI step (Gemini): [S]kip, [D]ry-run (write prompt, send nothing), [G] send (you see the prompt and confirm first)" -ForegroundColor Cyan
    switch ((Read-Host "Choice [S]").ToUpper()) {
        'G' { $cfg.AiMode = 'send' }
        'D' { $cfg.AiMode = 'dryrun' }
        default { $cfg.AiMode = 'skip' }
    }
    $cfg.Model = $script:Model
    if ($cfg.AiMode -ne 'skip') {
        $cfg.Model = Read-Default "Gemini model" $script:Model
        if ($cfg.AiMode -eq 'send' -and -not $script:ApiKey) {
            $k = Read-Host "GEMINI_API_KEY not set. Paste key now, or Enter to switch to dry-run"
            if ($k) { $script:ApiKey = $k.Trim() } else { $cfg.AiMode = 'dryrun' }
        }
        if ($cfg.AiMode -eq 'send') {
            $cfg.AiAttempts = Read-Default "Gemini attempts on timeout / busy server (0 = keep trying)" "$script:AiMaxAttempts"
        }
    }

    # Last look before running.
    while ($true) {
        Write-Host "`nSettings:" -ForegroundColor Cyan
        $keys = @($cfg.Keys)
        for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host ("  [{0}] {1,-20} {2}" -f ($i + 1), $keys[$i], $(if ($cfg[$keys[$i]]) { $cfg[$keys[$i]] } else { '(none)' })) }
        $edit = Read-Host "Enter a number to change, or press Enter to run"
        if ([string]::IsNullOrWhiteSpace($edit)) { break }
        if ($edit -match '^\d+$' -and [int]$edit -ge 1 -and [int]$edit -le $keys.Count) {
            $k = $keys[[int]$edit - 1]
            if ($k -eq 'AiMode') { $cfg[$k] = Read-Default "  AiMode (skip/dryrun/send)" $cfg[$k] }
            else { $cfg[$k] = Read-Default "  $k" $cfg[$k] }
        }
    }

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
        $prompt = New-EntraAiPrompt -Findings $eActive -Pz $pz -Snapshot $snap -Score $eScore
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
                $go = ((Read-Host "Open that file if you want, then: send $($eActive.Count) findings to Gemini (identifiers pseudonymized)? (y/N)") -match '^[Yy]')
            }
            else { Write-Host "AI prompt kept at $promptFile" }
            if ($go -and -not $ApiKey) { $ApiKey = Request-GeminiApiKey }
            if ($go -and $ApiKey) {
                $raw = Invoke-GeminiAnalysis -UserPrompt $prompt -ApiKey $ApiKey -Model $Model -MaxAttempts $AiMaxAttempts
                if ($raw) {
                    $responseFile = Get-AiSidecarPath $htmlFull '_ai_response.json'
                    Write-AiResponseFile -Path $responseFile -Raw $raw
                    Write-Host "Gemini reply (still pseudonymized) kept at $responseFile"
                    $eAi = ConvertFrom-AiResponse -Raw $raw -Pz $pz -Findings $eActive -Model $Model
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
if ($SkipLLM) { return }
if ($active.Count -eq 0) { Write-Host 'No findings: AI step skipped (nothing to ground a summary on).'; return }

$pz = New-Pseudonymizer -Snapshot $snap -Index $index
$userPrompt = New-AiPrompt -Findings $active -Pz $pz -Snapshot $snap -Score $score -Comparison $comparison
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
    Write-Host "  Sent: $($active.Count) findings grouped by check (max 12 objects per check), score, counts, comparison if any."
    Write-Host "  Pseudonymized: $($pz.Reverse.Count) identifiers (accounts, hosts, groups, DNs, SIDs, domain/trust names, paths). The map never leaves this machine."
    Write-Host "  Not sent: the snapshot, ACL dumps, descriptions, group memberships beyond what the finding text states."
    Write-Host "  Exactly what would be sent: $promptFile" -ForegroundColor Cyan
    $answer = Read-Host 'Open that file if you want, then: send to Gemini for an executive summary and remediation plan? (y/N)'
    if ($answer -notmatch '^[Yy]') { Write-Host "Nothing sent. Deterministic report saved to $OutHtml."; return }
}
else { Write-Host "AI prompt kept at $promptFile" }
if (-not $ApiKey) { $ApiKey = Request-GeminiApiKey }
if (-not $ApiKey) { Write-Host 'No API key given (-ApiKey or GEMINI_API_KEY), nothing sent. Deterministic report kept as is.' -ForegroundColor Yellow; return }

$raw = Invoke-GeminiAnalysis -UserPrompt $userPrompt -ApiKey $ApiKey -Model $Model -MaxAttempts $AiMaxAttempts
if (-not $raw) { Write-Host "AI step failed; deterministic report kept at $OutHtml." -ForegroundColor Yellow; return }
$responseFile = Get-AiSidecarPath $htmlFull '_ai_response.json'
Write-AiResponseFile -Path $responseFile -Raw $raw
Write-Host "Gemini reply (still pseudonymized) kept at $responseFile"
$aiResult = ConvertFrom-AiResponse -Raw $raw -Pz $pz -Findings $active -Model $Model

$html = ConvertTo-ReportHtml -Snapshot $snap -Index $index -PrivMap $privMap -Split $split -Score $score `
    -NotEvaluated $notEvaluated -Comparison $comparison -Config $config -ToolVersion $script:IDWolfVersion -ElapsedText $elapsedText -AiResult $aiResult
[System.IO.File]::WriteAllText($htmlFull, $html, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "AI section added to $OutHtml ($(@($aiResult.RemediationPlan).Count) remediation items)." -ForegroundColor Green
