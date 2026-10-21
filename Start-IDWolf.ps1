<#
.SYNOPSIS
    IDWolf launcher: one guided entry point for collection and analysis.

.DESCRIPTION
    A small menu, so nobody has to remember parameters:

      1  Full AD run                     (collect, then analyze or package)
      2  Full Entra run                  (collect, then analyze or package)
      3  Collect an AD snapshot          (Collect-ADSnapshot.ps1, RSAT)
      4  Collect password quality        (Export-PasswordQuality.ps1, DCSync rights)
      5  Collect an Entra ID snapshot    (Collect-EntraSnapshot.ps1)
      6  Analyze a snapshot              (IDWolf.ps1, anywhere; the AI summary is a step of it)
      7  Package for another machine     (snapshot + password quality in one zip)

    Nothing here writes to the directory.

    Answers are remembered between runs (%LOCALAPPDATA%\IDWolf\wizard.json: choices and paths,
    never a password or a key) and offered as defaults. On start the launcher offers to pick up
    a snapshot that was collected but never analyzed, or to repeat the last full run with the
    same answers. Every collection (1, 2, 3, 5) asks its questions first, then shows all the
    answers on one screen to change before Enter starts it; a single collection (3, 5) stops
    after collecting unless "Then" is changed there. After an analysis it offers to open the
    report in the default browser.

    [S] in the menu sets default settings (DC, deep, password quality, what to do after
    collecting, AI step, model, tenant...), kept apart from the remembered answers. Once set,
    every collection first asks whether to use them: yes skips the questions and goes straight
    to the settings screen, where a change applies to that run only; no asks as usual. Output
    paths are new on every run. Repeating the last run doesn't ask. Analysis on its own (6)
    offers their AI step. [S] also forgets the remembered answers (the default settings stay).

    Before an AD collection it tests the connection (DNS of the domain, DC locator, LDAP bind,
    the DC to be used and its ports, each with its time) and asks which DC to use: L lists
    them with site, role and ADWS latency. [D] in the menu does the same on its own.

.PARAMETER Credential
    Account for the AD collection and the password-quality step. If password
    quality is denied, the launcher offers to ask for another one and keeps it
    for the session.

.PARAMETER Server
    Domain controller (or domain) for the AD collections and the password-quality step
    (alias -DomainController). It replaces the remembered one for this session; without it the
    AD collections ask, with L to pick from the list of DCs. [D] in the menu lists the DCs and
    tests the connection to one.

.EXAMPLE
    .\Start-IDWolf.ps1 -Credential (Get-Credential)
.EXAMPLE
    .\Start-IDWolf.ps1 -Server dc07.corp.local
#>

[CmdletBinding()]
Param(
    [System.Management.Automation.PSCredential]$Credential,
    [Alias('DomainController')]
    [string]$Server = ''
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
. (Join-Path $root 'lib\Bundle.ps1')
. (Join-Path $root 'lib\Wizard.ps1')
. (Join-Path $root 'lib\Connection.ps1')
$script:ServerOverride = $Server

# "Run as administrator" starts in C:\Windows\System32, and the default paths below are
# relative (.\output): work from the IDWolf folder instead of writing into the Windows folder.
if ($env:windir -and (Get-Location).Path.TrimEnd('\').StartsWith($env:windir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
    Set-Location -LiteralPath $root
    Write-Host "Working folder: $root (started in the Windows folder, as an elevated window does)." -ForegroundColor DarkGray
}

function Show-Banner {
    # The version lives in IDWolf.ps1 only; read it from there so the two never drift.
    $ver = ''
    try {
        $m = Select-String -LiteralPath (Join-Path $root 'IDWolf.ps1') -Pattern '^\s*\$script:IDWolfVersion\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($m) { $ver = 'v' + $m.Matches[0].Groups[1].Value }
    } catch { }
    $b = @'
######################################################################
#                      .
#                     / V\
#                   / `  /
#                  <<   |                I D W o l f   {VERSION}
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
    $b = $b.Replace('{VERSION}', $ver)
    # Close the box on the right: pad every inner line to the border width.
    $b = (($b -split "`r?`n") | ForEach-Object { if ($_ -match '^#' -and $_ -notmatch '^#{10,}$') { $_.PadRight(69) + '#' } else { $_ } }) -join "`n"
    Write-Host $b -ForegroundColor DarkYellow
}

function Invoke-Sub {
    param([string]$Script, [hashtable]$Params = @{})
    $path = Join-Path $root $Script
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "Missing $Script next to the launcher." -ForegroundColor Red; return }
    Write-Host "`n--- $Script ---`n" -ForegroundColor Cyan
    # A failing step must not kill the menu: report it and return.
    try { & $path @Params }
    catch { Write-Host "$Script stopped: $($_.Exception.Message)" -ForegroundColor Red }
}

# Path prompt with Tab completion; falls back to Read-Host when redirected.
function Read-Path {
    param([string]$Prompt, [string]$Default = "")
    $label = "$Prompt" + $(if ($Default) { " [$Default]" } else { "" })
    $redirected = $true; try { $redirected = [Console]::IsInputRedirected } catch { }
    if ($redirected) { $v = Read-Host $label; if ([string]::IsNullOrWhiteSpace($v)) { return $Default } return $v.Trim() }
    Write-Host -NoNewline "${label}: "; $buf = ''; $tm = @(); $ti = 0
    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq 'Enter') { Write-Host ''; if ([string]::IsNullOrWhiteSpace($buf)) { return $Default } return $buf.Trim() }
        elseif ($key.Key -eq 'Backspace') { if ($buf.Length) { $buf = $buf.Substring(0, $buf.Length - 1); Write-Host -NoNewline "`b `b" }; $tm = @() }
        elseif ($key.Key -eq 'Tab') {
            if ($tm.Count -eq 0) {
                $hd = $buf -match '[\\/]'; $dir = if ($hd) { Split-Path $buf -Parent } else { '.' }; $leaf = if ($buf) { Split-Path $buf -Leaf } else { '' }
                try { $tm = @(Get-ChildItem -LiteralPath $dir -Filter ($leaf + '*') -ErrorAction SilentlyContinue | ForEach-Object { $n = if ($_.PSIsContainer) { $_.Name + [IO.Path]::DirectorySeparatorChar } else { $_.Name }; if ($hd) { Join-Path $dir $n } else { $n } }) } catch { $tm = @() }
                $ti = 0
            }
            if ($tm.Count) { $c = $tm[$ti % $tm.Count]; $ti++; if ($buf.Length) { Write-Host -NoNewline (("`b" * $buf.Length) + (" " * $buf.Length) + ("`b" * $buf.Length)) }; $buf = $c; Write-Host -NoNewline $buf }
        }
        elseif ($key.KeyChar -and -not [char]::IsControl($key.KeyChar)) { $buf += $key.KeyChar; Write-Host -NoNewline $key.KeyChar; $tm = @() }
    }
}
function Ts { Get-Date -Format 'yyyyMMdd_HHmmss' }

# Remembered answers (lib\Wizard.ps1). Read-Remembered asks with last time's answer as the
# default and saves the new one straight away, so a Ctrl+C half way keeps what was answered.
# While repeating the last run ($script:Replay) it takes the old answer without asking.
# Passwords, keys and credentials never go through here.
# The menu was renumbered in 1.4 (full runs first): a state file written before remembers the
# full AD run as 5 and the full Entra run as 8. Only full runs are ever saved as LastRun.
function Read-LauncherState {
    $st = Read-IDWolfState
    $old = @{ '5' = '1'; '8' = '2' }
    if ($old.ContainsKey("$($st.launcher.LastRun)")) {
        $st.launcher['LastRun'] = $old["$($st.launcher.LastRun)"]
        Save-IDWolfState -Section launcher -Values @{ LastRun = $st.launcher['LastRun'] }
    }
    return $st
}
$script:State = Read-LauncherState
$script:Replay = $false
# The default settings ([S]) while a run uses them: Read-Remembered takes them without asking
# (Required: an empty one is asked anyway) and saves nothing.
$script:Preset = $null
function Read-Remembered {
    param([string]$Key, [string]$Prompt, [string]$Default = '', [switch]$Path, [switch]$Required)
    if ($script:Preset -and $script:Preset.ContainsKey($Key) -and -not ($Required -and -not $script:Preset[$Key])) {
        $v = "$($script:Preset[$Key])"
        Write-Host ("{0}: {1}  (default settings)" -f $Prompt, $(if ($v) { $v } else { '(none)' })) -ForegroundColor DarkGray
        return $v
    }
    $mem = $script:State.launcher[$Key]
    if ($script:Replay -and $null -ne $mem) {
        Write-Host ("{0}: {1}  (as last time)" -f $Prompt, $(if ($mem) { $mem } else { '(none)' })) -ForegroundColor DarkGray
        return "$mem"
    }
    $def = if ($null -ne $mem) { "$mem" } else { $Default }
    if ($Path) { $v = Read-Path $Prompt $def }
    else {
        $v = Read-Host ($Prompt + $(if ($def) { " [$def]" } else { '' }))
        $v = if ([string]::IsNullOrWhiteSpace($v)) { $def } else { $v.Trim() }
    }
    if ($v -eq '-') { $v = '' }   # "-" clears a remembered optional path
    $script:State.launcher[$Key] = "$v"
    Save-IDWolfState -Section launcher -Values @{ $Key = "$v" }
    return "$v"
}
function Test-Yes { param($Answer) return ("$Answer" -match '^[YySs]') }
# A setting that isn't asked: the default settings in use, else the remembered answer.
function Get-RunDefault {
    param([string]$Key)
    if ($script:Preset -and $script:Preset.ContainsKey($Key)) { return "$($script:Preset[$Key])" }
    return "$($script:State.launcher[$Key])"
}
# A new output path: asked, except while repeating the last run or using the default settings
# (the timestamped default is used).
function Read-NewPath {
    param([string]$Prompt, [string]$Default)
    if ($script:Replay -or $script:Preset) { Write-Host "${Prompt}: $Default" -ForegroundColor DarkGray; return $Default }
    return (Read-Path $Prompt $Default)
}
# A collected snapshot stays "pending" until it is analyzed, packaged or dropped, so the next
# launch can offer it if this one was interrupted.
function Set-PendingSnapshot {
    param([string]$Kind, [string]$Snapshot, [string]$PasswordQuality = '')
    $v = @{ Kind = $Kind; Snapshot = (Resolve-Path -LiteralPath $Snapshot).ProviderPath; CollectedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm') }
    if ($PasswordQuality) { $v['PasswordQuality'] = (Resolve-Path -LiteralPath $PasswordQuality).ProviderPath }
    Save-IDWolfState -Section pending -Values $v -Replace
}
function Clear-PendingSnapshot { Save-IDWolfState -Section pending -Values @{} -Replace }

function ConvertTo-NextChoice { param($Answer) $a = "$Answer".Trim().ToUpper(); if ($a -eq 'Z' -or $a -eq 'S') { return $a } return 'A' }
function ConvertTo-AiChoice { param($Answer) $a = "$Answer".Trim().ToUpper(); if ($a -eq 'S' -or $a -eq 'D') { return $a } return 'A' }
function ConvertTo-YN { param($Answer) if (Test-Yes $Answer) { return 'y' } return 'n' }

# Collections (1, 2, 3, 5): the questions first, then every answer on one screen
# (Edit-RunSettings, lib\Wizard.ps1) to check or change before anything runs. Enter starts.
$script:RunLabels = @{
    Server     = 'Domain controller (empty = auto)'
    OutFile    = 'Snapshot output path'
    Deep       = 'Deep collection'
    Pq         = 'Password quality (DCSync rights)'
    PqOut      = 'Password-quality output path'
    WeakList   = 'Weak/breached password list'
    Tenant     = 'Tenant (empty = sign-in default)'
    DeviceCode = 'Device-code sign-in'
    Next       = 'Then (A analyze, Z zip, S stop)'
    OutHtml    = 'Report HTML path'
    Ai         = 'AI summary (S skip, A ask, D dry-run)'
    Model      = 'Gemini model'
    AiAttempts = 'Gemini attempts (0 = keep trying)'
}
# Settings that are remembered for next time; output paths are new on every run. A single
# collection (3, 5) starts from "Then = S" whatever was answered last, and doesn't save it.
$script:RunRemembered = @('Server', 'Deep', 'Pq', 'WeakList', 'Tenant', 'DeviceCode', 'Next', 'Ai', 'Model', 'AiAttempts')
$script:SingleStep = $false
function Save-RunSetting {
    param([string]$Key, $Value)
    if ($script:RunRemembered -notcontains $Key) { return }
    if ($script:SingleStep -and $Key -eq 'Next') { return }
    $script:State.launcher[$Key] = "$Value"
    Save-IDWolfState -Section launcher -Values @{ $Key = "$Value" }
}
# The AI step of an analysis: skip (-SkipLLM, so a long run never stops at the end on a
# question), ask (the analyzer writes the prompt and asks before sending) or dry-run (the
# prompt is written next to the report, nothing is sent). Model and attempts only for ask.
function Read-AiSettings {
    param($S)
    $S.Ai = ConvertTo-AiChoice (Read-Remembered 'Ai' "AI summary (Gemini): skip [S], ask before sending [A], or dry-run, writing the prompt only [D]?" 'A')
    if ($S.Ai -eq 'A') {
        $S.Model = Read-Remembered 'Model' "Gemini model" 'gemini-3.8-flash'
        $S.AiAttempts = Read-Remembered 'AiAttempts' "Gemini attempts on timeout / busy server, 0 = keep trying" '3'
    }
}
# What happens after the collection, asked up front unless Next is given (a single collection).
# The report, AI step, model and attempts get their defaults even when not asked, so switching
# to [A] on the settings screen has values to show.
function Add-AfterCollectionSettings {
    param($S, [string]$Next = '')
    $S.Next = if ($Next) { $Next } else { ConvertTo-NextChoice (Read-Remembered 'Next' "After collecting: analyze here [A], package a zip for another machine [Z], or stop [S]?" 'A') }
    $S.OutHtml = "output\report_{0}.html" -f (Ts)
    $ai = Get-RunDefault 'Ai'; $model = Get-RunDefault 'Model'; $attempts = Get-RunDefault 'AiAttempts'
    $S.Ai = if ($ai) { ConvertTo-AiChoice $ai } else { 'A' }
    $S.Model = if ($model) { $model } else { 'gemini-3.8-flash' }
    $S.AiAttempts = if ($attempts) { $attempts } else { '3' }
    if ($S.Next -eq 'A') {
        $S.OutHtml = Read-NewPath "Report HTML path" $S.OutHtml
        Read-AiSettings $S
    }
}
function Confirm-RunSettings {
    param($S, [bool]$Joined = $true)
    # The DC is picked from the list (or typed there); a new one gets its connection tested.
    $pickers = @{ Server = { param($Cur) Select-DomainController -Current $Cur -Credential $script:Credential } }
    return Edit-RunSettings -Settings $S -Labels $script:RunLabels -YesNo @('Deep', 'Pq', 'DeviceCode') -Choices @{ Next = @('A', 'Z', 'S'); Ai = @('S', 'A', 'D') } -Pickers $pickers `
        -Visible ({ param($Key, $Set)
            if (@('Pq', 'PqOut', 'WeakList') -contains $Key -and -not $Joined) { return $false }
            if (@('PqOut', 'WeakList') -contains $Key -and $Set.Pq -ne 'y') { return $false }
            if (@('OutHtml', 'Ai', 'Model', 'AiAttempts') -contains $Key -and $Set.Next -ne 'A') { return $false }
            if (@('Model', 'AiAttempts') -contains $Key -and $Set.Ai -ne 'A') { return $false }
            return $true
        }.GetNewClosure()) `
        -OnChange { param($Key, $Value) Save-RunSetting $Key $Value; if ($Key -eq 'Server') { Show-AdConnection $Value } }
}
# Default settings ([S]): the settings of a run, set once and kept apart from the remembered
# answers. Output paths are not among them (new on every run). Enter saves, Q leaves them as
# they were; X before the screen deletes them.
function Edit-DefaultSettings {
    $d = $script:State.defaults
    if ($d.Count) {
        $a = (Read-Host 'Change the default settings [Enter], or delete them [X]?').Trim().ToUpper()
        if ($a -eq 'X') {
            Save-IDWolfState -Section defaults -Values @{} -Replace
            $script:State.defaults = @{}
            Write-Host 'Default settings deleted: every run asks its questions again.' -ForegroundColor Green
            return
        }
    }
    # Unset keys start from the remembered answers, then the launcher's own defaults.
    $L = $script:State.launcher
    $get = { param([string]$Key, [string]$Fallback) if ($d.ContainsKey($Key)) { "$($d[$Key])" } elseif ($null -ne $L[$Key]) { "$($L[$Key])" } else { $Fallback } }
    $s = [ordered]@{
        Server     = & $get 'Server' ''
        Deep       = ConvertTo-YN (& $get 'Deep' 'n')
        Pq         = ConvertTo-YN (& $get 'Pq' 'n')
        WeakList   = & $get 'WeakList' ''
        Tenant     = & $get 'Tenant' ''
        DeviceCode = ConvertTo-YN (& $get 'DeviceCode' 'n')
        Next       = ConvertTo-NextChoice (& $get 'Next' 'A')
        Ai         = ConvertTo-AiChoice (& $get 'Ai' 'A')
        Model      = & $get 'Model' 'gemini-3.8-flash'
        AiAttempts = & $get 'AiAttempts' '3'
    }
    Write-Host "`nDefault settings: every collection asks whether to use them, then shows them on its settings screen; an analysis on its own (6) offers their AI step. Output paths are new on every run." -ForegroundColor Cyan
    $pickers = @{ Server = { param($Cur) Select-DomainController -Current $Cur -Credential $script:Credential } }
    $ok = Edit-RunSettings -Settings $s -Labels $script:RunLabels -YesNo @('Deep', 'Pq', 'DeviceCode') -Choices @{ Next = @('A', 'Z', 'S'); Ai = @('S', 'A', 'D') } -Pickers $pickers -Confirm 'save' `
        -Visible { param($Key, $Set)
            if ($Key -eq 'WeakList' -and $Set.Pq -ne 'y') { return $false }
            if (@('Ai', 'Model', 'AiAttempts') -contains $Key -and $Set.Next -ne 'A') { return $false }
            if (@('Model', 'AiAttempts') -contains $Key -and $Set.Ai -ne 'A') { return $false }
            return $true
        }
    if (-not $ok) { Write-Host 'Default settings not changed.' -ForegroundColor Yellow; return }
    Save-IDWolfState -Section defaults -Values $s -Replace
    $script:State.defaults = (Read-IDWolfState).defaults
    Write-Host "Default settings saved ($(Get-IDWolfStatePath))." -ForegroundColor Green
}
# The default settings in one line, for the question below.
function Format-DefaultSettings {
    param($D, [string]$Kind)
    $yn = { param($v) if (Test-Yes $v) { 'yes' } else { 'no' } }
    $parts = @()
    if ($Kind -eq 'entra') {
        $parts += "tenant $(if ($D.Tenant) { $D.Tenant } else { 'sign-in default' })"
        $parts += "device-code sign-in $(& $yn $D.DeviceCode)"
    }
    else {
        $parts += "DC $(if ($D.Server) { $D.Server } else { 'automatic' })"
        $parts += "deep $(& $yn $D.Deep)"
        $parts += "password quality $(& $yn $D.Pq)"
    }
    $next = ConvertTo-NextChoice $D.Next
    if ($next -eq 'Z') { $parts += 'then zip' }
    elseif ($next -eq 'S') { $parts += 'then stop' }
    else {
        $ai = ConvertTo-AiChoice $D.Ai
        $parts += "then analyze, AI $(if ($ai -eq 'S') { 'skipped' } elseif ($ai -eq 'D') { 'dry-run' } else { "ask ($($D.Model))" })"
    }
    return ($parts -join ', ')
}
# At the start of a collection: use the default settings? Not asked while repeating the last
# run, nor when there are none.
function Request-DefaultSettings {
    param([string]$Kind, [bool]$Full = $true)
    $script:Preset = $null
    $d = $script:State.defaults
    if ($script:Replay -or -not $d.Count) { return }
    $line = Format-DefaultSettings $d $Kind
    if (-not $Full) { $line = ($line -replace ', then .*$', '') + ', then stop' }
    Write-Host "`nDefault settings: $line." -ForegroundColor Cyan
    $a = Read-Host 'Use the default settings? (Y/n)'
    if ([string]::IsNullOrWhiteSpace($a) -or (Test-Yes $a)) { $script:Preset = $d }
}
# Connection diagnostics for an AD collection (lib\Connection.ps1): DNS, DC locator, LDAP bind,
# the DC that will be used and its ports, with timings.
function Show-AdConnection {
    param([string]$Server = '')
    Write-Host 'Testing the connection to the domain...' -ForegroundColor DarkGray
    try { Show-ConnectionDiagnostics (Get-ConnectionDiagnostics -Server $Server -Credential $script:Credential) }
    catch { Write-Host "  Connection diagnostics failed: $($_.Exception.Message)" -ForegroundColor Yellow }
}
# The DC for an AD collection on a domain-joined machine: -Server if given, else asked with the
# remembered one as default; L lists the DCs to pick from, - means automatic (DC locator).
function Read-ServerChoice {
    if ($script:ServerOverride) { Write-Host "Domain controller: $script:ServerOverride  (-Server)" -ForegroundColor DarkGray; return $script:ServerOverride }
    if ($script:Preset -and $script:Preset.ContainsKey('Server')) {
        $v = "$($script:Preset.Server)"
        Write-Host ("Domain controller: {0}  (default settings)" -f $(if ($v) { $v } else { 'automatic' })) -ForegroundColor DarkGray
        return $v
    }
    $mem = $script:State.launcher.Server
    if ($script:Replay -and $null -ne $mem) {
        Write-Host ("Domain controller: {0}  (as last time)" -f $(if ($mem) { $mem } else { 'automatic' })) -ForegroundColor DarkGray
        return "$mem"
    }
    $v = Read-Host ("Domain controller: name, L to list the DCs, - for automatic [{0}]" -f $(if ($mem) { $mem } else { 'automatic' }))
    $v = "$v".Trim()
    if (-not $v) { $v = "$mem" }
    elseif ($v -eq '-') { $v = '' }
    elseif ($v -match '^[Ll]$') { $v = Select-DomainController -Current "$mem" -Credential $script:Credential }
    $script:State.launcher['Server'] = $v
    Save-IDWolfState -Section launcher -Values @{ Server = $v }
    return $v
}
# The analyzer's parameters for the AI step chosen above.
function Add-AiParams {
    param([hashtable]$Params, [string]$Ai, [string]$Model, [string]$Attempts)
    if ($Ai -eq 'S') { $Params['SkipLLM'] = $true; return }
    if ($Ai -eq 'D') { $Params['AiDryRun'] = ($Params.OutHtml -replace '\.html?$', '') + '_ai_prompt.txt'; return }
    if ($Model) { $Params['Model'] = $Model }
    if ($Attempts -match '^\d+$') { $Params['AiMaxAttempts'] = [int]$Attempts }
}
# The default paths offered below are under .\output.
$od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }

# Collect here, analyze elsewhere: one zip with a hash for each file inside.
function Invoke-Package {
    param([string]$Snapshot, [string]$PasswordQuality = '')
    # A password wraps the zip in an encrypted container (.idwolf); Enter alone keeps a plain zip.
    $pw1 = Read-Host 'Password to encrypt the package (hidden; Enter for a plain zip)' -AsSecureString
    $pw = $null
    if ($pw1.Length -gt 0) {
        $pw2 = Read-Host 'Same password again' -AsSecureString
        $same = $false
        $b1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1); $b2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2)
        try { $same = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1) -ceq [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
        if (-not $same) { Write-Host 'The two passwords differ: nothing packaged.' -ForegroundColor Red; return }
        if ($pw1.Length -lt 12) { Write-Host 'Use at least 12 characters: nothing packaged.' -ForegroundColor Red; return }
        $pw = $pw1
    }
    $zipOut = Read-Path "Package path" ("output\idwolf_{0}.{1}" -f (Ts), $(if ($pw) { 'idwolf' } else { 'zip' }))
    try {
        $full = New-IDWolfBundle -Snapshot $Snapshot -PasswordQuality $PasswordQuality -OutFile $zipOut -Password $pw
        Write-Host "Ready: $full" -ForegroundColor Green
        Write-Host "Copy it to the analysis machine and run: .\IDWolf.ps1 -Snapshot $([System.IO.Path]::GetFileName($full))" -ForegroundColor Cyan
        if ($pw) { Write-Host "Encrypted: IDWolf.ps1 asks for the password when it opens it. Send the password over a different channel than the file." -ForegroundColor Cyan }
        else { Write-Host "It holds directory data (and account names with weak passwords, if included): move it like any confidential file, then delete the copies." -ForegroundColor Yellow }
    }
    catch { Write-Host "Packaging failed: $($_.Exception.Message)" -ForegroundColor Red }
}

# -Credential for the scripts that take it; empty means "use my session".
function Get-CredParams { if ($script:Credential) { @{ Credential = $script:Credential } } else { @{} } }

# Password quality, for options 2 and 5. If replication is denied, offer one
# retry with another account and keep it for the session. Returns the report
# path, or "" if there's none.
function Invoke-PasswordQualityStep {
    param([string]$OutFile, [string]$WeakList = "", [string]$Server = "")
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $p = @{ OutFile = $OutFile } + (Get-CredParams)
        if ($WeakList) { $p['WeakPasswordsFile'] = $WeakList }
        if ($Server) { $p['Server'] = $Server }
        Invoke-Sub 'Export-PasswordQuality.ps1' $p
        if (Test-Path -LiteralPath $OutFile) { return $OutFile }
        if ($attempt -eq 2) { break }
        $who = if ($script:Credential) { $script:Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME" }
        if ((Read-Host "Retry with a different account (Domain Admin / delegated DCSync), instead of $who? (y/N)") -notmatch '^[YySs]') { break }
        try { $script:Credential = Get-Credential -Message "Account with replication (DCSync) rights for the password-quality step" } catch { break }
        if (-not $script:Credential) { break }
    }
    return ""
}

# Workgroup PCs: no domain to find, no domain identity. The DC goes on the settings screen of an
# AD collection; the account is asked once and kept for the session.
function Test-DomainJoined {
    try { return [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { return $true }
}
function Request-WorkgroupCredential {
    if ($script:Credential) { return }
    try { $script:Credential = Get-Credential -Message "Domain account (DOMAIN\user) for the read-only AD collection" } catch { }
    if (-not $script:Credential) { Write-Host "No credentials given: the queries will probably be denied." -ForegroundColor Yellow }
}
# The domain password quality replicates from (Export-PasswordQuality.ps1 finds it the same
# way), for the name of its report. The report itself records the real one.
function Get-LocalDomainName {
    $d = "$env:USERDNSDOMAIN"
    if (-not $d) { try { $d = "$((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain)" } catch { } }
    if (-not $d) { $d = 'domain' }
    return $d.ToLower()
}
# False when the password-quality report names another domain than the snapshot: IDWolf.ps1
# would refuse the pair, so it is left out here already.
function Test-PqMatchesSnapshot {
    param([string]$Snapshot, [string]$PasswordQuality)
    $sd = Get-SnapshotDomainName $Snapshot
    $pd = ''
    try { $pd = "$(([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $PasswordQuality).ProviderPath) | ConvertFrom-Json).domain)" } catch { }
    if ($sd -and $pd -and $pd -ne 'domain' -and $pd -ne $sd) {
        Write-Host "The password-quality report is for $pd, the snapshot for ${sd}: it is left out." -ForegroundColor Yellow
        return $false
    }
    return $true
}

# After a collection: analyze here, package for another machine, or stop. The snapshot stays
# pending until it is analyzed or packaged (an analysis that wrote no report keeps it pending),
# so "stop" leaves it for the next start to offer.
# Preset: the answers of a collection, already checked on the settings screen (Next, OutHtml,
# Ai, Model, AiAttempts). Without it (a pending snapshot picked up on start) they are asked here.
function Invoke-AfterCollection {
    param([string]$Snapshot, [string]$PasswordQuality = '', $Preset = $null)
    if ($Preset) { $next = "$($Preset.Next)" }
    else {
        # Picked up on start: analyzing is the default, whatever the last run chose.
        $next = ConvertTo-NextChoice (Read-Host "Analyze here [A], package a zip to analyze on another machine [Z], or leave it for later [S]? [A]")
    }
    if ($next -eq 'Z') { Invoke-Package -Snapshot $Snapshot -PasswordQuality $PasswordQuality; Clear-PendingSnapshot }
    elseif ($next -eq 'S') { Write-Host "Snapshot kept for later: $Snapshot. The next start offers to analyze or package it." -ForegroundColor Cyan }
    else {
        $s = $Preset
        if (-not $s) {
            $s = [ordered]@{ OutHtml = (Read-NewPath "Report HTML path" ("output\report_{0}.html" -f (Ts))) }
            Read-AiSettings $s
        }
        $ap = @{ Snapshot = $Snapshot; OutHtml = "$($s.OutHtml)" }
        if ($PasswordQuality) { $ap['PasswordQualityFile'] = $PasswordQuality }
        Add-AiParams -Params $ap -Ai "$($s.Ai)" -Model "$($s.Model)" -Attempts "$($s.AiAttempts)"
        $t0 = Get-Date
        Invoke-Sub 'IDWolf.ps1' $ap
        if (Test-Path -LiteralPath $ap.OutHtml) { Clear-PendingSnapshot }
        [void](Request-OpenReport -Path $ap.OutHtml -Since $t0)
    }
}

# What the collecting account can do (Get-CollectorRights, lib\Wizard.ps1), shown just before the
# settings screen: a missing right is seen before the run, not as "not evaluated" checks or a
# denied password-quality step after it.
function Show-CollectorRights {
    param($S)
    $r = Get-CollectorRights -Server "$($S.Server)" -Credential $script:Credential
    $yn = { param($v) if ($null -eq $v) { 'unknown' } elseif ($v) { 'yes' } else { 'no' } }
    Write-Host "`nRights of $(if ($r.Account) { $r.Account } else { 'this account' }):" -ForegroundColor Cyan
    Write-Host ("  Elevated session (local admin)      {0}" -f (& $yn $r.Elevated))
    if ($r.Error) { Write-Host "  Domain rights not read: $($r.Error)" -ForegroundColor Yellow; return }
    if ($r.Protocol -eq 'LDAPS') { Write-Host '  (read over LDAPS, TCP 636: 389 does not answer)' -ForegroundColor DarkGray }
    $da = if ($r.FilteredByUac) { 'filtered by UAC (window not elevated)' } else { "$(& $yn $r.DomainAdmin) / $(& $yn $r.EnterpriseAdmin)" }
    Write-Host ("  Domain Admins / Enterprise Admins   {0}" -f $da)
    Write-Host ("  Replication rights (DCSync)         {0}" -f (& $yn $r.Replication))
    # The checks these rights leave out, from the catalog's Needs (the same ones the report will
    # list as "not evaluated").
    $gaps = @(Get-RightsGaps -Rights $r -Deep ($S.Deep -eq 'y'))
    if (-not $gaps.Count) { Write-Host '  Every check can be evaluated with these rights.' -ForegroundColor Green; return }
    $catalog = Get-IDWolfCheckCatalog
    Write-Host '  These checks will come back "not evaluated":' -ForegroundColor Yellow
    foreach ($g in $gaps) {
        $types = @(if ($catalog) { Get-ChecksNeeding -Catalog $catalog -Sections $g.Sections })
        Write-Host "    $($g.Reason)$(if ($types.Count) { " ($($types.Count)): $($types -join ', ')" })" -ForegroundColor Yellow
    }
    if ($r.FilteredByUac) { Write-Host '  Start Start-IDWolf.cmd with right-click > Run as administrator to collect with your full rights.' -ForegroundColor Yellow }
}
# The check catalog, only to name the checks above. Loaded in a function so the analyzer's own
# functions stay out of the launcher; only its $script: tables are kept.
function Get-IDWolfCheckCatalog {
    try {
        . (Join-Path $root 'lib\Checks.ps1')
        . (Join-Path $root 'lib\ChecksHost.ps1')
        return $script:CheckCatalog
    }
    catch { return $null }
}

# AD collection: a full run (1) asks what to do next and offers password quality; a single
# collection (3) starts from "Then = S". Both go through the same settings screen.
function Invoke-AdRun {
    param([bool]$Full)
    $script:SingleStep = -not $Full
    Request-DefaultSettings -Kind ad -Full $Full
    $joined = Test-DomainJoined
    $s = [ordered]@{}
    if (-not $joined) {
        Write-Host "This computer is not joined to a domain. Collection needs the name of a domain controller and a domain account." -ForegroundColor Yellow
        $s.Server = if ($script:ServerOverride) { $script:ServerOverride } else { Read-Remembered 'Server' "Domain controller or domain (e.g. dc01.corp.local; - to cancel)" -Required }
        if (-not $s.Server) { Write-Host "Cancelled: no domain controller given." -ForegroundColor Yellow; return }
        Request-WorkgroupCredential
    }
    else { $s.Server = Read-ServerChoice }
    # Timestamped file, so a re-run never overwrites the last snapshot.
    $s.OutFile = Read-NewPath "AD snapshot output path" ("output\adsnap_{0}.json" -f (Ts))
    $s.Deep = ConvertTo-YN (Read-Remembered 'Deep' "Deep collection? (y/n)" 'n')
    # Separate on purpose: it reads password hashes, the AD collection never does.
    $s.Pq = 'n'
    if ($Full -and $joined) { $s.Pq = ConvertTo-YN (Read-Remembered 'Pq' "Also collect password quality? Needs DSInternals and DCSync rights; run from the DC or a trusted admin host (y/n)" 'n') }
    elseif ($Full) { Write-Host "Password quality skipped: it needs a domain-joined machine (or the DC) to find the PDC. Run option 4 there." -ForegroundColor Yellow }
    $s.PqOut = "output\pwq_{0}_{1}.json" -f $(if ($joined) { Get-LocalDomainName } else { 'domain' }), (Ts)
    $s.WeakList = Get-RunDefault 'WeakList'
    if ($s.Pq -eq 'y') {
        $s.PqOut = Read-NewPath "Password-quality output path" $s.PqOut
        $s.WeakList = Read-Remembered 'WeakList' "Weak/breached password list path (optional; - for none)" -Path
    }
    if ($Full) { Add-AfterCollectionSettings $s } else { Add-AfterCollectionSettings $s -Next 'S' }
    Show-AdConnection "$($s.Server)"
    Show-CollectorRights $s
    if (-not (Confirm-RunSettings $s $joined)) { Write-Host "Cancelled: nothing collected." -ForegroundColor Yellow; return }
    # Cleared on the settings screen: there is nothing to fall back on.
    if (-not $joined -and -not $s.Server) { Write-Host "Cancelled: a workgroup PC needs a domain controller, and it was cleared. Nothing collected." -ForegroundColor Yellow; return }

    $p = @{ OutFile = $s.OutFile } + (Get-CredParams)
    if ($s.Server) { $p['Server'] = $s.Server }
    if ($s.Deep -eq 'y') { $p['Deep'] = $true }
    Invoke-Sub 'Collect-ADSnapshot.ps1' $p
    if (-not (Test-Path -LiteralPath $s.OutFile)) { Write-Host "Snapshot not produced; see messages above." -ForegroundColor Red; return }
    Write-Host "`nSnapshot ready: $($s.OutFile)" -ForegroundColor Green
    Set-PendingSnapshot -Kind ad -Snapshot $s.OutFile
    $pqOut = ""
    if ($joined -and $s.Pq -eq 'y') {
        $pqOut = Invoke-PasswordQualityStep -OutFile $s.PqOut -WeakList $s.WeakList -Server "$($s.Server)"
        if (-not $pqOut) { Write-Host "Password quality not produced (see messages); continuing without it." -ForegroundColor Yellow }
        elseif (-not (Test-PqMatchesSnapshot -Snapshot $s.OutFile -PasswordQuality $pqOut)) { $pqOut = "" }
        else { Set-PendingSnapshot -Kind ad -Snapshot $s.OutFile -PasswordQuality $pqOut }
    }
    Invoke-AfterCollection -Snapshot $s.OutFile -PasswordQuality $pqOut -Preset $s
}

# Entra collection: full run (2) or single collection (5), like the AD one.
function Invoke-EntraRun {
    param([bool]$Full)
    $script:SingleStep = -not $Full
    Request-DefaultSettings -Kind entra -Full $Full
    $s = [ordered]@{}
    $s.OutFile = Read-NewPath "Entra snapshot output path" ("output\entrasnapshot_{0}.json" -f (Ts))
    $s.Tenant = Read-Remembered 'Tenant' "Tenant ID or domain (Enter = last one or the sign-in default; - for the sign-in default)"
    $s.DeviceCode = ConvertTo-YN (Read-Remembered 'DeviceCode' "Use device-code sign-in? (y/n)" 'n')
    if ($Full) { Add-AfterCollectionSettings $s } else { Add-AfterCollectionSettings $s -Next 'S' }
    if (-not (Confirm-RunSettings $s)) { Write-Host "Cancelled: nothing collected." -ForegroundColor Yellow; return }

    $p = @{ OutFile = $s.OutFile }
    if ($s.Tenant) { $p['TenantId'] = $s.Tenant }
    if ($s.DeviceCode -eq 'y') { $p['UseDeviceCode'] = $true }
    Invoke-Sub 'Collect-EntraSnapshot.ps1' $p
    if (-not (Test-Path -LiteralPath $s.OutFile)) { Write-Host "Snapshot not produced; see messages above." -ForegroundColor Red; return }
    Write-Host "`nSnapshot ready: $($s.OutFile)" -ForegroundColor Green
    Set-PendingSnapshot -Kind entra -Snapshot $s.OutFile
    Invoke-AfterCollection -Snapshot $s.OutFile -Preset $s
}

Show-Banner

# This window, checked once: on a DC a window that is not elevated collects like a standard
# user, whatever the account (UAC filters the admin groups out of its token). The launcher
# can't restart itself elevated (the safety review forbids starting processes), so it says how
# and offers to quit; the answers given so far are remembered.
# Everything from here on goes to output\idwolf_<timestamp>.log (lib\Wizard.ps1).
$script:SessionLog = Start-IDWolfLog 'idwolf'
# A step that stops the launcher with an error still closes the log.
trap { Stop-IDWolfLog $script:SessionLog; break }

$script:Session = Get-SessionStatus
if ($script:Session.OnDc -and $script:Session.Elevated -eq $false) {
    Write-Host "`nThis is a domain controller and this window is not elevated. Windows filters the admin rights out of it (UAC):" -ForegroundColor Yellow
    Write-Host "even a Domain Admin collects like a standard user here, password quality is denied and many checks come back `"not evaluated`"." -ForegroundColor Yellow
    Write-Host "Close it and start Start-IDWolf.cmd with right-click > Run as administrator (analysis and packaging work as they are)." -ForegroundColor Yellow
    $a = Read-Host 'Quit now to restart elevated? (Y/n)'
    if ([string]::IsNullOrWhiteSpace($a) -or (Test-Yes $a)) { Write-Host "Bye." -ForegroundColor DarkYellow; Stop-IDWolfLog $script:SessionLog; return }
}
elseif ($script:Session.Elevated -eq $false -and $script:Session.Rsat -eq $false) {
    Write-Host "`nNot elevated, and RSAT (ActiveDirectory module) is not installed: an AD collection can't install it from this window. Start Start-IDWolf.cmd as administrator for that; Entra, analysis and packaging don't need it." -ForegroundColor DarkGray
}

# Interrupted last time? A snapshot collected but never analyzed comes first, then the offer
# to repeat the last full run with the same answers.
$script:QueuedChoice = $null
$pend = $script:State.pending
if ($pend.Snapshot -and (Test-Path -LiteralPath $pend.Snapshot)) {
    Write-Host "`nThe $(if ($pend.Kind -eq 'entra') { 'Entra' } else { 'AD' }) snapshot $($pend.Snapshot), collected $($pend.CollectedAt), was never analyzed or packaged." -ForegroundColor Cyan
    $a = (Read-Host "Pick up from there? (Y/n, F = forget it)").Trim().ToUpper()
    if ($a -eq 'F') { Clear-PendingSnapshot }
    elseif ($a -eq '' -or (Test-Yes $a)) {
        $pq = if ($pend.PasswordQuality -and (Test-Path -LiteralPath $pend.PasswordQuality)) { $pend.PasswordQuality } else { '' }
        Invoke-AfterCollection -Snapshot $pend.Snapshot -PasswordQuality $pq
    }
}
elseif ($pend.Snapshot) { Clear-PendingSnapshot }
elseif (@('1', '2') -contains $script:State.launcher.LastRun) {
    $L = $script:State.launcher
    $what = if ($L.LastRun -eq '1') {
        "full AD run$(if (Test-Yes $L.Deep) { ', deep collection' })$(if ($L.Server) { ", server $($L.Server)" })$(if (Test-Yes $L.Pq) { ', password quality' })"
    }
    else { "full Entra run$(if ($L.Tenant) { ", tenant $($L.Tenant)" })" }
    Write-Host "`nLast time: $what." -ForegroundColor Cyan
    $a = Read-Host "Repeat it with the same choices? (Y/n)"
    if ([string]::IsNullOrWhiteSpace($a) -or (Test-Yes $a)) { $script:Replay = $true; $script:QueuedChoice = $L.LastRun }
}

while ($true) {
    Write-Host ""
    Write-Host "  [1] Full AD run                 (collect, then analyze or package)" -ForegroundColor White
    Write-Host "  [2] Full Entra run              (collect, then analyze or package)" -ForegroundColor White
    Write-Host "  [3] Collect AD snapshot         (RSAT; a workgroup PC asks for the DC)" -ForegroundColor White
    Write-Host "  [4] Collect password quality    (DSInternals + DCSync rights, hashless)" -ForegroundColor White
    Write-Host "  [5] Collect Entra ID snapshot   (Microsoft Graph)" -ForegroundColor White
    Write-Host "  [6] Analyze a snapshot          (report, optional AI summary)" -ForegroundColor White
    Write-Host "  [7] Package for another machine (snapshot + password quality in one zip)" -ForegroundColor White
    Write-Host "  [D] Domain controllers and connection test" -ForegroundColor White
    Write-Host "  [S] Settings                    (default settings: $(if ($script:State.defaults.Count) { 'set' } else { 'not set' }); forget remembered answers)" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor White
    if ($script:QueuedChoice) { $choice = $script:QueuedChoice; $script:QueuedChoice = $null; Write-Host "`nChoice: $choice (repeating the last run)" }
    else { $script:Replay = $false; $choice = (Read-Host "`nChoice").Trim().ToUpper() }
    $script:Preset = $null
    if (@('1', '2') -contains $choice) { $script:State.launcher['LastRun'] = $choice; Save-IDWolfState -Section launcher -Values @{ LastRun = $choice } }
    switch ($choice) {
        '1' { Invoke-AdRun -Full $true }
        '2' { Invoke-EntraRun -Full $true }
        '3' { Invoke-AdRun -Full $false }
        '4' {
            if (-not (Test-DomainJoined)) {
                Write-Host "This computer is not joined to a domain: live replication can't find the PDC from here." -ForegroundColor Yellow
                Write-Host "Run this option on a domain-joined machine or the DC, or run Export-PasswordQuality.ps1 -FromDatabase ntds.dit -BootKeyFile SYSTEM." -ForegroundColor Yellow
                continue
            }
            $pqOut = Read-Path "Password-quality output path" ("output\pwq_{0}_{1}.json" -f (Get-LocalDomainName), (Ts))
            $wl = Read-Remembered 'WeakList' "Weak/breached password list path (optional; - for none)" -Path
            if (Invoke-PasswordQualityStep -OutFile $pqOut -WeakList $wl -Server $script:ServerOverride) { Write-Host "Password-quality report ready: $pqOut" -ForegroundColor Green }
        }
        '5' { Invoke-EntraRun -Full $false }
        '6' { Invoke-Sub 'IDWolf.ps1' }
        '7' {
            $snapDef = @(Get-ChildItem -Path '.', 'output' -Filter *.json -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)snapshot|adsnap|entra' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
            $s = Read-Path "Snapshot JSON" $(if ($snapDef.Count) { $snapDef[0] } else { "" })
            if (-not $s -or -not (Test-Path -LiteralPath $s)) { Write-Host "Snapshot not found." -ForegroundColor Red }
            else {
                # Only a report of the snapshot's domain is offered (none for an Entra snapshot).
                $pqDef = @(Get-PasswordQualityCandidates -Domain (Get-SnapshotDomainName $s))
                $pq = Read-Path "Password-quality JSON to add (optional, Enter to skip)" $(if ($pqDef.Count) { $pqDef[0] } else { "" })
                if ($pq -and -not (Test-Path -LiteralPath $pq)) { Write-Host "Password-quality file not found: $pq" -ForegroundColor Red }
                elseif ($pq -and -not (Test-PqMatchesSnapshot -Snapshot $s -PasswordQuality $pq)) { Write-Host "Nothing packaged." -ForegroundColor Yellow }
                else { Invoke-Package -Snapshot $s -PasswordQuality $pq }
            }
        }
        'D' {
            # Lists the DCs, then tests the one picked (Enter = the DC the next AD collection would use).
            $cur = if ($script:ServerOverride) { $script:ServerOverride } else { "$($script:State.launcher.Server)" }
            $dc = Select-DomainController -Current $cur -Credential $script:Credential
            Show-AdConnection $dc
            if ($dc -ne $cur -and -not $script:ServerOverride) {
                $script:State.launcher['Server'] = $dc
                Save-IDWolfState -Section launcher -Values @{ Server = $dc }
                Write-Host "The next AD collection will use $(if ($dc) { $dc } else { 'the DC the locator picks' })." -ForegroundColor Cyan
            }
        }
        'S' {
            Write-Host ""
            Write-Host "  [1] Default settings            ($(if ($script:State.defaults.Count) { 'set: each collection and analysis asks whether to use them' } else { 'not set' }))" -ForegroundColor White
            Write-Host "  [2] Forget remembered answers   (DCs, tenants, paths, last run, pending snapshot; default settings kept)" -ForegroundColor White
            switch ((Read-Host 'Choice (Enter = back)').Trim()) {
                '1' { Edit-DefaultSettings }
                '2' {
                    Clear-IDWolfState -KeepDefaults
                    $script:State = Read-LauncherState
                    Write-Host "Remembered answers deleted ($(Get-IDWolfStatePath))$(if ($script:State.defaults.Count) { '; the default settings are kept' })." -ForegroundColor Green
                }
            }
        }
        'Q' { break }
        default { Write-Host "Pick 1-7, D, S or Q." -ForegroundColor Yellow }
    }
    if ($choice -eq 'Q') { break }
}
Write-Host "Bye." -ForegroundColor DarkYellow
Stop-IDWolfLog $script:SessionLog
