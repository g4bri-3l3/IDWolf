<#
.SYNOPSIS
    IDWolf launcher: one guided entry point for collection and analysis.

.DESCRIPTION
    A small menu, so nobody has to remember parameters:

      1  Collect an AD snapshot          (Collect-ADSnapshot.ps1, domain-joined machine)
      2  Collect password quality        (Export-PasswordQuality.ps1, DCSync rights)
      3  Collect an Entra ID snapshot    (Collect-EntraSnapshot.ps1)
      4  Analyze a snapshot              (IDWolf.ps1, anywhere)
      5  Full AD run                     (collect, then analyze)
      6  Add an AI summary               (from a snapshot JSON or zip)
      7  Package for another machine     (snapshot + password quality in one zip)
      8  Full Entra run                  (collect, then analyze)

    Nothing here writes to the directory.

    Answers are remembered between runs (%LOCALAPPDATA%\IDWolf\wizard.json: choices and paths,
    never a password or a key) and offered as defaults. On start the launcher offers to pick up
    a snapshot that was collected but never analyzed, or to repeat the last full run with the
    same answers. A full run (5 or 8) asks everything first, then shows all the answers on
    one screen to change before Enter starts it. [C] in the menu deletes the file. After an analysis it offers to open the
    report in the default browser.

.PARAMETER Credential
    Account for the AD collection and the password-quality step. If password
    quality is denied, the launcher offers to ask for another one and keeps it
    for the session.

.EXAMPLE
    .\Start-IDWolf.ps1 -Credential (Get-Credential)
#>

[CmdletBinding()]
Param(
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
. (Join-Path $root 'lib\Bundle.ps1')
. (Join-Path $root 'lib\Wizard.ps1')

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
$script:State = Read-IDWolfState
$script:Replay = $false
function Read-Remembered {
    param([string]$Key, [string]$Prompt, [string]$Default = '', [switch]$Path)
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
# A new output path: asked, except while repeating the last run (the timestamped default is used).
function Read-NewPath {
    param([string]$Prompt, [string]$Default)
    if ($script:Replay) { Write-Host "${Prompt}: $Default" -ForegroundColor DarkGray; return $Default }
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
function ConvertTo-YN { param($Answer) if (Test-Yes $Answer) { return 'y' } return 'n' }

# Full runs (5 and 8): the questions first, then every answer on one screen (Edit-RunSettings,
# lib\Wizard.ps1) to check or change before anything runs. Enter starts.
$script:RunLabels = @{
    Server     = 'Domain controller or domain'
    OutFile    = 'Snapshot output path'
    Deep       = 'Deep collection'
    Pq         = 'Password quality (DCSync rights)'
    PqOut      = 'Password-quality output path'
    WeakList   = 'Weak/breached password list'
    Tenant     = 'Tenant (empty = sign-in default)'
    DeviceCode = 'Device-code sign-in'
    Next       = 'Then (A analyze, Z zip, S stop)'
    OutHtml    = 'Report HTML path'
    Model      = 'Gemini model'
    AiAttempts = 'Gemini attempts (0 = keep trying)'
}
# Settings that are remembered for next time; output paths are new on every run.
$script:RunRemembered = @('Server', 'Deep', 'Pq', 'WeakList', 'Tenant', 'DeviceCode', 'Next', 'Model', 'AiAttempts')
function Save-RunSetting {
    param([string]$Key, $Value)
    if ($Key -eq 'Server') { $script:Server = "$Value" }
    if ($script:RunRemembered -notcontains $Key) { return }
    $script:State.launcher[$Key] = "$Value"
    Save-IDWolfState -Section launcher -Values @{ $Key = "$Value" }
}
# What happens after the collection, asked up front. The report, model and attempts get their
# defaults even when not asked, so switching to [A] on the settings screen has values to show.
function Add-AfterCollectionSettings {
    param($S)
    $L = $script:State.launcher
    $S.Next = ConvertTo-NextChoice (Read-Remembered 'Next' "After collecting: analyze here [A], package a zip for another machine [Z], or stop [S]?" 'A')
    $S.OutHtml = "output\report_{0}.html" -f (Ts)
    $S.Model = if ($L.Model) { $L.Model } else { 'gemini-3.8-flash' }
    $S.AiAttempts = if ($L.AiAttempts) { $L.AiAttempts } else { '3' }
    if ($S.Next -eq 'A') {
        $S.OutHtml = Read-NewPath "Report HTML path" $S.OutHtml
        $S.Model = Read-Remembered 'Model' "Gemini model" 'gemini-3.8-flash'
        $S.AiAttempts = Read-Remembered 'AiAttempts' "Gemini attempts on timeout / busy server, 0 = keep trying" '3'
    }
}
function Confirm-RunSettings {
    param($S, [bool]$Joined = $true)
    return Edit-RunSettings -Settings $S -Labels $script:RunLabels -YesNo @('Deep', 'Pq', 'DeviceCode') -Choices @{ Next = @('A', 'Z', 'S') } `
        -Visible ({ param($Key, $Set)
            if (@('Pq', 'PqOut', 'WeakList') -contains $Key -and -not $Joined) { return $false }
            if (@('PqOut', 'WeakList') -contains $Key -and $Set.Pq -ne 'y') { return $false }
            if (@('OutHtml', 'Model', 'AiAttempts') -contains $Key -and $Set.Next -ne 'A') { return $false }
            return $true
        }.GetNewClosure()) `
        -OnChange { param($Key, $Value) Save-RunSetting $Key $Value }
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
    param([string]$OutFile, [string]$WeakList = "")
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $p = @{ OutFile = $OutFile } + (Get-CredParams)
        if ($WeakList) { $p['WeakPasswordsFile'] = $WeakList }
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

# Workgroup PCs: no domain to find, no domain identity. Ask once for the DC
# and an account and keep both for the session. Returns the extra collector
# parameters, or $null if the user gives up.
$script:Server = ''
function Test-DomainJoined {
    try { return [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { return $true }
}
function Get-WorkgroupParams {
    if (Test-DomainJoined) { return @{} }
    Write-Host "This computer is not joined to a domain. Collection needs the name of a domain controller and a domain account." -ForegroundColor Yellow
    if (-not $script:Server) { $script:Server = Read-Remembered 'Server' "Domain controller or domain (e.g. dc01.corp.local; - to cancel)" }
    if (-not $script:Server) { return $null }
    if (-not $script:Credential) {
        try { $script:Credential = Get-Credential -Message "Domain account (DOMAIN\user) for the read-only AD collection" } catch { }
        if (-not $script:Credential) { Write-Host "No credentials given: the queries will probably be denied." -ForegroundColor Yellow }
    }
    return @{ Server = $script:Server }
}

# After a collection: analyze here, package for another machine, or stop. The snapshot stays
# pending until one of them is done (an analysis that wrote no report keeps it pending).
# Preset: the answers of a full run, already checked on the settings screen (Next, OutHtml,
# Model, AiAttempts). Without it (a pending snapshot picked up on start) they are asked here.
function Invoke-AfterCollection {
    param([string]$Snapshot, [string]$PasswordQuality = '', $Preset = $null)
    if ($Preset) { $next = "$($Preset.Next)" }
    else { $next = ConvertTo-NextChoice (Read-Remembered 'Next' "Analyze here [A], package a zip to analyze on another machine [Z], or stop [S]?" 'A') }
    if ($next -eq 'Z') { Invoke-Package -Snapshot $Snapshot -PasswordQuality $PasswordQuality; Clear-PendingSnapshot }
    elseif ($next -eq 'S') { Clear-PendingSnapshot }
    else {
        if ($Preset) { $html = "$($Preset.OutHtml)"; $m = "$($Preset.Model)"; $r = "$($Preset.AiAttempts)" }
        else {
            $html = Read-NewPath "Report HTML path" ("output\report_{0}.html" -f (Ts))
            $m = Read-Remembered 'Model' "Gemini model" 'gemini-3.8-flash'
            $r = Read-Remembered 'AiAttempts' "Gemini attempts on timeout / busy server, 0 = keep trying" '3'
        }
        $ap = @{ Snapshot = $Snapshot; OutHtml = $html }
        if ($PasswordQuality) { $ap['PasswordQualityFile'] = $PasswordQuality }
        if ($m) { $ap['Model'] = $m }
        if ($r -match '^\d+$') { $ap['AiMaxAttempts'] = [int]$r }
        # The analyzer still asks whether to send to Gemini or skip.
        $t0 = Get-Date
        Invoke-Sub 'IDWolf.ps1' $ap
        if (Test-Path -LiteralPath $ap.OutHtml) { Clear-PendingSnapshot }
        [void](Request-OpenReport -Path $ap.OutHtml -Since $t0)
    }
}

Show-Banner

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
elseif (@('5', '8') -contains $script:State.launcher.LastRun) {
    $L = $script:State.launcher
    $what = if ($L.LastRun -eq '5') {
        "full AD run$(if (Test-Yes $L.Deep) { ', deep collection' })$(if ($L.Server) { ", server $($L.Server)" })$(if (Test-Yes $L.Pq) { ', password quality' })"
    }
    else { "full Entra run$(if ($L.Tenant) { ", tenant $($L.Tenant)" })" }
    Write-Host "`nLast time: $what." -ForegroundColor Cyan
    $a = Read-Host "Repeat it with the same choices? (Y/n)"
    if ([string]::IsNullOrWhiteSpace($a) -or (Test-Yes $a)) { $script:Replay = $true; $script:QueuedChoice = $L.LastRun }
}

while ($true) {
    Write-Host ""
    Write-Host "  [1] Collect AD snapshot        (on a domain-joined machine, RSAT)" -ForegroundColor White
    Write-Host "  [2] Collect password quality   (DSInternals + DCSync rights, hashless)" -ForegroundColor White
    Write-Host "  [3] Collect Entra ID snapshot  (Microsoft Graph)" -ForegroundColor White
    Write-Host "  [4] Analyze a snapshot         (report + choose Gemini model)" -ForegroundColor White
    Write-Host "  [5] Full AD run                (collect, then analyze)" -ForegroundColor White
    Write-Host "  [6] Add AI summary             (from the snapshot JSON or zip, not the report)" -ForegroundColor White
    Write-Host "  [7] Package for another machine (snapshot + password quality in one zip)" -ForegroundColor White
    Write-Host "  [8] Full Entra run             (collect, then analyze)" -ForegroundColor White
    Write-Host "  [C] Forget remembered choices" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor White
    if ($script:QueuedChoice) { $choice = $script:QueuedChoice; $script:QueuedChoice = $null; Write-Host "`nChoice: $choice (repeating the last run)" }
    else { $script:Replay = $false; $choice = (Read-Host "`nChoice").Trim().ToUpper() }
    if (@('5', '8') -contains $choice) { $script:State.launcher['LastRun'] = $choice; Save-IDWolfState -Section launcher -Values @{ LastRun = $choice } }
    switch ($choice) {
        '1' { Invoke-Sub 'Collect-ADSnapshot.ps1' (Get-CredParams) }
        '2' {
            if (-not (Test-DomainJoined)) {
                Write-Host "This computer is not joined to a domain: live replication can't find the PDC from here." -ForegroundColor Yellow
                Write-Host "Run this option on a domain-joined machine or the DC, or run Export-PasswordQuality.ps1 -FromDatabase ntds.dit -BootKeyFile SYSTEM." -ForegroundColor Yellow
                continue
            }
            $pqOut = Read-Path "Password-quality output path" ("output\pwq_{0}.json" -f (Ts))
            $wl = Read-Remembered 'WeakList' "Weak/breached password list path (optional; - for none)" -Path
            if (Invoke-PasswordQualityStep -OutFile $pqOut -WeakList $wl) { Write-Host "Password-quality report ready: $pqOut" -ForegroundColor Green }
        }
        '3' { Invoke-Sub 'Collect-EntraSnapshot.ps1' }
        '4' { Invoke-Sub 'IDWolf.ps1' }
        '5' {
            $wg = Get-WorkgroupParams
            if ($null -eq $wg) { Write-Host "Cancelled: no domain controller given." -ForegroundColor Yellow; continue }
            $joined = Test-DomainJoined
            $s = [ordered]@{}
            if ($wg.Server) { $s.Server = $wg.Server }
            # Timestamped file, so a re-run never overwrites the last snapshot.
            $s.OutFile = Read-NewPath "AD snapshot output path" ("output\adsnap_{0}.json" -f (Ts))
            $s.Deep = ConvertTo-YN (Read-Remembered 'Deep' "Deep collection? (y/n)" 'n')
            # Separate on purpose: it reads password hashes, the AD collection never does.
            $s.Pq = 'n'
            if ($joined) { $s.Pq = ConvertTo-YN (Read-Remembered 'Pq' "Also collect password quality? Needs DSInternals and DCSync rights; run from the DC or a trusted admin host (y/n)" 'n') }
            else { Write-Host "Password quality skipped: it needs a domain-joined machine (or the DC) to find the PDC. Run option 2 there." -ForegroundColor Yellow }
            $s.PqOut = "output\pwq_{0}.json" -f (Ts)
            $s.WeakList = "$($script:State.launcher.WeakList)"
            if ($s.Pq -eq 'y') {
                $s.PqOut = Read-NewPath "Password-quality output path" $s.PqOut
                $s.WeakList = Read-Remembered 'WeakList' "Weak/breached password list path (optional; - for none)" -Path
            }
            Add-AfterCollectionSettings $s
            if (-not (Confirm-RunSettings $s $joined)) { Write-Host "Cancelled: nothing collected." -ForegroundColor Yellow; continue }

            $p = @{ OutFile = $s.OutFile } + (Get-CredParams) + $wg
            if ($s.Server) { $p['Server'] = $s.Server }
            if ($s.Deep -eq 'y') { $p['Deep'] = $true }
            Invoke-Sub 'Collect-ADSnapshot.ps1' $p
            if (Test-Path -LiteralPath $s.OutFile) {
                Write-Host "`nSnapshot ready: $($s.OutFile)" -ForegroundColor Green
                Set-PendingSnapshot -Kind ad -Snapshot $s.OutFile
                $pqOut = ""
                if ($joined -and $s.Pq -eq 'y') {
                    $pqOut = Invoke-PasswordQualityStep -OutFile $s.PqOut -WeakList $s.WeakList
                    if (-not $pqOut) { Write-Host "Password quality not produced (see messages); continuing without it." -ForegroundColor Yellow }
                    else { Set-PendingSnapshot -Kind ad -Snapshot $s.OutFile -PasswordQuality $pqOut }
                }
                Invoke-AfterCollection -Snapshot $s.OutFile -PasswordQuality $pqOut -Preset $s
            }
            else { Write-Host "Snapshot not produced; see messages above." -ForegroundColor Red }
        }
        '6' {
            # AI summary for an existing analysis. It starts from the snapshot
            # (tokenizing needs the directory data) and rewrites the report.
            $snaps = @(Get-ChildItem -Path '.', 'output' -Filter *.json -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)snapshot|adsnap|entra' } | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
            if ($snaps.Count -eq 0) { $snaps = @(Get-ChildItem -Path '.', 'output' -Filter *.json -ErrorAction SilentlyContinue | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName }) }
            $snaps = @($snaps) + @(Get-ChildItem -Path '.', 'output' -Filter *.zip -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)idwolf' } | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
            $snap = ""
            if ($snaps.Count -gt 0) {
                for ($i = 0; $i -lt $snaps.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $snaps[$i]) }
                $pick = Read-Host "Pick a snapshot number, or type a path (Tab completes)"
                if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $snaps.Count) { $snap = $snaps[[int]$pick - 1] } elseif ($pick) { $snap = $pick } else { $snap = Read-Path "Snapshot path" }
            }
            else { $snap = Read-Path "Snapshot path" }
            if ($snap -and $snap -notmatch '(?i)\.(json|zip)$') {
                Write-Host "Option 6 needs the snapshot JSON (adsnapshot_*.json / entrasnapshot_*.json) or its zip, not a report ($snap)." -ForegroundColor Yellow
                Write-Host "The report is regenerated from the snapshot, with the AI section added." -ForegroundColor Yellow
                $snap = ""
            }
            if ($snap -and (Test-Path -LiteralPath $snap)) {
                $rep = Read-Path "Report HTML to (re)write" ("output\report_{0}.html" -f (Ts))
                $ap = @{ Snapshot = $snap; OutHtml = $rep }
                # No -SendToAI: the analyzer writes <report>_ai_prompt.txt first, shows its path, asks before
                # sending, and asks for the API key then if there is none. Nothing leaves before that "y".
                Write-Host "The exact text for Gemini will be saved next to the report as $([System.IO.Path]::GetFileNameWithoutExtension($rep))_ai_prompt.txt, and you confirm before anything is sent." -ForegroundColor Cyan
                $m = Read-Remembered 'Model' "Gemini model" 'gemini-3.8-flash'
                if ($m) { $ap['Model'] = $m }
                $r = Read-Remembered 'AiAttempts' "Gemini attempts on timeout / busy server, 0 = keep trying" '3'
                if ($r -match '^\d+$') { $ap['AiMaxAttempts'] = [int]$r }
                # A zip brings its own password-quality report, if it has one.
                if ($snap -notmatch '(?i)\.zip$') {
                    $pqf = @(Get-ChildItem -Path '.', 'output' -Filter '*.json' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)pwq|passwordquality' } | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
                    $pq = Read-Path "Password-quality JSON to include (optional, Enter to skip)" $(if ($pqf.Count) { $pqf[0] } else { "" })
                    if ($pq) { $ap['PasswordQualityFile'] = $pq }
                }
                $t0 = Get-Date
                Invoke-Sub 'IDWolf.ps1' $ap
                [void](Request-OpenReport -Path $rep -Since $t0)
            }
            elseif ($snap) { Write-Host "Snapshot not found." -ForegroundColor Red }
        }
        '7' {
            $snapDef = @(Get-ChildItem -Path '.', 'output' -Filter *.json -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)snapshot|adsnap|entra' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
            $s = Read-Path "Snapshot JSON" $(if ($snapDef.Count) { $snapDef[0] } else { "" })
            if (-not $s -or -not (Test-Path -LiteralPath $s)) { Write-Host "Snapshot not found." -ForegroundColor Red }
            else {
                $pqDef = @(Get-ChildItem -Path '.', 'output' -Filter *.json -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)pwq|passwordquality' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { Resolve-Path -Relative -LiteralPath $_.FullName })
                $pq = Read-Path "Password-quality JSON to add (optional, Enter to skip)" $(if ($pqDef.Count) { $pqDef[0] } else { "" })
                if ($pq -and -not (Test-Path -LiteralPath $pq)) { Write-Host "Password-quality file not found: $pq" -ForegroundColor Red }
                else { Invoke-Package -Snapshot $s -PasswordQuality $pq }
            }
        }
        '8' {
            $s = [ordered]@{}
            $s.OutFile = Read-NewPath "Entra snapshot output path" ("output\entrasnapshot_{0}.json" -f (Ts))
            $s.Tenant = Read-Remembered 'Tenant' "Tenant ID or domain (Enter = last one or the sign-in default; - for the sign-in default)"
            $s.DeviceCode = ConvertTo-YN (Read-Remembered 'DeviceCode' "Use device-code sign-in? (y/n)" 'n')
            Add-AfterCollectionSettings $s
            if (-not (Confirm-RunSettings $s)) { Write-Host "Cancelled: nothing collected." -ForegroundColor Yellow; continue }

            $p = @{ OutFile = $s.OutFile }
            if ($s.Tenant) { $p['TenantId'] = $s.Tenant }
            if ($s.DeviceCode -eq 'y') { $p['UseDeviceCode'] = $true }
            Invoke-Sub 'Collect-EntraSnapshot.ps1' $p
            if (Test-Path -LiteralPath $s.OutFile) {
                Write-Host "`nSnapshot ready: $($s.OutFile)" -ForegroundColor Green
                Set-PendingSnapshot -Kind entra -Snapshot $s.OutFile
                Invoke-AfterCollection -Snapshot $s.OutFile -Preset $s
            }
            else { Write-Host "Snapshot not produced; see messages above." -ForegroundColor Red }
        }
        'C' {
            Clear-IDWolfState
            $script:State = Read-IDWolfState
            Write-Host "Remembered choices deleted ($(Get-IDWolfStatePath))." -ForegroundColor Green
        }
        'Q' { break }
        default { Write-Host "Pick 1-8, C or Q." -ForegroundColor Yellow }
    }
    if ($choice -eq 'Q') { break }
}
Write-Host "Bye." -ForegroundColor DarkYellow
