# Interactive helpers shared by Start-IDWolf.ps1 and the IDWolf.ps1 wizard: open the finished
# report, and remember the wizard's choices between runs. Nothing here runs when IDWolf.ps1
# gets -Snapshot on the command line, or from Invoke-IDWolfScheduled.ps1.
#
# The remembered choices are a small JSON file in the user's profile
# (%LOCALAPPDATA%\IDWolf\wizard.json; IDWOLF_STATE_DIR moves it, for the tests). It holds
# choices and file paths only: never a password, an API key or anything read from the
# directory. Only the keys listed below are written, whatever a caller passes.

$script:WizardStateKeys = @{
    analyzer = @('Snapshot', 'OutJson', 'ExceptionsFile', 'CompareTo', 'PasswordQualityFile', 'AiMode', 'Model', 'AiAttempts', 'LastReport')
    launcher = @('LastRun', 'Server', 'Deep', 'Pq', 'WeakList', 'Next', 'Tenant', 'DeviceCode', 'Model', 'AiAttempts')
    pending  = @('Kind', 'Snapshot', 'PasswordQuality', 'CollectedAt')
}

function Get-IDWolfStatePath {
    $dir = $env:IDWOLF_STATE_DIR
    if (-not $dir) {
        $base = [Environment]::GetFolderPath('LocalApplicationData')
        if (-not $base) { $base = $HOME }
        $dir = Join-Path $base 'IDWolf'
    }
    return (Join-Path $dir 'wizard.json')
}

# Always returns @{ analyzer = @{}; launcher = @{}; pending = @{} }. A missing or damaged
# file is an empty state: remembering choices must never stop a run.
function Read-IDWolfState {
    $state = @{ analyzer = @{}; launcher = @{}; pending = @{} }
    $p = Get-IDWolfStatePath
    if (-not (Test-Path -LiteralPath $p)) { return $state }
    try {
        $raw = [System.IO.File]::ReadAllText($p) | ConvertFrom-Json
        foreach ($sec in @($script:WizardStateKeys.Keys)) {
            $o = $raw.$sec
            if (-not $o) { continue }
            foreach ($k in $script:WizardStateKeys[$sec]) {
                $v = $o.$k
                if ($null -ne $v) { $state[$sec][$k] = "$v" }
            }
        }
    }
    catch { Write-Warning "Remembered choices ignored (unreadable $p): $($_.Exception.Message)" }
    return $state
}

# Merges Values into one section and writes the file. A value of $null removes the key.
function Save-IDWolfState {
    param([ValidateSet('analyzer', 'launcher', 'pending')][string]$Section, [hashtable]$Values, [switch]$Replace)
    try {
        $state = Read-IDWolfState
        if ($Replace) { $state[$Section] = @{} }
        foreach ($k in @($Values.Keys)) {
            if ($script:WizardStateKeys[$Section] -notcontains $k) { continue }
            if ($null -eq $Values[$k]) { $state[$Section].Remove($k) } else { $state[$Section][$k] = "$($Values[$k])" }
        }
        $out = [ordered]@{ version = 1 }
        foreach ($sec in 'analyzer', 'launcher', 'pending') {
            $o = [ordered]@{}
            foreach ($k in $script:WizardStateKeys[$sec]) { if ($state[$sec].ContainsKey($k)) { $o[$k] = $state[$sec][$k] } }
            $out[$sec] = $o
        }
        $p = Get-IDWolfStatePath
        $dir = Split-Path -Parent $p
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllText($p, ($out | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
    }
    catch { Write-Warning "Could not remember the choices: $($_.Exception.Message)" }
}

function Clear-IDWolfState {
    $p = Get-IDWolfStatePath
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

# Last look before a run: every setting on one screen, change one by its number, Enter starts
# ($true), Q cancels ($false).
# Settings is an ordered dictionary (changed in place). Labels names each key. YesNo keys
# hold 'y' / 'n'; Choices limits a key to some values (upper case). Visible hides settings
# that don't apply (e.g. the report path when the run stops after collecting). OnChange
# runs after each edit with the key and the new value. Ask is there for the tests.
function Edit-RunSettings {
    param(
        [System.Collections.Specialized.OrderedDictionary]$Settings,
        [hashtable]$Labels = @{},
        [string[]]$YesNo = @(),
        [hashtable]$Choices = @{},
        [scriptblock]$Visible = { param($Key, $S) $true },
        [scriptblock]$OnChange = { param($Key, $Value) },
        [scriptblock]$Ask = { param($q) Read-Host $q }
    )
    while ($true) {
        $keys = @($Settings.Keys | Where-Object { & $Visible $_ $Settings })
        Write-Host "`nSettings:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $keys.Count; $i++) {
            $k = $keys[$i]; $v = "$($Settings[$k])"
            $shown = if ($YesNo -contains $k) { if ($v -eq 'y') { 'yes' } else { 'no' } } elseif ($v) { $v } else { '(none)' }
            $label = if ($Labels.ContainsKey($k)) { $Labels[$k] } else { $k }
            Write-Host ("  [{0}] {1,-34} {2}" -f ($i + 1), $label, $shown)
        }
        $e = & $Ask 'Enter a number to change, Q to cancel, or press Enter to start'
        if ([string]::IsNullOrWhiteSpace($e)) { return $true }
        if ("$e".Trim() -match '^[Qq]$') { return $false }
        if ("$e" -notmatch '^\d+$' -or [int]$e -lt 1 -or [int]$e -gt $keys.Count) { Write-Host "Pick 1-$($keys.Count), or Enter to start." -ForegroundColor Yellow; continue }
        $k = $keys[[int]$e - 1]
        $label = if ($Labels.ContainsKey($k)) { $Labels[$k] } else { $k }
        $hint = if ($YesNo -contains $k) { ' (y/n)' } elseif ($Choices.ContainsKey($k)) { " ($($Choices[$k] -join '/'))" } else { ' (- to clear)' }
        $v = & $Ask "  $label$hint [$($Settings[$k])]"
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        $v = "$v".Trim()
        if ($YesNo -contains $k) { $v = if ($v -match '^[YySs]') { 'y' } else { 'n' } }
        elseif ($Choices.ContainsKey($k)) {
            $v = $v.ToUpper()
            if ($Choices[$k] -notcontains $v) { Write-Host "Use one of: $($Choices[$k] -join ', ')." -ForegroundColor Yellow; continue }
        }
        elseif ($v -eq '-') { $v = '' }
        $Settings[$k] = $v
        & $OnChange $k $v
    }
}

# True only for a person at a console: not a scheduled task, not piped input or output.
function Test-InteractiveConsole {
    if (-not [Environment]::UserInteractive) { return $false }
    try { if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return $false } } catch { return $false }
    return $true
}

# Offers to open a report this run has just written, in the default browser. Only an .html
# file is ever opened (Invoke-Item on anything else could run it), and only one written at or
# after Since. Ask and Open are there for the tests.
function Request-OpenReport {
    param(
        [string]$Path,
        [datetime]$Since = [datetime]::MinValue,
        $Interactive = $null,
        [scriptblock]$Ask = { param($q) Read-Host $q },
        [scriptblock]$Open = { param($p) Invoke-Item -LiteralPath $p }
    )
    if ($null -eq $Interactive) { $Interactive = Test-InteractiveConsole }
    if (-not $Interactive -or -not $Path) { return $false }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    if ([System.IO.Path]::GetExtension($full) -ne '.html') { return $false }
    if ([System.IO.File]::GetLastWriteTime($full) -lt $Since) { return $false }
    $a = & $Ask 'Open the report in the default browser? (Y/n)'
    if ($a -and "$a" -notmatch '^\s*[YySs]') { return $false }
    try { & $Open $full; return $true }
    catch { Write-Host "Could not open it ($($_.Exception.Message)). The report is at $full" -ForegroundColor Yellow; return $false }
}
