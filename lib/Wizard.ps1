# Interactive helpers shared by Start-IDWolf.ps1 and the IDWolf.ps1 wizard: open the finished
# report, and remember the wizard's choices between runs. Nothing here runs when IDWolf.ps1
# gets -Snapshot on the command line, or from Invoke-IDWolfScheduled.ps1.
#
# The remembered choices are a small JSON file in the user's profile
# (%LOCALAPPDATA%\IDWolf\wizard.json; IDWOLF_STATE_DIR moves it, for the tests). It holds
# choices and file paths only: never a password, an API key or anything read from the
# directory. Only the keys listed below are written, whatever a caller passes.
# 'defaults' are the launcher's default settings ([S] in its menu): set on purpose, used by a
# run only when the user says so, never changed by the answers given during a run.

$script:WizardStateKeys = @{
    analyzer = @('Snapshot', 'OutJson', 'ExceptionsFile', 'CompareTo', 'PasswordQualityFile', 'AiMode', 'Model', 'AiAttempts', 'LastReport')
    launcher = @('LastRun', 'Server', 'Deep', 'Gentle', 'ThrottleMs', 'Pq', 'WeakList', 'Next', 'Ai', 'Tenant', 'DeviceCode', 'Model', 'AiAttempts')
    pending  = @('Kind', 'Snapshot', 'PasswordQuality', 'CollectedAt')
    defaults = @('Server', 'Deep', 'Gentle', 'ThrottleMs', 'Pq', 'WeakList', 'Tenant', 'DeviceCode', 'Next', 'Ai', 'Model', 'AiAttempts')
}
$script:WizardStateSections = @('analyzer', 'launcher', 'pending', 'defaults')

# The DNS name of the domain a plain JSON snapshot describes ('' for an Entra snapshot, a zip,
# or a file that can't be read).
function Get-SnapshotDomainName {
    param([string]$Path)
    if (-not $Path -or $Path -notmatch '(?i)\.json$' -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    try { return "$(([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).ProviderPath) | ConvertFrom-Json).domain.dnsRoot)" }
    catch { return '' }
}

# Password-quality reports (Export-PasswordQuality.ps1) in this folder and .\output for one
# domain, newest first. Matched on the domain written inside the report, never on the file
# name: a report of another domain is never offered for a snapshot.
function Get-PasswordQualityCandidates {
    param([string]$Domain, [string[]]$Dirs = @('.', 'output'))
    if (-not $Domain) { return }
    $files = @(Get-ChildItem -Path $Dirs -Filter '*.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)pwq|passwordquality' } | Sort-Object LastWriteTimeUtc, FullName -Descending)
    foreach ($f in $files) {
        try { $d = "$(([System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json).domain)" } catch { continue }
        if ($d -and $d -eq $Domain) { Resolve-Path -Relative -LiteralPath $f.FullName }
    }
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

# Always returns @{ analyzer = @{}; launcher = @{}; pending = @{}; defaults = @{} }. A missing
# or damaged file is an empty state: remembering choices must never stop a run.
function Read-IDWolfState {
    $state = @{ analyzer = @{}; launcher = @{}; pending = @{}; defaults = @{} }
    $p = Get-IDWolfStatePath
    if (-not (Test-Path -LiteralPath $p)) { return $state }
    try {
        $raw = [System.IO.File]::ReadAllText($p) | ConvertFrom-Json
        foreach ($sec in $script:WizardStateSections) {
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

# Merges Values (a hashtable or an ordered dictionary) into one section and writes the file.
# A value of $null removes the key.
function Save-IDWolfState {
    param([ValidateSet('analyzer', 'launcher', 'pending', 'defaults')][string]$Section, [System.Collections.IDictionary]$Values, [switch]$Replace)
    try {
        $state = Read-IDWolfState
        if ($Replace) { $state[$Section] = @{} }
        foreach ($k in @($Values.Keys)) {
            if ($script:WizardStateKeys[$Section] -notcontains $k) { continue }
            if ($null -eq $Values[$k]) { $state[$Section].Remove($k) } else { $state[$Section][$k] = "$($Values[$k])" }
        }
        $out = [ordered]@{ version = 1 }
        foreach ($sec in $script:WizardStateSections) {
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

# Deletes the file. KeepDefaults keeps the default settings and forgets everything else.
function Clear-IDWolfState {
    param([switch]$KeepDefaults)
    $p = Get-IDWolfStatePath
    if ($KeepDefaults) {
        $d = (Read-IDWolfState).defaults
        if ($d.Count) {
            foreach ($sec in 'analyzer', 'launcher', 'pending') { Save-IDWolfState -Section $sec -Values @{} -Replace }
            return
        }
    }
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

# Last look before a run: every setting on one screen, change one by its number, Enter starts
# ($true), Q cancels ($false).
# Settings is an ordered dictionary (changed in place). Labels names each key. YesNo keys
# hold 'y' / 'n'; Choices limits a key to some values (upper case). Visible hides settings
# that don't apply (e.g. the report path when the run stops after collecting). OnChange
# runs after each edit with the key and the new value. Pickers maps a key to a scriptblock
# that gets the current value and returns the new one (e.g. a list to pick from), instead of
# a typed answer. Confirm names what Enter does ('start'; 'save' for the default settings).
# Ask is there for the tests.
function Edit-RunSettings {
    param(
        [System.Collections.Specialized.OrderedDictionary]$Settings,
        [hashtable]$Labels = @{},
        [string[]]$YesNo = @(),
        [hashtable]$Choices = @{},
        [hashtable]$Pickers = @{},
        [scriptblock]$Visible = { param($Key, $S) $true },
        [scriptblock]$OnChange = { param($Key, $Value) },
        [string]$Confirm = 'start',
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
        $e = & $Ask "Enter a number to change, Q to cancel, or press Enter to $Confirm"
        if ([string]::IsNullOrWhiteSpace($e)) { return $true }
        if ("$e".Trim() -match '^[Qq]$') { return $false }
        if ("$e" -notmatch '^\d+$' -or [int]$e -lt 1 -or [int]$e -gt $keys.Count) { Write-Host "Pick 1-$($keys.Count), or Enter to $Confirm." -ForegroundColor Yellow; continue }
        $k = $keys[[int]$e - 1]
        $label = if ($Labels.ContainsKey($k)) { $Labels[$k] } else { $k }
        if ($Pickers.ContainsKey($k)) {
            $v = "$(& $Pickers[$k] "$($Settings[$k])")"
            if ($v -ne "$($Settings[$k])") { $Settings[$k] = $v; & $OnChange $k $v }
            continue
        }
        $hint =if ($YesNo -contains $k) { ' (y/n)' } elseif ($Choices.ContainsKey($k)) { " ($($Choices[$k] -join '/'))" } else { ' (- to clear)' }
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

# What the account that will collect can do, read before anything runs (launcher, AD
# collections): elevated session, Domain Admins / Enterprise Admins through its token groups,
# replication (DCSync) rights on the domain head. Read-only LDAP through .NET, so no RSAT is
# needed. Never throws: anything it can't read comes back as $null with the reason in Error.
function Get-CollectorRights {
    param([string]$Server = '', [System.Management.Automation.PSCredential]$Credential = $null)
    $r = [ordered]@{ Account = ''; Elevated = $null; DomainAdmin = $null; EnterpriseAdmin = $null; Replication = $null; FilteredByUac = $false; Protocol = ''; Error = '' }
    try {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent()
        $r.Elevated = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $r.Account = if ($Credential) { $Credential.UserName } else { $me.Name }
    }
    catch { }
    try {
        # LDAP on 389, or LDAPS on 636 when only that answers (Open-LdapRootDse, lib\Connection.ps1,
        # which the launcher loads too). An explicit bind, so a missing domain or a refused account
        # surfaces as LDAP's own message.
        $conn = Open-LdapRootDse -Server $Server -Credential $Credential -Properties @('defaultNamingContext', 'rootDomainNamingContext')
        if ($conn.Error) { throw "no domain controller answered over LDAP$(if ($Server) { " ($Server)" }): $($conn.Error)" }
        $prefix = $conn.Prefix; $r.Protocol = $conn.Protocol
        $open = { param([string]$Path) New-LdapEntry $Path $Credential -Ssl:$conn.Ssl }
        $rootDse = $conn.Root
        $nc = "$($rootDse.Properties['defaultNamingContext'].Value)"
        if (-not $nc) { throw 'the domain could not be reached' }
        $rootNc = "$($rootDse.Properties['rootDomainNamingContext'].Value)"
        $head = & $open ($prefix + $nc)
        $domSid = (New-Object Security.Principal.SecurityIdentifier([byte[]]$head.Properties['objectSid'].Value, 0)).Value
        $rootSid = $domSid
        if ($rootNc -and $rootNc -ne $nc) { $rootSid = (New-Object Security.Principal.SecurityIdentifier([byte[]](& $open ($prefix + $rootNc)).Properties['objectSid'].Value, 0)).Value }

        # The account's SID and its token groups (nested groups included).
        $sids = @{}
        if ($Credential) {
            $n = "$($Credential.UserName)"
            $sam = if ($n -match '\\') { ($n -split '\\', 2)[1] } elseif ($n -match '@') { ($n -split '@', 2)[0] } else { $n }
            $esc = [regex]::Replace($sam, '[\\*()\x00]', { param($m) '\{0:x2}' -f [int][char]$m.Value })
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($head, "(&(objectCategory=person)(sAMAccountName=$esc))", @('distinguishedName'))
            $hit = $searcher.FindOne()
            if (-not $hit) { throw "account $sam not found in $nc" }
            $u = & $open ($prefix + "$($hit.Properties['distinguishedname'][0])")
            $u.RefreshCache(@('tokenGroups', 'objectSid'))
            $sids[(New-Object Security.Principal.SecurityIdentifier([byte[]]$u.Properties['objectSid'].Value, 0)).Value] = $true
            foreach ($b in @($u.Properties['tokenGroups'])) { $sids[(New-Object Security.Principal.SecurityIdentifier([byte[]]$b, 0)).Value] = $true }
        }
        else {
            # In a session that is not elevated, UAC keeps the admin groups in the token as
            # deny-only: they grant nothing (on a DC that turns a Domain Admin into a standard user).
            $deny = @{}
            foreach ($c in @($me.Claims | Where-Object { "$($_.Type)" -like '*denyonlysid' })) { $deny["$($c.Value)"] = $true }
            $sids[$me.User.Value] = $true
            foreach ($g in @($me.Groups)) { if (-not $deny.ContainsKey($g.Value)) { $sids[$g.Value] = $true } }
            $r.FilteredByUac = $deny.ContainsKey("$domSid-512") -or $deny.ContainsKey("$rootSid-519")
        }
        $r.DomainAdmin = $sids.ContainsKey("$domSid-512")
        $r.EnterpriseAdmin = $sids.ContainsKey("$rootSid-519")

        # Replication needs both extended rights on the domain head, from any of those SIDs.
        $get = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; $getAll = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        $hasGet = $false; $hasAll = $false
        foreach ($ace in @($head.ObjectSecurity.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
            if ("$($ace.AccessControlType)" -ne 'Allow' -or -not $sids.ContainsKey($ace.IdentityReference.Value)) { continue }
            $rights = "$($ace.ActiveDirectoryRights)"; $ot = "$($ace.ObjectType)".ToLower()
            $any = $rights -match '\bGenericAll\b' -or ($rights -match '\bExtendedRight\b' -and $ot -eq '00000000-0000-0000-0000-000000000000')
            if ($any -or ($rights -match '\bExtendedRight\b' -and $ot -eq $get)) { $hasGet = $true }
            if ($any -or ($rights -match '\bExtendedRight\b' -and $ot -eq $getAll)) { $hasAll = $true }
        }
        $r.Replication = ($hasGet -and $hasAll)
    }
    catch { $r.Error = "$($_.Exception.Message)".Trim() }
    return [PSCustomObject]$r
}

# This window: elevated or not, on a domain controller or not, RSAT's ActiveDirectory module
# present or not. Local reads only, instant; anything unreadable comes back $null.
function Get-SessionStatus {
    $s = [ordered]@{ Elevated = $null; OnDc = $null; Rsat = $null }
    try { $s.Elevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
    # ProductType 2 = domain controller.
    try { $s.OnDc = ([int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType -eq 2) } catch { }
    try { $s.Rsat = [bool](Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction Stop) } catch { }
    return [PSCustomObject]$s
}

# What a collection with these rights will not see, as the catalog's Needs sections, by reason.
# Rights is Get-CollectorRights' result; an unreadable domain gives nothing (unknown, not clean).
function Get-RightsGaps {
    param($Rights, [bool]$Deep = $false)
    $gaps = New-Object System.Collections.Generic.List[object]
    if (-not $Rights -or $Rights.Error) { return $gaps }
    $admin = $Rights.DomainAdmin -or $Rights.EnterpriseAdmin
    $why = if ($Rights.FilteredByUac) { 'admin rights filtered by UAC (window not elevated)' } else { 'not a Domain or Enterprise Admin' }
    if (-not $admin) {
        $gaps.Add([PSCustomObject]@{ Reason = "$why`: fine-grained password policies and the DNS zone transfer setting"; Sections = @('domain.fineGrainedPolicies', 'dnsTransfer') })
        $gaps.Add([PSCustomObject]@{ Reason = "$why`: live state of the DCs and CA settings (admin on those servers)"; Sections = @('health.dcState', 'health.coercion', 'health.netbios', 'health.webClient', 'health.osBuild', 'adcs.caRegistry', 'adcs.caWebEnrollment') })
        if ($Deep) { $gaps.Add([PSCustomObject]@{ Reason = "$why`: the deep sweep (every object's ACL, KDS root keys)"; Sections = @('deepAcls', 'kdsRootKeys') }) }
    }
    if (-not $Rights.Replication) { $gaps.Add([PSCustomObject]@{ Reason = 'no replication (DCSync) rights: password quality'; Sections = @('passwordQuality') }) }
    return $gaps
}

# The checks of a catalog ($script:CheckCatalog) that need any of those sections, sorted.
function Get-ChecksNeeding {
    param($Catalog, [string[]]$Sections)
    return @($Catalog.Keys | Where-Object { $k = $_; @(@($Catalog[$k].Needs) | Where-Object { $Sections -contains $_ }).Count } | Sort-Object)
}

# Session log of an interactive run (launcher, analyzer wizard): a transcript in .\output with
# every question, every answer typed and everything printed, collector and analyzer included.
# Hidden prompts (-AsSecureString: API key, package passwords) and Get-Credential leave nothing
# in it. One log per session: the analyzer started from the launcher writes into the launcher's
# (IDWOLF_LOG). Returns the path, or '' when it is not this call's log to stop.
function Start-IDWolfLog {
    param([string]$Name = 'idwolf', [switch]$Force)
    if ($env:IDWOLF_LOG) { return '' }
    # Only a person at a console: piped answers (tests, scripts) are not hidden and stay out.
    if (-not $Force -and -not (Test-InteractiveConsole)) { return '' }
    try {
        $od = Join-Path (Get-Location).Path 'output'
        if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }
        $p = Join-Path $od ("{0}_{1}.log" -f $Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Start-Transcript -LiteralPath $p -ErrorAction Stop | Out-Null
        $env:IDWOLF_LOG = $p
        Write-Host "Session log: $p (choices and console output; it names directory objects: confidential)" -ForegroundColor DarkGray
        return $p
    }
    catch { Write-Warning "No session log: $($_.Exception.Message)"; return '' }
}
function Stop-IDWolfLog {
    param([string]$Path)
    if (-not $Path) { return }
    Write-Host "Session log written to $Path" -ForegroundColor DarkGray
    try { Stop-Transcript | Out-Null } catch { }
    $env:IDWOLF_LOG = $null
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
