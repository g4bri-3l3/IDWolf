# Shared helpers: constants, dates, the snapshot index and Tier 0 membership.
# Groups are matched by SID/RID, never by name, so "Admins. del dominio" works
# just like "Domain Admins".

# --------------------------------------------------------------------------
# userAccountControl flags
# --------------------------------------------------------------------------
$script:UAC = @{
    ACCOUNTDISABLE                 = 0x2
    PASSWD_NOTREQD                 = 0x20
    ENCRYPTED_TEXT_PWD_ALLOWED     = 0x80
    SERVER_TRUST_ACCOUNT           = 0x2000
    DONT_EXPIRE_PASSWORD           = 0x10000
    SMARTCARD_REQUIRED             = 0x40000
    TRUSTED_FOR_DELEGATION         = 0x80000
    NOT_DELEGATED                  = 0x100000
    USE_DES_KEY_ONLY               = 0x200000
    DONT_REQ_PREAUTH               = 0x400000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT        = 0x4000000
}
function Test-Uac {
    param($Principal, [string]$Flag)
    return ((([int64]$Principal.userAccountControl) -band $script:UAC[$Flag]) -ne 0)
}

# msDS-SupportedEncryptionTypes bits
$script:ENC_DES = 0x3
$script:ENC_RC4 = 0x4
$script:ENC_AES = 0x18

# trustAttributes bits
$script:TRUST_TREAT_AS_EXTERNAL = 0x40
$script:TRUST_ENABLE_TGT_DELEGATION = 0x800
# Trust passwords rotate every 30 days while the trust is alive: a TDO untouched for this long looks abandoned.
$script:TRUST_INACTIVE_DAYS = 180

# --------------------------------------------------------------------------
# Tier 0 groups. Rid: domain SID; RootRid: forest root SID; Sid: builtin.
# --------------------------------------------------------------------------
$script:PrivilegedGroupDefs = @(
    @{ Key = 'DomainAdmins';        Rid = 512;     Label = 'Domain Admins' }
    @{ Key = 'EnterpriseAdmins';    RootRid = 519; Label = 'Enterprise Admins' }
    @{ Key = 'SchemaAdmins';        RootRid = 518; Label = 'Schema Admins' }
    @{ Key = 'Administrators';      Sid = 'S-1-5-32-544'; Label = 'Administrators (builtin)' }
    @{ Key = 'AccountOperators';    Sid = 'S-1-5-32-548'; Label = 'Account Operators' }
    @{ Key = 'ServerOperators';     Sid = 'S-1-5-32-549'; Label = 'Server Operators' }
    @{ Key = 'PrintOperators';      Sid = 'S-1-5-32-550'; Label = 'Print Operators' }
    @{ Key = 'BackupOperators';     Sid = 'S-1-5-32-551'; Label = 'Backup Operators' }
    @{ Key = 'KeyAdmins';           Rid = 526;     Label = 'Key Admins' }
    @{ Key = 'EnterpriseKeyAdmins'; RootRid = 527; Label = 'Enterprise Key Admins' }
    @{ Key = 'GPCreatorOwners';     Rid = 520;     Label = 'Group Policy Creator Owners' }
    @{ Key = 'DnsAdmins';           Name = 'DnsAdmins'; Label = 'DnsAdmins' }
)

# RIDs whose members are expected machine accounts, not people.
$script:DcPrimaryGroupRids = @(516, 521)
# Normal primaryGroupID values: Domain Users, Domain Guests, Domain Computers, DCs, RODCs.
$script:NormalPrimaryGroupRids = @(513, 514, 515, 516, 521)

# --------------------------------------------------------------------------
# Dates are ISO 8601 UTC. PS 7 parses them into [datetime], PS 5.1 leaves
# strings; both work.
# --------------------------------------------------------------------------
function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        return [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
    }
    catch { return $null }
}

# Age in days at snapshot time, not today, so the same snapshot always gives
# the same findings. $null for never/unknown.
function Get-AgeDays {
    param($Value)
    $d = ConvertTo-UtcDate $Value
    if ($null -eq $d) { return $null }
    return [int][Math]::Floor(($script:RefDate - $d).TotalDays)
}

function Format-Age {
    param($Days)
    if ($null -eq $Days) { return 'never' }
    return "$Days days"
}

# --------------------------------------------------------------------------
# Snapshot loading and indexing
# --------------------------------------------------------------------------
# Members should be DN strings, but PS 5.1 sometimes hands back an object.
# Either way, get a DN string out.
function Get-DnString {
    param($Member)
    if ($null -eq $Member) { return $null }
    if ($Member -is [string]) { return $Member }
    if ($Member -is [System.Collections.IDictionary]) {
        foreach ($k in 'distinguishedName', 'DistinguishedName', 'dn', 'Dn', 'Value') { if ($Member.Contains($k) -and $Member[$k]) { return "$($Member[$k])" } }
    }
    else {
        foreach ($k in 'distinguishedName', 'DistinguishedName', 'dn', 'Dn', 'Value') {
            $p = $Member.PSObject.Properties[$k]
            if ($p -and $p.Value) { return "$($p.Value)" }
        }
    }
    $s = "$Member"
    if ($s -match '(?i)(CN|OU|DC)=') { return $s }
    return $null
}

function Import-ADSnapshot {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Snapshot not found: $Path" }
    $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path)
    $trim = $raw.TrimStart([char]0xFEFF, ' ', "`t", "`r", "`n")
    if (-not $trim.StartsWith('{')) {
        $hint = if ($Path -match '(?i)\.(csv|html?)$' -or $trim -match '^("Severity"|<!DOCTYPE|<html)') { ' This is an IDWolf report, not a snapshot: pass the snapshot JSON written by Collect-ADSnapshot.ps1 / Collect-EntraSnapshot.ps1 (adsnapshot_*.json).' } else { '' }
        throw "File is not a JSON snapshot: $Path.$hint"
    }
    # Older PS 5.1 snapshots hold {} where a list was empty; read it as null,
    # or it looks like a value (an empty SPN on every account).
    $raw = [regex]::Replace($raw, '(?<=[^\\]"):\s*\{\s*\}', ': null')
    $snap = $raw | ConvertFrom-Json
    if (-not $snap.meta -or @('IDWolf', 'ADSheep', 'MooseAD') -notcontains "$($snap.meta.tool)") {
        throw "File does not look like an IDWolf snapshot (missing meta.tool): $Path"
    }
    return $snap
}

function New-SnapshotIndex {
    param($Snapshot)
    $idx = [ordered]@{
        DomainSid     = $Snapshot.domain.sid
        RootSid       = if ($Snapshot.domain.forestRootSid) { $Snapshot.domain.forestRootSid } else { $Snapshot.domain.sid }
        ByDn          = @{}
        BySid         = @{}
        Users         = @($Snapshot.users) + @($Snapshot.serviceAccounts | Where-Object { $_ })
        Computers     = @($Snapshot.computers)
        Groups        = @($Snapshot.groups)
        ByPrimaryGroup = @{}
        DcDns         = @{}
        DcHostNames   = @{}
        CollectionErrorSections = @{}
    }
    $idx.Users = @($idx.Users | Where-Object { $_ })
    $idx.Computers = @($idx.Computers | Where-Object { $_ })
    $idx.Groups = @($idx.Groups | Where-Object { $_ })

    foreach ($u in $idx.Users) { $u | Add-Member -NotePropertyName '_type' -NotePropertyValue 'user' -Force; $idx.ByDn[$u.distinguishedName.ToLower()] = $u; if ($u.sid) { $idx.BySid[$u.sid] = $u } }
    foreach ($c in $idx.Computers) { $c | Add-Member -NotePropertyName '_type' -NotePropertyValue 'computer' -Force; $idx.ByDn[$c.distinguishedName.ToLower()] = $c; if ($c.sid) { $idx.BySid[$c.sid] = $c } }
    foreach ($g in $idx.Groups) { $g | Add-Member -NotePropertyName '_type' -NotePropertyValue 'group' -Force; $idx.ByDn[$g.distinguishedName.ToLower()] = $g; if ($g.sid) { $idx.BySid[$g.sid] = $g } }
    foreach ($f in @($Snapshot.foreignPrincipals | Where-Object { $_ })) {
        $f | Add-Member -NotePropertyName '_type' -NotePropertyValue 'foreign' -Force
        $idx.ByDn[$f.distinguishedName.ToLower()] = $f
    }

    # A DC is anything the DC list, the SERVER_TRUST flag or the primary group says is one.
    foreach ($dc in @($Snapshot.domainControllers | Where-Object { $_ })) {
        if ($dc.computerDN) { $idx.DcDns[$dc.computerDN.ToLower()] = $true }
        if ($dc.hostName) { $idx.DcHostNames[$dc.hostName.ToLower()] = $true }
        if ($dc.name) { $idx.DcHostNames[$dc.name.ToLower()] = $true }
    }
    foreach ($c in $idx.Computers) {
        $isDc = $idx.DcDns.ContainsKey($c.distinguishedName.ToLower()) -or (Test-Uac $c 'SERVER_TRUST_ACCOUNT') -or ($script:DcPrimaryGroupRids -contains [int]$c.primaryGroupId)
        $c | Add-Member -NotePropertyName '_isDc' -NotePropertyValue $isDc -Force
        if ($isDc) {
            if ($c.dnsHostName) { $idx.DcHostNames[$c.dnsHostName.ToLower()] = $true }
            $idx.DcHostNames[$c.samAccountName.TrimEnd('$').ToLower()] = $true
        }
    }

    foreach ($p in @($idx.Users) + @($idx.Computers)) {
        if ($null -eq $p.primaryGroupId) { continue }
        $k = [int64]$p.primaryGroupId
        if (-not $idx.ByPrimaryGroup.ContainsKey($k)) { $idx.ByPrimaryGroup[$k] = New-Object System.Collections.Generic.List[object] }
        $idx.ByPrimaryGroup[$k].Add($p)
    }

    foreach ($e in @($Snapshot.meta.collectionErrors | Where-Object { $_ })) {
        $idx.CollectionErrorSections[$e.section] = $e.message
    }
    return $idx
}

function Get-GroupBySid {
    param($Index, [string]$Sid)
    $o = $Index.BySid[$Sid]
    if ($o -and $o._type -eq 'group') { return $o }
    return $null
}

function Resolve-PrivilegedGroupDef {
    param($Index, $Def)
    if ($Def.Rid) { return Get-GroupBySid $Index "$($Index.DomainSid)-$($Def.Rid)" }
    if ($Def.RootRid) { return Get-GroupBySid $Index "$($Index.RootSid)-$($Def.RootRid)" }
    if ($Def.Sid) { return Get-GroupBySid $Index $Def.Sid }
    if ($Def.Name) { return $Index.Groups | Where-Object { $_.samAccountName -eq $Def.Name -or $_.name -eq $Def.Name } | Select-Object -First 1 }
    return $null
}

function Get-RidFromSid {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    $parts = $Sid.Split('-')
    return [int64]$parts[-1]
}

# --------------------------------------------------------------------------
# Effective membership: follows "member" recursively (loops are fine) and adds
# primaryGroupID members, which never show in "member" or in most GUIs.
# One entry per principal and path.
# --------------------------------------------------------------------------
function Get-EffectiveMembers {
    param($Index, $Group)
    $results = New-Object System.Collections.Generic.List[object]
    $visited = @{}
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@($Group, $Group.name))

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $g = $item[0]; $path = $item[1]
        $gKey = "$($g.distinguishedName)".ToLower()
        if ($visited.ContainsKey($gKey)) { continue }
        $visited[$gKey] = $true

        foreach ($mRaw in @($g.members)) {
            $mDn = Get-DnString $mRaw
            if (-not $mDn) { continue }
            $m = $Index.ByDn[$mDn.ToLower()]
            if (-not $m) {
                $results.Add([PSCustomObject]@{ Principal = $null; Dn = $mDn; Type = 'unresolved'; Path = "$path > $mDn"; ViaPrimaryGroup = $false })
                continue
            }
            if ($m._type -eq 'group') {
                $queue.Enqueue(@($m, "$path > $($m.name)"))
            }
            else {
                $label = if ($m.samAccountName) { $m.samAccountName } else { $m.name }
                $results.Add([PSCustomObject]@{ Principal = $m; Dn = $m.distinguishedName; Type = $m._type; Path = "$path > $label"; ViaPrimaryGroup = $false })
            }
        }

        # primaryGroupID only exists for domain-local SIDs of the same domain.
        if ($g.sid -and $g.sid.StartsWith("$($Index.DomainSid)-")) {
            $rid = Get-RidFromSid $g.sid
            if ($Index.ByPrimaryGroup.ContainsKey($rid)) {
                foreach ($p in $Index.ByPrimaryGroup[$rid]) {
                    $results.Add([PSCustomObject]@{ Principal = $p; Dn = $p.distinguishedName; Type = $p._type; Path = "$path > $($p.samAccountName) (primaryGroupID)"; ViaPrimaryGroup = $true })
                }
            }
        }
    }
    return $results
}

# The Tier 0 map: who is privileged, through which groups and paths. Built once, used everywhere.
function Get-PrivilegedMap {
    param($Index)
    $groupsResolved = [ordered]@{}
    $principals = @{}   # DN(lower) -> record

    foreach ($def in $script:PrivilegedGroupDefs) {
        $g = Resolve-PrivilegedGroupDef $Index $def
        if (-not $g) { continue }
        $members = @(Get-EffectiveMembers $Index $g)
        $groupsResolved[$def.Key] = [PSCustomObject]@{ Def = $def; Group = $g; Members = $members }
        foreach ($m in $members) {
            $key = $m.Dn.ToLower()
            if (-not $principals.ContainsKey($key)) {
                $principals[$key] = [PSCustomObject]@{
                    Dn        = $m.Dn
                    Principal = $m.Principal
                    Type      = $m.Type
                    Groups    = New-Object System.Collections.Generic.List[string]
                    Paths     = New-Object System.Collections.Generic.List[string]
                    ViaPrimaryGroup = $false
                }
            }
            $rec = $principals[$key]
            if (-not $rec.Groups.Contains($def.Label)) { $rec.Groups.Add($def.Label) }
            if (-not $rec.Paths.Contains($m.Path)) { $rec.Paths.Add($m.Path) }
            if ($m.ViaPrimaryGroup) { $rec.ViaPrimaryGroup = $true }
        }
    }

    $protectedUsers = Get-GroupBySid $Index "$($Index.DomainSid)-525"
    $protectedSet = @{}
    if ($protectedUsers) {
        foreach ($m in @(Get-EffectiveMembers $Index $protectedUsers)) { $protectedSet[$m.Dn.ToLower()] = $true }
    }

    return [PSCustomObject]@{
        Groups              = $groupsResolved
        Principals          = $principals
        ProtectedUsersGroup = $protectedUsers
        ProtectedUsersSet   = $protectedSet
    }
}

function Test-IsPrivileged {
    param($PrivMap, $Principal)
    return $PrivMap.Principals.ContainsKey($Principal.distinguishedName.ToLower())
}

function Get-PrivilegedGroupsText {
    param($PrivMap, $Principal)
    $rec = $PrivMap.Principals[$Principal.distinguishedName.ToLower()]
    if (-not $rec) { return '' }
    return ($rec.Groups -join ', ')
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}
