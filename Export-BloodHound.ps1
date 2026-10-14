<#
.SYNOPSIS
    Converts an IDWolf snapshot into BloodHound-ingestable JSON (SharpHound
    style) and writes them as a .zip you can drag into BloodHound.

.DESCRIPTION
    The snapshot already holds what BloodHound wants: users, computers, groups,
    membership, delegation, RBCD, trusts and ACLs (Tier 0, or everything with
    -Deep). This turns it into SharpHound v5 JSON, so you can explore the paths
    in BloodHound CE without running SharpHound on the network.

    Beta: not yet imported into a real BloodHound, and the format changes
    between versions.

.PARAMETER Snapshot
    Path to an IDWolf snapshot JSON (from Collect-ADSnapshot.ps1).
.PARAMETER OutZip
    Output .zip path. Default: output\bloodhound_<domain>_<ts>.zip
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$Snapshot,
    [string]$OutZip = ""
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Snapshot)) { Write-Host "Snapshot not found: $Snapshot" -ForegroundColor Red; exit 1 }
$snap = Get-Content -Raw -LiteralPath $Snapshot | ConvertFrom-Json
if (-not $snap.meta -or @('IDWolf', 'ADSheep', 'MooseAD') -notcontains "$($snap.meta.tool)") { Write-Host "Not an IDWolf snapshot." -ForegroundColor Red; exit 1 }
if ("$($snap.meta.kind)" -eq 'entra') { Write-Host "This is an Entra snapshot; BloodHound export works on AD snapshots." -ForegroundColor Red; exit 1 }

$domainDns = "$($snap.domain.dnsRoot)"
$domainName = $domainDns.ToUpper()
$domainSid = "$($snap.domain.sid)"

# ---- index: DN -> {sid,type}, for membership and ACL principal typing ----
$byDn = @{}
$sidType = @{}
function Add-Index { param($rec, [string]$type) if ($rec.distinguishedName) { $byDn[("$($rec.distinguishedName)").ToLower()] = @{ Sid = "$($rec.sid)"; Type = $type } }; if ($rec.sid) { $sidType["$($rec.sid)"] = $type } }
foreach ($u in @($snap.users)) { Add-Index $u 'User' }
foreach ($s in @($snap.serviceAccounts)) { Add-Index $s 'User' }
foreach ($c in @($snap.computers)) { Add-Index $c 'Computer' }
foreach ($g in @($snap.groups)) { Add-Index $g 'Group' }

function Get-BhType { param([string]$Sid) if ($sidType.ContainsKey($Sid)) { return $sidType[$Sid] } if ($Sid -match '-5(12|18|19|20)$') { return 'Group' } return 'Base' }

# ---- UAC helpers ----
function Test-Uac2 { param($v, [int]$flag) if ($null -eq $v) { return $false } return ([int64]$v -band $flag) -ne 0 }

# ---- ACL mapping: snapshot ACE -> BloodHound Ace(s) ----
$GUID_MEMBER = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
$GUID_KCL = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
$GUID_SPN = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
$GUID_FCP = '00299570-246d-11d0-a768-00aa006e0529'
$GUID_GETCHANGES = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GETCHANGESALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$EMPTY = '00000000-0000-0000-0000-000000000000'

function ConvertTo-BhAces {
    param($AclRecord)
    $aces = New-Object System.Collections.Generic.List[object]
    $ownerSid = "$($AclRecord.ownerSid)"
    if ($ownerSid) { $aces.Add([ordered]@{ PrincipalSID = $ownerSid; PrincipalType = (Get-BhType $ownerSid); RightName = 'Owns'; IsInherited = $false }) }
    foreach ($ace in @($AclRecord.aces | Where-Object { $_ })) {
        if ("$($ace.accessType)" -ne 'Allow') { continue }
        $rights = "$($ace.rights)"; $ot = "$($ace.objectType)".ToLower(); $sid = "$($ace.sid)"
        if (-not $sid) { continue }
        $names = New-Object System.Collections.Generic.List[string]
        if ($rights -match '\bGenericAll\b') { $names.Add('GenericAll') }
        if ($rights -match '\bWriteDacl\b') { $names.Add('WriteDacl') }
        if ($rights -match '\bWriteOwner\b') { $names.Add('WriteOwner') }
        if ($rights -match '\bGenericWrite\b') { $names.Add('GenericWrite') }
        if ($rights -match '\bWriteProperty\b') {
            if ($ot -eq $GUID_MEMBER) { $names.Add('AddMember') }
            elseif ($ot -eq $GUID_KCL) { $names.Add('AddKeyCredentialLink') }
            elseif ($ot -eq $GUID_SPN) { $names.Add('WriteSPN') }
            elseif ($ot -eq $EMPTY -or $ot -eq '') { $names.Add('GenericWrite') }
        }
        if ($rights -match '\bExtendedRight\b') {
            if ($ot -eq $GUID_FCP) { $names.Add('ForceChangePassword') }
            elseif ($ot -eq $GUID_GETCHANGES) { $names.Add('GetChanges') }
            elseif ($ot -eq $GUID_GETCHANGESALL) { $names.Add('GetChangesAll') }
            elseif ($ot -eq $EMPTY -or $ot -eq '') { $names.Add('AllExtendedRights') }
        }
        if ($rights -match '\bSelf\b' -and $ot -eq $GUID_MEMBER) { $names.Add('AddSelf') }
        foreach ($rn in ($names | Select-Object -Unique)) {
            $aces.Add([ordered]@{ PrincipalSID = $sid; PrincipalType = (Get-BhType $sid); RightName = $rn; IsInherited = [bool]$ace.isInherited })
        }
    }
    return $aces.ToArray()
}

# Collect ACL records by target DN (Tier 0 acls + deep acls).
$aclByDn = @{}
foreach ($a in @($snap.acls) + @($snap.deepAcls)) {
    if (-not $a -or -not $a.distinguishedName) { continue }
    $aclByDn[("$($a.distinguishedName)").ToLower()] = $a
}
function Get-AcesForDn { param([string]$Dn) $k = "$Dn".ToLower(); if ($aclByDn.ContainsKey($k)) { return ConvertTo-BhAces $aclByDn[$k] } return @() }

$nowEpoch = [int][double]::Parse((Get-Date -UFormat %s))
function ConvertTo-Epoch { param($iso) if (-not $iso) { return -1 }; try { return [int][double]::Parse((Get-Date ([datetime]$iso) -UFormat %s)) } catch { return -1 } }

# ---------------- users ----------------
$bhUsers = foreach ($u in (@($snap.users) + @($snap.serviceAccounts))) {
    if (-not $u.sid) { continue }
    $spns = @($u.servicePrincipalNames | Where-Object { $_ })
    [ordered]@{
        ObjectIdentifier = "$($u.sid)"
        Properties       = [ordered]@{
            domain = $domainName; domainsid = $domainSid
            name = "$($u.samAccountName)@$domainDns".ToUpper()
            distinguishedname = "$($u.distinguishedName)".ToUpper()
            samaccountname = "$($u.samAccountName)"
            enabled = [bool]$u.enabled
            pwdlastset = (ConvertTo-Epoch $u.pwdLastSet)
            lastlogontimestamp = (ConvertTo-Epoch $u.lastLogonTimestamp)
            dontreqpreauth = (Test-Uac2 $u.userAccountControl 0x400000)
            unconstraineddelegation = (Test-Uac2 $u.userAccountControl 0x80000)
            trustedtoauth = (Test-Uac2 $u.userAccountControl 0x1000000)
            passwordnotreqd = (Test-Uac2 $u.userAccountControl 0x20)
            hasspn = ($spns.Count -gt 0)
            serviceprincipalnames = $spns
            admincount = [bool]([int]("0$($u.adminCount)") -eq 1)
        }
        PrimaryGroupSID  = if ($u.primaryGroupId) { "$domainSid-$($u.primaryGroupId)" } else { $null }
        HasSIDHistory    = @(@($u.sidHistory | Where-Object { $_ }) | ForEach-Object { [ordered]@{ ObjectIdentifier = "$_"; ObjectType = (Get-BhType "$_") } })
        SPNTargets       = @()
        Aces             = (Get-AcesForDn $u.distinguishedName)
        AllowedToDelegate = @(@($u.allowedToDelegateTo | Where-Object { $_ }) | ForEach-Object { [ordered]@{ ObjectIdentifier = "$_"; ObjectType = 'Computer' } })
        IsDeleted        = $false; IsACLProtected = $false
    }
}

# ---------------- computers ----------------
$bhComputers = foreach ($c in @($snap.computers)) {
    if (-not $c.sid) { continue }
    [ordered]@{
        ObjectIdentifier = "$($c.sid)"
        Properties       = [ordered]@{
            domain = $domainName; domainsid = $domainSid
            name = "$("$($c.samAccountName)".TrimEnd('$')).$domainDns".ToUpper()
            distinguishedname = "$($c.distinguishedName)".ToUpper()
            samaccountname = "$($c.samAccountName)"
            enabled = [bool]$c.enabled
            operatingsystem = "$($c.operatingSystem)"
            unconstraineddelegation = (Test-Uac2 $c.userAccountControl 0x80000)
            trustedtoauth = (Test-Uac2 $c.userAccountControl 0x1000000)
            lastlogontimestamp = (ConvertTo-Epoch $c.lastLogonTimestamp)
            pwdlastset = (ConvertTo-Epoch $c.pwdLastSet)
        }
        PrimaryGroupSID  = if ($c.primaryGroupId) { "$domainSid-$($c.primaryGroupId)" } else { $null }
        Aces             = (Get-AcesForDn $c.distinguishedName)
        AllowedToDelegate = @(@($c.allowedToDelegateTo | Where-Object { $_ }) | ForEach-Object { [ordered]@{ ObjectIdentifier = "$_"; ObjectType = 'Computer' } })
        AllowedToAct     = @(@($c.rbcdPrincipals | Where-Object { $_ }) | ForEach-Object { $o = $byDn[("$_").ToLower()]; if ($o) { [ordered]@{ ObjectIdentifier = $o.Sid; ObjectType = $o.Type } } })
        HasSIDHistory    = @(); DumpSMSAPassword = @(); Sessions = @{ Results = @(); Collected = $false }
        IsDeleted        = $false; IsACLProtected = $false; Status = $null
    }
}

# ---------------- groups ----------------
$bhGroups = foreach ($g in @($snap.groups)) {
    if (-not $g.sid) { continue }
    $members = @()
    foreach ($m in @($g.members | Where-Object { $_ })) {
        $o = $byDn[("$m").ToLower()]
        if ($o -and $o.Sid) { $members += [ordered]@{ ObjectIdentifier = $o.Sid; ObjectType = $o.Type } }
    }
    [ordered]@{
        ObjectIdentifier = "$($g.sid)"
        Properties       = [ordered]@{
            domain = $domainName; domainsid = $domainSid
            name = "$($g.samAccountName)@$domainDns".ToUpper()
            distinguishedname = "$($g.distinguishedName)".ToUpper()
            samaccountname = "$($g.samAccountName)"
            admincount = [bool]([int]("0$($g.adminCount)") -eq 1)
        }
        Members          = $members
        Aces             = (Get-AcesForDn $g.distinguishedName)
        IsDeleted        = $false; IsACLProtected = $false
    }
}

# ---------------- domain (with trusts + Tier 0 ACL) ----------------
$bhTrusts = foreach ($t in @($snap.trusts | Where-Object { $_ -and -not $_.intraForest })) {
    [ordered]@{
        TargetDomainName = "$($t.name)".ToUpper()
        TargetDomainSid = $null
        IsTransitive = [bool]$t.forestTransitive
        TrustDirection = switch ("$($t.direction)") { 'Inbound' { 1 } 'Outbound' { 2 } 'BiDirectional' { 3 } default { 0 } }
        TrustType = if ($t.forestTransitive) { 'Forest' } else { 'External' }
        SidFilteringEnabled = [bool]$t.sidFilteringQuarantined
    }
}
$domainRootAcl = @($snap.acls | Where-Object { $_.target -eq 'DomainRoot' } | Select-Object -First 1)
$bhDomain = [ordered]@{
    ObjectIdentifier = $domainSid
    Properties       = [ordered]@{ domain = $domainName; domainsid = $domainSid; name = $domainName; distinguishedname = "$($snap.domain.distinguishedName)".ToUpper(); functionallevel = "$($snap.domain.domainMode)" }
    Trusts           = @($bhTrusts)
    Aces             = if ($domainRootAcl) { ConvertTo-BhAces $domainRootAcl[0] } else { @() }
    Links            = @(); ChildObjects = @(); GPOChanges = @{}
    IsDeleted        = $false; IsACLProtected = $false
}

# ---------------- write files + zip ----------------
function New-BhFile { param([string]$Type, [array]$Data) [ordered]@{ data = @($Data); meta = [ordered]@{ methods = 0; type = $Type; count = @($Data).Count; version = 5 } } }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("bh_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$files = @{
    'users.json'     = (New-BhFile 'users' $bhUsers)
    'computers.json' = (New-BhFile 'computers' $bhComputers)
    'groups.json'    = (New-BhFile 'groups' $bhGroups)
    'domains.json'   = (New-BhFile 'domains' @($bhDomain))
}
foreach ($fn in $files.Keys) {
    $p = Join-Path $work $fn
    [System.IO.File]::WriteAllText($p, ($files[$fn] | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))
}
if (-not $OutZip) {
    # Unnamed outputs go to .\output, not next to everything else.
    $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }
    $OutZip = Join-Path $od ("bloodhound_{0}_{1}.zip" -f $domainDns, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$fullZip = if ([System.IO.Path]::IsPathRooted($OutZip)) { $OutZip } else { [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutZip)) }
if (Test-Path -LiteralPath $fullZip) { Remove-Item -LiteralPath $fullZip -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($work, $fullZip)
Remove-Item -Recurse -Force $work

Write-Host "BloodHound export (beta) written to $fullZip" -ForegroundColor Green
Write-Host ("  users={0} computers={1} groups={2} trusts={3}" -f @($bhUsers).Count, @($bhComputers).Count, @($bhGroups).Count, @($bhTrusts).Count)
Write-Host "Import it in BloodHound (CE/SharpHound v5 JSON). Validate on import; ACL edges beyond Tier 0 require an IDWolf -Deep snapshot." -ForegroundColor Yellow
