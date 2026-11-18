# Attack-path and trust maps: what can reach Tier 0, and whom the domain
# trusts. Built from the findings, drawn as plain SVG so it works offline;
# the bit of script only highlights paths on hover. The Entra report gets the
# same map toward its admin roles.

# Escalation finding types -> edge label toward Tier 0. Order roughly by impact.
$script:EscalationKinds = [ordered]@{
    dcsync_rights                              = 'DCSync'
    dangerous_ace_tier0                        = 'Dangerous ACL on Tier 0'
    nonstandard_owner_tier0                    = 'Owns Tier 0 object'
    gpo_dangerous_acl                          = 'GPO control -> DCs'
    adcs_esc1                                  = 'AD CS ESC1'
    adcs_esc2                                  = 'AD CS ESC2'
    adcs_esc3                                  = 'AD CS ESC3'
    adcs_esc4                                  = 'AD CS ESC4'
    adcs_esc5                                  = 'AD CS ESC5'
    adcs_esc6                                  = 'AD CS ESC6 (SAN in any request)'
    adcs_esc7                                  = 'AD CS ESC7 (CA officer)'
    adcs_esc8                                  = 'AD CS ESC8 (relay to web enrollment)'
    adcs_esc9                                  = 'AD CS ESC9'
    adcs_esc10                                 = 'AD CS ESC10'
    adcs_esc11                                 = 'AD CS ESC11 (relay to RPC)'
    adcs_esc13                                 = 'AD CS ESC13'
    adcs_esc15                                 = 'AD CS ESC15'
    adcs_esc16                                 = 'AD CS ESC16 (no SID extension)'
    adcs_esc17                                 = 'AD CS ESC17 (spoofed update server)'
    altsecid_weak_mapping                      = 'Weak certificate mapping (ESC14)'
    badsuccessor_dmsa_create                   = 'BadSuccessor (dMSA)'
    kds_root_key_readable                      = 'Golden gMSA (KDS root key)'
    constrained_delegation_protocol_transition = 'Protocol transition'
    unconstrained_delegation                   = 'Unconstrained delegation'
    constrained_delegation                     = 'Constrained delegation'
    rbcd_configured                            = 'RBCD'
    privileged_kerberoastable                  = 'Kerberoastable Tier 0'
    asrep_roastable                            = 'AS-REP roastable Tier 0'
    sid_history                                = 'Privileged SID history'
    privileged_foreign_member                  = 'Foreign Tier 0 member'
    privileged_computer_member                 = 'Computer in Tier 0'
    operator_groups_populated                  = 'Operator group (logon on DCs)'
    dnsadmins_populated                        = 'DnsAdmins (DLL on a DC)'
    rodc_tier0_revealed                        = 'Tier 0 password cached on RODC'
    trust_sid_filtering_disabled               = 'Trust without SID filtering'
    gmsa_password_readable                     = 'gMSA password read'
    shadow_credentials_present                 = 'Shadow credentials'
    gpo_runs_code_from_share                   = 'GPO runs code from a share'
    gpp_cpassword                              = 'GPP password in SYSVOL'
    sysvol_writable                            = 'Writable SYSVOL / NETLOGON'
    sync_laps_rights                           = 'DirSync of LAPS passwords'
    laps_readers                               = 'Reads LAPS passwords'
    sccm_system_management_writable            = 'SCCM System Management'
    gpo_broad_local_group                      = 'Local admin by GPO'
    gpo_autologon_password                     = 'Autologon password in a GPO'
    sysvol_script_secrets                      = 'Password in a SYSVOL script'
    dsrm_logon_behavior                        = 'DSRM account logs on over the network'
    rodc_prp_too_broad                         = 'RODC allowed to cache Tier 0 passwords'
    dangerous_ace_anywhere                     = 'ACL path'
    dangerous_privilege_right                  = 'Sensitive right on DCs'
}
# Weak credentials on an account that already has a path: they turn it into a starting point for
# anyone with an ordinary account. Only ever drawn into a box that is already on the map.
$script:WeakCredentialKinds = [ordered]@{
    kerberoastable_user           = 'Kerberoast'
    asrep_roastable               = 'AS-REP roast'
    password_in_description       = 'Password in the description'
    reversible_encryption_account = 'Reversible encryption (cleartext password)'
    unix_password_present         = 'Password in a Unix attribute'
    timeroast_computer_password   = 'Timeroast (NTP password hash)'
}
# Kinds that are a path only under a condition: 'skip' leaves the finding off the map,
# 'unverified' draws it dashed (the right is real, reaching Tier 0 is an assumption).
$script:EscalationConditions = @{
    sid_history                     = { param($f) if ($f.Severity -eq 'Critical') { 'ok' } else { 'skip' } }
    asrep_roastable                 = { param($f) if ($f.Severity -eq 'Critical') { 'ok' } else { 'skip' } }
    altsecid_weak_mapping           = { param($f) if ("$($f.Detail)" -match 'Tier 0 account') { 'ok' } else { 'skip' } }
    gpo_runs_code_from_share        = { param($f) if ($f.Severity -eq 'Critical' -or $f.Severity -eq 'High') { 'ok' } else { 'unverified' } }
    gpp_cpassword                   = { param($f) 'unverified' }
    sysvol_writable                 = { param($f) 'unverified' }
    gpo_autologon_password          = { param($f) 'unverified' }
    sysvol_script_secrets           = { param($f) 'unverified' }
    # The DSRM hash has to come from somewhere (an old backup, a dump), so the step is real but not shown.
    dsrm_logon_behavior             = { param($f) 'unverified' }
    rodc_prp_too_broad              = { param($f) 'unverified' }
    # Critical means the GPO puts a broad group in local Administrators on the Domain Controllers OU;
    # High is the same on member servers or workstations, which is a path only through what runs there.
    gpo_broad_local_group           = { param($f) if ($f.Severity -eq 'Critical') { 'ok' } elseif ($f.Severity -eq 'High') { 'unverified' } else { 'skip' } }
    sync_laps_rights                = { param($f) 'unverified' }
    laps_readers                    = { param($f) 'unverified' }
    sccm_system_management_writable = { param($f) 'unverified' }
}
# Groups that stand for every account in the domain: drawn as one "Any domain user" box.
$script:BroadPrincipalRegex = '(?i)(^|\\)(Authenticated Users|Everyone|Domain Users|Domain Computers|Users|ANONYMOUS LOGON)$'
$script:BroadPrincipalText = '(?i)\b(Authenticated Users|Everyone|Domain Users|Domain Computers)\b'

# Entra: finding types -> edge label toward the admin roles.
$script:EntraEscalationKinds = [ordered]@{
    entra_sp_in_admin_role              = 'Holds an admin role'
    entra_app_high_privilege            = 'Tenant-takeover permission'
    entra_connect_app_extra_credentials = 'Entra Connect app credential'
    entra_privileged_group_owner        = 'Group holds an admin role'
    entra_privileged_app_owner          = 'Privileged app'
    entra_privileged_app_sp_owner       = 'Privileged app'
    entra_app_scoped_admin_privileged   = 'Privileged app'
    entra_access_package_grants_admin   = 'Access package grants admin'
    entra_catalog_role_privileged_group = 'Catalog holds an admin group'
}

$script:GraphSevColor = @{ Critical = '#E2372A'; High = '#EF8A6F'; Medium = '#F2B632'; Low = '#B9B1A1' }

# How far nested group membership is followed behind a source group, and how many member boxes the
# whole map may add. Both are there to keep one nested mess from drowning the real paths.
$script:MemberHopMaxDepth = 3
$script:MemberNodeBudget = 120

function Get-GraphSevRank { param([string]$S) if ($script:SeverityRank.ContainsKey($S)) { return $script:SeverityRank[$S] } return 0 }

# --------------------------------------------------------------------------
# Graph plumbing shared by the AD and the Entra map
# --------------------------------------------------------------------------
function New-GraphState { return [PSCustomObject]@{ Nodes = [ordered]@{}; Edges = New-Object System.Collections.Generic.List[object] } }
# Every object one finding was raised over. Merge-DuplicateFindings keeps them all in ObjectDns
# (several hits on one principal are one finding); an unmerged finding has only ObjectDn.
function Get-FindingObjectDns {
    param($F)
    if ($F.PSObject.Properties['ObjectDns']) {
        $all = @($F.ObjectDns | Where-Object { $_ })
        if ($all.Count -gt 0) { return $all }
    }
    if ("$($F.ObjectDn)") { return @("$($F.ObjectDn)") }
    return @()
}
# "WriteDacl over user 'x'." -> "ACL path (WriteDacl)", for the hit that names this victim. A merged
# detail is "N hits: a | b | c", so the prefix goes and the right segment is picked.
function Get-AclPathKind {
    param($F, [string]$VictimName)
    $segs = @("$($F.Detail)" -split ' \| ')
    $hit = $null
    if ($VictimName) { foreach ($s in $segs) { if ("$s" -match [regex]::Escape("'$VictimName'")) { $hit = "$s"; break } } }
    if (-not $hit) { $hit = "$($segs[0])" }
    $hit = $hit -replace '^\d+ hits:\s*', ''
    if ($hit -match '^(.+?) over ') { return "ACL path ($($Matches[1]))" }
    return 'ACL path'
}
# One node per label; the worst severity wins.
function Add-GraphNode {
    param($Gs, [string]$Label, [string]$Type, [string]$Sev)
    if (-not $Gs.Nodes.Contains($Label)) {
        $Gs.Nodes[$Label] = [PSCustomObject]@{ Id = $Gs.Nodes.Count; Label = $Label; Type = $Type; Sev = $Sev; Techniques = New-Object System.Collections.Generic.List[string]; Level = 0 }
    }
    $n = $Gs.Nodes[$Label]
    if ((Get-GraphSevRank $Sev) -gt (Get-GraphSevRank $n.Sev)) { $n.Sev = $Sev }
    return $n
}
# $To is a node, or $null for the anchor (Tier 0 / admin roles).
function Add-GraphEdge {
    param($Gs, $From, $To, [string]$Kind, [string]$Sev, [bool]$Unverified = $false)
    $toId = if ($To) { [int]$To.Id } else { -1 }
    if ($toId -eq $From.Id) { return }
    if ($From.Techniques -notcontains $Kind) { $From.Techniques.Add($Kind) }
    if ((Get-GraphSevRank $Sev) -gt (Get-GraphSevRank $From.Sev)) { $From.Sev = $Sev }
    $Gs.Edges.Add([PSCustomObject]@{ From = $From.Id; To = $toId; Kind = $Kind; Sev = $Sev; Unverified = $Unverified; EdgeKey = "$($From.Label)|$Kind|$toId|$Unverified" })
}
# Dedup edges (worst severity kept), hop levels, sort. Returns Nodes and Edges.
function Complete-AttackGraph {
    param($Gs)
    # Same source, same technique, same destination: one arrow. A verified step wins over an
    # assumed one (the same right can be held over a Tier 0 object and over a plain one), then the
    # worst severity wins.
    $byEdge = [ordered]@{}
    foreach ($e in $Gs.Edges) {
        $k = "$($e.From)|$($e.Kind)|$($e.To)"
        if (-not $byEdge.Contains($k)) { $byEdge[$k] = $e; continue }
        $old = $byEdge[$k]
        if ($old.Unverified -and -not $e.Unverified) { $byEdge[$k] = $e }
        elseif (($old.Unverified -eq $e.Unverified) -and (Get-GraphSevRank $e.Sev) -gt (Get-GraphSevRank $old.Sev)) { $byEdge[$k] = $e }
    }
    # Hops to the anchor: 0 when every edge goes straight there, else 1 + the longest chain behind it.
    $outTo = @{}; foreach ($e in $byEdge.Values) { if ($e.To -ge 0) { if (-not $outTo.ContainsKey($e.From)) { $outTo[$e.From] = New-Object System.Collections.Generic.List[int] }; $outTo[$e.From].Add($e.To) } }
    $memo = @{}
    $levelOf = $null
    $levelOf = { param($id, $path)
        if ($memo.ContainsKey($id)) { return $memo[$id] }
        if (-not $outTo.ContainsKey($id) -or $path -contains $id) { return 0 }
        $best = 0
        foreach ($t in $outTo[$id]) { $l = 1 + (& $levelOf $t (@($path) + $id)); if ($l -gt $best) { $best = $l } }
        $memo[$id] = $best
        return $best
    }
    foreach ($n in $Gs.Nodes.Values) { $n.Level = [int](& $levelOf $n.Id @()) }
    # Only nodes with an edge out: a hop target that no longer leads anywhere is dropped.
    $hasOut = @{}; foreach ($e in $byEdge.Values) { $hasOut[$e.From] = $true }
    $nodeList = @($Gs.Nodes.Values | Where-Object { $hasOut.ContainsKey($_.Id) } | Sort-Object @{ Expression = { - (Get-GraphSevRank $_.Sev) } }, @{ Expression = 'Label' })
    return [PSCustomObject]@{ Nodes = $nodeList; Edges = @($byEdge.Values) }
}

# --------------------------------------------------------------------------
# AD: edges toward Tier 0
# --------------------------------------------------------------------------
function Get-AttackGraph {
    param($Snapshot, $Index, $PrivMap, $Findings)
    $Gs = New-GraphState
    $anyKey = 'Any domain user'
    $findings = @($Findings | Where-Object { $_ })

    # DNs of everything that already is Tier 0, to tell "a right over Tier 0" from "a right over something".
    $t0Dns = @{}
    foreach ($k in $PrivMap.Principals.Keys) { $t0Dns["$k".ToLower()] = $true }
    foreach ($e in $PrivMap.Groups.Values) { if ($e.Group -and $e.Group.distinguishedName) { $t0Dns["$($e.Group.distinguishedName)".ToLower()] = $true } }
    # A golden gMSA only reaches Tier 0 through a gMSA that is Tier 0.
    $privGmsa = @($Index.Users | Where-Object { $_.kind -eq 'msa' -and $_.isGroupManaged -eq $true -and $_.distinguishedName -and $t0Dns.ContainsKey("$($_.distinguishedName)".ToLower()) }).Count -gt 0
    # samAccountName -> object, for the principals a finding names in its detail and for the
    # password-quality lists.
    $objBySam = @{}
    foreach ($o in @($Index.Users) + @($Index.Computers) + @($Index.Groups)) {
        if ($o.samAccountName -and -not $objBySam.ContainsKey("$($o.samAccountName)".ToLower())) { $objBySam["$($o.samAccountName)".ToLower()] = $o }
    }

    $types = @{}; foreach ($f in $findings) { $types[$f.Type] = $true }

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in $findings) {
        if (-not $script:EscalationKinds.Contains($f.Type) -or -not "$($f.Object)") { continue }
        $cond = if ($script:EscalationConditions.ContainsKey($f.Type)) { & $script:EscalationConditions[$f.Type] $f } else { 'ok' }
        if ($f.Type -eq 'kds_root_key_readable' -and -not $privGmsa) { $cond = 'unverified' }
        # What the RODC already caches is the precise finding; "it is allowed to" adds nothing then.
        if ($f.Type -eq 'rodc_prp_too_broad' -and $types['rodc_tier0_revealed']) { $cond = 'skip' }
        if ($cond -eq 'skip') { continue }
        $key = if ("$($f.Object)" -match $script:BroadPrincipalRegex) { $anyKey } else { "$($f.Object)" }
        $n = Add-GraphNode $Gs $key $(if ($key -eq $anyKey) { 'entry' } else { "$($f.ObjectType)" }) $f.Severity
        $items.Add([PSCustomObject]@{ F = $f; Node = $n; Unverified = ($cond -eq 'unverified') })
    }
    # A node is found by the short name of its object ("TEST\sales" -> "sales"). A principal of
    # another domain ("PARTNER\sales") must not be taken for the local object of the same name, so
    # a local label owns the slot and a foreign one is not a hop target at all.
    $nb = "$($Snapshot.domain.netbios)".ToLower()
    $localPrefix = @{ 'builtin' = $true; 'nt authority' = $true; 'nt service' = $true }
    if ($nb) { $localPrefix[$nb] = $true }
    $nodeByName = @{}
    foreach ($n in $Gs.Nodes.Values) {
        if ($n.Label -eq $anyKey) { continue }
        $parts = @("$($n.Label)" -split '\\')
        if ($parts.Count -gt 1 -and $nb -and -not $localPrefix.ContainsKey($parts[0].ToLower())) { continue }
        $nodeByName[$parts[-1].ToLower()] = $n
    }

    foreach ($it in $items) {
        $f = $it.F; $n = $it.Node
        $kind = $script:EscalationKinds[$f.Type]
        # An ACL over an object that is itself a source is a hop, not a jump to Tier 0:
        # group A -> GenericWrite over account B -> B has DCSync. One finding can hold the rights
        # over many objects (they are merged by principal), so every one of them is looked at: the
        # second hit is often the one that leads somewhere.
        if ($f.Type -eq 'dangerous_ace_anywhere') {
            $hops = 0; $overT0 = $false
            foreach ($dn in @(Get-FindingObjectDns $f)) {
                $low = "$dn".ToLower()
                $victim = $Index.ByDn[$low]
                $t = $null
                $vn = ''
                if ($victim) {
                    $vn = if ($victim.samAccountName) { "$($victim.samAccountName)" } else { "$($victim.name)" }
                    $t = $nodeByName[$vn.ToLower()]
                }
                # The hop says more than the jump, so an object that is both Tier 0 and a source of
                # its own is drawn as a hop.
                if ($t -and $t.Id -ne $n.Id) {
                    Add-GraphEdge $Gs $n $t (Get-AclPathKind $f $vn) $f.Severity $false
                    $hops++
                    continue
                }
                if ($t0Dns.ContainsKey($low)) { $overT0 = $true }
            }
            # A right over Tier 0 itself is the end of the path; with no hop and nothing Tier 0 the
            # right is real, but nothing in the findings shows where it leads, so the arrow is dashed.
            if ($overT0) { Add-GraphEdge $Gs $n $null $kind $f.Severity $false }
            elseif ($hops -eq 0) { Add-GraphEdge $Gs $n $null $kind $f.Severity $true }
            continue
        }
        Add-GraphEdge $Gs $n $null $kind $f.Severity $it.Unverified
        # RBCD is held by someone else: the attacker is the principal allowed to act on the object,
        # which the check names in its detail, and the object is the hop. Without this the box that
        # matters most (the computer account an attacker already owns) is not on the map at all.
        if ($f.Type -eq 'rbcd_configured') {
            foreach ($m in [regex]::Matches("$($f.Detail)", 'act on behalf of other identities: (.+?)\.(?:\s|$)')) {
                foreach ($nm in @("$($m.Groups[1].Value)" -split ',\s*')) {
                    $o = $objBySam["$nm".ToLower()]
                    if (-not $o -or -not $o.distinguishedName -or $t0Dns.ContainsKey("$($o.distinguishedName)".ToLower())) { continue }
                    $sn = Add-GraphNode $Gs "$($o.samAccountName)" "$($o._type)" $f.Severity
                    if ($sn.Id -eq $n.Id) { continue }
                    Add-GraphEdge $Gs $sn $n 'Allowed to act on it (RBCD)' $f.Severity $false
                    $skey = "$($o.samAccountName)".ToLower()
                    if (-not $nodeByName.ContainsKey($skey)) { $nodeByName[$skey] = $sn }
                }
            }
        }
    }

    # ---- Entry point: what any domain account (or anyone on the network) can start from ----
    $any = { param($To, [string]$Kind, [string]$Sev, [bool]$Unv = $false)
        $a = Add-GraphNode $Gs $anyKey 'entry' $Sev
        if ($To -and $To.Id -eq $a.Id) { return }
        Add-GraphEdge $Gs $a $To $Kind $Sev $Unv
    }
    $lowEnroll = [bool]($types['adcs_esc1'] -or $types['adcs_esc2'] -or $types['adcs_esc3'] -or $types['adcs_esc9'] -or $types['adcs_esc15'] -or $types['adcs_low_priv_enroll'])
    foreach ($f in $findings) {
        $tn = if ("$($f.Object)") { $Gs.Nodes["$($f.Object)"] } else { $null }
        switch ($f.Type) {
            { $_ -in 'adcs_esc1', 'adcs_esc2', 'adcs_esc3', 'adcs_esc9', 'adcs_esc13', 'adcs_esc15' } { if ($tn) { & $any $tn 'Enroll' $f.Severity }; break }
            'adcs_esc4' { if ($tn -and "$($f.Detail)" -match $script:BroadPrincipalText) { & $any $tn 'Edit the template' $f.Severity }; break }
            { $_ -in 'adcs_esc8', 'adcs_esc11' } { if ($tn) { & $any $tn 'Coerce a DC, relay' $f.Severity }; break }
            { $_ -in 'adcs_esc6', 'adcs_esc16' } { if ($tn -and $lowEnroll) { & $any $tn 'Enroll' $f.Severity }; break }
            'adcs_esc7' { if ($tn -and $f.Severity -eq 'Critical') { & $any $tn 'CA officer rights' $f.Severity }; break }
            'gpp_cpassword' { if ($tn) { & $any $tn 'Read SYSVOL' $f.Severity $true }; break }
            'sysvol_writable' { if ($tn -and "$($f.Detail)" -match $script:BroadPrincipalText) { & $any $tn 'Write logon scripts' $f.Severity $true }; break }
            'privileged_kerberoastable' { if ($tn) { & $any $tn 'Kerberoast' $f.Severity }; break }
            'asrep_roastable' { if ($tn) { & $any $tn 'AS-REP roast' $f.Severity }; break }
            # noPac needs a computer account the attacker controls: the machine account quota gives one to everyone.
            'nopac_unpatched_dc' { if ($types['machine_account_quota']) { & $any $null "noPac ($($f.Object))" $f.Severity }; break }
            'gpo_autologon_password' { if ($tn) { & $any $tn 'Read SYSVOL' $f.Severity $true }; break }
            'sysvol_script_secrets' { if ($tn) { & $any $tn 'Read SYSVOL' $f.Severity $true }; break }
            # The member the GPO adds is always a broad principal, so every account is already in it.
            'gpo_broad_local_group' { if ($tn) { & $any $tn 'Already in the group' $f.Severity ($f.Severity -ne 'Critical') }; break }
            # A DC that still accepts a weak Netlogon secure channel is domain compromise from the
            # network: no account needed at all.
            'netlogon_vulnerable_channel' { & $any $null 'Zerologon (weak Netlogon secure channel)' $f.Severity; break }
        }
    }
    # Coerce a DC to authenticate (spooler, WebClient, unfiltered RPC), relay it to LDAP on another
    # DC: with no LDAP signing or channel binding the relayed DC account can write to the directory.
    # The classic end is RBCD on the DC, which needs a computer account the machine account quota
    # hands to every user; without it the relay is still a write as a DC account, hence dashed.
    $coerce = @(@('spooler_on_dc', 'webclient_on_dc', 'coercion_unfiltered_dc') | Where-Object { $types[$_] })
    $relay = @(@('ldap_signing_not_required', 'ldap_channel_binding_off') | Where-Object { $types[$_] })
    if ($coerce.Count -gt 0 -and $relay.Count -gt 0) {
        $relaySev = 'Low'
        foreach ($f in $findings) {
            if (($coerce -notcontains $f.Type) -and ($relay -notcontains $f.Type)) { continue }
            if ((Get-GraphSevRank $f.Severity) -gt (Get-GraphSevRank $relaySev)) { $relaySev = $f.Severity }
        }
        & $any $null 'Coerce a DC, relay to LDAP (RBCD)' $relaySev (-not $types['machine_account_quota'])
    }
    # Weak credentials on an account that is already a source: the chain now starts at the entry box.
    foreach ($f in $findings) {
        if (-not $script:WeakCredentialKinds.Contains($f.Type) -or -not "$($f.Object)") { continue }
        $wn = $nodeByName[(("$($f.Object)" -split '\\')[-1]).ToLower()]
        if ($wn -and $wn.Label -ne $anyKey) { & $any $wn $script:WeakCredentialKinds[$f.Type] $f.Severity }
    }
    # Password quality: a guessable Tier 0 password, or a Tier 0 password shared with a normal account.
    $pq = $Snapshot.passwordQuality
    if ($pq) {
        $isT0 = { param([string]$Name) $o = $objBySam[$Name.ToLower()]; [bool]($o -and $o.distinguishedName -and $t0Dns.ContainsKey("$($o.distinguishedName)".ToLower())) }
        foreach ($l in @(@{ P = 'emptyPassword'; K = 'Empty password'; S = 'Critical' }, @{ P = 'defaultOrUsernamePassword'; K = 'Guessable password'; S = 'Critical' }, @{ P = 'breachedPassword'; K = 'Breached password'; S = 'High' })) {
            foreach ($a in @(ConvertTo-PqNameList $pq.($l.P))) {
                if (& $isT0 $a) { & $any $null "$($l.K) ($a)" $l.S; continue }
                # Not Tier 0, but the account already holds a path: the password is how it is taken.
                $pn = $nodeByName[$a.ToLower()]
                if ($pn -and $pn.Label -ne $anyKey) { & $any $pn $l.K $l.S }
            }
        }
        foreach ($grp in @($pq.duplicatePasswordGroups | Where-Object { $_ })) {
            $accts = @(ConvertTo-PqNameList $grp)
            $t0 = @($accts | Where-Object { & $isT0 $_ })
            if (-not $t0.Count) { continue }
            foreach ($a in @($accts | Where-Object { $t0 -notcontains $_ })) {
                $o = $objBySam[$a.ToLower()]
                $on = Add-GraphNode $Gs $a $(if ($o) { "$($o._type)" } else { 'user' }) 'High'
                Add-GraphEdge $Gs $on $null "Same password as $($t0 -join ', ')" 'High'
            }
        }
    }

    # ---- Membership: the members of a (non Tier 0) source group inherit its path ----
    # Nested groups are followed, because the group that holds the right is rarely the one the
    # people are in: a right over Tier 0 on "IT-Ops" is reached by whoever is in "Helpdesk" inside
    # it. Bounded on purpose (depth and a node budget) so one huge group cannot flood the map.
    $groupBySam = @{}; foreach ($o in @($Index.Groups)) { foreach ($k in @($o.samAccountName, $o.name)) { if ($k) { $groupBySam["$k".ToLower()] = $o } } }
    $queue = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($Gs.Nodes.Values)) {
        if ($n.Label -eq $anyKey -or $n.Type -eq 'members') { continue }
        $queue.Add([PSCustomObject]@{ Node = $n; Depth = 0; Chain = @{} })
    }
    $seenGroup = @{}
    $budget = $script:MemberNodeBudget
    for ($qi = 0; $qi -lt $queue.Count; $qi++) {
        if ($budget -le 0) { break }
        $n = $queue[$qi].Node
        if ($queue[$qi].Depth -ge $script:MemberHopMaxDepth) { continue }
        $grp = $groupBySam[(($n.Label -split '\\')[-1]).ToLower()]
        if (-not $grp -or -not $grp.distinguishedName) { continue }
        $gkey = "$($grp.distinguishedName)".ToLower()
        if ($seenGroup.ContainsKey($gkey)) { continue }
        $seenGroup[$gkey] = $true
        if ($t0Dns.ContainsKey($gkey) -or "$($grp.name)" -match $script:BroadPrincipalRegex) { continue }
        $members = @(@($grp.members | Where-Object { $_ }) | ForEach-Object { $d = Get-DnString $_; if ($d) { $Index.ByDn[$d.ToLower()] } } | Where-Object {
                $_ -and $_.distinguishedName -and -not $t0Dns.ContainsKey("$($_.distinguishedName)".ToLower()) -and ($_._type -eq 'group' -or $_.enabled)
            })
        if (-not $members.Count) { continue }
        $via = "Member of $($grp.name)"
        # The groups walked to get here, so a circular nesting doesn't produce an arrow pointing
        # back up the chain (which would also break the left-to-right layout).
        $childChain = @{}
        foreach ($k in $queue[$qi].Chain.Keys) { $childChain[$k] = $true }
        $childChain[$gkey] = $true
        # A group inside is always drawn: it carries the path on to its own members.
        foreach ($m in @($members | Where-Object { $_._type -eq 'group' })) {
            if ($budget -le 0) { break }
            if ($childChain.ContainsKey("$($m.distinguishedName)".ToLower())) { continue }
            $gn = Add-GraphNode $Gs $(if ($m.samAccountName) { "$($m.samAccountName)" } else { "$($m.name)" }) 'group' $n.Sev
            Add-GraphEdge $Gs $gn $n $via $n.Sev
            $budget--
            $queue.Add([PSCustomObject]@{ Node = $gn; Depth = $queue[$qi].Depth + 1; Chain = $childChain })
        }
        $direct = @($members | Where-Object { $_._type -ne 'group' })
        if ($direct.Count -eq 0) { continue }
        if ($direct.Count -le 5) {
            foreach ($m in $direct) {
                if ($budget -le 0) { break }
                $mn = Add-GraphNode $Gs $(if ($m.samAccountName) { "$($m.samAccountName)" } else { "$($m.name)" }) "$($m._type)" $n.Sev
                Add-GraphEdge $Gs $mn $n $via $n.Sev
                $budget--
            }
        }
        else {
            # Too many to draw one by one: one box stands for them.
            $mn = Add-GraphNode $Gs "$($direct.Count) members of $($grp.name)" 'members' $n.Sev
            Add-GraphEdge $Gs $mn $n $via $n.Sev
            $budget--
        }
    }

    $done = Complete-AttackGraph $Gs

    # Trusts.
    $trusts = @()
    foreach ($t in @($Snapshot.trusts | Where-Object { $_ -and -not $_.intraForest })) {
        $risk = ($t.usesRC4Encryption -or -not $t.sidFilteringQuarantined -or $t.tgtDelegation)
        $trusts += [PSCustomObject]@{ Name = $t.name; Direction = "$($t.direction)"; Type = "$($t.trustType)"; Forest = [bool]$t.forestTransitive; Risk = [bool]$risk }
    }

    return [PSCustomObject]@{ Nodes = $done.Nodes; Edges = $done.Edges; Trusts = $trusts }
}

# The real paths, tokenized, for the AI prompt, so the model describes them instead of making them up.
function Get-AttackPathLines {
    param($Findings, $Pz, [int]$Max = 30)
    $lines = New-Object System.Collections.Generic.List[string]
    $rows = @()
    foreach ($f in @($Findings | Where-Object { $_ })) {
        if (-not $script:EscalationKinds.Contains($f.Type)) { continue }
        $cond = if ($script:EscalationConditions.ContainsKey($f.Type)) { & $script:EscalationConditions[$f.Type] $f } else { 'ok' }
        if ($cond -eq 'skip') { continue }
        # Same wording as the map: the right is real, that it reaches Tier 0 is an assumption. The
        # model is told to present an assumed step as assumed instead of as a fact.
        $dest = if ($cond -eq 'unverified') { 'Tier 0 (assumed)' } else { 'Tier 0' }
        $rows += [PSCustomObject]@{ Sev = $f.Severity; Obj = $f.Object; Kind = $script:EscalationKinds[$f.Type]; Dest = $dest }
    }
    # Worst first, otherwise input order (Sort-Object on PS 5.1 isn't stable).
    $rows = @(foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $rows | Where-Object { $_.Sev -eq $s } })
    $rows = @($rows | Select-Object -First $Max)
    foreach ($r in $rows) {
        $o = if ($Pz) { Protect-AiText $Pz $r.Obj } else { $r.Obj }
        $lines.Add("- [$($r.Sev)] $o  ->  $($r.Dest)  via $($r.Kind)")
    }
    return $lines
}

# --------------------------------------------------------------------------
# Entra: edges toward the admin roles
# --------------------------------------------------------------------------
function Get-EntraAttackGraph {
    param($Snapshot, $Findings)
    $Gs = New-GraphState
    $anyKey = 'Any user'
    $findings = @($Findings | Where-Object { $_ })
    $usersById = @{}; foreach ($u in @($Snapshot.users | Where-Object { $_ })) { $usersById["$($u.id)"] = $u }
    $spById = @{}; foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ })) { $spById["$($sp.id)"] = $sp }
    $groupsById = @{}; foreach ($g in @($Snapshot.groups | Where-Object { $_ })) { $groupsById["$($g.id)"] = $g }
    # Admins are the destination, not a source: their ownerships are not drawn.
    $admins = @{}
    foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ })) {
        if (-not $script:EntraPrivRoleTemplates.ContainsKey("$($r.roleTemplateId)")) { continue }
        foreach ($m in @($r.members | Where-Object { $_ })) { $admins["$m"] = $true }
    }
    $nameOf = { param([string]$Id, [string]$Type)
        if ($Type -eq 'servicePrincipal' -and $spById[$Id]) { return "$($spById[$Id].displayName)" }
        if ($usersById[$Id]) { return "$($usersById[$Id].upn)" }
        return $Id
    }
    # Owners (non-admin users and service principals) of an object, from an id -> type map.
    $owners = { param($OwnerTypes)
        if (-not $OwnerTypes) { return @() }
        $props = if ($OwnerTypes -is [System.Collections.IDictionary]) { @($OwnerTypes.Keys | ForEach-Object { [PSCustomObject]@{ Name = "$_"; Value = "$($OwnerTypes[$_])" } }) } else { @($OwnerTypes.PSObject.Properties) }
        @($props | Where-Object { -not $admins.ContainsKey("$($_.Name)") -and ("$($_.Value)" -eq 'user' -and $usersById["$($_.Name)"] -or "$($_.Value)" -eq 'servicePrincipal') } |
            ForEach-Object { [PSCustomObject]@{ Label = (& $nameOf "$($_.Name)" "$($_.Value)"); Type = $(if ("$($_.Value)" -eq 'servicePrincipal') { 'serviceprincipal' } else { 'user' }) } })
    }

    foreach ($f in $findings) {
        if (-not $script:EntraEscalationKinds.Contains($f.Type) -or -not "$($f.Object)") { continue }
        $n = Add-GraphNode $Gs "$($f.Object)" "$($f.ObjectType)" $f.Severity
        Add-GraphEdge $Gs $n $null $script:EntraEscalationKinds[$f.Type] $f.Severity
        $via = $null
        switch ($f.Type) {
            'entra_privileged_group_owner' { $g = $groupsById["$($f.ObjectDn)"]; if ($g) { $via = @{ Kind = 'Owns the group'; List = @(& $owners $g.ownerTypes) } }; break }
            { $_ -in 'entra_privileged_app_owner', 'entra_privileged_app_sp_owner' } {
                $sp = $spById["$($f.ObjectDn)"]
                if ($sp -and $sp.PSObject.Properties['ownerTypes']) {
                    $list = @(& $owners $sp.ownerTypes)
                    if ($f.Type -eq 'entra_privileged_app_owner') { $list = @($list | Where-Object { $_.Type -eq 'user' }) } else { $list = @($list | Where-Object { $_.Type -eq 'serviceprincipal' }) }
                    $via = @{ Kind = 'Owns the app'; List = $list }
                }
                break
            }
            'entra_app_scoped_admin_privileged' {
                if ("$($f.Detail)" -match 'Scoped app admin\(s\): (.+?)\. The app holds') {
                    $via = @{ Kind = 'App admin on the app'; List = @($Matches[1] -split ', ' | ForEach-Object { [PSCustomObject]@{ Label = ($_ -replace ' \([^)]*\)$', ''); Type = 'user' } }) }
                }
                break
            }
            'entra_access_package_grants_admin' {
                if ("$($f.Detail)" -match ': (all\w*) can request') { $a = Add-GraphNode $Gs $anyKey 'entry' $f.Severity; Add-GraphEdge $Gs $a $n "Request the package ($($Matches[1]))" $f.Severity }
                break
            }
        }
        if ($via) {
            foreach ($o in @($via.List | Where-Object { $_ -and $_.Label })) {
                $on = Add-GraphNode $Gs $o.Label $o.Type $f.Severity
                Add-GraphEdge $Gs $on $n $via.Kind $f.Severity
            }
        }
    }
    # An admin with no MFA at all is one password away.
    foreach ($f in @($findings | Where-Object { $_.Type -eq 'entra_admins_without_mfa' -and "$($_.Object)" })) {
        $a = Add-GraphNode $Gs $anyKey 'entry' $f.Severity
        Add-GraphEdge $Gs $a $null "No MFA ($($f.Object))" $f.Severity
    }
    # "Privileged app" only says why its owner matters: drop it where a more precise arrow exists.
    $precise = @{}; foreach ($e in $Gs.Edges) { if ($e.To -lt 0 -and $e.Kind -ne 'Privileged app') { $precise[$e.From] = $true } }
    $kept = @($Gs.Edges | Where-Object { -not ($_.To -lt 0 -and $_.Kind -eq 'Privileged app' -and $precise.ContainsKey($_.From)) })
    $Gs.Edges.Clear(); foreach ($e in $kept) { $Gs.Edges.Add($e) }
    return (Complete-AttackGraph $Gs)
}

# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
function ConvertTo-GraphLabel { param([string]$S, [int]$Max = 28) if ($null -eq $S) { return '' }; if ($S.Length -le $Max) { return $S }; return $S.Substring(0, $Max - 1) + [char]0x2026 }

# The SVG of a graph from Complete-AttackGraph, plus what the caption needs.
function ConvertTo-AttackGraphSvg {
    param($Graph, [string]$AnchorTitle = 'Tier 0', [string]$AnchorSub = 'domain compromise', [int]$Cap = 26)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $allNodes = @($Graph.Nodes)
    $shown = @($allNodes | Select-Object -First $Cap)
    # Layout. With no chains, up to two columns of sources on the left and the anchor on the right.
    # With chains (A has a right over B, B reaches Tier 0), one column per hop: the longest chain starts
    # at the left, and every arrow points one or more columns to the right.
    $shownIds = @{}; foreach ($n in $shown) { $shownIds[$n.Id] = $true }
    $edgesList = @($Graph.Edges)
    # Keep the targets of the visible hops, or a chain would end in the air.
    do {
        $grew = $false
        foreach ($e in $edgesList) {
            if ($shownIds.ContainsKey($e.From) -and $e.To -ge 0 -and -not $shownIds.ContainsKey($e.To)) {
                $t = $allNodes | Where-Object { $_.Id -eq $e.To } | Select-Object -First 1
                if ($t) { $shown += $t; $shownIds[$t.Id] = $true; $grew = $true }
            }
        }
    } while ($grew)
    $maxLevel = [int](($shown | ForEach-Object { $_.Level } | Measure-Object -Maximum).Maximum)
    $chain = $maxLevel -gt 0
    $boxH = 24; $rowH = 32; $top = 54; $t0w = 150; $t0h = 44
    $pos = @{}
    if ($chain) {
        $boxW = 190; $gapX = 70
        $colX = @(0..$maxLevel | ForEach-Object { 16 + $_ * ($boxW + $gapX) })
        $byCol = @{}
        foreach ($n in ($shown | Sort-Object @{ Expression = { - (Get-GraphSevRank $_.Sev) } }, Label)) {
            $c = $maxLevel - $n.Level
            if (-not $byCol.ContainsKey($c)) { $byCol[$c] = 0 }
            $pos[$n.Id] = @{ X = $colX[$c]; Y = $top + $byCol[$c] * $rowH }
            $byCol[$c]++
        }
        $rows = [int](($byCol.Values | Measure-Object -Maximum).Maximum)
        $svgH = [int]([Math]::Max($rows, 3) * $rowH + $top + 30)
        $t0x = 16 + ($maxLevel + 1) * ($boxW + $gapX); $svgW = $t0x + $t0w + 20
    }
    else {
        $boxW = 210; $colX = @(16, 250)
        $perCol = [Math]::Ceiling($shown.Count / [double]($colX.Count))
        $svgH = [int]([Math]::Max($perCol, 3) * $rowH + $top + 30)
        $svgW = 760; $t0x = 560
        for ($i = 0; $i -lt $shown.Count; $i++) {
            $col = [int]([Math]::Floor($i / $perCol))
            $pos[$shown[$i].Id] = @{ X = $colX[[Math]::Min($col, $colX.Count - 1)]; Y = $top + ($i % $perCol) * $rowH }
        }
    }
    $t0y = [int]($svgH / 2)

    $svg = New-Object System.Text.StringBuilder
    [void]$svg.AppendLine("<svg viewBox='0 0 $svgW $svgH' width='100%' preserveAspectRatio='xMinYMin meet' font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif' class='attack-map'>")
    [void]$svg.AppendLine("<defs><marker id='amArrow' markerWidth='9' markerHeight='9' refX='8' refY='3' orient='auto'><path d='M0,0 L8,3 L0,6 Z' fill='#5F5A51'/></marker></defs>")
    # Edges first (under nodes).
    $nodeById = @{}; foreach ($n in $shown) { $nodeById[$n.Id] = $n }
    foreach ($e in $edgesList) {
        if (-not $pos.ContainsKey($e.From)) { continue }
        $p = $pos[$e.From]
        $x1 = $p.X + $boxW; $y1 = $p.Y + [int]($boxH / 2)
        $toHop = ($e.To -ge 0 -and $pos.ContainsKey($e.To) -and $chain)
        if ($toHop) { $x2 = $pos[$e.To].X; $y2 = $pos[$e.To].Y + [int]($boxH / 2); $dest = & $H $nodeById[$e.To].Label }
        else { $x2 = $t0x; $y2 = $t0y; $dest = & $H $AnchorTitle }
        $mx = [int](($x1 + $x2) / 2)
        $col = $script:GraphSevColor[$e.Sev]
        $dataTo = if ($toHop) { " data-to='$($e.To)'" } else { '' }
        $dash = if ($e.Unverified) { " stroke-dasharray='5,4'" } else { '' }
        $unv = if ($e.Unverified) { " (unverified: the object is not known to lead to $AnchorTitle)" } else { '' }
        [void]$svg.AppendLine("<path class='am-edge am-from-$($e.From)'$dataTo d='M$x1,$y1 C$mx,$y1 $mx,$y2 $x2,$y2' fill='none' stroke='$col' stroke-width='1.6' opacity='0.45'$dash marker-end='url(#amArrow)'><title>$(& $H $nodeById[$e.From].Label) -> $dest via $(& $H $e.Kind) [$($e.Sev)]$(& $H $unv)</title></path>")
    }
    # Anchor.
    [void]$svg.AppendLine("<rect x='$t0x' y='$([int]($t0y-$t0h/2))' width='$t0w' height='$t0h' rx='8' fill='#161513' stroke='#161513' stroke-width='2'/>")
    [void]$svg.AppendLine("<text x='$([int]($t0x+$t0w/2))' y='$([int]($t0y-2))' text-anchor='middle' fill='#F3EFE6' font-size='13' font-weight='700'>$(& $H $AnchorTitle)</text>")
    [void]$svg.AppendLine("<text x='$([int]($t0x+$t0w/2))' y='$([int]($t0y+13))' text-anchor='middle' fill='#B9B1A1' font-size='10'>$(& $H $AnchorSub)</text>")
    # Source nodes; the entry point ("any user") is drawn dark, like the anchor.
    foreach ($n in $shown) {
        $p = $pos[$n.Id]
        $col = $script:GraphSevColor[$n.Sev]
        $entry = ($n.Type -eq 'entry')
        $label = & $H (ConvertTo-GraphLabel $n.Label)
        $tech = & $H (($n.Techniques | Select-Object -First 3) -join ', ')
        [void]$svg.AppendLine("<g class='am-node' data-nid='$($n.Id)' onmouseover='amMap(this,true)' onmouseout='amMap(this,false)'>")
        [void]$svg.AppendLine("<rect x='$($p.X)' y='$($p.Y)' width='$boxW' height='$boxH' rx='5' fill='$(if ($entry) { '#3A3631' } else { '#fff' })' stroke='$col' stroke-width='1.6'/>")
        [void]$svg.AppendLine("<rect x='$($p.X)' y='$($p.Y)' width='4' height='$boxH' rx='2' fill='$col'/>")
        [void]$svg.AppendLine("<text x='$($p.X + 10)' y='$($p.Y + 16)' font-size='11' fill='$(if ($entry) { '#F3EFE6' } else { '#161513' })'$(if ($entry) { " font-weight='700'" })>$label</text>")
        [void]$svg.AppendLine("<title>$(& $H $n.Label) [$($n.Type)] - $tech</title>")
        [void]$svg.AppendLine("</g>")
    }
    [void]$svg.AppendLine('</svg>')
    return [PSCustomObject]@{
        Svg = $svg.ToString(); ShownCount = $shown.Count; MoreCount = ($allNodes.Count - $shown.Count); Chain = $chain; MaxLevel = $maxLevel
        HasUnverified = (@($edgesList | Where-Object { $_.Unverified }).Count -gt 0); HasEntry = (@($shown | Where-Object { $_.Type -eq 'entry' }).Count -gt 0)
    }
}

# Caption under a map: what boxes, arrows, dashes and hops mean.
function Get-AttackMapCaption {
    param($R, [string]$AnchorTitle, [string]$EntryLabel)
    $out = New-Object System.Collections.Generic.List[string]
    # ShownCount, not the cap: a chain whose first box made the cut brings the rest of its boxes in.
    if ($R.MoreCount -gt 0) { $out.Add("<p class='meta'>Showing the $($R.ShownCount) highest-severity sources and the boxes their paths run through; $($R.MoreCount) more escalation source(s) are in the findings tables below.</p>") }
    $note = ''
    if ($R.HasEntry) { $note += " The dark box <b>$EntryLabel</b> is where an attacker starts with no special rights: every arrow out of it needs nothing more than an ordinary account (or, for a guessed password, none)." }
    if ($R.HasUnverified) { $note += " Dashed arrows: the right is real but the object it is held over is not known to lead to $AnchorTitle, so that step is an assumption; check those first." }
    if ($R.Chain) { $note += " Boxes joined by an arrow are hops of one chain: a principal that holds a right over the next box (or owns it, or is a member of it) and so inherits what it reaches ($($R.MaxLevel + 1) steps at most). Hover a box to light up its whole path." }
    $out.Add("<p class='meta'>Each box is a principal or object that has a path to $AnchorTitle; the arrow is the technique. Colour is the severity. Hover an arrow for the exact path.$note This is derived from the deterministic findings, not a live reachability test.</p>")
    return ($out -join "`n")
}

# Renders the attack-path map + trust map as one collapsible report section.
function ConvertTo-AttackMapHtml {
    param($Snapshot, $Index, $PrivMap, $Findings)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $g = Get-AttackGraph -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap -Findings $Findings
    $cap = 26

    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    & $w '<details open class="map-details"><summary><h2>Attack-path map (toward Tier 0)</h2></summary>'

    if (@($g.Nodes).Count -eq 0) {
        & $w '<p class="meta">No escalation path toward Tier 0 was found in this snapshot. This is a good sign, but remember that deep ACL findings need a <code>-Deep</code> collection and password-based paths need the password-quality report.</p>'
    }
    else {
        $r = ConvertTo-AttackGraphSvg -Graph $g -AnchorTitle 'Tier 0' -AnchorSub 'domain compromise' -Cap $cap
        & $w "<div class='map-wrap'>$($r.Svg)</div>"
        & $w (Get-AttackMapCaption -R $r -AnchorTitle 'Tier 0' -EntryLabel 'Any domain user')
    }

    # ---- Trust map ----
    & $w "<h3 style='margin-top:18px'>Trust map</h3>"
    $trusts = @($g.Trusts)
    if ($trusts.Count -eq 0) {
        & $w '<p class="meta">No external or forest trusts.</p>'
    }
    else {
        $tw = 760; $cx = 380; $cy = 150; $r = 110
        $tsvg = New-Object System.Text.StringBuilder
        [void]$tsvg.AppendLine("<svg viewBox='0 0 $tw 320' width='100%' preserveAspectRatio='xMinYMin meet' font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif'>")
        $n = $trusts.Count
        for ($i = 0; $i -lt $n; $i++) {
            $ang = (2 * [Math]::PI * $i / [Math]::Max(1, $n)) - [Math]::PI / 2
            $tx = [int]($cx + $r * [Math]::Cos($ang) * 1.6)
            $ty = [int]($cy + $r * [Math]::Sin($ang))
            $tr = $trusts[$i]
            $col = if ($tr.Risk) { '#E2372A' } else { '#8A857A' }
            $dash = if ($tr.Forest) { "stroke-dasharray='5,3'" } else { '' }
            [void]$tsvg.AppendLine("<line x1='$cx' y1='$cy' x2='$tx' y2='$ty' stroke='$col' stroke-width='1.6' opacity='0.6' $dash/>")
            $boxw = 150; $bx = [int]($tx - $boxw / 2); $by = [int]($ty - 14)
            [void]$tsvg.AppendLine("<rect x='$bx' y='$by' width='$boxw' height='28' rx='5' fill='#fff' stroke='$col' stroke-width='1.6'/>")
            [void]$tsvg.AppendLine("<text x='$tx' y='$([int]($ty+1))' text-anchor='middle' font-size='10.5' fill='#161513'>$(& $H (ConvertTo-GraphLabel $tr.Name 20))</text>")
            [void]$tsvg.AppendLine("<text x='$tx' y='$([int]($ty+13))' text-anchor='middle' font-size='9' fill='#5F5A51'>$(& $H $tr.Direction) $(if ($tr.Forest){'forest'}else{'external'})</text>")
        }
        [void]$tsvg.AppendLine("<rect x='$([int]($cx-85))' y='$([int]($cy-18))' width='170' height='36' rx='8' fill='#161513' stroke='#161513' stroke-width='2'/>")
        [void]$tsvg.AppendLine("<text x='$cx' y='$([int]($cy+5))' text-anchor='middle' fill='#F3EFE6' font-size='12' font-weight='700'>$(& $H (ConvertTo-GraphLabel $Snapshot.domain.dnsRoot 24))</text>")
        [void]$tsvg.AppendLine('</svg>')
        & $w "<div class='map-wrap'>$($tsvg.ToString())</div>"
        & $w "<p class='meta'>Red = a trust with a weak setting (RC4, no SID filtering, or TGT delegation). Dashed = forest trust. See the Domain Configuration findings for detail.</p>"
    }

    # ---- Tier 0 members ----
    # The map shows what can reach Tier 0. The accounts that already are Tier 0 (Administrator, Domain
    # Admins...) are the destination, so they are listed here instead of drawn as sources.
    $t0 = @($PrivMap.Principals.Values | Where-Object { $_ })
    if ($t0.Count -gt 0) {
        & $w "<h3 style='margin-top:18px'>Tier 0 members ($($t0.Count))</h3>"
        & $w '<p class="meta">These principals already hold Tier 0 rights, so they are the target of the paths above, not a source. Compromising any of them is domain compromise.</p>'
        & $w '<div class="table-wrap"><table><tr><th>Principal</th><th>Kind</th><th>Status</th><th>Last logon</th><th>Password age</th><th>Tier 0 through</th></tr>'
        $rows = foreach ($rec in $t0) {
            $p = $rec.Principal
            $name = if ($p) { "$($p.samAccountName)" } else { "$($rec.Dn)" }
            $kind = if ($rec.Type -eq 'foreign' -or $rec.Type -eq 'unresolved') { "$($rec.Type)" } elseif ($rec.Type -eq 'computer') { 'computer' } elseif ($p -and ($p.kind -ne 'user' -or @($p.servicePrincipalNames | Where-Object { $_ }).Count)) { 'service account' } else { 'user' }
            $status = if ($p) { if ($p.enabled) { 'enabled' } else { 'disabled' } } else { '' }
            $ll = if ($p) { Get-AgeDays $p.lastLogonTimestamp } else { $null }
            $pa = if ($p) { Get-AgeDays $p.pwdLastSet } else { $null }
            [PSCustomObject]@{ Name = $name; Kind = $kind; Status = $status; Logon = $(if ($p) { if ($null -eq $ll) { 'never' } else { "$ll d ago" } } else { '' }); Pwd = $(if ($null -ne $pa) { "$pa d" } else { '' }); Groups = ($rec.Groups -join ', ') }
        }
        foreach ($r in @($rows | Sort-Object Kind, Name)) {
            & $w "<tr class=`"data-row`"><td><b>$(& $H $r.Name)</b></td><td>$(& $H $r.Kind)</td><td>$(& $H $r.Status)</td><td>$(& $H $r.Logon)</td><td>$(& $H $r.Pwd)</td><td>$(& $H $r.Groups)</td></tr>"
        }
        & $w '</table></div>'
    }

    & $w '</details>'
    return $sb.ToString()
}

# The same map for the Entra report: what can reach an admin role.
function ConvertTo-EntraAttackMapHtml {
    param($Snapshot, $Findings)
    $g = Get-EntraAttackGraph -Snapshot $Snapshot -Findings $Findings
    $cap = 26
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    & $w '<details open class="map-details"><summary><h2>Attack-path map (toward the admin roles)</h2></summary>'
    if (@($g.Nodes).Count -eq 0) {
        & $w '<p class="meta">No path toward an admin role was found in this snapshot: no app, group, owner or access package that hands out admin rights to someone who is not an admin.</p>'
    }
    else {
        $r = ConvertTo-AttackGraphSvg -Graph $g -AnchorTitle 'Admin roles' -AnchorSub 'tenant takeover' -Cap $cap
        & $w "<div class='map-wrap'>$($r.Svg)</div>"
        & $w (Get-AttackMapCaption -R $r -AnchorTitle 'an admin role' -EntryLabel 'Any user')
    }
    & $w '</details>'
    return $sb.ToString()
}
