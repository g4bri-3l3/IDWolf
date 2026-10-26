# IDWolf reporting: HTML report, findings CSV, JSON Lines (SIEM) and
# comparison with a previous run.

# Regulatory controls of a check (lib\Compliance.ps1), empty when that file isn't loaded.
function Get-FindingControls {
    param([string]$Type)
    # Get-CheckControls hands back one array object: assign it, don't wrap it in @() again.
    if (Get-Command Get-CheckControls -ErrorAction SilentlyContinue) { $c = Get-CheckControls $Type; return , [string[]]$c }
    return , [string[]]@()
}

function Export-FindingsCsv {
    param($Findings, [string]$Path)
    $rows = @($Findings | Select-Object Severity, Type, Title, Category, Object, ObjectType, ObjectDn, Detail, Mitre, @{ Name = 'Controls'; Expression = { (Get-FindingControls $_.Type) -join '; ' } })
    if ($rows.Count -eq 0) {
        # Keep the header so -CompareTo works against a clean run.
        'Severity,Type,Title,Category,Object,ObjectType,ObjectDn,Detail,Mitre,Controls' | Set-Content -LiteralPath $Path -Encoding UTF8
        return
    }
    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

# One JSON object per line, flat fields, for any SIEM (Splunk _json, Sentinel,
# Elastic). Three kinds of event, told apart by event_type:
#   finding  - one per active finding; status new/persisting with -CompareTo
#   resolved - in the previous run, gone now (only with -CompareTo)
#   summary  - one per run: score, counts, checks not evaluated
# finding_id is the same for the same check on the same object in every run,
# so a SIEM can follow one issue over time. run_id groups the lines of a run.
$script:SeverityScore = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }

function Get-FindingId {
    param([string]$Type, [string]$Object)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Type|$Object".ToLower()))
        return (-join ($bytes[0..7] | ForEach-Object { $_.ToString('x2') }))
    }
    finally { $sha.Dispose() }
}

function Export-FindingsJsonl {
    param($Findings, $Snapshot, [string]$Path, [string]$ToolVersion,
        $Score = $null, $Comparison = $null, $NotEvaluated = @(), [int]$AcceptedCount = 0)
    $sb = New-Object System.Text.StringBuilder
    $collected = ConvertTo-UtcDate $Snapshot.meta.collectedAtUtc
    $isEntra = "$($Snapshot.meta.kind)" -eq 'entra'
    $source = if ($isEntra) { if ($Snapshot.org) { "$($Snapshot.org.displayName)" } else { "$($Snapshot.meta.tenantId)" } } else { "$($Snapshot.domain.dnsRoot)" }
    $runId = "{0}-{1}" -f ($source -replace '[^\w\.\-]', '_'), $collected.ToString('yyyyMMddHHmmss')
    $base = {
        param([string]$EventType)
        $o = [ordered]@{
            time         = $collected.ToString('o')
            event_type   = $EventType
            run_id       = $runId
            tool         = 'IDWolf'
            tool_version = $ToolVersion
            source_kind  = $(if ($isEntra) { 'entra' } else { 'ad' })
            domain       = $source
        }
        if ($isEntra) { $o['tenant_id'] = "$($Snapshot.meta.tenantId)" }
        $o
    }
    $newKeys = @{}
    if ($Comparison) { foreach ($n in @($Comparison.New)) { $newKeys["$($n.Type)|$($n.Object)".ToLower()] = $true } }
    foreach ($f in $Findings) {
        $o = & $base 'finding'
        $o['severity'] = $f.Severity
        $o['severity_score'] = $script:SeverityScore[$f.Severity]
        $o['check'] = $f.Type
        $o['title'] = $f.Title
        $o['category'] = $f.Category
        $o['object'] = $f.Object
        $o['object_type'] = $f.ObjectType
        $o['object_dn'] = $f.ObjectDn
        $o['detail'] = $f.Detail
        $o['mitre'] = $f.Mitre
        $o['controls'] = Get-FindingControls $f.Type
        $o['finding_id'] = Get-FindingId $f.Type $f.Object
        $o['status'] = $(if (-not $Comparison) { $null } elseif ($newKeys.ContainsKey("$($f.Type)|$($f.Object)".ToLower())) { 'new' } else { 'persisting' })
        [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
    }
    if ($Comparison) {
        foreach ($r in @($Comparison.Resolved)) {
            $o = & $base 'resolved'
            $o['severity'] = $r.Severity
            $o['severity_score'] = $script:SeverityScore["$($r.Severity)"]
            $o['check'] = $r.Type
            $o['title'] = $r.Title
            $o['object'] = $r.Object
            $o['finding_id'] = Get-FindingId $r.Type $r.Object
            $o['status'] = 'resolved'
            [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
        }
    }
    if ($Score) {
        $o = & $base 'summary'
        $o['score'] = $Score.Score
        $o['grade'] = $Score.Grade
        $o['score_reliable'] = [bool]$Score.Reliable
        $o['coverage_pct'] = $Score.Coverage
        $o['findings'] = @($Findings).Count
        foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $o[$s.ToLower()] = @($Findings | Where-Object { $_.Severity -eq $s }).Count }
        $o['accepted'] = $AcceptedCount
        $o['new'] = $(if ($Comparison) { @($Comparison.New).Count } else { $null })
        $o['resolved'] = $(if ($Comparison) { @($Comparison.Resolved).Count } else { $null })
        $o['not_evaluated'] = @($NotEvaluated).Count
        $o['not_evaluated_checks'] = [string[]]@($NotEvaluated | ForEach-Object { $_.Type })
        [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
    }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-FindingsComparison {
    param($Findings, [string]$PreviousCsv)
    $prev = @(Import-Csv -LiteralPath $PreviousCsv)
    $key = { param($f) "$($f.Type)|$($f.Object)".ToLower() }
    $prevMap = @{}; foreach ($p in $prev) { $prevMap[(& $key $p)] = $p }
    $curMap = @{}; foreach ($c in $Findings) { $curMap[(& $key $c)] = $c }
    $new = @($Findings | Where-Object { -not $prevMap.ContainsKey((& $key $_)) })
    $resolved = @($prev | Where-Object { -not $curMap.ContainsKey((& $key $_)) })
    $persisting = @($Findings | Where-Object { $prevMap.ContainsKey((& $key $_)) })
    return [PSCustomObject]@{ New = $new; Resolved = $resolved; Persisting = $persisting; PreviousPath = $PreviousCsv }
}

function Get-SevPill {
    param([string]$Severity)
    # The comparison and the accepted list read Severity back from an earlier CSV: encode it.
    $s = if ($script:SeverityRank.ContainsKey($Severity)) { $Severity.ToLower() } else { 'unknown' }
    return "<span class=`"sev-pill sev-pill-$s`">$(ConvertTo-HtmlSafe $Severity)</span>"
}

function Get-MitreLink {
    param([string]$Id)
    if (-not $Id) { return '' }
    $path = $Id -replace '\.', '/'
    return "<a href=`"https://attack.mitre.org/techniques/$path/`" target=`"_blank`" rel=`"noopener`">$Id</a>"
}

# Names of the ATT&CK techniques the catalogs use, as attack.mitre.org shows them
# (sub-techniques as "Technique: Sub-technique"). The regression asserts that every
# Mitre ID in a catalog is here, so a new ID needs its name added.
$script:MitreTechniqueNames = @{
    'T1003'     = 'OS Credential Dumping'
    'T1003.001' = 'OS Credential Dumping: LSASS Memory'
    'T1003.005' = 'OS Credential Dumping: Cached Domain Credentials'
    'T1003.006' = 'OS Credential Dumping: DCSync'
    'T1006'     = 'Direct Volume Access'
    'T1021.001' = 'Remote Services: Remote Desktop Protocol'
    'T1036'     = 'Masquerading'
    'T1059.005' = 'Command and Scripting Interpreter: Visual Basic'
    'T1068'     = 'Exploitation for Privilege Escalation'
    'T1072'     = 'Software Deployment Tools'
    'T1078'     = 'Valid Accounts'
    'T1078.001' = 'Valid Accounts: Default Accounts'
    'T1078.002' = 'Valid Accounts: Domain Accounts'
    'T1078.003' = 'Valid Accounts: Local Accounts'
    'T1078.004' = 'Valid Accounts: Cloud Accounts'
    'T1087'     = 'Account Discovery'
    'T1087.002' = 'Account Discovery: Domain Account'
    'T1087.004' = 'Account Discovery: Cloud Account'
    'T1098'     = 'Account Manipulation'
    'T1098.001' = 'Account Manipulation: Additional Cloud Credentials'
    'T1098.003' = 'Account Manipulation: Additional Cloud Roles'
    'T1098.005' = 'Account Manipulation: Device Registration'
    'T1110'     = 'Brute Force'
    'T1110.001' = 'Brute Force: Password Guessing'
    'T1110.002' = 'Brute Force: Password Cracking'
    'T1110.003' = 'Brute Force: Password Spraying'
    'T1110.004' = 'Brute Force: Credential Stuffing'
    'T1111'     = 'Multi-Factor Authentication Interception'
    'T1134.005' = 'Access Token Manipulation: SID-History Injection'
    'T1136.002' = 'Create Account: Domain Account'
    'T1136.003' = 'Create Account: Cloud Account'
    'T1187'     = 'Forced Authentication'
    'T1199'     = 'Trusted Relationship'
    'T1204.002' = 'User Execution: Malicious File'
    'T1207'     = 'Rogue Domain Controller'
    'T1210'     = 'Exploitation of Remote Services'
    'T1484.001' = 'Domain or Tenant Policy Modification: Group Policy Modification'
    'T1485'     = 'Data Destruction'
    'T1528'     = 'Steal Application Access Token'
    'T1547.012' = 'Boot or Logon Autostart Execution: Print Processors'
    'T1548'     = 'Abuse Elevation Control Mechanism'
    'T1548.002' = 'Abuse Elevation Control Mechanism: Bypass User Account Control'
    'T1550'     = 'Use Alternate Authentication Material'
    'T1550.001' = 'Use Alternate Authentication Material: Application Access Token'
    'T1550.002' = 'Use Alternate Authentication Material: Pass the Hash'
    'T1550.003' = 'Use Alternate Authentication Material: Pass the Ticket'
    'T1552'     = 'Unsecured Credentials'
    'T1552.001' = 'Unsecured Credentials: Credentials In Files'
    'T1552.006' = 'Unsecured Credentials: Group Policy Preferences'
    'T1553.004' = 'Subvert Trust Controls: Install Root Certificate'
    'T1555'     = 'Credentials from Password Stores'
    'T1556.003' = 'Modify Authentication Process: Pluggable Authentication Modules'
    'T1556.005' = 'Modify Authentication Process: Reversible Encryption'
    'T1556.006' = 'Modify Authentication Process: Multi-Factor Authentication'
    'T1556.009' = 'Modify Authentication Process: Conditional Access Policies'
    'T1557'     = 'Adversary-in-the-Middle'
    'T1557.001' = 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
    'T1558'     = 'Steal or Forge Kerberos Tickets'
    'T1558.001' = 'Steal or Forge Kerberos Tickets: Golden Ticket'
    'T1558.002' = 'Steal or Forge Kerberos Tickets: Silver Ticket'
    'T1558.003' = 'Steal or Forge Kerberos Tickets: Kerberoasting'
    'T1558.004' = 'Steal or Forge Kerberos Tickets: AS-REP Roasting'
    'T1562.002' = 'Impair Defenses: Disable Windows Event Logging'
    'T1562.004' = 'Impair Defenses: Disable or Modify System Firewall'
    'T1563.002' = 'Remote Service Session Hijacking: RDP Hijacking'
    'T1566'     = 'Phishing'
    'T1590'     = 'Gather Victim Network Information'
    'T1606.002' = 'Forge Web Credentials: SAML Tokens'
    'T1621'     = 'Multi-Factor Authentication Request Generation'
    'T1649'     = 'Steal or Forge Authentication Certificates'
}

# Checks tied to attack vectors seen in public incidents or research, mostly 2023-2026
# (the "Recent attacks" table in README.md and COVERAGE.md). Shown in the report next to
# the check and given to the AI step. Ordered, so the prompt is
# the same in every process. Labels hold no directory names.
$script:RecentAttackVectors = [ordered]@{
    badsuccessor_dmsa_create             = 'BadSuccessor: dMSA successor link on Windows Server 2025 (CVE-2025-53779, 2025)'
    kds_root_key_readable                = 'Golden gMSA / Golden dMSA: managed service account passwords from the KDS root key (2025)'
    coercion_unfiltered_dc               = 'Coercion of a DC (PetitPotam family) feeding NTLM relay (CVE-2025-24054 exploited in 2025)'
    webclient_on_dc                      = 'Coercion over WebDAV for NTLM relay to LDAP or AD CS'
    webclient_not_disabled               = 'Coercion over WebDAV for NTLM relay to LDAP or AD CS'
    adcs_esc8                            = 'NTLM relay to AD CS web enrollment (ESC8), common in ransomware intrusions'
    adcs_esc11                           = 'NTLM relay to AD CS RPC enrollment (ESC11)'
    ldap_signing_not_required            = 'NTLM relay to LDAP on the DCs'
    ldap_channel_binding_off             = 'NTLM relay to LDAPS on the DCs'
    ntlm_weak_lmcompat                   = 'NTLMv1 downgrade and relay'
    smb_signing_not_required             = 'NTLM relay and reflection over SMB (CVE-2025-33073, 2025)'
    smb_client_signing_not_required      = 'NTLM relay and reflection over SMB (CVE-2025-33073, 2025)'
    adcs_esc1                            = 'AD CS certificate template abuse (ESC1), common in ransomware intrusions'
    adcs_esc2                            = 'AD CS certificate template abuse (ESC2)'
    adcs_esc3                            = 'AD CS enrollment agent abuse (ESC3)'
    adcs_esc4                            = 'AD CS template ACL abuse (ESC4)'
    adcs_esc15                           = 'AD CS EKUwu (ESC15, CVE-2024-49019, 2024)'
    adcs_esc16                           = 'AD CS SID extension disabled CA-wide (ESC16, 2025)'
    kerberoastable_user                  = 'Kerberoasting, seen in ransomware intrusions through 2026'
    privileged_kerberoastable            = 'Kerberoasting of a privileged account, seen in ransomware intrusions through 2026'
    spn_account_rc4                      = 'Kerberoasting with RC4 tickets (faster offline cracking)'
    asrep_roastable                      = 'AS-REP roasting'
    shadow_credentials_present           = 'Shadow Credentials (msDS-KeyCredentialLink)'
    nopac_unpatched_dc                   = 'noPac (CVE-2021-42278/42287), still used by ransomware operators'
    gpp_cpassword                        = 'Group Policy Preferences passwords in SYSVOL, routinely harvested in intrusions'
    netlogon_vulnerable_channel          = 'ZeroLogon (CVE-2020-1472), still exploited'
    point_and_print_unsafe               = 'PrintNightmare (Point and Print)'
    entra_admin_synced_from_onprem       = 'Hybrid identity abuse: synced admins (Entra Connect, SyncJacking, 2025)'
    entra_connect_app_extra_credentials  = 'Entra Connect abuse (Black Hat 2025 research)'
    entra_smart_lockout_weak             = 'Password spraying, the main cloud initial access vector (Microsoft, 2026)'
    entra_banned_passwords_off           = 'Password spraying, the main cloud initial access vector (Microsoft, 2026)'
    entra_legacy_auth_allowed            = 'Password spraying through legacy authentication'
    entra_admins_without_mfa             = 'Password spraying and credential stuffing against admins'
    entra_device_code_flow_allowed       = 'Device code phishing (Storm-2372 and later kits, 2025-2026)'
    entra_no_phishing_resistant_admins   = 'Adversary-in-the-middle phishing and session token theft'
    entra_token_protection_off           = 'Session token theft and replay'
    entra_users_can_consent              = 'OAuth consent phishing'
    entra_risky_delegated_grant          = 'OAuth consent phishing and over-privileged apps'
    entra_app_high_privilege             = 'Over-privileged OAuth apps (Midnight Blizzard, 2024)'
    entra_privileged_app_sp_owner        = 'Escalation through service principal ownership (Entra Agent ID flaw, 2026)'
    entra_privileged_app_owner           = 'Escalation through app ownership'
    entra_intune_no_multi_admin_approval = 'Mass device wipe from a compromised Intune admin (Stryker, reported 2026)'
    entra_intune_role_weak_group         = 'Code execution on all managed devices through Intune'
}

# "Attack it enables." in a check's details: the ATT&CK technique with its name, and the
# attack seen in public incidents when the check is in $script:RecentAttackVectors.
function Format-CheckAttackHtml {
    param([string]$Type, $Meta)
    $parts = @()
    if ($Meta.Mitre) {
        $name = $script:MitreTechniqueNames["$($Meta.Mitre)"]
        $parts += "$(Get-MitreLink $Meta.Mitre)$(if ($name) { ' ' + (ConvertTo-HtmlSafe $name) })"
    }
    if ($script:RecentAttackVectors.Contains($Type)) { $parts += "Seen in attacks: $(ConvertTo-HtmlSafe $script:RecentAttackVectors[$Type])." }
    if ($parts.Count -eq 0) { return '' }
    return "<div class=`"kv`"><b>Attack it enables.</b> $($parts -join '<br>')</div>"
}

# Wolf-fur palette, charcoal to silver. Only severity and risk keep a muted
# colour, because there it means something.
$script:WolfCategoryRamp = @('#161513', '#2B2925', '#45413A', '#5F5A51', '#78726A', '#8F887C', '#ABA497', '#C6BFB0', '#DDD6C8')
$script:WolfSeverityColors = @('#E2372A', '#EF8A6F', '#F2B632', '#B9B1A1')

# Same wolf as the console banner. Single-quoted: the art has a backtick in it.
$script:WolfAscii = @'
                     .
                    / V\
                  / `  /
                 <<   |
                 /    |
               /      |
             /        |
           /    \  \ /
          (      ) | |
  ________|   _/_  | |
<__________\______)\__)
'@
function Get-WolfLogoHtml {
    return "<pre class='wolf-logo' role='img' aria-label='IDWolf wolf'>$(ConvertTo-HtmlSafe $script:WolfAscii)</pre>"
}

# Donut chart in plain SVG: each slice is a dash on a ring.
function Get-SvgPieChart {
    param([string[]]$Labels, [int[]]$Values, [string[]]$Colors, [int]$Size = 130, [string]$CenterLabel = "")
    $total = ($Values | Measure-Object -Sum).Sum
    if ($total -le 0) { return "<p class='meta'>No data.</p>" }
    $cx = $Size / 2; $cy = $Size / 2
    $strokeWidth = [Math]::Round($Size * 0.13, 1)
    $r = ($Size / 2) - ($strokeWidth / 2) - 1
    $circ = [Math]::Round(2 * [Math]::PI * $r, 2)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $rings = "<circle cx='$cx' cy='$cy' r='$($r.ToString($inv))' fill='none' stroke='#E8E2D4' stroke-width='$($strokeWidth.ToString($inv))' />"
    $legend = ""; $cum = 0
    for ($i = 0; $i -lt $Labels.Count; $i++) {
        $v = $Values[$i]
        if ($v -le 0) { continue }
        $seg = [Math]::Round(($v / $total) * $circ, 2)
        $off = [Math]::Round(-1 * $cum, 2)
        $rings += "<circle cx='$cx' cy='$cy' r='$($r.ToString($inv))' fill='none' stroke='$($Colors[$i])' stroke-width='$($strokeWidth.ToString($inv))' stroke-dasharray='$($seg.ToString($inv)) $($circ.ToString($inv))' stroke-dashoffset='$($off.ToString($inv))'><title>$(ConvertTo-HtmlSafe $Labels[$i]): $v</title></circle>"
        $cum += $seg
        $pct = [Math]::Round(($v / $total) * 100, 1).ToString($inv)
        $legend += "<div class='pie-legend-item'><span class='pie-legend-swatch' style='background:$($Colors[$i])'></span>$(ConvertTo-HtmlSafe $Labels[$i]) ($v, $pct%)</div>"
    }
    $svg = "<svg viewBox='0 0 $Size $Size' width='$Size' height='$Size' role='img'><g transform='rotate(-90 $cx $cy)'>$rings</g><text x='$cx' y='$($cy - 2)' text-anchor='middle' font-size='20' font-weight='600' fill='#161513'>$total</text><text x='$cx' y='$($cy + 14)' text-anchor='middle' font-size='9' fill='#5F5A51'>$CenterLabel</text></svg>"
    return "<div class='pie-chart-wrap'>$svg<div class='pie-legend'>$legend</div></div>"
}

function Get-ChartsRowHtml {
    param($Findings, $Index, $PrivMap)
    $sevLabels = @('Critical', 'High', 'Medium', 'Low')
    $sevVals = @($sevLabels | ForEach-Object { $s = $_; @($Findings | Where-Object { $_.Severity -eq $s }).Count })
    $sevPie = Get-SvgPieChart -Labels $sevLabels -Values $sevVals -Colors $script:WolfSeverityColors -CenterLabel 'findings'

    $cats = @('Kerberos', 'Privileged Access', 'Account Hygiene', 'Domain Configuration', 'Permissions', 'Certificate Services', 'Host Hardening', 'Password Quality', 'Operational Health')
    $catVals = @($cats | ForEach-Object { $c = $_; @($Findings | Where-Object { $_.Category -eq $c }).Count })
    $catPie = Get-SvgPieChart -Labels $cats -Values $catVals -Colors $script:WolfCategoryRamp -CenterLabel 'findings'

    # Tier 0: people actually using it versus dormant, machine or foreign members.
    $t = @{ active = 0; dormant = 0; disabled = 0; service = 0; computer = 0; foreign = 0 }
    foreach ($rec in $PrivMap.Principals.Values) {
        $p = $rec.Principal
        if (-not $p -or $rec.Type -eq 'foreign' -or $rec.Type -eq 'unresolved') { $t.foreign++; continue }
        if ($rec.Type -eq 'computer') { $t.computer++; continue }
        if (-not $p.enabled) { $t.disabled++; continue }
        if ($p.kind -ne 'user' -or @($p.servicePrincipalNames | Where-Object { $_ }).Count -gt 0) { $t.service++; continue }
        $ll = Get-AgeDays $p.lastLogonTimestamp
        if ($null -eq $ll -or $ll -gt 90) { $t.dormant++ } else { $t.active++ }
    }
    $tierPie = Get-SvgPieChart -Labels @('Active admins', 'Dormant (90d+)', 'Service accounts', 'Disabled', 'Computers', 'Foreign / unresolved') `
        -Values @($t.active, $t.dormant, $t.service, $t.disabled, $t.computer, $t.foreign) `
        -Colors @('#2B2925', '#F2B632', '#161513', '#D3CCBD', '#A39C8F', '#E2372A') -CenterLabel 'Tier 0'

    # Enabled user accounts by activity (standard + privileged, no MSA).
    $a = @{ recent = 0; inactive = 0; never = 0 }
    foreach ($u in @($Index.Users | Where-Object { $_.enabled -and $_.kind -eq 'user' })) {
        $ll = Get-AgeDays $u.lastLogonTimestamp
        if ($null -eq $ll) { $a.never++ } elseif ($ll -gt 180) { $a.inactive++ } else { $a.recent++ }
    }
    $actPie = Get-SvgPieChart -Labels @('Logon within 180d', 'Inactive 180d+', 'Never logged on') -Values @($a.recent, $a.inactive, $a.never) `
        -Colors @('#2B2925', '#8F887C', '#D3CCBD') -CenterLabel 'enabled users'

    $h = "<div class='chart-row'>"
    $h += "<div><div class='pie-chart-title'>Findings by severity</div>$sevPie</div>"
    $h += "<div><div class='pie-chart-title'>Findings by category</div>$catPie</div>"
    $h += "<div><div class='pie-chart-title'>Tier 0 composition</div>$tierPie</div>"
    $h += "<div><div class='pie-chart-title'>Enabled users by activity</div>$actPie</div>"
    $h += "</div>"
    return $h
}

# Pies about the directory itself rather than the findings: how many accounts, of what kind,
# how old the passwords are, what the machines run. A pie with no data is left out.
function Get-AdInfoChartsRow {
    param($Snapshot, $Index)
    $pies = New-Object System.Collections.Generic.List[string]
    $add = {
        param([string]$Title, [string]$Center, [string[]]$Labels, [int[]]$Values, [string[]]$Colors)
        if (($Values | Measure-Object -Sum).Sum -gt 0) {
            $pies.Add("<div><div class='pie-chart-title'>$(ConvertTo-HtmlSafe $Title)</div>$(Get-SvgPieChart -Labels $Labels -Values $Values -Colors $Colors -CenterLabel $Center)</div>")
        }
    }
    $users = @($Index.Users)
    $isSvc = { param($u) $u.kind -ne 'user' -or @($u.servicePrincipalNames | Where-Object { $_ }).Count -gt 0 }
    $enabled = @($users | Where-Object { $_.enabled })
    $svc = @($enabled | Where-Object { & $isSvc $_ }).Count
    & $add 'All accounts' 'accounts' @('User accounts', 'Service accounts', 'Disabled (users and MSAs)', 'Computers') `
        @(($enabled.Count - $svc), $svc, ($users.Count - $enabled.Count), @($Index.Computers).Count) @('#2B2925', '#78726A', '#D3CCBD', '#F2B632')

    $pw = @{ recent = 0; mid = 0; old = 0; never = 0 }
    foreach ($u in $enabled) {
        $a = Get-AgeDays $u.pwdLastSet
        if ($null -eq $a) { $pw.never++ } elseif ($a -le 90) { $pw.recent++ } elseif ($a -le 365) { $pw.mid++ } else { $pw.old++ }
    }
    & $add 'Password age (enabled accounts)' 'accounts' @('Changed within 90d', '91 to 365 days', 'Over 1 year', 'Never set') @($pw.recent, $pw.mid, $pw.old, $pw.never) @('#2B2925', '#8F887C', '#E2372A', '#D3CCBD')

    $notReq = @($enabled | Where-Object { Test-Uac $_ 'PASSWD_NOTREQD' }).Count
    $never = @($enabled | Where-Object { -not (Test-Uac $_ 'PASSWD_NOTREQD') -and (Test-Uac $_ 'DONT_EXPIRE_PASSWORD') }).Count
    & $add 'Password settings (enabled accounts)' 'accounts' @('Expires normally', 'Never expires', 'Password not required') @(($enabled.Count - $notReq - $never), $never, $notReq) @('#2B2925', '#F2B632', '#E2372A')

    $comps = @($Index.Computers)
    $osNames = @{}
    foreach ($c in $comps) { $n = if ($c.operatingSystem) { "$($c.operatingSystem)" -replace '(?i)^Windows\s+', '' } else { 'Unknown' }; if ($osNames.ContainsKey($n)) { $osNames[$n]++ } else { $osNames[$n] = 1 } }
    $top = @($osNames.GetEnumerator() | Sort-Object @{ Expression = { $_.Value }; Descending = $true }, Name)
    $labels = @(); $vals = @()
    foreach ($e in @($top | Select-Object -First 5)) { $labels += "$($e.Name)"; $vals += [int]$e.Value }
    $rest = ($top | Select-Object -Skip 5 | ForEach-Object { $_.Value } | Measure-Object -Sum).Sum
    if ($rest) { $labels += 'Other'; $vals += [int]$rest }
    if ($labels.Count) { & $add 'Computers by operating system' 'computers' $labels $vals @($script:WolfCategoryRamp[1], $script:WolfCategoryRamp[3], $script:WolfCategoryRamp[4], $script:WolfCategoryRamp[6], $script:WolfCategoryRamp[7], $script:WolfCategoryRamp[8]) }

    $cr = 0; $cs = 0; $cn = 0
    foreach ($c in @($comps | Where-Object { $_.enabled })) {
        $a = Get-AgeDays $c.lastLogonTimestamp
        if ($null -eq $a) { $cn++ } elseif ($a -le 90) { $cr++ } else { $cs++ }
    }
    & $add 'Enabled computers by activity' 'computers' @('Seen within 90d', 'Stale 90d+', 'Never logged on') @($cr, $cs, $cn) @('#2B2925', '#8F887C', '#D3CCBD')

    $grp = @{ Global = 0; DomainLocal = 0; Universal = 0 }
    foreach ($g in @($Index.Groups)) { $s = "$($g.groupScope)"; if ($grp.ContainsKey($s)) { $grp[$s]++ } }
    & $add 'Groups by scope' 'groups' @('Global', 'Domain local', 'Universal') @($grp.Global, $grp.DomainLocal, $grp.Universal) @('#2B2925', '#8F887C', '#D3CCBD')

    # Password quality (DSInternals), worst problem per account. Only with a report attached.
    $pq = $Snapshot.passwordQuality
    if ($pq) {
        $lists = [ordered]@{
            'Empty password'      = @(ConvertTo-PqNameList $pq.emptyPassword)
            'Cleartext stored'    = @(ConvertTo-PqNameList $pq.clearTextPassword)
            'Breached password'   = @(ConvertTo-PqNameList $pq.breachedPassword)
            'Default / username'  = @(ConvertTo-PqNameList $pq.defaultOrUsernamePassword)
            'Shared password'     = @($pq.duplicatePasswordGroups | Where-Object { $_ } | ForEach-Object { ConvertTo-PqNameList $_ })
        }
        $seen = @{}; $counts = @()
        foreach ($k in $lists.Keys) {
            $c = 0
            foreach ($name in @($lists[$k] | Where-Object { $_ })) { $key = "$name".ToLower(); if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $c++ } }
            $counts += $c
        }
        $clean = [Math]::Max(0, $enabled.Count - $seen.Count)
        $pqLabels = @('No weakness found') + @($lists.Keys)
        $pqVals = @($clean) + @($counts)
        & $add 'Password quality (enabled accounts)' 'accounts' $pqLabels $pqVals @('#2B2925', '#E2372A', '#A8261C', '#EF8A6F', '#F2B632', '#8F887C')
    }
    if (-not $pies.Count) { return '' }
    return "<div class='chart-row'>$($pies -join '')</div>"
}

# The report theme, shared by the AD and the Entra report: one <style> block, no external
# resource (system font stacks), so the HTML opens the same on an offline machine.
function Get-IDWolfThemeCss {
    return @'
<style>
  /* "Keycap" theme: paper, ink, hard shadows. Self-contained: system font stacks, no web fonts. */
  :root {
    --paper: #F3EFE6; --surface: #FFFDF8; --tint: #E8E2D4; --ink: #161513; --muted: #5F5A51;
    --red: #E2372A; --red-soft: #FBD9D2; --coral: #EF8A6F; --amber: #F2B632; --amber-soft: #FBE7B5; --green: #84CC5F;
    --line: 3px solid var(--ink);
    --shadow: 7px 7px 0 var(--ink); --shadow-sm: 4px 4px 0 var(--ink); --shadow-xs: 3px 3px 0 var(--ink);
    --display: "Bahnschrift", "Segoe UI Variable Display", "Segoe UI", system-ui, sans-serif;
    --body: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Helvetica, Arial, sans-serif;
    --mono: "Cascadia Mono", "Cascadia Code", Consolas, ui-monospace, monospace;
  }
  body {
    max-width: 1240px; margin: 0 auto; padding: 28px 24px 64px; color: var(--ink); line-height: 1.5;
    font-family: var(--body); font-size: 15px; -webkit-font-smoothing: antialiased;
    background: var(--paper) radial-gradient(circle, rgba(22, 21, 19, .10) 1.1px, transparent 1.5px) 0 0 / 18px 18px;
  }
  @media (max-width: 700px) { body { padding: 16px 16px 40px; } .wolf-logo { font-size: 7px; } }
  :focus-visible { outline: 3px solid var(--ink); outline-offset: 3px; }

  h1 {
    font-family: var(--display); font-weight: 800; letter-spacing: -0.04em; line-height: .95; font-size: clamp(2rem, 4.6vw, 3.4rem);
    border: var(--line); border-radius: 22px; background: var(--surface); box-shadow: var(--shadow); padding: 22px 26px; margin: 0 0 28px;
  }
  h1.title { display: flex; align-items: center; gap: 22px; }
  .wolf-logo {
    font-family: var(--mono); font-size: 10px; line-height: 1.05; font-weight: 700; margin: 0; flex-shrink: 0;
    color: var(--surface); background: var(--ink); border-radius: 14px; padding: 10px 12px; box-shadow: 4px 4px 0 var(--red);
  }
  h2 { margin: 0; font-family: var(--display); font-weight: 750; letter-spacing: -0.03em; font-size: clamp(1.35rem, 2.4vw, 1.9rem); color: var(--ink); }
  h3 { font-family: var(--display); letter-spacing: -0.02em; }
  .meta { font-family: var(--mono); font-size: 12px; line-height: 1.55; letter-spacing: .01em; color: var(--muted); }
  h1 + .meta { text-transform: uppercase; letter-spacing: .06em; font-size: 11.5px; }
  code { background: var(--tint); border: 1.5px solid var(--ink); border-radius: 6px; padding: 0 5px; font-family: var(--mono); font-size: 0.92em; }

  /* Score cards: keys with a hard shadow, the number is the label. */
  .cards { display: flex; flex-wrap: wrap; gap: 18px; margin: 26px 0 30px; clear: both; }
  .card {
    border: var(--line); border-radius: 18px; background: var(--surface); box-shadow: var(--shadow-sm);
    padding: 14px 20px 16px; min-width: 150px; transition: transform .12s ease, box-shadow .12s ease;
  }
  .card:hover { transform: translate(-2px, -2px); box-shadow: 6px 6px 0 var(--ink); }
  .card .num, .grade { font-family: var(--display); font-weight: 800; font-size: 2.6rem; letter-spacing: -0.04em; line-height: 1; color: var(--ink); }
  .card .lbl { font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin-top: 6px; }
  .card.critical { background: var(--red); } .card.critical .num, .card.critical .lbl { color: var(--surface); }
  .card.high { background: var(--red-soft); } .card.medium { background: var(--amber); } .card.low { background: var(--tint); }

  /* Severity pills as small keycaps. */
  .sev-pill {
    display: inline-block; white-space: nowrap; font-family: var(--mono); font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
    border: 2px solid var(--ink); border-radius: 8px; padding: 3px 9px; box-shadow: 2px 2px 0 var(--ink); color: var(--ink);
  }
  .sev-pill-critical { background: var(--red); color: var(--surface); }
  .sev-pill-high { background: var(--red-soft); }
  .sev-pill-medium { background: var(--amber); }
  .sev-pill-low { background: var(--tint); }

  /* Sections and checks: bento panels. */
  details { margin-top: 34px; }
  details > summary { cursor: pointer; list-style: none; border-bottom: var(--line); padding-bottom: 10px; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary h2 { display: inline-block; }
  details > summary::before { content: '\25b6'; display: inline-block; margin-right: 8px; font-size: 14px; color: var(--red); transition: transform .15s ease; }
  details[open] > summary::before { transform: rotate(90deg); }
  details.check {
    margin: 12px 0; border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-xs);
    transition: box-shadow .12s ease, transform .12s ease;
  }
  details.check:hover { transform: translate(-1px, -1px); box-shadow: var(--shadow-sm); }
  details.check[open] { box-shadow: var(--shadow); }
  details.check > summary { border-bottom: none; padding: 12px 16px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  details.check[open] > summary { border-bottom: var(--line); }
  details.check > summary::before { margin-right: 0; }
  details.check .body { padding: 12px 18px 16px; }
  .check-title { font-family: var(--display); font-weight: 700; font-size: 1.02rem; letter-spacing: -0.01em; }
  .check-id { font-family: var(--mono); font-size: 11px; letter-spacing: .06em; color: var(--muted); }
  .count { margin-left: auto; font-family: var(--mono); font-size: 11px; letter-spacing: .06em; background: var(--tint); border: 2px solid var(--ink); border-radius: 99px; padding: 1px 10px; }
  .kv { font-size: 13px; margin: 6px 0; }
  .kv b { font-family: var(--mono); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--ink); }

  /* Tables: ink header, mono labels, framed panel. */
  .table-wrap { border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-sm); overflow-x: auto; margin: 14px 0; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  th, td { padding: 8px 12px; text-align: left; vertical-align: top; border-top: 1.5px solid var(--tint); }
  th { background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 10.5px; font-weight: 500; letter-spacing: .1em; text-transform: uppercase; padding: 10px 12px; border-top: none; }
  /* Key / value tables (a th at the start of a data row): light row headers, not a black column. */
  tr:has(> td) > th { background: var(--tint); color: var(--ink); border-top: 1.5px solid var(--surface); }
  tr.data-row:nth-child(even) td { background: #FAF6EE; }
  tr.data-row:hover td { background: var(--amber-soft); }
  tr.filter-row td { background: var(--tint); padding: 5px 6px; }
  tr.filter-row input { width: 100%; box-sizing: border-box; font-family: var(--mono); font-size: 11px; padding: 4px 7px; border: 2px solid var(--ink); border-radius: 8px; background: var(--surface); }
  tr.filter-row input:focus { outline: 3px solid var(--red); outline-offset: 1px; }
  .filter-status { font-family: var(--mono); font-size: 11px; color: var(--muted); margin: 6px 0 0 2px; }
  .compare-new { color: var(--red); font-weight: bold; }
  .compare-resolved { color: var(--muted); font-weight: bold; }
  .yes { color: var(--red); font-weight: 600; } .no { color: var(--muted); }

  /* Callouts. */
  blockquote { background: var(--surface); border: var(--line); border-left-width: 10px; border-radius: 14px; box-shadow: var(--shadow-xs); margin: 14px 0; padding: 12px 16px; }
  .warn { background: var(--red-soft); border-left-color: var(--red); }

  /* Charts and map. */
  .chart-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 22px; margin: 18px 0; }
  .pie-chart-wrap { display: flex; align-items: center; gap: 16px; }
  .pie-chart-wrap svg { flex-shrink: 0; }
  .pie-chart-title { font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
  .pie-legend { font-size: 12px; min-width: 0; }
  .pie-legend-item { display: flex; align-items: center; gap: 6px; margin: 3px 0; }
  .pie-legend-swatch { display: inline-block; width: 10px; height: 10px; border: 1.5px solid var(--ink); border-radius: 3px; flex-shrink: 0; }
  .map-wrap { border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-sm); padding: 10px; margin: 14px 0; overflow-x: auto; }
  .attack-map .am-edge.am-hot { opacity: 1 !important; stroke-width: 2.6px; }

  /* AI section. */
  .ai-section { background: var(--surface); border: var(--line); border-radius: 18px; box-shadow: var(--shadow); padding: 6px 24px 20px; margin-top: 18px; }
  .ai-badge { display: inline-block; font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--ink); background: var(--green); border: 2px solid var(--ink); border-radius: 8px; box-shadow: 2px 2px 0 var(--ink); padding: 2px 10px; margin: 12px 0 8px; }
  .ai-section h3 { color: var(--ink); margin: 16px 0 6px; }
  .ai-section ol li { margin: 6px 0; }
  .ai-script { background: var(--ink); color: #ECE7DC; border: var(--line); border-radius: 12px; padding: 10px 12px; font-family: var(--mono); font-size: 12px; white-space: pre-wrap; overflow-x: auto; margin: 6px 0; }
  .ai-triage td { vertical-align: top; }

  /* Dashboard / Details tabs. Panes are hidden only by the script, so without it everything shows. */
  .tabs { display: flex; gap: 12px; margin: 4px 0 6px; flex-wrap: wrap; }
  .tab-btn {
    font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; cursor: pointer;
    color: var(--ink); background: var(--surface); border: var(--line); border-radius: 12px; padding: 8px 18px; box-shadow: var(--shadow-xs);
  }
  .tab-btn[aria-selected="true"] { background: var(--ink); color: var(--surface); box-shadow: 3px 3px 0 var(--red); }
  .panel { border: var(--line); border-radius: 18px; background: var(--surface); box-shadow: var(--shadow-sm); padding: 16px 18px; min-width: 0; }
  .dash-h { margin: 34px 0 14px; border-bottom: var(--line); padding-bottom: 10px; }
  .dash-note { margin: -4px 0 14px; }

  /* Score hero. */
  .hero { display: flex; gap: 26px; align-items: center; flex-wrap: wrap; margin-top: 18px; padding: 20px 24px; box-shadow: var(--shadow); }
  .hero svg { flex-shrink: 0; }
  .hero-body { flex: 1 1 320px; min-width: 0; }
  .hero-kicker { font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
  .hero-title { font-family: var(--display); font-weight: 800; font-size: 1.9rem; letter-spacing: -0.03em; line-height: 1.1; margin: 4px 0 8px; }
  .pills { display: flex; gap: 8px; flex-wrap: wrap; margin: 10px 0 8px; }
  .sev-pill-clean { background: var(--green); }
  .sev-pill-na { background: var(--surface); color: var(--muted); border-style: dashed; box-shadow: none; }
  .grade-a, .grade-b { background: var(--green); } .grade-c, .grade-d { background: var(--amber); } .grade-e, .grade-f { background: var(--red); color: var(--surface); }
  details.score-how { margin: 6px 0 0; }
  details.score-how > summary { border: none; padding: 0; font-family: var(--mono); font-size: 11px; color: var(--muted); }
  details.score-how > summary::before { font-size: 9px; }

  /* Framework cards. */
  .fw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
  .fw-head { display: flex; gap: 14px; align-items: center; margin-bottom: 10px; }
  .fw-name { font-family: var(--display); font-weight: 750; font-size: 1.2rem; letter-spacing: -0.02em; }
  .fw-sub { font-family: var(--mono); font-size: 11px; line-height: 1.45; color: var(--muted); }
  .fw-row { display: grid; grid-template-columns: minmax(0, 1fr) auto 64px; gap: 10px; align-items: center; font-size: 12px; padding: 5px 0; border-top: 1.5px solid var(--tint); }
  .fw-row .ctl b { font-family: var(--mono); font-size: 11px; margin-right: 5px; white-space: nowrap; }
  .fw-row .n { font-family: var(--mono); font-size: 11px; font-weight: 600; text-align: right; white-space: nowrap; }
  .fw-row .n.na { grid-column: span 2; color: var(--muted); font-weight: 400; }
  .bar { height: 10px; border: 2px solid var(--ink); border-radius: 99px; background: var(--tint); overflow: hidden; }
  .bar > span { display: block; height: 100%; }

  /* Category tiles. */
  .tile-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(175px, 1fr)); gap: 16px; }
  .tile { padding: 12px 14px; }
  .tile .lbl { font-family: var(--mono); font-size: 10.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
  .tile .num { font-family: var(--display); font-weight: 800; font-size: 2rem; letter-spacing: -0.04em; line-height: 1.1; }
  .tile .sub { font-family: var(--mono); font-size: 11px; color: var(--muted); margin-bottom: 6px; }

  /* Top risks. */
  .risk-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 18px; }
  .risk { border-left-width: 10px; display: flex; flex-direction: column; gap: 6px; }
  .risk.critical { border-left-color: var(--red); } .risk.high { border-left-color: var(--coral); }
  .risk.medium { border-left-color: var(--amber); } .risk.low { border-left-color: #B9B1A1; }
  .risk-title { font-family: var(--display); font-weight: 700; font-size: 1.02rem; letter-spacing: -0.01em; line-height: 1.25; }
  .risk p { margin: 0; font-size: 13px; display: -webkit-box; -webkit-line-clamp: 4; -webkit-box-orient: vertical; overflow: hidden; }
  .risk .meta { margin-top: auto; }
  .risk a { color: var(--ink); }

  @media print {
    body { background: #fff; max-width: none; }
    h1, .card, details.check, .table-wrap, .map-wrap, blockquote, .ai-section, .panel { box-shadow: none; }
    .card:hover, details.check:hover { transform: none; }
    .tabs { display: none; }
    .tab-pane[hidden] { display: block !important; }
  }
</style>
'@
}

# Scripts shared by the AD and the Entra report: table filter, attack-map highlight, tabs.
# The "js" class is what hides the Details tab, so a browser without scripts shows everything.
function Get-IDWolfReportScript {
    return @'
<script>
document.documentElement.className += ' js';
function filterIDWolfTable(input) {
  var table = input.closest('table');
  var filters = Array.prototype.map.call(table.querySelectorAll('tr.filter-row input'), function (i) { return i.value.toLowerCase(); });
  var rows = table.querySelectorAll('tr.data-row'); var shown = 0;
  rows.forEach(function (row) {
    var cells = row.children; var ok = true;
    for (var i = 0; i < filters.length; i++) { if (filters[i] && (!cells[i] || cells[i].textContent.toLowerCase().indexOf(filters[i]) === -1)) { ok = false; break; } }
    row.style.display = ok ? '' : 'none'; if (ok) shown++;
  });
  var status = table.parentNode.parentNode.querySelector('.filter-status');
  if (status) status.textContent = shown + ' of ' + rows.length + ' rows shown';
}
function amMap(g, on) {
  try {
    var nid = g.getAttribute('data-nid');
    var svg = g.ownerSVGElement; if (!svg) return;
    var seen = {};
    (function walk(id) {
      if (seen[id]) return; seen[id] = 1;
      var edges = svg.querySelectorAll('.am-from-' + id);
      for (var i = 0; i < edges.length; i++) {
        if (on) { edges[i].classList.add('am-hot'); } else { edges[i].classList.remove('am-hot'); }
        var to = edges[i].getAttribute('data-to'); if (to) walk(to);
      }
    })(nid);
  } catch (e) { }
}
function idwTab(name) {
  var btns = document.querySelectorAll('.tab-btn'), panes = document.querySelectorAll('.tab-pane');
  for (var i = 0; i < btns.length; i++) { btns[i].setAttribute('aria-selected', btns[i].getAttribute('data-tab') === name ? 'true' : 'false'); }
  for (var j = 0; j < panes.length; j++) { panes[j].hidden = panes[j].id !== 'tab-' + name; }
  return false;
}
function idwGo(id) {
  var el = document.getElementById(id); if (!el) return false;
  idwTab('details');
  for (var p = el; p; p = p.parentElement) { if (p.tagName === 'DETAILS') p.open = true; }
  el.scrollIntoView();
  return false;
}
document.addEventListener('DOMContentLoaded', function () {
  if (!document.querySelector('.tab-pane')) return;
  var h = (location.hash || '').replace('#', '');
  if (h.indexOf('chk-') === 0 && document.getElementById(h)) { idwGo(h); }
  else if (h === 'tab-details') { idwTab('details'); }
  else { idwTab('dashboard'); }
});
</script>
'@
}

function Get-ReportTabsHtml {
    return '<nav class="tabs" role="tablist"><button type="button" class="tab-btn" role="tab" data-tab="dashboard" aria-selected="true" onclick="idwTab(''dashboard'')">Dashboard</button><button type="button" class="tab-btn" role="tab" data-tab="details" aria-selected="false" onclick="idwTab(''details'')">Details</button></nav>'
}

# A ring in plain SVG: Pct of the circle filled, or an empty dashed ring for "n/a" (Pct below 0).
function Get-RingSvg {
    param([int]$Pct, [string]$Color, [string]$Big, [string]$Small, [int]$Size = 120)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $f = { param($x) ([double]$x).ToString('0.##', $inv) }
    $sw = $Size * 0.12; $c = $Size / 2; $r = $c - ($sw / 2) - 2
    $circ = 2 * [Math]::PI * $r
    $track = if ($Pct -lt 0) { " stroke-dasharray='4 4'" } else { '' }
    $svg = "<svg viewBox='0 0 $Size $Size' width='$Size' height='$Size' role='img' aria-label='$(ConvertTo-HtmlSafe "$Big $Small")'>"
    $svg += "<circle cx='$c' cy='$c' r='$(& $f $r)' fill='none' stroke='#E8E2D4' stroke-width='$(& $f $sw)'$track />"
    if ($Pct -gt 0) {
        $seg = $circ * [Math]::Min(100, $Pct) / 100
        $svg += "<circle cx='$c' cy='$c' r='$(& $f $r)' fill='none' stroke='$Color' stroke-width='$(& $f $sw)' stroke-dasharray='$(& $f $seg) $(& $f $circ)' transform='rotate(-90 $c $c)' />"
    }
    $svg += "<text x='$c' y='$(& $f ($c + $Size * 0.06))' text-anchor='middle' font-size='$(& $f ($Size * 0.24))' font-weight='800' fill='#161513'>$(ConvertTo-HtmlSafe $Big)</text>"
    if ($Small) { $svg += "<text x='$c' y='$(& $f ($c + $Size * 0.2))' text-anchor='middle' font-size='$(& $f ($Size * 0.085))' fill='#5F5A51'>$(ConvertTo-HtmlSafe $Small)</text>" }
    return $svg + '</svg>'
}

# Clean share of the evaluated checks: green from 90%, amber from 70%, red below.
function Get-CleanColor {
    param([double]$Pct)
    if ($Pct -ge 90) { return '#84CC5F' } elseif ($Pct -ge 70) { return '#F2B632' } else { return '#E2372A' }
}

# Dashboard head: the score ring, the grade, the severity counts and what was read.
# Kicker is the line above the title (scope and inventory), Extra one more line under the counts.
function ConvertTo-ScoreHeroHtml {
    param($Score, $Findings, [int]$CheckTotal, [int]$NotEvaluatedCount, [string]$Kicker, [string]$Extra = '')
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $words = @{ A = 'Strong'; B = 'Good'; C = 'Partial protection'; D = 'Weak'; E = 'Poor'; F = 'Critical exposure' }
    if ($Score.Reliable) {
        $color = if ($Score.Grade -in 'A', 'B') { '#84CC5F' } elseif ($Score.Grade -in 'C', 'D') { '#F2B632' } else { '#E2372A' }
        $ring = Get-RingSvg -Pct $Score.Score -Color $color -Big "$($Score.Score)" -Small '/ 100' -Size 130
        $grade = "<span class=`"sev-pill grade-$("$($Score.Grade)".ToLower())`">Grade $($Score.Grade) &middot; $($words["$($Score.Grade)"])</span>"
    }
    else {
        $ring = Get-RingSvg -Pct -1 -Color '' -Big 'n/a' -Small 'not reliable' -Size 130
        $grade = "<span class=`"sev-pill sev-pill-na`">Only $($Score.Coverage)% of the checks could be evaluated</span>"
    }
    $pills = foreach ($s in 'Critical', 'High', 'Medium', 'Low') {
        "<span class=`"sev-pill sev-pill-$($s.ToLower())`">$(@($Findings | Where-Object { $_.Severity -eq $s }).Count) $s</span>"
    }
    $types = @($Findings | ForEach-Object { $_.Type } | Select-Object -Unique).Count
    $line = "$(@($Findings).Count) finding(s) &middot; $types of $($CheckTotal - $NotEvaluatedCount) evaluated checks triggered"
    if ($NotEvaluatedCount -gt 0) { $line += " &middot; $NotEvaluatedCount not evaluated" }
    $line += " &middot; <a href=`"#tab-details`" onclick=`"return idwTab('details')`">open the details</a>"
    $how = 'Score = 100 &times; e<sup>&minus;penalty/100</sup>, where penalty sums a weight per triggered check at its worst severity (Critical 20, High 8, Medium 3, Low 1), capped by the worst severity present: any Critical check limits the score to 35 (grade E), any High to 65 (grade C). It never reaches zero, so a bad environment and a catastrophic one still rank differently. Per-object counts are shown separately so that many low-impact objects do not hide a single critical exposure.'
    $out = "<div class=`"panel hero`">$ring<div class=`"hero-body`"><div class=`"hero-kicker`">$Kicker</div><div class=`"hero-title`">Hygiene score</div>$grade"
    $out += "<div class=`"pills`">$($pills -join '')</div><div class=`"meta`">$line</div>"
    if ($Extra) { $out += "<div class=`"meta`">$Extra</div>" }
    $out += "<details class=`"score-how`"><summary>How the score is computed</summary><p class=`"meta`">$how</p></details></div></div>"
    return $out
}

# One card per framework: the share of evaluated checks with no finding, then one bar per
# control. Not-evaluated checks are left out of the share and counted apart, never as clean.
function ConvertTo-FrameworkCardsHtml {
    param($Catalog, $Findings, $NotEvaluated)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $ne = @{}; foreach ($n in @($NotEvaluated | Where-Object { $_ })) { $ne["$($n.Type)"] = $true }
    $worstOf = @{}
    foreach ($f in $Findings) {
        $cur = $worstOf["$($f.Type)"]
        if (-not $cur -or $script:SeverityRank[$f.Severity] -gt $script:SeverityRank[$cur]) { $worstOf["$($f.Type)"] = $f.Severity }
    }
    $sevColor = @{ Critical = '#E2372A'; High = '#EF8A6F'; Medium = '#F2B632'; Low = '#B9B1A1' }
    $short = @{ NIS2 = 'NIS2'; ISO27001 = 'ISO/IEC 27001'; DORA = 'DORA'; GDPR = 'GDPR' }
    $keys = @($Catalog.Keys)
    $cards = foreach ($fw in $script:ComplianceFrameworks.Keys) {
        $def = $script:ComplianceFrameworks[$fw]
        $fwChecks = @($keys | Where-Object { @(Get-CheckControls $_ | Where-Object { $_.StartsWith("$fw ") }).Count -gt 0 })
        $eval = @($fwChecks | Where-Object { -not $ne.ContainsKey("$_") })
        $clean = @($eval | Where-Object { -not $worstOf.ContainsKey("$_") }).Count
        $pct = if ($eval.Count) { [int][Math]::Floor(100.0 * $clean / $eval.Count) } else { -1 }
        $ring = if ($pct -ge 0) { Get-RingSvg -Pct $pct -Color (Get-CleanColor $pct) -Big "$pct%" -Small 'clean' -Size 84 } else { Get-RingSvg -Pct -1 -Color '' -Big 'n/a' -Size 84 }
        $nNe = $fwChecks.Count - $eval.Count
        $sub = if ($eval.Count) { "$clean of $($eval.Count) evaluated checks clean" } else { 'No check could be evaluated' }
        if ($nNe) { $sub += " &middot; $nNe not evaluated" }
        $rows = foreach ($c in $def.Controls.Keys) {
            $id = "$fw $c"
            $cc = @($keys | Where-Object { (Get-CheckControls $_) -contains $id })
            $ce = @($cc | Where-Object { -not $ne.ContainsKey("$_") })
            $label = "<span class=`"ctl`"><b>$(& $H $c)</b>$(& $H $def.Controls[$c].Title)</span>"
            if ($ce.Count -eq 0) {
                $why = if ($cc.Count) { 'not evaluated' } else { 'no check' }
                "<div class=`"fw-row`">$label<span class=`"n na`">$why</span></div>"
                continue
            }
            $hit = @($ce | Where-Object { $worstOf.ContainsKey("$_") })
            $ok = $ce.Count - $hit.Count
            $worst = ''; foreach ($s in 'Critical', 'High', 'Medium', 'Low') { if (@($hit | Where-Object { $worstOf["$_"] -eq $s }).Count) { $worst = $s; break } }
            $color = if ($worst) { $sevColor[$worst] } else { '#84CC5F' }
            $pctW = [int][Math]::Round(100.0 * $ok / $ce.Count)
            $tip = if ($worst) { "$($hit.Count) check(s) with findings, worst $worst" } else { 'no findings' }
            if ($ce.Count -lt $cc.Count) { $tip += ", $($cc.Count - $ce.Count) not evaluated" }
            "<div class=`"fw-row`" title=`"$tip`">$label<span class=`"n`">$ok/$($ce.Count)</span><span class=`"bar`"><span style=`"width:$pctW%;background:$color`"></span></span></div>"
        }
        "<div class=`"panel`"><div class=`"fw-head`">$ring<div><div class=`"fw-name`">$(& $H $short[$fw])</div><div class=`"fw-sub`">$sub</div></div></div>$($rows -join '')</div>"
    }
    $note = '<p class="meta dash-note">Checks with no finding, out of the checks mapped to each control. A clean check is evidence for the technical, directory-side part of a control, not compliance with it. Bars take the colour of the worst finding; the full tables are under Details.</p>'
    return "<h2 class=`"dash-h`">Regulatory frameworks</h2>$note<div class=`"fw-grid`">$($cards -join '')</div>"
}

# One tile per category, in catalog order: findings, checks triggered, worst severity.
function ConvertTo-CategoryTilesHtml {
    param($Catalog, $Findings, $NotEvaluated)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $ne = @{}; foreach ($n in @($NotEvaluated | Where-Object { $_ })) { $ne["$($n.Type)"] = $true }
    $cats = @($Catalog.Values | ForEach-Object { "$($_.Category)" } | Select-Object -Unique)
    $tiles = foreach ($c in $cats) {
        $checks = @($Catalog.Keys | Where-Object { "$($Catalog[$_].Category)" -eq $c })
        $cf = @($Findings | Where-Object { $_.Category -eq $c })
        $trig = @($cf | ForEach-Object { $_.Type } | Select-Object -Unique).Count
        $nNe = @($checks | Where-Object { $ne.ContainsKey("$_") }).Count
        $worst = ''; foreach ($s in 'Critical', 'High', 'Medium', 'Low') { if (@($cf | Where-Object { $_.Severity -eq $s }).Count) { $worst = $s; break } }
        $pill = if ($worst) { "worst $(Get-SevPill $worst)" } elseif ($nNe -eq $checks.Count) { '<span class="sev-pill sev-pill-na">not evaluated</span>' } else { '<span class="sev-pill sev-pill-clean">clean</span>' }
        $sub = "$trig of $($checks.Count) check(s) triggered"
        if ($nNe) { $sub += ", $nNe not evaluated" }
        "<div class=`"panel tile`"><div class=`"lbl`">$(& $H $c)</div><div class=`"num`">$($cf.Count)</div><div class=`"sub`">$sub</div>$pill</div>"
    }
    return "<h2 class=`"dash-h`">Categories</h2><div class=`"tile-grid`">$($tiles -join '')</div>"
}

# The checks to fix first: worst severity, then most objects, then catalog order (stable on 5.1 and 7).
function ConvertTo-TopRisksHtml {
    param($Catalog, $Findings, [int]$Max = 6)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    if (@($Findings).Count -eq 0) { return '' }
    $groups = @($Findings | Group-Object Type | ForEach-Object {
            $worst = ($_.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
            [PSCustomObject]@{ Type = $_.Name; Worst = $worst; Rank = $script:SeverityRank[$worst]; Count = @($_.Group).Count }
        } | Sort-Object @{ Expression = 'Rank'; Descending = $true }, @{ Expression = 'Count'; Descending = $true }, @{ Expression = { Get-CheckPosition $_.Type } } | Select-Object -First $Max)
    $cards = foreach ($g in $groups) {
        $meta = $Catalog[$g.Type]
        $bits = @("$($g.Count) object$(if ($g.Count -ne 1) { 's' })")
        if ($meta.Mitre) { $bits += "$(& $H $meta.Mitre)" }
        if ($script:RecentAttackVectors.Contains($g.Type)) { $bits += 'seen in recent attacks' }
        $bits += "<a href=`"#chk-$($g.Type)`" onclick=`"return idwGo('chk-$($g.Type)')`">details</a>"
        "<div class=`"panel risk $($g.Worst.ToLower())`"><div class=`"risk-title`">$(Get-SevPill $g.Worst) $(& $H $meta.Title)</div><p>$(& $H $meta.Description)</p><div class=`"meta`">$($bits -join ' &middot; ')</div></div>"
    }
    return "<h2 class=`"dash-h`">Top risks</h2><div class=`"risk-grid`">$($cards -join '')</div>"
}

# How the snapshot was taken: the DC that served it, the collector's connection diagnostics
# (DNS, DC locator, LDAP bind, ports, with timings). Snapshots from older collectors only have the
# server name. Everything comes from meta, so the same snapshot gives the same section.
function ConvertTo-ConnectionHtml {
    param($Meta)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $ms = { param($v) if ($null -eq $v -or "$v" -eq '') { '' } else { "$v ms" } }
    $c = $Meta.connection
    $rows = [ordered]@{
        'Collected from' = "$($Meta.collectedFrom) as $($Meta.collectedBy)"
        'Server asked for' = if ($c -and $c.requestedServer) { "$($c.requestedServer)" } elseif ($c) { 'automatic (DC locator)' } else { "$($Meta.server)" }
    }
    if ($c) {
        $rows['Served by'] = "$(if ($c.servedBy) { $c.servedBy } else { 'not recorded' }) over $($c.protocol) (TCP $($c.port)), first answer in $(& $ms $c.firstAnswerMs)"
    }
    $d = if ($c) { $c.diagnostics } else { $null }
    $out = New-Object System.Text.StringBuilder
    [void]$out.Append('<details><summary><h2>Collection and connection</h2></summary>')
    if (-not $c) { [void]$out.Append('<p class="meta">This snapshot was taken by an older collector: only the server name was recorded.</p>') }
    elseif (-not $d) { [void]$out.Append('<p class="meta">Connection diagnostics were not run (lib\Connection.ps1 missing next to the collector).</p>') }
    if ($d) {
        if (@($d.localDnsServers).Count) { $rows['DNS servers of the collecting machine'] = (@($d.localDnsServers) -join ', ') }
        if ($d.domainDns) {
            $rows["DNS lookup of $($d.domain)"] = if ($d.domainDns.error) { "failed in $(& $ms $d.domainDns.ms): $($d.domainDns.error)" } else { "$(@($d.domainDns.addresses) -join ', ') in $(& $ms $d.domainDns.ms)" }
        }
        if ($d.dcLocator) {
            $rows['DC locator (DNS SRV)'] = if ($d.dcLocator.error) { "$($d.dcLocator.record): $($d.dcLocator.error)" } else { "$(@($d.dcLocator.targets).Count) DC(s) in $(& $ms $d.dcLocator.ms): $(@($d.dcLocator.targets) -join ', ')" }
        }
        if ($d.ldap) {
            $over = if ("$($d.ldap.protocol)" -eq 'LDAPS') { ' over LDAPS (TCP 636: 389 did not answer)' } else { '' }
            $rows['LDAP bind (RootDSE)'] = if ($d.ldap.error) { "failed in $(& $ms $d.ldap.ms)$($over): $($d.ldap.error)" } else { "$(& $ms $d.ldap.ms)$over, answered by $($d.ldap.answeredBy)$(if ($d.ldap.site) { ", site $($d.ldap.site)" })" }
        }
        if ($d.dc) {
            $rows['Domain controller tested'] = "$($d.dc) ($($d.dcSelectedBy))" + $(if ($d.dcDns -and $d.dcDns.error) { ": DNS lookup failed, $($d.dcDns.error)" } elseif ($d.dcDns) { " = $(@($d.dcDns.addresses) -join ', ') in $(& $ms $d.dcDns.ms)" } else { '' })
        }
    }
    [void]$out.Append('<div class="table-wrap"><table><tr><th>Item</th><th>Value</th></tr>')
    foreach ($k in $rows.Keys) { [void]$out.Append("<tr class=`"data-row`"><td>$(& $H $k)</td><td>$(& $H $rows[$k])</td></tr>") }
    [void]$out.Append('</table></div>')
    if ($d -and @($d.ports).Count) {
        [void]$out.Append("<p class=`"meta`">TCP ports on $(& $H $d.dc), tested from the collecting machine (connect only, nothing sent).</p>")
        [void]$out.Append('<div class="table-wrap"><table><tr><th>Port</th><th>Service</th><th>State</th><th>Connect time</th><th>Used for</th></tr>')
        foreach ($p in @($d.ports)) {
            $state = if ($p.open) { '<span class="yes">open</span>' } elseif ($p.used) { "<span class=`"no`">closed</span> $(& $H $p.error)" } else { "closed $(& $H $p.error)" }
            [void]$out.Append("<tr class=`"data-row`"><td>$(& $H $p.port)</td><td>$(& $H $p.service)</td><td>$state</td><td>$(& $H (& $ms $p.ms))</td><td>$(& $H $p.usedFor)</td></tr>")
        }
        [void]$out.Append('</table></div>')
    }
    [void]$out.Append('</details>')
    return $out.ToString()
}

function ConvertTo-ReportHtml {
    param(
        $Snapshot, $Index, $PrivMap, $Split, $Score, $NotEvaluated, $Comparison,
        [hashtable]$Config, [string]$ToolVersion, [string]$ElapsedText,
        $AiResult = $null
    )
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $findings = @($Split.Active)
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }

    $sevOrder = @('Critical', 'High', 'Medium', 'Low')
    $counts = @{}; foreach ($s in $sevOrder) { $counts[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }
    $collected = ConvertTo-UtcDate $Snapshot.meta.collectedAtUtc

    & $w '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<title>IDWolf report - $(& $H $Snapshot.domain.dnsRoot)</title>"
    & $w (Get-IDWolfThemeCss)
    & $w (Get-IDWolfReportScript)
    & $w '</head><body>'
    & $w "<h1 class=`"title`">$(Get-WolfLogoHtml)<span>IDWolf: Active Directory Hygiene Report</span></h1>"
    & $w "<div class=`"meta`">Domain <b>$(& $H $Snapshot.domain.dnsRoot)</b> ($(& $H $Snapshot.domain.netbios)) &middot; forest $(& $H $Snapshot.domain.forestName) &middot; snapshot $(& $H $collected.ToString('yyyy-MM-dd HH:mm')) UTC by $(& $H $Snapshot.meta.collectedBy) from $(& $H $Snapshot.meta.collectedFrom)$(if ($Snapshot.meta.connection -and $Snapshot.meta.connection.servedBy) { " via $(& $H $Snapshot.meta.connection.servedBy)" }) &middot; IDWolf v$ToolVersion &middot; analysis $ElapsedText$(if ($AiResult -and $AiResult.Model) { " &middot; AI $(& $H $AiResult.Model)$(if ($AiResult.AiElapsedText) { " in $(& $H $AiResult.AiElapsedText)" })" })</div>"
    if ($Snapshot.meta.synthetic) {
        & $w '<blockquote>Synthetic snapshot generated for testing and demonstration. No real directory data.</blockquote>'
    }
    & $w (Get-ReportTabsHtml)

    # ---------------- Dashboard ----------------
    & $w '<section id="tab-dashboard" class="tab-pane" role="tabpanel">'
    $kicker = "$(& $H $Snapshot.domain.dnsRoot) &middot; $(@($Index.Users).Count) users and service accounts &middot; $(@($Index.Computers).Count) computers &middot; $($PrivMap.Principals.Count) Tier 0 principals"
    $extra = if ($Comparison) { "Since the previous run: <b>$(@($Comparison.New).Count) new</b>, $(@($Comparison.Resolved).Count) resolved, $(@($Comparison.Persisting).Count) still present." } else { '' }
    & $w (ConvertTo-ScoreHeroHtml -Score $Score -Findings $findings -CheckTotal $script:CheckCatalog.Count -NotEvaluatedCount @($NotEvaluated).Count -Kicker $kicker -Extra $extra)

    $errs = @($Snapshot.meta.collectionErrors | Where-Object { $_ })
    if ($errs.Count -gt 0 -or @($NotEvaluated).Count -gt 0) {
        & $w '<blockquote class="warn"><b>Incomplete coverage.</b> Some sections could not be collected; the checks below were <b>not evaluated</b> (zero findings there does not mean compliant).<ul>'
        foreach ($n in $NotEvaluated) { & $w "<li><code>$($n.Type)</code> $(& $H $n.Title): $(& $H $n.Reason)</li>" }
        & $w '</ul></blockquote>'
    }

    # Gemini and the attack map stay at the top; both are <details>, so they collapse.
    if ($AiResult) { & $w (ConvertTo-AiSectionHtml -AiResult $AiResult) }
    if (Get-Command ConvertTo-AttackMapHtml -ErrorAction SilentlyContinue) {
        try { & $w (ConvertTo-AttackMapHtml -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap -Findings $findings) }
        catch { Write-Warning "Attack-path map skipped: $($_.Exception.Message)" }
    }
    if (Get-Command Get-CheckControls -ErrorAction SilentlyContinue) {
        try { & $w (ConvertTo-FrameworkCardsHtml -Catalog $script:CheckCatalog -Findings $findings -NotEvaluated $NotEvaluated) }
        catch { Write-Warning "Framework cards skipped: $($_.Exception.Message)" }
    }
    & $w (ConvertTo-CategoryTilesHtml -Catalog $script:CheckCatalog -Findings $findings -NotEvaluated $NotEvaluated)
    & $w (ConvertTo-TopRisksHtml -Catalog $script:CheckCatalog -Findings $findings)
    & $w '<details open><summary><h2>Directory at a glance</h2></summary>'
    & $w (Get-ChartsRowHtml -Findings $findings -Index $Index -PrivMap $PrivMap)
    try { & $w (Get-AdInfoChartsRow -Snapshot $Snapshot -Index $Index) } catch { Write-Warning "Directory charts skipped: $($_.Exception.Message)" }
    & $w '</details></section>'

    # ---------------- Details ----------------
    & $w '<section id="tab-details" class="tab-pane" role="tabpanel">'

    # ---------------- Category summary ----------------
    & $w '<details open><summary><h2>Summary by category</h2></summary><div class="table-wrap"><table><tr><th>Category</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Checks triggered</th></tr>'
    $cats = @($script:CheckCatalog.Values | ForEach-Object { $_.Category } | Select-Object -Unique)
    foreach ($c in $cats) {
        $cf = @($findings | Where-Object { $_.Category -eq $c })
        $row = "<tr class=`"data-row`"><td>$(& $H $c)</td>"
        foreach ($s in $sevOrder) { $row += "<td>$(@($cf | Where-Object { $_.Severity -eq $s }).Count)</td>" }
        $row += "<td>$(@($cf | ForEach-Object { $_.Type } | Select-Object -Unique).Count)</td></tr>"
        & $w $row
    }
    & $w '</table></div></details>'

    if (Get-Command ConvertTo-ComplianceHtml -ErrorAction SilentlyContinue) {
        try { & $w (ConvertTo-ComplianceHtml -Catalog $script:CheckCatalog -Findings $findings -NotEvaluated $NotEvaluated) }
        catch { Write-Warning "Regulatory mapping skipped: $($_.Exception.Message)" }
    }

    # ---------------- Checks ----------------
    & $w '<details open><summary><h2>Findings by check</h2></summary>'
    if ($findings.Count -eq 0) { & $w '<p>No findings.</p>' }
    $byType = $findings | Group-Object Type
    $typeRows = @($byType | ForEach-Object {
            $worst = ($_.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
            [PSCustomObject]@{ Type = $_.Name; Worst = $worst; Items = $_.Group; Rank = $script:SeverityRank[$worst] }
        } | Sort-Object @{ Expression = 'Rank'; Descending = $true }, @{ Expression = { $_.Items.Count }; Descending = $true }, @{ Expression = { Get-CheckPosition $_.Type } })
    foreach ($t in $typeRows) {
        $meta = $script:CheckCatalog[$t.Type]
        $n = @($t.Items).Count
        & $w "<details class=`"check`" id=`"chk-$($t.Type)`"><summary>$(Get-SevPill $t.Worst)<span class=`"check-title`">$(& $H $meta.Title)</span><span class=`"check-id`">$($t.Type) &middot; $(& $H $meta.Category)</span><span class=`"count`">$n object$(if ($n -ne 1) { 's' })</span></summary><div class=`"body`">"
        & $w "<div class=`"kv`"><b>Why it matters.</b> $(& $H $meta.Description)</div>"
        & $w "<div class=`"kv`"><b>Remediation.</b> $(& $H $meta.Remediation)</div>"
        $attack = Format-CheckAttackHtml $t.Type $meta; if ($attack) { & $w $attack }
        if (Get-Command Format-CheckControls -ErrorAction SilentlyContinue) { & $w "<div class=`"kv`"><b>Regulatory controls.</b> $(& $H (Format-CheckControls $t.Type))</div>" }
        & $w '<div class="table-wrap"><table><tr><th>Severity</th><th>Object</th><th>Type</th><th>Detail</th></tr>'
        foreach ($f in ($t.Items | Sort-Object { - $script:SeverityRank[$_.Severity] }, Object)) {
            & $w "<tr class=`"data-row`"><td>$(Get-SevPill $f.Severity)</td><td title=`"$(& $H $f.ObjectDn)`"><b>$(& $H $f.Object)</b></td><td>$(& $H $f.ObjectType)</td><td>$(& $H $f.Detail)</td></tr>"
        }
        & $w '</table></div></div></details>'
    }
    & $w '</details>'

    # ---------------- Tier 0 inventory ----------------
    & $w '<details><summary><h2>Tier 0 inventory</h2></summary>'
    & $w '<p class="meta">Effective members of privileged groups, resolved by SID through nested groups and primaryGroupID. PU = Protected Users, ND = "sensitive and cannot be delegated".</p>'
    & $w '<div class="table-wrap"><table><tr><th>Principal</th><th>Type</th><th>Enabled</th><th>Privileged groups</th><th>Membership path</th><th>Last logon</th><th>Password age</th><th>SPN</th><th>PU / ND</th><th>Never expires</th></tr>'
    $tierRows = @($PrivMap.Principals.Values | Sort-Object { if ($_.Principal -and $_.Principal.samAccountName) { $_.Principal.samAccountName } else { $_.Dn } })
    foreach ($r in $tierRows) {
        $p = $r.Principal
        $name = if ($p -and $p.samAccountName) { $p.samAccountName } elseif ($p -and $p.name) { $p.name } else { $r.Dn }
        $enabled = if ($p -and $null -ne $p.enabled) { if ($p.enabled) { 'yes' } else { '<span class="no">no</span>' } } else { 'n/a' }
        $ll = if ($p) { Format-Age (Get-AgeDays $p.lastLogonTimestamp) } else { '' }
        $pa = if ($p) { Format-Age (Get-AgeDays $p.pwdLastSet) } else { '' }
        $spn = if ($p -and @($p.servicePrincipalNames | Where-Object { $_ }).Count -gt 0) { '<span class="yes">yes</span>' } else { '<span class="no">no</span>' }
        $pu = if ($p -and $PrivMap.ProtectedUsersSet.ContainsKey($r.Dn.ToLower())) { 'PU' } else { '' }
        $nd = if ($p -and $p.userAccountControl -and (Test-Uac $p 'NOT_DELEGATED')) { 'ND' } else { '' }
        $pund = (@($pu, $nd) | Where-Object { $_ }) -join ' '
        if (-not $pund) { $pund = if ($r.Type -eq 'user') { '<span class="yes">none</span>' } else { '' } }
        $ne = if ($p -and $p.userAccountControl -and (Test-Uac $p 'DONT_EXPIRE_PASSWORD')) { '<span class="yes">yes</span>' } else { '<span class="no">no</span>' }
        & $w "<tr class=`"data-row`"><td title=`"$(& $H $r.Dn)`"><b>$(& $H $name)</b></td><td>$(& $H $r.Type)</td><td>$enabled</td><td>$(& $H ($r.Groups -join ', '))</td><td>$(& $H ($r.Paths -join ' | '))</td><td>$ll</td><td>$pa</td><td>$spn</td><td>$pund</td><td>$ne</td></tr>"
    }
    & $w '</table></div></details>'

    # ---------------- Domain posture ----------------
    & $w '<details><summary><h2>Domain posture</h2></summary><div class="table-wrap"><table><tr><th>Item</th><th>Value</th></tr>'
    $krb = $Index.BySid["$($Index.DomainSid)-502"]
    $pp = $Snapshot.domain.passwordPolicy
    $postureRows = [ordered]@{
        'Domain / forest functional level' = "$($Snapshot.domain.domainMode) / $($Snapshot.domain.forestMode)"
        'krbtgt password age'              = if ($krb) { Format-Age (Get-AgeDays $krb.pwdLastSet) } else { 'n/a' }
        'Domain controllers'               = (@($Snapshot.domainControllers | Where-Object { $_ } | ForEach-Object { "$($_.name) ($($_.operatingSystem)$(if ($_.isReadOnly) { ', RODC' }))" }) -join '; ')
        'Password policy'                  = if ($pp) { "min length $($pp.minPasswordLength), complexity $($pp.complexityEnabled), lockout $($pp.lockoutThreshold), max age $($pp.maxPasswordAgeDays)d, history $($pp.passwordHistoryCount)" } else { 'not collected' }
        'Fine-grained policies'            = if ($null -ne $Snapshot.domain.fineGrainedPolicies) { "$(@($Snapshot.domain.fineGrainedPolicies | Where-Object { $_ }).Count)" } else { 'not collected (requires read access to the Password Settings Container)' }
        'ms-DS-MachineAccountQuota'        = "$($Snapshot.domain.machineAccountQuota)"
        'LAPS schema (legacy / Windows)'   = "$($Snapshot.domain.lapsLegacySchema) / $($Snapshot.domain.lapsV2Schema)"
        'Recycle Bin'                      = "$($Snapshot.domain.recycleBinEnabled)"
        'dSHeuristics'                     = if ($Snapshot.domain.dsHeuristics) { "$($Snapshot.domain.dsHeuristics)" } else { '(not set)' }
        'External / forest trusts'         = "$(@($Snapshot.trusts | Where-Object { $_ -and -not $_.intraForest }).Count)"
        'SYSVOL scanned for cpassword'     = "$($Snapshot.sysvol.scanned)"
    }
    foreach ($k in $postureRows.Keys) { & $w "<tr class=`"data-row`"><td>$(& $H $k)</td><td>$(& $H $postureRows[$k])</td></tr>" }
    & $w '</table></div>'
    & $w "<p class=`"meta`">Thresholds: krbtgt $($Config.KrbtgtMaxAgeDays)/$($Config.KrbtgtCriticalDays) days, privileged inactivity $($Config.PrivInactiveDays) days, user inactivity $($Config.InactiveDays) days, stale computer $($Config.StaleComputerDays) days, password age $($Config.PasswordMaxAgeDays) days, minimum length $($Config.MinPasswordLength), max Domain Admins $($Config.MaxDomainAdmins).</p></details>"

    # ---------------- Collection and connection ----------------
    try { & $w (ConvertTo-ConnectionHtml -Meta $Snapshot.meta) } catch { Write-Warning "Connection section skipped: $($_.Exception.Message)" }

    # ---------------- Comparison ----------------
    if ($Comparison) {
        & $w "<details open><summary><h2>Comparison with previous run</h2></summary><p class=`"meta`">Baseline: $(& $H $Comparison.PreviousPath). Matched by (check, object).</p>"
        & $w "<div class=`"cards`"><div class=`"card`"><div class=`"num compare-new`">$(@($Comparison.New).Count)</div><div class=`"lbl`">New</div></div><div class=`"card`"><div class=`"num compare-resolved`">$(@($Comparison.Resolved).Count)</div><div class=`"lbl`">Resolved</div></div><div class=`"card`"><div class=`"num`">$(@($Comparison.Persisting).Count)</div><div class=`"lbl`">Still present</div></div></div>"
        & $w '<div class="table-wrap"><table><tr><th>Status</th><th>Severity</th><th>Check</th><th>Object</th><th>Detail</th></tr>'
        foreach ($f in $Comparison.New) { & $w "<tr class=`"data-row`"><td class=`"compare-new`">NEW</td><td>$(Get-SevPill $f.Severity)</td><td>$(& $H $f.Type)</td><td>$(& $H $f.Object)</td><td>$(& $H $f.Detail)</td></tr>" }
        foreach ($f in $Comparison.Resolved) { & $w "<tr class=`"data-row`"><td class=`"compare-resolved`">RESOLVED</td><td>$(Get-SevPill $f.Severity)</td><td>$(& $H $f.Type)</td><td>$(& $H $f.Object)</td><td>$(& $H $f.Detail)</td></tr>" }
        & $w '</table></div></details>'
    }

    # ---------------- Accepted risks ----------------
    if (@($Split.Accepted).Count -gt 0 -or @($Split.Expired).Count -gt 0) {
        & $w '<details><summary><h2>Accepted risks (exceptions)</h2></summary>'
        if (@($Split.Expired).Count -gt 0) {
            & $w '<blockquote class="warn"><b>Expired exceptions ignored</b> (their findings are back in the report):<ul>'
            foreach ($e in $Split.Expired) { & $w "<li><code>$(& $H $e.type)</code> / $(& $H $e.object): expired $(& $H $e.expires). $(& $H $e.reason)</li>" }
            & $w '</ul></blockquote>'
        }
        & $w '<div class="table-wrap"><table><tr><th>Severity</th><th>Check</th><th>Object</th><th>Reason</th><th>Owner</th><th>Expires</th></tr>'
        foreach ($a in $Split.Accepted) {
            & $w "<tr class=`"data-row`"><td>$(Get-SevPill $a.Finding.Severity)</td><td>$($a.Finding.Type)</td><td>$(& $H $a.Finding.Object)</td><td>$(& $H $a.Exception.reason)</td><td>$(& $H $a.Exception.owner)</td><td>$(& $H $a.Exception.expires)</td></tr>"
        }
        & $w '</table></div></details>'
    }

    # ---------------- All findings (filterable) ----------------
    & $w '<details><summary><h2>All findings</h2></summary><div class="table-wrap"><table>'
    & $w '<tr><th>Severity</th><th>Check</th><th>Category</th><th>Object</th><th>Type</th><th>Detail</th><th>MITRE</th></tr>'
    & $w ('<tr class="filter-row">' + ((1..7 | ForEach-Object { '<td><input type="text" placeholder="filter" oninput="filterIDWolfTable(this)"></td>' }) -join '') + '</tr>')
    foreach ($f in ($findings | Sort-Object { - $script:SeverityRank[$_.Severity] }, Type, Object)) {
        & $w "<tr class=`"data-row`"><td>$(Get-SevPill $f.Severity)</td><td>$(& $H $f.Type)</td><td>$(& $H $f.Category)</td><td title=`"$(& $H $f.ObjectDn)`">$(& $H $f.Object)</td><td>$(& $H $f.ObjectType)</td><td>$(& $H $f.Detail)</td><td>$(Get-MitreLink $f.Mitre)</td></tr>"
    }
    & $w "</table></div><div class=`"filter-status`">$($findings.Count) rows</div></details>"

    & $w '</section>'

    & $w '<p class="meta" style="margin-top:32px">Generated by IDWolf from a read-only snapshot. The report contains directory data: handle as confidential.</p>'
    & $w '</body></html>'
    return $sb.ToString()
}
