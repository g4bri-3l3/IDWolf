# Host hardening (from the GPOs in SYSVOL) and password quality checks.
# They add to the catalog in Checks.ps1, so load this after it.
# Password quality comes from Export-PasswordQuality.ps1: account names
# grouped by problem, never a password or a hash.

$script:HostCheckCatalog = [ordered]@{
    # ---------------- Host hardening (GPO) ----------------
    smb_signing_not_required = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1557.001'; Needs = @('gpo')
        Title = 'SMB signing not required on domain controllers'
        Description = 'No effective GPO requires SMB server signing on the DCs. Without it, an attacker who coerces authentication (PetitPotam, PrinterBug) can relay it over SMB, a primary NTLM-relay path.'
        Remediation = 'Require SMB signing (Microsoft network server: Digitally sign communications = Enabled) via a GPO linked to the Domain Controllers OU. Pair with LDAP signing and channel binding.' }
    ldap_signing_not_required = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1557.001'; Needs = @('gpo')
        Title = 'LDAP server signing not required'
        Description = 'The DCs do not require LDAP signing (LDAPServerIntegrity < 2). LDAP is a common NTLM-relay target for privilege escalation (e.g. relay to LDAP then RBCD).'
        Remediation = 'Set "Domain controller: LDAP server signing requirements" to "Require signing" once clients support it.' }
    ldap_channel_binding_off = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1557.001'; Needs = @('gpo')
        Title = 'LDAP channel binding not enforced'
        Description = 'LdapEnforceChannelBinding is not set to Always. Channel binding blocks relaying LDAPS authentication.'
        Remediation = 'Set LDAP channel binding to "When supported" then "Always" after validating clients.' }
    lm_hash_stored = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1003'; Needs = @('gpo')
        Title = 'LM hash storage not disabled'
        Description = 'NoLMHash is not enforced, so LM hashes (trivially crackable) may be stored for accounts, weakening every password against offline cracking.'
        Remediation = 'Enable "Network security: Do not store LAN Manager hash value on next password change" and force a password change.' }
    ntlm_weak_lmcompat = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1550.002'; Needs = @('gpo')
        Title = 'Weak LM/NTLM compatibility level'
        Description = 'LmCompatibilityLevel is below 5, so the DCs may accept LM/NTLMv1 authentication, which is weak and relayable.'
        Remediation = 'Set "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" (level 5) after auditing NTLMv1 usage.' }
    dangerous_privilege_right = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1078.002'; Needs = @('gpo')
        Title = 'Sensitive privilege granted to a non-privileged principal on DCs'
        Description = 'A GPO on the Domain Controllers OU grants a Tier 0 equivalent user right (SeDebug, SeBackup/Restore, SeTakeOwnership, SeTcb, SeLoadDriver, SeEnableDelegation, "Log on as a batch/service") to a principal that is not a default Tier 0 group.'
        Remediation = 'Remove the assignment or scope it to a dedicated admin group; these rights on a DC are equivalent to domain compromise.' }
    anonymous_sam_enum = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1087'; Needs = @('gpo')
        Title = 'Anonymous SAM / share enumeration allowed'
        Description = 'RestrictAnonymous / RestrictAnonymousSAM are not enforced, allowing anonymous enumeration of accounts and shares that feeds password spraying and recon.'
        Remediation = 'Enable "Do not allow anonymous enumeration of SAM accounts and shares".' }
    audit_policy_insufficient = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1562.002'; Needs = @('gpo')
        Title = 'Advanced audit policy gaps on domain controllers'
        Description = 'Key audit subcategories that the CIS benchmark expects on DCs are not set to log Success and/or Failure. Without them, attacks like Kerberoasting, DCSync, account and group changes and privilege abuse leave little or no trace for the SIEM.'
        Remediation = 'Configure the Advanced Audit Policy on the Domain Controllers OU for the listed subcategories (Success and Failure where noted), and forward the events to your SIEM.' }
    audit_advanced_policy_missing = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1562.002'; Needs = @('gpo')
        Title = 'No advanced audit policy applied to domain controllers'
        Description = 'No GPO linked to the Domain Controllers OU defines an advanced audit policy (audit.csv). Security auditing on the DCs is effectively at defaults, so most attacker actions are not recorded.'
        Remediation = 'Deploy an Advanced Audit Policy GPO to the Domain Controllers OU covering credential validation, Kerberos, account/group management, DS access/changes, logon, privilege use and policy change.' }
    kerberos_rc4_allowed = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1558.003'; Needs = @('gpo')
        Title = 'Kerberos encryption allows RC4 or DES on domain controllers'
        Description = 'The effective "Configure encryption types allowed for Kerberos" GPO still permits RC4 (or DES). RC4 service tickets crack far faster than AES, making Kerberoasting cheap.'
        Remediation = 'Set the allowed Kerberos encryption types to AES128 + AES256 only, after confirming no legacy client or trust needs RC4.' }
    wdigest_cleartext = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1003.001'; Needs = @('gpo')
        Title = 'WDigest cleartext credential caching enabled'
        Description = 'UseLogonCredential = 1 makes LSASS keep cleartext passwords in memory, so a single dump on a DC or server yields plaintext credentials.'
        Remediation = 'Set WDigest UseLogonCredential to 0 (the modern default) via GPO.' }
    lsass_not_protected = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1003.001'; Needs = @('gpo')
        Title = 'LSASS not running as a protected process (RunAsPPL)'
        Description = 'RunAsPPL is not enforced, so credential-theft tools can open LSASS and dump secrets more easily on the DCs.'
        Remediation = 'Enable "Configure LSASS to run as a protected process" (RunAsPPL = 1) after checking driver/AV compatibility.' }
    smb_client_signing_not_required = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1557.001'; Needs = @('gpo')
        Title = 'SMB client signing not required'
        Description = 'The SMB client does not require signing, which allows an attacker to relay or tamper with outbound SMB authentication from the DCs.'
        Remediation = 'Set "Microsoft network client: Digitally sign communications (always)" to Enabled via GPO.' }

    netlogon_vulnerable_channel = @{ Category = 'Host Hardening'; Severity = 'Critical'; Mitre = 'T1210'; Needs = @('gpo')
        Title = 'Netlogon secure channel enforcement disabled (ZeroLogon exposure)'
        Description = 'A GPO explicitly turns off Netlogon secure-channel enforcement (FullSecureChannelProtection = 0 or RequireStrongKey = 0). This re-opens CVE-2020-1472 (ZeroLogon) and insecure netlogon channels, which allow resetting a DC machine password and taking over the domain.'
        Remediation = 'Remove the GPO weakening and keep FullSecureChannelProtection = 1 and RequireStrongKey = 1 (the enforced default since the August 2020 updates).' }
    llmnr_enabled = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1557.001'; Needs = @('gpo')
        Title = 'LLMNR not disabled'
        Description = 'Link-Local Multicast Name Resolution is not disabled (DNSClient EnableMulticast not set to 0). LLMNR lets an attacker on the same subnet answer name queries and capture or relay NTLM credentials (Responder-style poisoning).'
        Remediation = 'Disable LLMNR via GPO (Turn off multicast name resolution = Enabled), together with NBT-NS hardening.' }
    spooler_on_dc = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1547.012'; Needs = @('gpo')
        Title = 'Print Spooler not disabled on domain controllers'
        Description = 'No GPO disables the Print Spooler service on the DCs. A running spooler on a DC is the lever for coercion attacks (PrinterBug / MS-RPRN) that force the DC to authenticate to an attacker, feeding NTLM relay and unconstrained-delegation chains.'
        Remediation = 'Disable the Print Spooler service on all domain controllers via GPO (service startup = Disabled).' }
    cached_credentials = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1003.005'; Needs = @('gpo')
        Title = 'Too many cached logon credentials'
        Description = 'The number of cached interactive logons is high or unset (default 10). Cached domain credentials can be extracted offline from a stolen or compromised machine; domain controllers and admin hosts should cache few or none.'
        Remediation = 'Set "Interactive logon: Number of previous logons to cache" to a low value (0 on DCs and PAWs, <= 4 elsewhere) via GPO.' }
    smb1_server_enabled = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1210'; Needs = @('gpo')
        Title = 'SMBv1 not disabled on domain controllers'
        Description = 'No effective GPO disables the SMBv1 server (mrxsmb10 driver start or SMB1 parameter). SMBv1 is obsolete, exploitable (EternalBlue / MS17-010) and should not run on a domain controller.'
        Remediation = 'Disable the SMBv1 server and client via GPO (set mrxsmb10 Start to 4 and SMB1 to 0), then confirm no legacy client still needs it.' }
    unc_hardening_disabled = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1557'; Needs = @('gpo')
        Title = 'UNC hardened paths not configured for SYSVOL / NETLOGON'
        Description = 'Hardened UNC paths for \\*\SYSVOL and \\*\NETLOGON (RequireMutualAuthentication and RequireIntegrity) are not enforced. Without them, GPO and logon-script delivery can be tampered with or spoofed on the path to the DC (a GPO-over-SMB attack vector).'
        Remediation = 'Configure "Hardened UNC Paths" for \\*\SYSVOL and \\*\NETLOGON with RequireMutualAuthentication=1 and RequireIntegrity=1 via GPO.' }
    cmdline_audit_not_enabled = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1562.002'; Needs = @('gpo')
        Title = 'Command-line auditing not enabled in process creation events'
        Description = 'ProcessCreationIncludeCmdLine_Enabled is not set, so 4688 events do not record the full command line. Without it, malicious use of living-off-the-land binaries and scripts is far harder to detect.'
        Remediation = 'Enable "Include command line in process creation events" via GPO, together with Audit Process Creation (Success).' }
    powershell_logging_not_enabled = @{ Category = 'Host Hardening'; Severity = 'Medium'; Mitre = 'T1562.002'; Needs = @('gpo')
        Title = 'PowerShell script block / module logging not enabled'
        Description = 'EnableScriptBlockLogging (and module logging) is not set, so PowerShell activity, a very common attacker tool, is not recorded for the SIEM.'
        Remediation = 'Enable PowerShell Script Block Logging (and Module Logging) via GPO, and forward events 4104/4103 to the SIEM.' }
    kerberos_armoring_not_enforced = @{ Category = 'Host Hardening'; Severity = 'Low'; Mitre = 'T1558'; Needs = @('gpo')
        Title = 'Kerberos armoring (FAST) not enforced on domain controllers'
        Description = 'EnableCbacAndArmor / the KDC "fail unarmored" setting is not enforced, so Kerberos pre-authentication is not protected by FAST and remains exposed to AS-REP roasting and some downgrade attacks.'
        Remediation = 'Once the functional level and clients support it, enable KDC support for claims/armoring and require armored requests via GPO.' }
    point_and_print_unsafe = @{ Category = 'Host Hardening'; Severity = 'High'; Mitre = 'T1068'; Needs = @('gpo')
        Title = 'Point and Print lets non-admins install printer drivers (PrintNightmare)'
        Description = 'An effective GPO sets RestrictDriverInstallationToAdministrators to 0, which undoes the August 2021 PrintNightmare fix (CVE-2021-34527): any user can install a printer driver, and a malicious driver runs as SYSTEM. With NoWarningNoElevationOnInstall = 1 or UpdatePromptSettings set to skip the prompt, it happens silently.'
        Remediation = 'Remove the setting or set RestrictDriverInstallationToAdministrators to 1, and allow Point and Print only from an approved list of print servers (PackagePointAndPrintServerList).' }
    adcs_esc10 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('gpo')
        Title = 'Weak certificate binding on domain controllers (ESC10)'
        Description = 'An effective GPO sets Kdc StrongCertificateBindingEnforcement to 0 (Disabled) or 1 (Compatibility), or enables weak Schannel UPN certificate mapping. With weak binding a certificate without the SID security extension can authenticate as another account, the second half of ESC9/ESC10. Only detectable here when the value is pushed through a GPO security template; a value set locally on the DC is not visible in the snapshot.'
        Remediation = 'Set StrongCertificateBindingEnforcement to 2 (Full Enforcement) on the domain controllers and remove weak Schannel certificate mapping, after confirming all certificates carry the SID extension.' }
    gpo_dangerous_acl = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1484.001'; Needs = @('gpo')
        Title = 'Non-privileged principal can edit a GPO linked to Tier 0'
        Description = 'A non-privileged principal holds write/control rights (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty, or ownership) on a Group Policy object that is linked to the Domain Controllers OU or the domain root. Whoever can edit that GPO can push settings, scripts or scheduled tasks to the domain controllers, which is equivalent to domain compromise (BloodHound GPO control path).'
        Remediation = 'Remove the write permission from the GPO (gpcFileSysPath and the GPC object), or re-scope the delegation. GPOs linked to the DC OU or domain root must be editable only by Tier 0.' }

    gpo_runs_code_from_share = @{ Category = 'Permissions'; Severity = 'Medium'; Mitre = 'T1484.001'; Needs = @('gpo', 'gpo.execution')
        Title = 'GPO runs a script or task from a share outside SYSVOL'
        Description = 'A GPO starts a script or a scheduled task from a network path that is not SYSVOL or NETLOGON. Whoever can write to that share runs code on every machine the GPO applies to, often as SYSTEM, and SYSVOL''s protections don''t cover it.'
        Remediation = 'Move the script into the GPO''s folder in SYSVOL, or make sure only Tier 0 admins (for GPOs on DCs or the domain root) can write to that share and file. Check share and NTFS permissions both.' }
    gpo_broad_local_group = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1078.002'; Needs = @('gpo', 'gpo.execution')
        Title = 'GPO makes everyone a local administrator or RDP user'
        Description = 'Through Restricted Groups or Group Policy Preferences, a GPO adds Everyone, Authenticated Users, Domain Users, Domain Computers or Users to a local Administrators or Remote Desktop Users group. Any account in the domain then gets admin rights or remote logon on those machines: lateral movement for free.'
        Remediation = 'Replace the broad group with a dedicated, small group per machine tier (or use LAPS for local admin access), and remove the broad entry from the GPO.' }
    # ---------------- Password quality (DSInternals, hashless) ----------------
    pwq_duplicate_passwords = @{ Category = 'Password Quality'; Severity = 'High'; Mitre = 'T1110.004'; Needs = @('passwordQuality')
        Title = 'Accounts sharing the same password'
        Description = 'Multiple accounts use an identical password (credential-stuffing / spray amplifier: one cracked password unlocks the whole cluster). Detected from a DSInternals report; IDWolf never sees the password itself.'
        Remediation = 'Reset the shared password on all accounts in the cluster with distinct values; investigate why they matched (shared build, scripted provisioning).' }
    pwq_default_password = @{ Category = 'Password Quality'; Severity = 'High'; Mitre = 'T1078'; Needs = @('passwordQuality')
        Title = 'Account with a default or username-equal password'
        Description = 'The account password equals the username or a known default. Trivial to guess in a spray.'
        Remediation = 'Force a password change and enforce a banned-password policy.' }
    pwq_empty_password = @{ Category = 'Password Quality'; Severity = 'Critical'; Mitre = 'T1078'; Needs = @('passwordQuality')
        Title = 'Account with an empty password'
        Description = 'The account has a blank password and can be logged into with no secret.'
        Remediation = 'Set a compliant password immediately and clear PASSWD_NOTREQD.' }
    pwq_breached_password = @{ Category = 'Password Quality'; Severity = 'High'; Mitre = 'T1110.004'; Needs = @('passwordQuality', 'passwordQualityWeakList')
        Title = 'Account using a known-breached password'
        Description = 'The password appears in a breach corpus (e.g. HaveIBeenPwned) checked offline by DSInternals. Prime spray/stuffing target.'
        Remediation = 'Force a change and enable banned-password filtering (Entra Password Protection on-prem).' }
    pwq_cleartext_stored = @{ Category = 'Password Quality'; Severity = 'High'; Mitre = 'T1003'; Needs = @('passwordQuality')
        Title = 'Password recoverable in cleartext (reversible encryption)'
        Description = 'DSInternals recovered a cleartext password (reversible encryption enabled for the account). Anyone with NTDS access reads it directly.'
        Remediation = 'Disable reversible encryption and reset the password.' }
}
foreach ($k in $script:HostCheckCatalog.Keys) { $script:CheckCatalog[$k] = $script:HostCheckCatalog[$k] }

# --------------------------------------------------------------------------
# GPO effective-setting helpers
# --------------------------------------------------------------------------
# Which GPO wins on a DC, roughly: enforced links (DC OU, then root), then
# the DC OU, then the root. The first one that sets a value wins.
function Get-EffectiveGpoOrder {
    param($Gpo)
    $byGuid = @{}
    foreach ($g in @($Gpo.gpos)) { $byGuid[$g.guid.ToUpper()] = $g }
    $order = New-Object System.Collections.Generic.List[object]
    $add = { param($links, $enforcedOnly, $notEnforced)
        foreach ($l in @($links)) {
            if (-not $l.enabled) { continue }
            if ($enforcedOnly -and -not $l.enforced) { continue }
            if ($notEnforced -and $l.enforced) { continue }
            $g = $byGuid[("$($l.guid)").ToUpper()]
            if ($g) { $order.Add($g) }
        }
    }
    & $add $Gpo.dcOuLinks $true $false
    & $add $Gpo.domainRootLinks $true $false
    & $add $Gpo.dcOuLinks $false $true
    & $add $Gpo.domainRootLinks $false $true
    return $order
}

# Member by name, from a hashtable or from a JSON-loaded object. $null if absent.
function Get-Member2 {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}
function Test-Member2 {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $false }
    if ($Obj -is [System.Collections.IDictionary]) { return $Obj.Contains($Name) }
    return [bool]$Obj.PSObject.Properties[$Name]
}

# Returns the winning "<type>,<value>" string for a registry-value key, or $null.
function Get-EffectiveRegValue {
    param($Order, [string]$Key)
    foreach ($g in $Order) {
        $v = Get-Member2 (Get-Member2 $g 'registryValues') $Key
        if ($null -ne $v) { return $v }
    }
    return $null
}
function Get-RegInt {
    param([string]$Raw)
    if (-not $Raw) { return $null }
    $parts = "$Raw".Split(',')
    try { return [int]$parts[-1].Trim() } catch { return $null }
}

$script:DangerousPrivileges = @{
    'SeDebugPrivilege'              = 'Debug programs'
    'SeBackupPrivilege'             = 'Back up files and directories'
    'SeRestorePrivilege'            = 'Restore files and directories'
    'SeTakeOwnershipPrivilege'     = 'Take ownership'
    'SeTcbPrivilege'                = 'Act as part of the OS'
    'SeLoadDriverPrivilege'         = 'Load and unload device drivers'
    'SeEnableDelegationPrivilege'  = 'Enable delegation'
    'SeCreateTokenPrivilege'        = 'Create a token object'
}
# Well-known SIDs allowed to hold these on a DC (Tier 0 defaults).
$script:PrivRightDefaultSids = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-549', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-32-550')

# CIS audit baseline by subcategory GUID. require: 1 success, 2 failure, 3 both.
$script:AuditBaseline = @(
    @{ Guid = '0cce923f-69ae-11d9-bed3-505054503030'; Name = 'Credential Validation'; Require = 3 }
    @{ Guid = '0cce9242-69ae-11d9-bed3-505054503030'; Name = 'Kerberos Authentication Service'; Require = 3 }
    @{ Guid = '0cce9240-69ae-11d9-bed3-505054503030'; Name = 'Kerberos Service Ticket Operations'; Require = 3 }
    @{ Guid = '0cce9235-69ae-11d9-bed3-505054503030'; Name = 'User Account Management'; Require = 3 }
    @{ Guid = '0cce9236-69ae-11d9-bed3-505054503030'; Name = 'Computer Account Management'; Require = 1 }
    @{ Guid = '0cce9237-69ae-11d9-bed3-505054503030'; Name = 'Security Group Management'; Require = 1 }
    @{ Guid = '0cce923b-69ae-11d9-bed3-505054503030'; Name = 'Directory Service Access'; Require = 2 }
    @{ Guid = '0cce923c-69ae-11d9-bed3-505054503030'; Name = 'Directory Service Changes'; Require = 1 }
    @{ Guid = '0cce9215-69ae-11d9-bed3-505054503030'; Name = 'Logon'; Require = 3 }
    @{ Guid = '0cce921b-69ae-11d9-bed3-505054503030'; Name = 'Special Logon'; Require = 1 }
    @{ Guid = '0cce9228-69ae-11d9-bed3-505054503030'; Name = 'Sensitive Privilege Use'; Require = 3 }
    @{ Guid = '0cce922f-69ae-11d9-bed3-505054503030'; Name = 'Audit Policy Change'; Require = 3 }
    @{ Guid = '0cce9211-69ae-11d9-bed3-505054503030'; Name = 'Security System Extension'; Require = 1 }
    @{ Guid = '0cce9212-69ae-11d9-bed3-505054503030'; Name = 'System Integrity'; Require = 3 }
)
$script:AuditWord = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success+Failure' }

function Invoke-GpoChecks {
    param($Snapshot, $Index, $PrivMap)
    $gpo = $Snapshot.gpo
    if (-not $gpo -or -not $gpo.collected) { return }
    $order = Get-EffectiveGpoOrder $gpo
    $dcLabel = 'Domain Controllers'

    $smb = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature')
    if ($null -eq $smb -or $smb -ne 1) {
        Add-Finding -Type smb_signing_not_required -Object $dcLabel -ObjectType 'gpo' -Detail "RequireSecuritySignature (server) = $(if ($null -eq $smb) { 'not configured' } else { $smb })."
    }
    $ldapS = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity')
    if ($null -eq $ldapS -or $ldapS -lt 2) {
        Add-Finding -Type ldap_signing_not_required -Object $dcLabel -ObjectType 'gpo' -Detail "LDAPServerIntegrity = $(if ($null -eq $ldapS) { 'not configured' } else { $ldapS }) (2 = require)."
    }
    $cb = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding')
    if ($null -eq $cb -or $cb -lt 2) {
        Add-Finding -Type ldap_channel_binding_off -Object $dcLabel -ObjectType 'gpo' -Detail "LdapEnforceChannelBinding = $(if ($null -eq $cb) { 'not configured' } else { $cb }) (2 = always)."
    }
    $lm = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash')
    if ($null -eq $lm -or $lm -ne 1) {
        Add-Finding -Type lm_hash_stored -Object $dcLabel -ObjectType 'gpo' -Detail "NoLMHash = $(if ($null -eq $lm) { 'not configured' } else { $lm })."
    }
    $lmcompat = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel')
    if ($null -ne $lmcompat -and $lmcompat -lt 5) {
        Add-Finding -Type ntlm_weak_lmcompat -Object $dcLabel -ObjectType 'gpo' -Detail "LmCompatibilityLevel = $lmcompat (5 = NTLMv2 only, refuse LM & NTLM)."
    }
    $ra = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM')
    if ($null -eq $ra -or $ra -ne 1) {
        Add-Finding -Type anonymous_sam_enum -Object $dcLabel -ObjectType 'gpo' -Detail "RestrictAnonymousSAM = $(if ($null -eq $ra) { 'not configured' } else { $ra })."
    }
    # Kerberos encryption types: flag if DES (0x1|0x2) or RC4 (0x4) still allowed.
    $kenc = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
    if ($null -ne $kenc -and ($kenc -band 0x7) -ne 0) {
        $bits = @(); if ($kenc -band 0x3) { $bits += 'DES' }; if ($kenc -band 0x4) { $bits += 'RC4' }
        Add-Finding -Type kerberos_rc4_allowed -Object $dcLabel -ObjectType 'gpo' -Detail "SupportedEncryptionTypes = $kenc allows $($bits -join '/')."
    }
    $wd = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential')
    if ($wd -eq 1) {
        Add-Finding -Type wdigest_cleartext -Object $dcLabel -ObjectType 'gpo' -Detail 'WDigest UseLogonCredential = 1 (cleartext credentials cached in LSASS).'
    }
    $ppl = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL')
    if ($null -eq $ppl -or $ppl -lt 1) {
        Add-Finding -Type lsass_not_protected -Object $dcLabel -ObjectType 'gpo' -Detail "RunAsPPL = $(if ($null -eq $ppl) { 'not configured' } else { $ppl })."
    }
    $smbc = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature')
    if ($null -eq $smbc -or $smbc -ne 1) {
        Add-Finding -Type smb_client_signing_not_required -Object $dcLabel -ObjectType 'gpo' -Detail "LanmanWorkstation RequireSecuritySignature (client) = $(if ($null -eq $smbc) { 'not configured' } else { $smbc })."
    }
    # ESC10: only an explicit weak value counts. Not configured means the OS
    # default (full enforcement).
    $sbe = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement')
    if ($null -ne $sbe -and $sbe -lt 2) {
        Add-Finding -Type adcs_esc10 -Object $dcLabel -ObjectType 'gpo' -Detail "StrongCertificateBindingEnforcement = $sbe (0 = disabled, 1 = compatibility; 2 = full enforcement)."
    }
    else {
        $cmm = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods')
        if ($null -ne $cmm -and ($cmm -band 0x4) -ne 0) {
            Add-Finding -Type adcs_esc10 -Object $dcLabel -ObjectType 'gpo' -Detail "Schannel CertificateMappingMethods = $cmm enables weak UPN certificate mapping (0x4)."
        }
    }
    # Logging.
    $cmdl = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled')
    if ($null -eq $cmdl -or $cmdl -ne 1) {
        Add-Finding -Type cmdline_audit_not_enabled -Object $dcLabel -ObjectType 'gpo' -Detail "ProcessCreationIncludeCmdLine_Enabled = $(if ($null -eq $cmdl) { 'not configured' } else { $cmdl })."
    }
    $psl = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging')
    if ($null -eq $psl -or $psl -ne 1) {
        Add-Finding -Type powershell_logging_not_enabled -Object $dcLabel -ObjectType 'gpo' -Detail "EnableScriptBlockLogging = $(if ($null -eq $psl) { 'not configured' } else { $psl })."
    }
    $arm = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kdc\EnableCbacAndArmor')
    if ($null -eq $arm -or $arm -lt 1) {
        Add-Finding -Type kerberos_armoring_not_enforced -Object $dcLabel -ObjectType 'gpo' -Detail "KDC EnableCbacAndArmor = $(if ($null -eq $arm) { 'not configured' } else { $arm })."
    }
    # SMBv1: only an explicit enable. Modern DCs ship with it off.
    $smb1a = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\mrxsmb10\Start')
    $smb1b = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1')
    if (($null -ne $smb1a -and ($smb1a -eq 2 -or $smb1a -eq 3)) -or $smb1b -eq 1) {
        Add-Finding -Type smb1_server_enabled -Object $dcLabel -ObjectType 'gpo' -Detail "SMBv1 enabled via GPO (mrxsmb10 Start = $(if ($null -eq $smb1a) { 'n/a' } else { $smb1a }), LanmanServer SMB1 = $(if ($null -eq $smb1b) { 'n/a' } else { $smb1b }))."
    }
    # Hardened UNC paths for SYSVOL / NETLOGON.
    $uncS = Get-EffectiveRegValue $order 'MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\SYSVOL'
    $uncN = Get-EffectiveRegValue $order 'MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\NETLOGON'
    $uncMissing = @(); if (-not $uncS) { $uncMissing += '\\*\SYSVOL' }; if (-not $uncN) { $uncMissing += '\\*\NETLOGON' }
    if ($uncMissing.Count -gt 0) {
        Add-Finding -Type unc_hardening_disabled -Object $dcLabel -ObjectType 'gpo' -Detail "Hardened UNC Paths not configured for: $($uncMissing -join ', ')."
    }
    # Netlogon secure channel (ZeroLogon): only flag an explicit disable.
    $nlFull = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\FullSecureChannelProtection')
    $nlStrong = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey')
    if ($nlFull -eq 0 -or $nlStrong -eq 0) {
        Add-Finding -Type netlogon_vulnerable_channel -Object $dcLabel -ObjectType 'gpo' -Detail "Netlogon enforcement weakened (FullSecureChannelProtection = $(if ($null -eq $nlFull) { 'n/a' } else { $nlFull }), RequireStrongKey = $(if ($null -eq $nlStrong) { 'n/a' } else { $nlStrong }))."
    }
    # LLMNR must be disabled (EnableMulticast = 0).
    $llmnr = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast')
    if ($null -eq $llmnr -or $llmnr -ne 0) {
        Add-Finding -Type llmnr_enabled -Object $dcLabel -ObjectType 'gpo' -Detail "DNSClient EnableMulticast = $(if ($null -eq $llmnr) { 'not configured' } else { $llmnr }) (0 = LLMNR disabled)."
    }
    # Print Spooler should be disabled on DCs (service start = 4).
    $spool = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\System\CurrentControlSet\Services\Spooler\Start')
    if ($null -eq $spool -or $spool -ne 4) {
        $gpoText = "Spooler service Start = $(if ($null -eq $spool) { 'not configured by GPO' } else { $spool }) (4 = Disabled)"
        # The GPO only says what is enforced. When the collector read the real service state
        # of each DC, trust that: a Spooler that is Disabled on every DC is not a finding.
        $recs = @($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error })
        $live = @($recs | Where-Object { $_.spoolerStartMode })
        $exposed = @($live | Where-Object { "$($_.spoolerStartMode)" -notin 'Disabled', 'absent' })
        $unknown = @($Snapshot.health.dcState | Where-Object { $_ }).Count - $live.Count
        if ($exposed.Count) {
            $list = ($exposed | ForEach-Object { "$($_.dc) ($($_.spoolerStartMode), $($_.spoolerState))" }) -join ', '
            Add-Finding -Type spooler_on_dc -Object $dcLabel -ObjectType 'gpo' -Detail "$gpoText. Running config: $list."
        }
        elseif ($live.Count -eq 0) {
            Add-Finding -Type spooler_on_dc -Object $dcLabel -ObjectType 'gpo' -Detail "$gpoText."
        }
        elseif ($unknown -gt 0) {
            Add-Finding -Type spooler_on_dc -Object $dcLabel -ObjectType 'gpo' -Detail "$gpoText. Disabled on the $($live.Count) DC(s) that could be read; $unknown could not be checked."
        }
    }
    # Point and Print: only an explicit 0 counts; not configured means the post-2021 default (admins only).
    $pnpKey = 'MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    $pnpRestrict = Get-RegInt (Get-EffectiveRegValue $order "$pnpKey\RestrictDriverInstallationToAdministrators")
    if ($pnpRestrict -eq 0) {
        $pnpNoWarn = Get-RegInt (Get-EffectiveRegValue $order "$pnpKey\NoWarningNoElevationOnInstall")
        $pnpUpdate = Get-RegInt (Get-EffectiveRegValue $order "$pnpKey\UpdatePromptSettings")
        $silent = ($pnpNoWarn -eq 1) -or ($null -ne $pnpUpdate -and $pnpUpdate -ge 1)
        Add-Finding -Type point_and_print_unsafe -Object $dcLabel -ObjectType 'gpo' -Severity $(if ($silent) { 'Critical' } else { 'High' }) `
            -Detail "RestrictDriverInstallationToAdministrators = 0; NoWarningNoElevationOnInstall = $(if ($null -eq $pnpNoWarn) { 'not configured' } else { $pnpNoWarn }); UpdatePromptSettings = $(if ($null -eq $pnpUpdate) { 'not configured' } else { $pnpUpdate })$(if ($silent) { ' (drivers install with no prompt)' })."
    }
    # Cached logon credentials should be low.
    $cached = Get-RegInt (Get-EffectiveRegValue $order 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount')
    if ($null -eq $cached -or $cached -gt 4) {
        Add-Finding -Type cached_credentials -Object $dcLabel -ObjectType 'gpo' -Detail "CachedLogonsCount = $(if ($null -eq $cached) { 'not configured (default 10)' } else { $cached })."
    }

    # Dangerous privilege rights assigned by DC-OU-linked GPOs.
    $dcOrder = @()
    $byGuid = @{}; foreach ($g in @($gpo.gpos)) { $byGuid[$g.guid.ToUpper()] = $g }
    foreach ($l in @($gpo.dcOuLinks)) { if ($l.enabled) { $g = $byGuid[("$($l.guid)").ToUpper()]; if ($g) { $dcOrder += $g } } }
    foreach ($g in $dcOrder) {
        $pr = Get-Member2 $g 'privilegeRights'
        foreach ($priv in $script:DangerousPrivileges.Keys) {
            if (-not (Test-Member2 $pr $priv)) { continue }
            $bad = @((Get-Member2 $pr $priv) | Where-Object { $_ -and $script:PrivRightDefaultSids -notcontains $_ -and $_ -notmatch '-51[269]$' })
            if ($bad.Count -gt 0) {
                Add-Finding -Type dangerous_privilege_right -Object "$($script:DangerousPrivileges[$priv])" -ObjectType 'gpo' -ObjectDn $g.displayName `
                    -Detail "GPO '$($g.displayName)' grants $priv to: $($bad -join ', ')."
            }
        }
    }

    # Advanced audit policy: effective per subcategory across applicable GPOs.
    $auditEff = @{}
    $anyAudit = $false
    foreach ($g in $order) {
        $ap = Get-Member2 $g 'auditPolicy'
        if (-not $ap) { continue }
        $names = if ($ap -is [System.Collections.IDictionary]) { @($ap.Keys) } else { @($ap.PSObject.Properties.Name) }
        foreach ($k in $names) {
            $anyAudit = $true
            $gk = "$k".ToLower()
            if (-not $auditEff.ContainsKey($gk)) { $auditEff[$gk] = [int](Get-Member2 $ap $k) }  # first in precedence order wins
        }
    }
    if (-not $anyAudit) {
        Add-Finding -Type audit_advanced_policy_missing -Object $dcLabel -ObjectType 'gpo' -Detail 'No GPO linked to the Domain Controllers OU defines an advanced audit policy (audit.csv).'
    }
    else {
        $gaps = @()
        foreach ($b in $script:AuditBaseline) {
            $have = if ($auditEff.ContainsKey($b.Guid)) { [int]$auditEff[$b.Guid] } else { 0 }
            if (($have -band $b.Require) -ne $b.Require) {
                $missing = $b.Require -band (-bnot $have)
                $gaps += "$($b.Name) (need $($script:AuditWord[$b.Require]), have $(if ($have) { $script:AuditWord[$have] } else { 'None' }))"
            }
        }
        if ($gaps.Count -gt 0) {
            Add-Finding -Type audit_policy_insufficient -Object $dcLabel -ObjectType 'gpo' `
                -Detail ("$($gaps.Count) subcategory gap(s): " + (($gaps | Select-Object -First 12) -join '; ') + '.')
        }
    }

    # Whoever can edit a GPO linked to the DCs or the domain root controls the DCs.
    if ($Index -and (Get-Command Get-Tier0SidSet -ErrorAction SilentlyContinue)) {
        $tier0 = Get-Tier0SidSet $Index $PrivMap
        $byGuid2 = @{}; foreach ($g in @($gpo.gpos)) { $byGuid2[("$($g.guid)").ToUpper()] = $g }
        $linkedScope = [ordered]@{}
        foreach ($l in @($gpo.dcOuLinks)) { if ($l.enabled) { $linkedScope[("$($l.guid)").ToUpper()] = 'Domain Controllers OU' } }
        foreach ($l in @($gpo.domainRootLinks)) { $k = ("$($l.guid)").ToUpper(); if ($l.enabled -and -not $linkedScope.Contains($k)) { $linkedScope[$k] = 'domain root' } }
        foreach ($guid in $linkedScope.Keys) {
            $g = $byGuid2[$guid]
            if (-not $g) { continue }
            $scope = $linkedScope[$guid]
            $sev = if ($scope -eq 'Domain Controllers OU') { 'Critical' } else { 'High' }
            $per = [ordered]@{}
            foreach ($ace in @((Get-Member2 $g 'aces') | Where-Object { $_ })) {
                if ("$($ace.accessType)" -ne 'Allow') { continue }
                if ($ace.isInherited) { continue }
                if ($tier0.ContainsKey($ace.sid)) { continue }
                if ($ace.sid -in @('S-1-5-18', 'S-1-5-10', 'S-1-3-0', 'S-1-5-9')) { continue }
                $rights = "$($ace.rights)"
                $hit = @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty') | Where-Object { $rights -match "\b$_\b" }
                if (@($hit).Count -eq 0) { continue }
                $name = if ($ace.name) { $ace.name } else { $ace.sid }
                if (-not $per.Contains($ace.sid)) { $per[$ace.sid] = [PSCustomObject]@{ Name = $name; Rights = New-Object System.Collections.Generic.List[string] } }
                foreach ($r in $hit) { if (-not $per[$ace.sid].Rights.Contains($r)) { $per[$ace.sid].Rights.Add($r) } }
            }
            $ownerSid = Get-Member2 $g 'ownerSid'
            if ($ownerSid -and -not $tier0.ContainsKey($ownerSid) -and $ownerSid -ne 'S-1-5-18') {
                if (-not $per.Contains($ownerSid)) { $on = Get-Member2 $g 'ownerName'; $per[$ownerSid] = [PSCustomObject]@{ Name = $(if ($on) { $on } else { $ownerSid }); Rights = New-Object System.Collections.Generic.List[string] } }
                if (-not $per[$ownerSid].Rights.Contains('Owner')) { $per[$ownerSid].Rights.Add('Owner') }
            }
            foreach ($sid in $per.Keys) {
                Add-Finding -Type gpo_dangerous_acl -Object $g.displayName -ObjectType 'gpo' -ObjectDn $g.displayName -Severity $sev `
                    -Detail "$($per[$sid].Name) holds $(($per[$sid].Rights | Select-Object -Unique) -join ', ') on this GPO, linked (enabled) to the $scope."
            }
        }
    }

    # Snapshots from older collectors have no execution / localGroups: listed
    # as not evaluated, and silent here.
    if (-not $gpo.PSObject.Properties['execution']) { return }
    $where = @{}
    foreach ($l in @($gpo.domainRootLinks)) { if ($l.enabled) { $where[("$($l.guid)").ToUpper()] = 'the domain root' } }
    foreach ($l in @($gpo.dcOuLinks)) { if ($l.enabled) { $where[("$($l.guid)").ToUpper()] = 'the Domain Controllers OU' } }

    # Code from a UNC path that isn't SYSVOL/NETLOGON. Local paths and bare
    # file names (resolved inside the GPO folder) are fine.
    $seen = @{}
    foreach ($e in @($gpo.execution | Where-Object { $_ })) {
        $cmd = "$($e.command)".Trim('"', ' ')
        if ($cmd -notmatch '^\\\\(?<host>[^\\]+)\\(?<share>[^\\]+)') { continue }
        $share = $Matches['share']
        if ($share -match '^(?i)(sysvol|netlogon)$') { continue }
        $key = "$($e.guid)|$cmd".ToLower()
        if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        $scope = $where[("$($e.guid)").ToUpper()]
        $sev = if ($scope -eq 'the Domain Controllers OU') { 'Critical' } elseif ($scope) { 'High' } else { 'Medium' }
        $linked = if ($scope) { "linked to $scope" } else { 'not linked to the domain root or the DC OU (check its other links)' }
        # One finding per GPO and command: type + object must stay unique (finding_id, -CompareTo).
        Add-Finding -Type gpo_runs_code_from_share -Object "$($e.gpo): $cmd" -ObjectType 'gpo' -ObjectDn $e.guid -Severity $sev `
            -Detail "$($e.scope) $($e.kind): $cmd. GPO $linked."
    }

    # Broad groups put into local Administrators / Remote Desktop Users.
    $dom = if ($Index) { $Index.DomainSid } else { 'S-1-0-unknown' }
    $broad = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'Users'; "$dom-513" = 'Domain Users'; "$dom-515" = 'Domain Computers' }
    $broadNames = '^(?i)(.*\\)?(Everyone|Authenticated Users|Users|Domain Users|Domain Computers)$'
    $targets = @{ 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-555' = 'Remote Desktop Users' }
    $targetNames = '^(?i)(BUILTIN\\)?(Administrators|Remote Desktop Users)( \(built-in\))?$'
    $seen = @{}
    foreach ($m in @($gpo.localGroups | Where-Object { $_ })) {
        $grp = "$($m.group)"; $mem = "$($m.member)"
        $tName = if ($targets.ContainsKey($grp)) { $targets[$grp] } elseif ($grp -match $targetNames) { $Matches[2] } else { $null }
        if (-not $tName) { continue }
        $mName = if ($broad.ContainsKey($mem)) { $broad[$mem] } elseif ("$($m.memberName)" -match $broadNames -or $mem -match $broadNames) { $Matches[2] } else { $null }
        if (-not $mName) { continue }
        $key = "$($m.guid)|$tName|$mName".ToLower()
        if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        $scope = $where[("$($m.guid)").ToUpper()]
        $sev = if ($tName -eq 'Administrators') { if ($scope -eq 'the Domain Controllers OU') { 'Critical' } else { 'High' } } else { 'Medium' }
        $via = if ("$($m.source)" -eq 'Restricted Groups') { 'Restricted Groups' } else { 'Group Policy Preferences' }
        Add-Finding -Type gpo_broad_local_group -Object "$($m.gpo): local $tName" -ObjectType 'gpo' -ObjectDn $m.guid -Severity $sev `
            -Detail "$mName added to local $tName through $via$(if ($scope) { ", GPO linked to $scope" })."
    }
}

# --------------------------------------------------------------------------
# Password quality (hashless DSInternals report)
# --------------------------------------------------------------------------
# Account names of one list in the report. Windows PowerShell 5.1 can write an empty list as {} or as
# {"value": [...], "Count": n}: unwrap the second, and skip empty names.
function ConvertTo-PqNameList {
    param($List)
    if ($List -and $List -isnot [array] -and $List -isnot [string] -and $List.PSObject.Properties['value'] -and $List.PSObject.Properties['Count']) { $List = $List.value }
    return @($List | Where-Object { $_ -is [string] -or $_ -is [ValueType] } | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
}

function Invoke-PasswordQualityChecks {
    param($Snapshot)
    $pq = $Snapshot.passwordQuality
    if (-not $pq) { return }
    $names = { param($list) ConvertTo-PqNameList $list }
    foreach ($grp in @($pq.duplicatePasswordGroups | Where-Object { $_ })) {
        $accts = @(& $names $grp)
        if ($accts.Count -lt 2) { continue }
        $shown = ($accts | Select-Object -First 8) -join ', '
        if ($accts.Count -gt 8) { $shown += " (+$($accts.Count - 8) more)" }
        Add-Finding -Type pwq_duplicate_passwords -Object "$($accts.Count) accounts" -ObjectType 'cluster' -Detail "Same password: $shown."
    }
    foreach ($a in (& $names $pq.emptyPassword)) { Add-Finding -Type pwq_empty_password -Object $a -ObjectType 'user' -Detail 'Empty password.' }
    foreach ($a in (& $names $pq.defaultOrUsernamePassword)) { Add-Finding -Type pwq_default_password -Object $a -ObjectType 'user' -Detail 'Password equals username or a known default.' }
    foreach ($a in (& $names $pq.breachedPassword)) { Add-Finding -Type pwq_breached_password -Object $a -ObjectType 'user' -Detail 'Password found in the breach corpus.' }
    foreach ($a in (& $names $pq.clearTextPassword)) { Add-Finding -Type pwq_cleartext_stored -Object $a -ObjectType 'user' -Detail 'Cleartext recoverable (reversible encryption).' }
}
