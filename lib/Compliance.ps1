# Regulatory mapping: which controls of NIS2, ISO/IEC 27001:2022, DORA and
# GDPR each check gives evidence for. A check gets one or more themes (from
# its category, then from words in its ID); each control lists the themes it
# covers. The mapping is about the technical, directory-side part of a
# control: a clean row is evidence, not compliance.

$script:ComplianceThemes = [ordered]@{
    auth   = 'Authentication and credentials'
    mfa    = 'Multi-factor and strong authentication'
    priv   = 'Privileged access'
    access = 'Identity lifecycle and access rights'
    config = 'Secure configuration'
    vuln   = 'Unsupported software and known vulnerabilities'
    crypto = 'Cryptography'
    log    = 'Logging and monitoring'
    resil  = 'Backup, redundancy and availability'
    net    = 'Network security'
}

# Category -> default themes.
$script:ComplianceCategoryThemes = @{
    'Kerberos'             = @('auth')
    'Privileged Access'    = @('priv')
    'Account Hygiene'      = @('access')
    'Domain Configuration' = @('config')
    'Operational Health'   = @('resil')
    'Permissions'          = @('priv')
    'Certificate Services' = @('priv', 'config')
    'Host Hardening'       = @('config')
    'Password Quality'     = @('auth')
    'Entra Access Policy'  = @('access')
    'Entra Identity'       = @('priv')
    'Entra Applications'   = @('access')
}

# Words in a check ID -> extra themes.
$script:ComplianceIdThemes = [ordered]@{
    auth   = 'password|kerberoast|asrep|krbtgt|laps|pwq_|des_enabled|spn_account|protected_users|lockout|banned_passwords|unix_password|lm_hash|lmcompat|wdigest|cached_credentials|precreated|credential|auth_methods|authenticator'
    mfa    = 'mfa|phishing_resistant|security_defaults|legacy_auth|device_code|authenticator|auth_methods|system_preferred|security_info_registration|risk_polic|sign_in_risk'
    priv   = 'admin|privileged|uac_|dcsync|delegation|delegable|rbcd|operator|owner|dangerous_ace|gmsa|shadow|laps_readers|sync_laps|rodc|pim|role|silo|sid_history|primary_group|krbtgt|adcs_esc'
    access = 'inactive|never_logged|stale_|guest|orphaned|anonymous|pre_win2000|consent|register_apps|create_tenants|create_security_groups|create_m365|device_join|device_quota|access_review|access_package|b2b|cross_tenant|broad_local_group|machine_account_quota|precreated'
    config = 'policy|functional_level|recycle_bin|gpo|signing|channel_binding|unc_hardening|llmnr|spooler|smb1|netlogon|lsass|wdigest|cached_credentials|armoring|point_and_print|dns_|dhcp|trust_|sysvol_frs|app_management|redirect'
    vuln   = 'obsolete_os|netlogon_vulnerable|smb1|spooler|point_and_print|functional_level|des_enabled|lm_hash|sysvol_frs'
    crypto = 'rc4|des_enabled|lm_hash|lmcompat|reversible|weak_ca_key|ca_cert_expiring|wdigest|signing|channel_binding|armoring|unix_password|token_protection|^bitlocker|trusted_root'
    log    = 'audit|logging|cmdline'
    resil  = 'backup|replication|single_dc|fsmo|dc_unreachable|time_skew|low_disk|service_stopped|recycle_bin|sysvol_frs|emergency_access|global_admins_too_few|sync_stale|ca_cert_expiring'
    net    = 'signing|channel_binding|llmnr|dns_|unc_hardening|anonymous_sam|smb1|dhcp|trust_|anonymous_ldap|trusted_locations|geo_restriction|cross_tenant|b2b|firewall'
}

# Framework -> control -> themes. Ids are short so they fit a CSV column and a SIEM field.
$script:ComplianceFrameworks = [ordered]@{
    NIS2     = [ordered]@{
        Name     = 'NIS2, Directive (EU) 2022/2555, Art. 21(2)'
        Note     = 'In Italy: Art. 24 of Legislative Decree 138/2024. Running IDWolf on a schedule is also evidence for point (f), assessing the effectiveness of the measures.'
        Controls = [ordered]@{
            '21(2)(b)' = @{ Title = 'Incident handling'; Themes = @('log') }
            '21(2)(c)' = @{ Title = 'Business continuity, backup management, disaster recovery'; Themes = @('resil') }
            '21(2)(e)' = @{ Title = 'Security in maintenance of systems, vulnerability handling'; Themes = @('vuln', 'config', 'net') }
            '21(2)(g)' = @{ Title = 'Basic cyber hygiene practices'; Themes = @('config', 'access') }
            '21(2)(h)' = @{ Title = 'Cryptography and encryption'; Themes = @('crypto') }
            '21(2)(i)' = @{ Title = 'Access control policies and asset management'; Themes = @('access', 'priv', 'auth') }
            '21(2)(j)' = @{ Title = 'Multi-factor or continuous authentication'; Themes = @('mfa') }
        }
    }
    ISO27001 = [ordered]@{
        Name     = 'ISO/IEC 27001:2022, Annex A'
        Note     = 'Periodic runs with -CompareTo support the reviews of A.5.35 and A.5.36.'
        Controls = [ordered]@{
            'A.5.15' = @{ Title = 'Access control'; Themes = @('access', 'priv') }
            'A.5.16' = @{ Title = 'Identity management'; Themes = @('access') }
            'A.5.17' = @{ Title = 'Authentication information'; Themes = @('auth') }
            'A.5.18' = @{ Title = 'Access rights'; Themes = @('access', 'priv') }
            'A.8.2'  = @{ Title = 'Privileged access rights'; Themes = @('priv') }
            'A.8.5'  = @{ Title = 'Secure authentication'; Themes = @('auth', 'mfa') }
            'A.8.8'  = @{ Title = 'Management of technical vulnerabilities'; Themes = @('vuln') }
            'A.8.9'  = @{ Title = 'Configuration management'; Themes = @('config') }
            'A.8.13' = @{ Title = 'Information backup'; Themes = @('resil') }
            'A.8.14' = @{ Title = 'Redundancy of information processing facilities'; Themes = @('resil') }
            'A.8.15' = @{ Title = 'Logging'; Themes = @('log') }
            'A.8.16' = @{ Title = 'Monitoring activities'; Themes = @('log') }
            'A.8.20' = @{ Title = 'Networks security'; Themes = @('net') }
            'A.8.24' = @{ Title = 'Use of cryptography'; Themes = @('crypto') }
        }
    }
    DORA     = [ordered]@{
        Name     = 'DORA, Regulation (EU) 2022/2554'
        Note     = 'Applies to financial entities. The detailed access-control and authentication requirements sit in the ICT risk management RTS, Delegated Regulation (EU) 2024/1774.'
        Controls = [ordered]@{
            '9(2)'    = @{ Title = 'ICT security policies and tools for resilience, integrity and confidentiality'; Themes = @('config') }
            '9(4)(b)' = @{ Title = 'Sound network and infrastructure management'; Themes = @('net', 'config') }
            '9(4)(c)' = @{ Title = 'Logical access limited to what is required'; Themes = @('access', 'priv') }
            '9(4)(d)' = @{ Title = 'Strong authentication, protection of cryptographic keys'; Themes = @('auth', 'mfa', 'crypto') }
            '9(4)(f)' = @{ Title = 'Patches and updates'; Themes = @('vuln') }
            '10(1)'   = @{ Title = 'Detection of anomalous activities'; Themes = @('log') }
            '12(1)'   = @{ Title = 'Backup, restoration and recovery'; Themes = @('resil') }
        }
    }
    GDPR     = [ordered]@{
        Name     = 'GDPR, Regulation (EU) 2016/679, Art. 32(1)'
        Note     = 'Running IDWolf regularly is also evidence for point (d), regularly testing and evaluating the effectiveness of the measures.'
        Controls = [ordered]@{
            '32(1)(a)' = @{ Title = 'Pseudonymisation and encryption'; Themes = @('crypto') }
            '32(1)(b)' = @{ Title = 'Ongoing confidentiality, integrity, availability and resilience'; Themes = @('auth', 'mfa', 'priv', 'access', 'config', 'vuln', 'net', 'log') }
            '32(1)(c)' = @{ Title = 'Timely restoration of availability and access'; Themes = @('resil') }
        }
    }
}

# --------------------------------------------------------------------------
# Benchmarks: the CIS and DISA STIG items a check gives evidence for.
# Unlike the frameworks above this is a hand-made list, item by item: a
# benchmark recommendation is one setting, so there is no theme to match on.
# It is partial on purpose and says so: an item with no check is listed with
# the reason (manual in the portal, procedural, or not visible in a snapshot),
# the way COVERAGE.md does. Kind keeps an Entra benchmark out of an AD report
# and the other way round. The version is pinned: CIS renumbers between major
# releases and DISA reuses V-ids between releases.
# --------------------------------------------------------------------------
$script:Benchmarks = [ordered]@{
    'CIS M365' = [ordered]@{
        Name  = 'CIS Microsoft 365 Foundations Benchmark v7.0.0'
        Kind  = 'entra'
        Note  = 'Section 5 is the Microsoft Entra admin center, section 1 holds the admin accounts. The Microsoft 365 workload items (Exchange, Teams, Purview and the rest) are outside an identity snapshot and are not listed. E5 marks items that need an E5 / Entra ID P2 licence.'
        Items = [ordered]@{
            '1.1.1'     = @{ Level = 'L1'; Title = 'Administrative accounts are cloud-only'; Checks = @('entra_admin_synced_from_onprem') }
            '1.1.2'     = @{ Level = 'L1'; Title = 'Two emergency access accounts defined'; Checks = @('entra_no_emergency_access', 'entra_global_admins_too_few') }
            '1.1.3'     = @{ Level = 'L1'; Title = 'Between two and four Global Admins'; Checks = @('entra_global_admins_too_few', 'entra_global_admins_excessive') }
            '1.1.4'     = @{ Level = 'L1'; Title = 'Admin accounts use licences with a reduced application footprint'; Checks = @('entra_admin_licensed') }
            '1.3.1'     = @{ Level = 'L1'; Title = 'Password expiration policy set to never expire'; Checks = @('entra_password_expiry_set') }
            '1.3.2'     = @{ Level = 'L2'; Title = 'Idle session timeout for unmanaged devices'; Checks = @('entra_idle_timeout_missing') }
            '5.1.2.1'   = @{ Level = 'L1'; Title = 'Per-user MFA disabled in favour of Conditional Access'; Checks = @('entra_per_user_mfa_admins'); Note = 'Admin accounts only: the per-user MFA state costs one Graph call per user.' }
            '5.1.2.2'   = @{ Level = 'L1'; Title = 'Third-party integrated applications not allowed'; Checks = @('entra_users_can_register_apps') }
            '5.1.2.3'   = @{ Level = 'L1'; Title = 'Non-admin users cannot create tenants'; Checks = @('entra_users_can_create_tenants') }
            '5.1.2.4'   = @{ Level = 'L1'; Title = 'Access to the Entra admin center restricted'; Checks = @(); Note = 'Manual: no Graph API for this setting.' }
            '5.1.2.5'   = @{ Level = 'L2'; Title = 'Stay signed in option hidden'; Checks = @('entra_kmsi_shown') }
            '5.1.2.6'   = @{ Level = 'L2'; Title = 'LinkedIn account connections disabled'; Checks = @(); Note = 'Manual: no Graph API for this setting.' }
            '5.1.3.1'   = @{ Level = 'L1'; Title = 'Users cannot create security groups'; Checks = @('entra_users_can_create_security_groups') }
            '5.1.3.2'   = @{ Level = 'L2'; Title = 'Users cannot use the My Groups features'; Checks = @(); Note = 'Manual: no Graph API for this setting.' }
            '5.1.3.3'   = @{ Level = 'L1'; Title = 'Owners cannot manage membership requests in My Groups'; Checks = @(); Note = 'Manual: no Graph API for this setting.' }
            '5.1.3.4'   = @{ Level = 'L2'; Title = 'Users cannot create Microsoft 365 groups'; Checks = @('entra_users_can_create_m365_groups') }
            '5.1.4.1'   = @{ Level = 'L2'; Title = 'Device join restricted to selected users'; Checks = @('entra_device_join_unrestricted') }
            '5.1.4.2'   = @{ Level = 'L1'; Title = 'Maximum number of devices per user limited'; Checks = @('entra_device_quota_high') }
            '5.1.4.3'   = @{ Level = 'L1'; Title = 'Global Admins not added as local admins on join'; Checks = @('entra_device_join_ga_local_admin') }
            '5.1.4.4'   = @{ Level = 'L1'; Title = 'Registering user not added as local admin'; Checks = @('entra_device_join_user_local_admin') }
            '5.1.4.5'   = @{ Level = 'L1'; Title = 'LAPS enabled for Entra-joined devices'; Checks = @('entra_device_laps_off') }
            '5.1.4.6'   = @{ Level = 'L2'; Title = 'Users cannot recover their own BitLocker keys'; Checks = @('entra_users_read_bitlocker_keys') }
            '5.1.5.1'   = @{ Level = 'L2'; Title = 'User consent to applications not allowed'; Checks = @('entra_user_consent_allowed') }
            '5.1.5.2'   = @{ Level = 'L1'; Title = 'Admin consent workflow enabled'; Checks = @('entra_users_can_consent') }
            '5.1.5.3'   = @{ Level = 'L2'; Title = 'Password (secret) addition blocked for applications'; Checks = @('entra_app_management_policy_weak') }
            '5.1.5.4'   = @{ Level = 'L1'; Title = 'Application secret lifetime 180 days or less'; Checks = @('entra_app_management_policy_weak', 'entra_app_secret_long_lived') }
            '5.1.5.5'   = @{ Level = 'L1'; Title = 'New application secrets are system-generated'; Checks = @('entra_app_management_policy_weak') }
            '5.1.5.6'   = @{ Level = 'L1'; Title = 'Application certificate lifetime 180 days or less'; Checks = @('entra_app_management_policy_weak') }
            '5.1.6.1'   = @{ Level = 'L2'; Title = 'Guest invitations only to allowed domains'; Checks = @(); Note = 'Manual: no supported Graph v1.0 API for the domain allow list.' }
            '5.1.6.2'   = @{ Level = 'L1'; Title = 'Guest user access restricted'; Checks = @('entra_guest_access_not_restricted') }
            '5.1.6.3'   = @{ Level = 'L2'; Title = 'Only administrators can invite guests'; Checks = @('entra_guest_invite_open') }
            '5.1.8.1'   = @{ Level = 'L1'; Title = 'Password hash sync enabled for hybrid tenants'; Checks = @('entra_password_hash_sync_off') }
            '5.2.2.1'   = @{ Level = 'L1'; Title = 'MFA required for administrative roles'; Checks = @('entra_no_ca_mfa_admins', 'entra_admins_without_mfa') }
            '5.2.2.2'   = @{ Level = 'L1'; Title = 'MFA required for all users'; Checks = @('entra_security_defaults_off') }
            '5.2.2.3'   = @{ Level = 'L1'; Title = 'Legacy authentication blocked'; Checks = @('entra_legacy_auth_allowed') }
            '5.2.2.4'   = @{ Level = 'L1'; Title = 'Sign-in frequency and non-persistent browser for admins'; Checks = @('entra_admin_sign_in_frequency') }
            '5.2.2.5'   = @{ Level = 'L2'; Title = 'Phishing-resistant MFA strength for admins'; Checks = @('entra_no_phishing_resistant_admins') }
            '5.2.2.6'   = @{ Level = 'E5 L1'; Title = 'User risk policy enabled'; Checks = @('entra_risk_policies_missing') }
            '5.2.2.7'   = @{ Level = 'E5 L1'; Title = 'Sign-in risk policy enabled'; Checks = @('entra_risk_policies_missing') }
            '5.2.2.8'   = @{ Level = 'E5 L2'; Title = 'Medium and high sign-in risk blocked'; Checks = @('entra_sign_in_risk_not_blocked') }
            '5.2.2.9'   = @{ Level = 'L1'; Title = 'Managed device required for authentication'; Checks = @('entra_no_managed_device') }
            '5.2.2.10'  = @{ Level = 'L1'; Title = 'Managed device required to register security info'; Checks = @('entra_security_info_registration') }
            '5.2.2.11'  = @{ Level = 'L1'; Title = 'Sign-in frequency every time for Intune enrollment'; Checks = @('entra_intune_enrollment_reauth') }
            '5.2.2.12'  = @{ Level = 'L1'; Title = 'Device code flow blocked'; Checks = @('entra_device_code_flow_allowed') }
            '5.2.2.13'  = @{ Level = 'L1'; Title = 'Periodic reauthentication for all users'; Checks = @('entra_no_periodic_reauth') }
            '5.2.2.14'  = @{ Level = 'L2'; Title = 'Trusted named locations defined'; Checks = @('entra_no_trusted_locations') }
            '5.2.2.15'  = @{ Level = 'L2'; Title = 'Geographic access restrictions in use'; Checks = @('entra_no_geo_restriction') }
            '5.2.2.16'  = @{ Level = 'L2'; Title = 'Token protection enforced'; Checks = @('entra_token_protection_off') }
            '5.2.2.17'  = @{ Level = 'L1'; Title = 'Authentication transfer blocked'; Checks = @('entra_auth_transfer_allowed') }
            '5.2.3.1'   = @{ Level = 'L1'; Title = 'Authenticator shows application name and location'; Checks = @('entra_authenticator_context_off') }
            '5.2.3.2'   = @{ Level = 'L1'; Title = 'Custom banned password list in use'; Checks = @('entra_banned_passwords_off') }
            '5.2.3.3'   = @{ Level = 'L1'; Title = 'Password protection enabled on-premises'; Checks = @(); Note = 'Out: needs the password protection agent on the DCs.' }
            '5.2.3.4'   = @{ Level = 'L1'; Title = 'All member users are MFA capable'; Checks = @('entra_users_not_mfa_capable') }
            '5.2.3.5'   = @{ Level = 'L1'; Title = 'SMS and voice call disabled as methods'; Checks = @('entra_weak_auth_methods') }
            '5.2.3.6'   = @{ Level = 'L1'; Title = 'System-preferred MFA enabled'; Checks = @('entra_system_preferred_mfa_off') }
            '5.2.3.7'   = @{ Level = 'L2'; Title = 'Email OTP disabled'; Checks = @('entra_weak_auth_methods') }
            '5.2.3.8'   = @{ Level = 'L1'; Title = 'Account lockout threshold 10 or less'; Checks = @('entra_smart_lockout_weak') }
            '5.2.3.9'   = @{ Level = 'L1'; Title = 'Account lockout duration 60 seconds or more'; Checks = @('entra_smart_lockout_weak') }
            '5.2.3.10'  = @{ Level = 'L1'; Title = 'Authenticator Lite (companion apps) disabled'; Checks = @('entra_authenticator_lite_on') }
            '5.2.4.1-5' = @{ Level = 'L1/L2'; Title = 'Self-service password reset settings'; Checks = @(); Note = 'Manual: Graph does not expose the SSPR settings.' }
            '5.3.1'     = @{ Level = 'E5 L2'; Title = 'PIM manages privileged roles'; Checks = @('entra_pim_not_used') }
            '5.3.2'     = @{ Level = 'E5 L1'; Title = 'Access reviews for guest users'; Checks = @('entra_no_guest_access_review') }
            '5.3.3'     = @{ Level = 'E5 L1'; Title = 'Access reviews for privileged roles'; Checks = @('entra_no_admin_access_review') }
            '5.3.4'     = @{ Level = 'E5 L1'; Title = 'Approval required for Global Admin activation'; Checks = @('entra_pim_activation_no_approval') }
            '5.3.5'     = @{ Level = 'E5 L1'; Title = 'Approval required for Privileged Role Admin activation'; Checks = @('entra_pim_activation_no_approval') }
        }
    }
    'STIG AD'  = [ordered]@{
        Name  = 'DISA Active Directory Domain STIG, V3R6 (5 January 2026)'
        Kind  = 'ad'
        Note  = 'The domain STIG, not the Windows Server one: its 36 requirements are about the directory itself. About half are procedural or about the network around AD (cross-domain solutions, VPN, IDS, contingency plans) and cannot be read from a snapshot; those are listed with the reason. The severities are the STIG ones (CAT I / II / III).'
        Items = [ordered]@{
            'V-243466' = @{ Level = 'CAT I'; Title = 'Membership of Enterprise Admins restricted to forest management accounts'; Checks = @('schema_enterprise_admins_populated') }
            'V-243467' = @{ Level = 'CAT I'; Title = 'Membership of Domain Admins restricted to domain management accounts'; Checks = @('privileged_group_oversized', 'privileged_kerberoastable', 'privileged_computer_member') }
            'V-243468' = @{ Level = 'CAT II'; Title = 'Separate accounts for managing domain member servers'; Checks = @(); Note = 'Procedural: a snapshot cannot tell which account is used where.' }
            'V-243469' = @{ Level = 'CAT II'; Title = 'Separate accounts for managing domain workstations'; Checks = @(); Note = 'Procedural: a snapshot cannot tell which account is used where.' }
            'V-243470' = @{ Level = 'CAT I'; Title = 'Delegation of privileged accounts prohibited'; Checks = @('privileged_account_delegable') }
            'V-243471' = @{ Level = 'CAT II'; Title = 'Local administrator accounts do not share the same password'; Checks = @('laps_not_deployed', 'laps_missing', 'laps_stale') }
            'V-243472' = @{ Level = 'CAT II'; Title = 'Separate smart cards for Enterprise Admin and Domain Admin accounts'; Checks = @(); Note = 'Out: the card behind a certificate mapping is not in the directory.' }
            'V-243473' = @{ Level = 'CAT II'; Title = 'Separate accounts for public facing and internal servers'; Checks = @(); Note = 'Procedural.' }
            'V-243475' = @{ Level = 'CAT II'; Title = 'Domain controllers blocked from Internet access'; Checks = @(); Note = 'Out: network state, not directory state.' }
            'V-243476' = @{ Level = 'CAT II'; Title = 'NT hash of smart-card accounts rotated at least every 60 days'; Checks = @('smartcard_password_not_rotated'); Note = 'IDWolf uses -PasswordMaxAgeDays (365 by default): pass -PasswordMaxAgeDays 60 for the STIG threshold.' }
            'V-243477' = @{ Level = 'CAT II'; Title = 'Domain administrators are members of Protected Users'; Checks = @('protected_users_empty', 'privileged_logon_unrestricted') }
            'V-243478' = @{ Level = 'CAT II'; Title = 'Domain-joined systems other than DCs are not trusted for delegation'; Checks = @('unconstrained_delegation') }
            'V-243479' = @{ Level = 'CAT II'; Title = 'DSRM password changed at least annually on each DC'; Checks = @(); Note = 'Out: the DSRM password age is not exposed by AD. dsrm_logon_behavior covers the logon behaviour, a different requirement.' }
            'V-243480' = @{ Level = 'CAT II'; Title = 'Domain functional level still supported by Microsoft'; Checks = @('functional_level_outdated') }
            'V-243481' = @{ Level = 'CAT II'; Title = 'Access to need-to-know information restricted'; Checks = @(); Note = 'Procedural.' }
            'V-243482' = @{ Level = 'CAT I'; Title = 'Cross-domain solution for trusts between classification levels'; Checks = @(); Note = 'Procedural.' }
            'V-243483' = @{ Level = 'CAT I'; Title = 'Controlled interface between DoD and non-DoD systems'; Checks = @(); Note = 'Procedural.' }
            'V-243484' = @{ Level = 'CAT II'; Title = 'SID filtering configured on external and forest trusts'; Checks = @('trust_sid_filtering_disabled', 'sid_history') }
            'V-243485' = @{ Level = 'CAT II'; Title = 'Selective Authentication enabled on outgoing forest trusts'; Checks = @('trust_no_selective_auth') }
            'V-243486' = @{ Level = 'CAT II'; Title = 'Anonymous Logon and Everyone not in Pre-Windows 2000 Compatible Access'; Checks = @('pre_win2000_anonymous') }
            'V-243487' = @{ Level = 'CAT II'; Title = 'Membership of Group Policy Creator Owners and Incoming Forest Trust Builders limited'; Checks = @(); Note = 'Partial: members of Group Policy Creator Owners count as Tier 0 throughout the report, but no check reports the group on its own.' }
            'V-243488' = @{ Level = 'CAT III'; Title = 'Delegated accounts removed from built-in administrative groups'; Checks = @('operator_groups_populated') }
            'V-243489' = @{ Level = 'CAT II'; Title = 'RODC architecture and configuration comply with directory requirements'; Checks = @('rodc_prp_too_broad', 'rodc_tier0_revealed', 'rodc_tier0_unprotected', 'rodc_krbtgt_password_old') }
            'V-243490' = @{ Level = 'CAT II'; Title = 'Use of administrative accounts is monitored'; Checks = @('audit_policy_insufficient', 'audit_advanced_policy_missing') }
            'V-243491' = @{ Level = 'CAT II'; Title = 'Remote logons with local accounts are monitored'; Checks = @(); Note = 'Out: event monitoring, not a directory setting.' }
            'V-243492' = @{ Level = 'CAT II'; Title = 'Remote desktop logons are monitored'; Checks = @(); Note = 'Out: event monitoring, not a directory setting.' }
            'V-243493' = @{ Level = 'CAT II'; Title = 'Active Directory data backed up daily'; Checks = @('ad_backup_overdue'); Note = 'IDWolf flags a backup older than 7 days; the STIG asks for daily, weekly where availability is categorised low.' }
            'V-243494' = @{ Level = 'CAT III'; Title = 'Cross-directory authentication configuration documented'; Checks = @(); Note = 'Procedural.' }
            'V-243495' = @{ Level = 'CAT II'; Title = 'VPN protects directory traffic across enclave boundaries'; Checks = @(); Note = 'Out: network state.' }
            'V-243496' = @{ Level = 'CAT II'; Title = 'Outside accounts removed from highly privileged groups'; Checks = @('privileged_foreign_member') }
            'V-243497' = @{ Level = 'CAT II'; Title = 'Inter-site replication enabled and occurring at least daily'; Checks = @('replication_stale', 'replication_failures') }
            'V-243498' = @{ Level = 'CAT II'; Title = 'VPN traffic inspected by the network IDS'; Checks = @(); Note = 'Out: network state.' }
            'V-243499' = @{ Level = 'CAT III'; Title = 'Active Directory added to the organization contingency plan'; Checks = @(); Note = 'Procedural.' }
            'V-243500' = @{ Level = 'CAT II'; Title = 'Active Directory supported by multiple domain controllers'; Checks = @('single_dc') }
            'V-243501' = @{ Level = 'CAT III'; Title = 'Impact of CPCON changes on cross-directory authentication documented'; Checks = @(); Note = 'Procedural.' }
            'V-269097' = @{ Level = 'CAT II'; Title = 'Kerberos logging enabled on DCs hosting AD CS'; Checks = @(); Note = 'Out: that registry value is read on the DC, not from the directory.' }
        }
    }
}

$script:ComplianceCache = @{}

function Get-ComplianceCatalogEntry {
    param([string]$Type)
    if ($script:CheckCatalog -and $script:CheckCatalog.Contains($Type)) { return $script:CheckCatalog[$Type] }
    if ($script:EntraCheckCatalog -and $script:EntraCheckCatalog.Contains($Type)) { return $script:EntraCheckCatalog[$Type] }
    return $null
}

function Get-CheckThemes {
    param([string]$Type)
    $meta = Get-ComplianceCatalogEntry $Type
    $themes = New-Object System.Collections.Generic.List[string]
    if ($meta -and $script:ComplianceCategoryThemes.ContainsKey("$($meta.Category)")) {
        foreach ($t in $script:ComplianceCategoryThemes["$($meta.Category)"]) { $themes.Add($t) }
    }
    foreach ($t in $script:ComplianceIdThemes.Keys) {
        if ($Type -match $script:ComplianceIdThemes[$t] -and -not $themes.Contains($t)) { $themes.Add($t) }
    }
    if ($themes.Count -eq 0) { $themes.Add('config') }
    return , $themes.ToArray()
}

# "NIS2 21(2)(i)", "ISO27001 A.8.2"... for one check, in framework order.
function Get-CheckControls {
    param([string]$Type)
    if ($script:ComplianceCache.ContainsKey($Type)) { return , $script:ComplianceCache[$Type] }
    $themes = Get-CheckThemes $Type
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        $ctrls = $script:ComplianceFrameworks[$fw].Controls
        foreach ($c in $ctrls.Keys) {
            if (@($ctrls[$c].Themes | Where-Object { $themes -contains $_ }).Count -gt 0) { $out.Add("$fw $c") }
        }
    }
    $arr = $out.ToArray()
    $script:ComplianceCache[$Type] = $arr
    return , $arr
}

# Same list, grouped for reading: "NIS2 21(2)(i), 21(2)(j); ISO27001 A.8.2".
function Format-CheckControls {
    param([string]$Type)
    $parts = @()
    $all = Get-CheckControls $Type
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        $ids = @($all | Where-Object { $_.StartsWith("$fw ") } | ForEach-Object { $_.Substring($fw.Length + 1) })
        if ($ids.Count) { $parts += "$fw $($ids -join ', ')" }
    }
    return ($parts -join '; ')
}

# One row per control: how many checks give evidence for it, how many could not
# be evaluated, and what was found.
function Get-ComplianceCoverage {
    param($Catalog, $Findings, $NotEvaluated)
    $ne = @{}; foreach ($n in @($NotEvaluated | Where-Object { $_ })) { $ne["$($n.Type)"] = $true }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        foreach ($c in $script:ComplianceFrameworks[$fw].Controls.Keys) {
            $id = "$fw $c"
            $checks = @($Catalog.Keys | Where-Object { (Get-CheckControls $_) -contains $id })
            $hits = @($Findings | Where-Object { $checks -contains $_.Type })
            $worst = ''
            foreach ($s in 'Critical', 'High', 'Medium', 'Low') { if (@($hits | Where-Object { $_.Severity -eq $s }).Count) { $worst = $s; break } }
            $notEval = @($checks | Where-Object { $ne.ContainsKey($_) }).Count
            $status = if ($hits.Count) { 'Gaps found' } elseif ($checks.Count -eq 0) { 'No check' } elseif ($notEval -eq $checks.Count) { 'Not evaluated' } elseif ($notEval) { 'No findings (partly evaluated)' } else { 'No findings' }
            $rows.Add([PSCustomObject]@{
                    Framework = $fw; Control = $c; Title = $script:ComplianceFrameworks[$fw].Controls[$c].Title
                    Checks = $checks.Count; NotEvaluated = $notEval; Triggered = @($hits | ForEach-Object { $_.Type } | Select-Object -Unique).Count
                    Findings = $hits.Count; Worst = $worst; Status = $status
                })
        }
    }
    return $rows.ToArray()
}

function ConvertTo-ComplianceHtml {
    param($Catalog, $Findings, $NotEvaluated)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $rows = Get-ComplianceCoverage -Catalog $Catalog -Findings $Findings -NotEvaluated $NotEvaluated
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<details><summary><h2>Regulatory mapping</h2></summary>')
    [void]$sb.AppendLine('<blockquote>Which controls the checks of this report give evidence for. The mapping covers the technical, directory-side part of each control: a row with no findings is evidence for that part, not compliance with the control. Policies, processes, people and other systems are outside a directory snapshot.</blockquote>')
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        $def = $script:ComplianceFrameworks[$fw]
        [void]$sb.AppendLine("<h3>$(& $H $def.Name)</h3><p class=`"meta`">$(& $H $def.Note)</p>")
        [void]$sb.AppendLine('<div class="table-wrap"><table><tr><th>Control</th><th>Requirement</th><th>Checks</th><th>Not evaluated</th><th>Checks triggered</th><th>Findings</th><th>Worst</th><th>Status</th></tr>')
        foreach ($r in @($rows | Where-Object { $_.Framework -eq $fw })) {
            $worst = if ($r.Worst) { Get-SevPill $r.Worst } else { '' }
            [void]$sb.AppendLine("<tr class=`"data-row`"><td><b>$(& $H $r.Control)</b></td><td>$(& $H $r.Title)</td><td>$($r.Checks)</td><td>$($r.NotEvaluated)</td><td>$($r.Triggered)</td><td>$($r.Findings)</td><td>$worst</td><td>$(& $H $r.Status)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div>')
    }
    [void]$sb.AppendLine('<p class="meta">Each check lists its controls under "Findings by check"; the CSV and the JSON Lines carry them in the Controls / controls field.</p></details>')
    return $sb.ToString()
}

$script:BenchmarkCache = $null

# check -> @('CIS M365 5.1.2.2', 'STIG AD V-243478'), built once.
function Get-BenchmarkIndex {
    if ($null -ne $script:BenchmarkCache) { return $script:BenchmarkCache }
    $idx = @{}
    foreach ($b in $script:Benchmarks.Keys) {
        $items = $script:Benchmarks[$b].Items
        foreach ($i in $items.Keys) {
            foreach ($c in @($items[$i].Checks | Where-Object { $_ })) {
                if (-not $idx.ContainsKey($c)) { $idx[$c] = New-Object System.Collections.Generic.List[string] }
                if (-not $idx[$c].Contains("$b $i")) { $idx[$c].Add("$b $i") }
            }
        }
    }
    $script:BenchmarkCache = $idx
    return $idx
}

function Get-CheckBenchmarks {
    param([string]$Type)
    $idx = Get-BenchmarkIndex
    if ($idx.ContainsKey($Type)) { return , [string[]]$idx[$Type].ToArray() }
    return , [string[]]@()
}

# Same list, grouped for reading: "CIS M365 5.1.5.4, 5.1.5.5; STIG AD V-243478".
function Format-CheckBenchmarks {
    param([string]$Type)
    $all = Get-CheckBenchmarks $Type
    $parts = @()
    foreach ($b in $script:Benchmarks.Keys) {
        $ids = @($all | Where-Object { $_.StartsWith("$b ") } | ForEach-Object { $_.Substring($b.Length + 1) })
        if ($ids.Count) { $parts += "$b $($ids -join ', ')" }
    }
    return ($parts -join '; ')
}

# One row per benchmark item of this snapshot kind: what measures it and what was found.
function Get-BenchmarkCoverage {
    param($Catalog, $Findings, $NotEvaluated, [string]$Kind = 'ad')
    $ne = @{}; foreach ($n in @($NotEvaluated | Where-Object { $_ })) { $ne["$($n.Type)"] = $true }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($b in $script:Benchmarks.Keys) {
        if ("$($script:Benchmarks[$b].Kind)" -ne $Kind) { continue }
        $items = $script:Benchmarks[$b].Items
        foreach ($i in $items.Keys) {
            $item = $items[$i]
            # Only checks this report's catalog holds: an id that is not there must not count as covered.
            $checks = @(@($item.Checks | Where-Object { $_ }) | Where-Object { $Catalog.Contains($_) })
            $hits = @($Findings | Where-Object { $checks -contains $_.Type })
            $worst = ''
            foreach ($s in 'Critical', 'High', 'Medium', 'Low') { if (@($hits | Where-Object { $_.Severity -eq $s }).Count) { $worst = $s; break } }
            $notEval = @($checks | Where-Object { $ne.ContainsKey($_) }).Count
            $status = if ($hits.Count) { 'Gaps found' } elseif ($checks.Count -eq 0) { 'No check' } elseif ($notEval -eq $checks.Count) { 'Not evaluated' } elseif ($notEval) { 'No findings (partly evaluated)' } else { 'No findings' }
            $rows.Add([PSCustomObject]@{
                    Benchmark = $b; Item = $i; Level = "$($item.Level)"; Title = "$($item.Title)"
                    Checks = $checks; NotEvaluated = $notEval; Findings = $hits.Count; Worst = $worst
                    Status = $status; Note = "$($item.Note)"
                })
        }
    }
    return $rows.ToArray()
}

function ConvertTo-BenchmarkHtml {
    param($Catalog, $Findings, $NotEvaluated, [string]$Kind = 'ad')
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $rows = @(Get-BenchmarkCoverage -Catalog $Catalog -Findings $Findings -NotEvaluated $NotEvaluated -Kind $Kind)
    if ($rows.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<details><summary><h2>Benchmarks (CIS, DISA STIG)</h2></summary>')
    [void]$sb.AppendLine('<blockquote>Which benchmark items this report measures, one row each. The list is partial on purpose: an item with no check says why. A row with no findings is evidence for the part a directory snapshot can see, not a passed audit, and IDWolf never turns a benchmark into a score.</blockquote>')
    foreach ($b in $script:Benchmarks.Keys) {
        $br = @($rows | Where-Object { $_.Benchmark -eq $b })
        if ($br.Count -eq 0) { continue }
        $covered = @($br | Where-Object { @($_.Checks).Count -gt 0 }).Count
        [void]$sb.AppendLine("<h3>$(& $H $script:Benchmarks[$b].Name)</h3><p class=`"meta`">$(& $H $script:Benchmarks[$b].Note) Measured here: $covered of $($br.Count) items.</p>")
        [void]$sb.AppendLine('<div class="table-wrap"><table><tr><th>Item</th><th>Level</th><th>Requirement</th><th>Checks</th><th>Not evaluated</th><th>Findings</th><th>Worst</th><th>Status</th></tr>')
        foreach ($r in $br) {
            $worst = if ($r.Worst) { Get-SevPill $r.Worst } else { '' }
            $req = & $H $r.Title
            if ($r.Note) { $req += "<br><span class=`"meta`">$(& $H $r.Note)</span>" }
            $checkText = if (@($r.Checks).Count) { (@($r.Checks) | ForEach-Object { "<code>$(& $H $_)</code>" }) -join ', ' } else { '<span class="meta">none</span>' }
            [void]$sb.AppendLine("<tr class=`"data-row`"><td><b>$(& $H $r.Item)</b></td><td>$(& $H $r.Level)</td><td>$req</td><td>$checkText</td><td>$($r.NotEvaluated)</td><td>$($r.Findings)</td><td>$worst</td><td>$(& $H $r.Status)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div>')
    }
    [void]$sb.AppendLine('<p class="meta">Each check lists its items under "Findings by check"; the CSV and the JSON Lines carry them in the Benchmarks / benchmarks field.</p></details>')
    return $sb.ToString()
}
