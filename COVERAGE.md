# What IDWolf covers

How IDWolf's checks line up against the references people actually use to
judge an AD or Entra audit. One place, kept in sync with the code: every check
named here exists in the catalog (167 AD, 88 Entra).

**Legend**
- **Yes**: detected directly.
- **Deep**: needs a `-Deep` collection.
- **PQ**: needs the hashless password-quality report (`-PasswordQualityFile`).
- **GPO**: read from the GPO templates in SYSVOL. A value set by hand on a DC is not visible.
- **Partial**: covered in part (the table says which part).
- **Planned**: doable from a read-only snapshot, not written yet.
- **Manual**: the setting isn't exposed through any API, so it has to be checked in the portal (CIS marks most of these as manual too).
- **Live**: read over CIM at collection time, on the DCs (services, network adapters, OS build) or on the CA hosts (CA registry, installed roles). Needs admin rights on each of those servers; otherwise not evaluated, and only partly evaluated when some DCs refuse.
- **Out**: not something a read-only snapshot can see (patch level, live host or network state), apart from the Live items above.

## Active Directory

### InfosecMatter Top 16 AD vulnerabilities

| # | Issue | IDWolf |
|---|---|---|
| 1 | Users can add computers to the domain | Yes `machine_account_quota` |
| 2 | adminCount left on normal users | Yes `orphaned_admincount` |
| 3 | Too many users in privileged groups | Yes `privileged_group_oversized` |
| 4 | Service accounts in Domain Admins | Yes `privileged_kerberoastable` |
| 5 | Shadow admins (ACL escalation) | Yes / Deep `dangerous_ace_tier0`, `dangerous_ace_anywhere` |
| 6 | Kerberoastable accounts | Yes `kerberoastable_user` |
| 7 | Passwords that never expire | Yes `password_never_expires`, `privileged_password_never_expires` |
| 8 | Password not required | Yes `password_not_required` |
| 9 | Reversible encryption | Yes `reversible_encryption_account`, `reversible_encryption_policy` |
| 10 | LM hashes stored | GPO `lm_hash_stored` |
| 11 | AS-REP roasting | Yes `asrep_roastable` |
| 12 | Weak domain password policy | Yes `password_policy_*`, `fgpp_weak` |
| 13 | Inactive accounts | Yes `inactive_user`, `stale_computer`, `privileged_inactive` |
| 14 | Admin passwords not rotated | Yes `privileged_password_old` |
| 15 | Weak passwords | PQ `pwq_breached_password`, `pwq_duplicate_passwords` |
| 16 | Credentials in SYSVOL / GPP | Yes `gpp_cpassword`, `sysvol_script_secrets` |

All 16 covered.

### CIS benchmarks (Windows Server, domain controller profile)

CIS has no "Active Directory" benchmark of its own. The DC profile of the
Windows Server benchmark is mostly GPO hardening, which IDWolf reads from SYSVOL.

| CIS area | IDWolf |
|---|---|
| Password and lockout policy | Yes `password_policy_*`, `fgpp_weak` |
| SMB signing, SMBv1 | GPO `smb_signing_not_required`, `smb_client_signing_not_required`, `smb1_server_enabled` |
| LDAP signing and channel binding | GPO `ldap_signing_not_required`, `ldap_channel_binding_off` |
| LM hash, NTLM level | GPO `lm_hash_stored`, `ntlm_weak_lmcompat` |
| Anonymous access | GPO `anonymous_sam_enum`; Yes `anonymous_ldap_enabled`, `pre_win2000_anonymous` |
| Sensitive user rights (SeDebug, SeBackup...) | GPO `dangerous_privilege_right` |
| Advanced audit policy, command line, PowerShell logging | GPO `audit_policy_insufficient`, `audit_advanced_policy_missing`, `cmdline_audit_not_enabled`, `powershell_logging_not_enabled` |
| Credential protection (WDigest, LSA PPL, cached logons) | GPO `wdigest_cleartext`, `lsass_not_protected`, `cached_credentials` |
| Kerberos encryption types, armoring | GPO `kerberos_rc4_allowed`, `kerberos_armoring_not_enforced` |
| Netlogon secure channel, Print Spooler, WebClient, LLMNR, mDNS, UNC hardening | GPO `netlogon_vulnerable_channel`, `spooler_on_dc`, `webclient_not_disabled`, Live `webclient_on_dc`, `llmnr_enabled`, `mdns_enabled`, `unc_hardening_disabled` |
| Firewall, Defender, TLS versions, BitLocker | Out (host build state) |

### PingCastle rules

PingCastle scores rules; IDWolf reports objects, so this maps by coverage, not
by score. Rule list: pingcastle.com, engine 3.3.

| Area | Rules | IDWolf |
|---|---|---|
| Stale objects | S-Inactive, S-C-Inactive, S-PwdLastSet-DC, S-PrimaryGroup, S-Reversible, S-NoPreAuth(Admin), S-PwdNotRequired, S-PwdNeverExpires, S-SIDHistory, S-DesEnabled, S-AesNotEnabled, S-FunctionalLevel*, S-DC-20xx, S-OS-*, S-DC-SubnetMissing | Yes |
| | S-SMB-v1, S-OldNtlm, S-KerberosArmoring | GPO |
| | S-Duplicate | PQ |
| | S-PwdLastSet-45/90 | Partial `stale_computer` (inactivity, not the 45/90-day split) |
| | S-Vuln-MS14-068, MS17-010 | Out (patch level) |
| | S-DC-NotUpdated | Partial: Live `nopac_unpatched_dc` checks only the November 2021 fix; general patch age Out |
| | S-JavaSchema | Yes `schema_java_objects` |
| | S-ADRegistrationSchema | Yes `schema_class_poss_superior` |
| Anomalies | A-AdminCount, A-PreWin2000*, A-DsHeuristicsAnonymous, A-LAPS-Not-Installed, A-Krbtgt, A-NTFRSOnSysvol, A-ReversiblePwd, A-UnixPwd, A-MinPwdLen | Yes |
| | A-CertTemp* (ESC1-4, ESC9), ESC10, ESC13, ESC15, A-WeakRSARootCert2 | Yes `adcs_*` |
| | A-CertEnrollHttp / ChannelBinding (ESC8) | Live `adcs_esc8` (web enrollment installed; HTTPS and EPA in IIS are not read) |
| | A-DCLdapSign, A-DCLdapsChannelBinding, A-SMB-Signing, A-Audit*, A-HardenedPaths | GPO |
| | A-DnsZoneUpdate*, A-DnsZoneTransfer, A-DnsScavenging, wildcard / WPAD records | Yes `dns_*` (zone transfer needs DNS rights, see README) |
| | A-DnsZoneAUCreateChild | Yes `dns_zone_create_child` |
| | A-SmartCardPwdRotation | Yes `smartcard_password_not_rotated` |
| Privileged | P-Delegated, P-Kerberoasting, P-ServiceDomainAdmin, P-AdminPwdTooOld, P-AdminLogin, P-SchemaAdmin, P-DNSAdmin, P-OperatorsEmpty, P-ProtectedUsers, P-RecycleBin, P-AdminNum, P-RODCAdminRevealed, P-AuthPolicySilo | Yes |
| | P-ControlPathIndirect*, P-DelegationEveryone, P-DelegationGPO, P-UnprotectedOU | Yes / Deep `dcsync_rights`, `dangerous_ace_*`, `gpo_dangerous_acl`, `shadow_credentials_present`, `gmsa_password_readable` |
| | P-LogonDenied | Partial `dangerous_privilege_right` |
| | P-RODCRevealOnDemand, P-RODCNeverReveal, P-RODCDeniedGroup | Yes `rodc_prp_too_broad`, `rodc_tier0_unprotected` (P-RODCAdminRevealed: `rodc_tier0_revealed`) |
| Trusts | T-SIDFiltering, T-SIDHistory, T-TGTDelegation, T-AesNotEnabled, T-SelectiveAuth, T-DownLevel | Yes `trust_*` (T-Inactive: `trust_inactive`), `sid_history` |

### Attack techniques seen in recent incidents

| Technique | IDWolf |
|---|---|
| Kerberoasting, AS-REP roasting | Yes `kerberoastable_user`, `privileged_kerberoastable`, `spn_account_rc4`, `asrep_roastable` |
| DCSync | Yes `dcsync_rights` |
| Delegation abuse (unconstrained, constrained, RBCD, SPN-jacking) | Yes `unconstrained_delegation`, `constrained_delegation*`, `rbcd_configured`, `delegation_orphan_spn`, `privileged_account_delegable` |
| AD CS ESC1-5, 9, 10, 13, 15 | Yes `adcs_esc*` (ESC10 GPO) |
| AD CS ESC6, 7, 8, 11, 16 | Live `adcs_esc6`, `adcs_esc7`, `adcs_esc8`, `adcs_esc11`, `adcs_esc16` (read on the CA host); `adcs_manual_checks` for a CA that could not be read |
| Shadow Credentials | Yes `shadow_credentials_present` |
| ReadGMSAPassword, LAPS password readers, SyncLAPSPassword, Golden gMSA / dMSA | Yes `gmsa_password_readable`, `sync_laps_rights`; Deep `laps_readers`, `kds_root_key_readable` |
| BadSuccessor (dMSA successor link, CVE-2025-53779) | Yes `badsuccessor_dmsa_create`, only with a Windows Server 2025 DC; its Live update revision sets the severity |
| RODC credential theft (RODC golden ticket, Kerberos key list) | Yes `rodc_tier0_revealed`, `rodc_prp_too_broad`, `rodc_tier0_unprotected`, `rodc_krbtgt_password_old` |
| PrintNightmare | GPO `point_and_print_unsafe` (the Point and Print downgrade), `spooler_on_dc`; patch level Out |
| GPO takeover | Yes `gpo_dangerous_acl` |
| Pre-created computer accounts | Yes `precreated_computer_account` |
| Coercion + NTLM relay (PetitPotam, PrinterBug, DFSCoerce, MS-EVEN) | Live `coercion_unfiltered_dc` (services behind MS-EFSR, MS-DFSNM, MS-EVEN and the RPC filters, with the open relay targets; interfaces are not probed); preconditions (`smb_signing_*`, `ldap_signing_not_required`, `ldap_channel_binding_off`, `spooler_on_dc`, `webclient_not_disabled`, Live `webclient_on_dc`, `unconstrained_delegation`) |
| ZeroLogon | GPO `netlogon_vulnerable_channel` (patch level itself is Out) |
| Password spraying | Yes `password_policy_no_lockout`; PQ `pwq_*` |
| LLMNR / mDNS / NBT-NS / WPAD poisoning | GPO `llmnr_enabled`, `mdns_enabled`; Live `nbtns_enabled_dc`; Yes `dns_dangerous_record`, `dns_zone_create_child` |
| noPac (CVE-2021-42278/42287) | Live `nopac_unpatched_dc` (build and update revision), with `machine_account_quota` setting the severity |
| Certifried (CVE-2022-26923) | Partial `machine_account_quota`; patch level Out |
| Timeroasting | Partial `precreated_computer_account` (pre-created computers with a predictable password); the attack itself Out |
| AD CS ESC5 (access to PKI objects), ESC14 (weak explicit certificate mappings) | Yes `adcs_esc5`, `altsecid_weak_mapping`; write access to `altSecurityIdentities` is a dangerous ACE |
| Exchange privileges (PrivExchange, Exchange Windows Permissions) | Yes `dangerous_ace_tier0` (WriteDacl on the domain head or on Tier 0 groups, as for any non-Tier 0 principal) |
| SID history abuse, cross-forest trust tickets | Yes `sid_history`, `trust_sid_filtering_disabled`, `trust_tgt_delegation`, `trust_no_selective_auth`, `trust_rc4` |
| Golden / Silver Ticket | Yes `krbtgt_password_old`, `dc_password_old`; the forging itself Out |
| Local admin password reuse | Partial `laps_not_deployed`, `laps_missing` (the condition, not the reuse) |
| Writable shares | Yes `sysvol_writable` (NETLOGON and SYSVOL Policies); Partial `gpo_runs_code_from_share`; other shares Out (they need a connection to every machine) |
| MSSQL, DCOM, RDP and WinRM rights, sessions on each host | Out (a live connection to every host); accounts with MSSQLSvc SPNs are covered by the Kerberoasting checks |
| LSASS / SAM / DPAPI dumping, Skeleton Key, custom SSP, local privilege escalation | Out (attacks, or a DC's memory and local registry); mitigations `lsass_not_protected`, `wdigest_cleartext`, `cached_credentials` |
| Pass-the-hash / ticket | Out |

### DC health

The DC health checks that fit a read-only snapshot taken from a workstation:

| Health check | IDWolf |
|---|---|
| Replication failures and delays | Yes `replication_failures`, `replication_stale` |
| FSMO role holders | Yes `fsmo_holder_invalid` (role held by a server that is no longer a DC) |
| DC reachable | Yes `dc_unreachable` (LDAP through ADWS from the collecting machine) |
| Time offset | Yes `dc_time_skew` (spread between DCs, via `w32tm`, so the collector's own clock doesn't matter) |
| Free disk space | Yes `dc_low_disk` (CIM, needs admin rights on the DCs) |
| Critical services running | Yes `dc_service_stopped` (CIM, needs admin rights on the DCs) |
| Last backup | Yes `ad_backup_overdue` |
| `dcdiag` | Not used: its output is translated (Italian, German...) and too fragile to parse reliably |
| Uptime, NTDS.dit size, DNS client settings of the DC | Not used: little security value, or needs remote registry |

## Microsoft Entra ID

### CIS Microsoft 365 Foundations Benchmark v7.0.0

This is the CIS benchmark for Entra: section 5 is the Microsoft Entra admin
center, section 1 holds the admin accounts. IDs, titles and profiles come from
v7.0.0 (as published on hub.prowler.com). E5 marks controls that need an
E5 / Entra ID P2 licence.

Section 1 is mostly about Microsoft 365 workloads (Exchange shared mailboxes,
calendars, Forms, Bookings, Sway, add-ins, Customer Lockbox): 1.2.x and
1.3.3-1.3.9 are out of scope for an identity tool. The identity-related part:

| CIS | Level | Recommendation | IDWolf |
|---|---|---|---|
| 1.1.1 | L1 | Administrative accounts are cloud-only | Yes `entra_admin_synced_from_onprem` |
| 1.1.2 | L1 | Two emergency access accounts defined | Yes `entra_no_emergency_access` (accounts excluded from every CA policy), `entra_global_admins_too_few` |
| 1.1.3 | L1 | Between two and four Global Admins | Yes `entra_global_admins_too_few`, `entra_global_admins_excessive` (threshold 4, as CIS) |
| 1.1.4 | L1 | Admin accounts use licences with a reduced application footprint | Yes `entra_admin_licensed` |
| 1.3.1 | L1 | Password expiration policy: never expire | Yes `entra_password_expiry_set` |
| 1.3.2 | L2 | Idle session timeout for unmanaged devices | Yes `entra_idle_timeout_missing` |

Section 5:

| CIS | Level | Recommendation | IDWolf |
|---|---|---|---|
| 5.1.2.1 | L1 | Per-user MFA disabled (use Conditional Access) | Partial `entra_per_user_mfa_admins` (admin accounts only: one Graph call per user) |
| 5.1.2.2 | L1 | Third-party integrated applications not allowed | Yes `entra_users_can_register_apps` |
| 5.1.2.3 | L1 | Non-admin users cannot create tenants | Yes `entra_users_can_create_tenants` |
| 5.1.2.4 | L1 | Access to the Entra admin center restricted | Manual (no Graph API for this setting) |
| 5.1.2.5 | L2 | "Stay signed in" option hidden | Yes `entra_kmsi_shown` |
| 5.1.2.6 | L2 | LinkedIn account connections disabled | Manual (no Graph API for this setting) |
| 5.1.3.1 | L1 | Users cannot create security groups | Yes `entra_users_can_create_security_groups` |
| 5.1.3.2 | L2 | Users can't use the My Groups features | Manual (no Graph API for this setting) |
| 5.1.3.3 | L1 | Owners can't manage membership requests in My Groups | Manual (no Graph API for this setting) |
| 5.1.3.4 | L2 | Users cannot create Microsoft 365 groups | Yes `entra_users_can_create_m365_groups` |
| 5.1.4.1 | L2 | Device join restricted to selected users | Yes `entra_device_join_unrestricted` |
| 5.1.4.2 | L1 | Maximum devices per user limited | Yes `entra_device_quota_high` |
| 5.1.4.3 | L1 | Global Admins not added as local admins on join | Yes `entra_device_join_ga_local_admin` |
| 5.1.4.4 | L1 | Registering user not added as local admin | Yes `entra_device_join_user_local_admin` |
| 5.1.4.5 | L1 | LAPS enabled for Entra-joined devices | Yes `entra_device_laps_off` |
| 5.1.4.6 | L2 | Users can't recover their own BitLocker keys | Yes `entra_users_read_bitlocker_keys` |
| 5.1.5.1 | L2 | User consent to apps not allowed | Yes `entra_user_consent_allowed` |
| 5.1.5.2 | L1 | Admin consent workflow enabled | Yes `entra_users_can_consent` |
| 5.1.5.3 | L2 | Password (secret) addition blocked for applications | Yes `entra_app_management_policy_weak` |
| 5.1.5.4 | L1 | Application secret lifetime 180 days or less | Yes `entra_app_management_policy_weak` (tenant policy), `entra_app_secret_long_lived` (secrets already there) |
| 5.1.5.5 | L1 | New application secrets are system-generated | Yes `entra_app_management_policy_weak` |
| 5.1.5.6 | L1 | Application certificate lifetime 180 days or less | Yes `entra_app_management_policy_weak` |
| 5.1.6.1 | L2 | Guest invitations only to allowed domains | Manual (no supported Graph v1.0 API for the domain allow list) |
| 5.1.6.2 | L1 | Guest user access restricted | Yes `entra_guest_access_not_restricted` |
| 5.1.6.3 | L2 | Only admins can invite guests | Yes `entra_guest_invite_open` |
| 5.1.8.1 | L1 | Password hash sync enabled (hybrid) | Yes `entra_password_hash_sync_off` |
| 5.2.2.1 | L1 | MFA for admin roles | Yes `entra_no_ca_mfa_admins`, `entra_admins_without_mfa` |
| 5.2.2.2 | L1 | MFA for all users | Yes `entra_security_defaults_off` |
| 5.2.2.3 | L1 | Legacy authentication blocked | Yes `entra_legacy_auth_allowed` |
| 5.2.2.4 | L1 | Sign-in frequency and non-persistent browser for admins | Yes `entra_admin_sign_in_frequency` (frequency and non-persistent browser) |
| 5.2.2.5 | L2 | Phishing-resistant MFA strength for admins | Yes `entra_no_phishing_resistant_admins` |
| 5.2.2.6 | E5 L1 | User risk policy | Yes `entra_risk_policies_missing` |
| 5.2.2.7 | E5 L1 | Sign-in risk policy | Yes `entra_risk_policies_missing` |
| 5.2.2.8 | E5 L2 | Medium and high sign-in risk blocked | Yes `entra_sign_in_risk_not_blocked` |
| 5.2.2.9 | L1 | Managed device required for authentication | Yes `entra_no_managed_device` |
| 5.2.2.10 | L1 | Managed device required to register security info | Yes `entra_security_info_registration` |
| 5.2.2.11 | L1 | Sign-in frequency "every time" for Intune enrollment | Yes `entra_intune_enrollment_reauth` |
| 5.2.2.12 | L1 | Device code flow blocked | Yes `entra_device_code_flow_allowed` |
| 5.2.2.13 | L1 | Periodic reauthentication for all users | Yes `entra_no_periodic_reauth` |
| 5.2.2.14 | L2 | Trusted named locations defined | Yes `entra_no_trusted_locations` |
| 5.2.2.15 | L2 | Geographic access restrictions in use | Yes `entra_no_geo_restriction` |
| 5.2.2.16 | L2 | Token protection enforced | Yes `entra_token_protection_off` |
| 5.2.2.17 | L1 | Authentication transfer blocked | Yes `entra_auth_transfer_allowed` |
| 5.2.3.1 | L1 | Authenticator shows app name and location (MFA fatigue) | Yes `entra_authenticator_context_off` |
| 5.2.3.2 | L1 | Custom banned passwords in use | Yes `entra_banned_passwords_off` |
| 5.2.3.3 | L1 | Password protection enabled on-premises | Out (agent on the DCs) |
| 5.2.3.4 | L1 | All member users MFA capable | Yes `entra_users_not_mfa_capable` |
| 5.2.3.5 | L1 | SMS and voice call disabled | Yes `entra_weak_auth_methods` |
| 5.2.3.6 | L1 | System-preferred MFA enabled | Yes `entra_system_preferred_mfa_off` |
| 5.2.3.7 | L2 | Email OTP disabled | Yes `entra_weak_auth_methods` |
| 5.2.3.8 | L1 | Lockout threshold 10 or less | Yes `entra_smart_lockout_weak` |
| 5.2.3.9 | L1 | Lockout duration at least 60 seconds | Yes `entra_smart_lockout_weak` |
| 5.2.3.10 | L1 | Authenticator Lite (companion apps) disabled | Yes `entra_authenticator_lite_on` |
| 5.2.4.1-5 | L1/L2 | Self-service password reset: enabled for all, two methods, re-registration, user and admin notifications | Manual (Graph doesn't expose the SSPR settings) |
| 5.3.1 | E5 L2 | PIM manages privileged roles | Yes `entra_pim_not_used` |
| 5.3.2 | E5 L1 | Access reviews for guest users | Yes `entra_no_guest_access_review` |
| 5.3.3 | E5 L1 | Access reviews for privileged roles | Yes `entra_no_admin_access_review` |
| 5.3.4 | E5 L1 | Approval required for Global Admin activation | Yes `entra_pim_activation_no_approval` |
| 5.3.5 | E5 L1 | Approval required for Privileged Role Admin activation | Yes `entra_pim_activation_no_approval` |

Rows in these two tables: 58 covered (57 fully, 1 in part), 6 manual (no Graph API), 0 planned, 1 out of scope (5.2.4.1-5 counted as one row).

### Beyond CIS: PingCastle 4.0 and non-human identities

PingCastle 4.0 (August 2026) announced 102 Entra ID checks, but the list isn't
public: its open-source repository holds only six cloud rules (Entra Connect
version, guest access restriction, user consent, app registration), and the
documentation doesn't enumerate the rest. So this is a comparison by the themes
Netwrix announced, not rule by rule.

| Theme | IDWolf |
|---|---|
| Missing MFA, weak methods | Yes `entra_admins_without_mfa`, `entra_users_not_mfa_capable`, `entra_admin_no_phishing_resistant_method`, `entra_weak_auth_methods` |
| Excessive or standing admin roles | Yes `entra_global_admins_excessive`, `entra_pim_not_used`, `entra_sp_in_admin_role`, `entra_admin_inactive`, `entra_admin_password_old` |
| Unsafe app consent grants | Yes `entra_risky_delegated_grant`, `entra_user_consent_allowed`, `entra_users_can_consent` |
| Conditional Access gaps | Yes (the 5.2.2.x rows above) |
| Non-human identities: app owners, credentials, permissions | Yes `entra_privileged_app_owner`, `entra_first_party_sp_credentials`, `entra_app_high_privilege`, `entra_app_insecure_redirect`, `entra_app_secret_long_lived` |
| Hybrid: sync and federation | Yes `entra_sync_stale`, `entra_password_hash_sync_off`, `entra_federated_domain`, `entra_admin_synced_from_onprem` |
| Cross-tenant trust | Yes `entra_cross_tenant_mfa_trust`, `entra_b2b_direct_connect_open` |
| Workload identities | Yes `entra_no_workload_identity_ca` |
| Intune RBAC: roles that push scripts, apps or configuration to devices, or change Intune roles | Yes `entra_intune_role_weak_group` (given through a group that is not role-assignable or is dynamic). Not yet verified on a real tenant: the action names are matched from documentation |
| Intune Multi Admin Approval for device wipes and scripts | Yes `entra_intune_no_multi_admin_approval`. Not yet verified on a real tenant: the policy types are matched from documentation |
| Indirect paths to admin roles: owners, exclusions, scoped admins, look-alikes | Yes `entra_privileged_group_owner`, `entra_privileged_app_sp_owner`, `entra_privileged_app_inactive`, `entra_app_instance_lock_off`, `entra_connect_app_extra_credentials`, `entra_sp_lookalike_name`, `entra_ca_excluded_group_weak`, `entra_scoped_admin_outside_ca`, `entra_app_scoped_admin_privileged`, `entra_pim_role_settings_weak`, `entra_access_package_grants_admin` |
| Guest access restriction (public rule) | Yes `entra_guest_access_not_restricted` |
| Entra Connect version (public rule) | Not available through Graph; `entra_sync_stale` covers a stopped sync instead |
| AI agent identities | Planned (the Graph API for Entra agent identities is still in preview) |

### Microsoft guidance

Source: Microsoft Learn "Best practices to secure with Microsoft Entra ID".

| Practice | IDWolf |
|---|---|
| Strong / phishing-resistant MFA for everyone, admins first | Yes `entra_security_defaults_off`, `entra_no_ca_mfa_admins`, `entra_admins_without_mfa`, `entra_no_phishing_resistant_admins` |
| Block legacy authentication | Yes `entra_legacy_auth_allowed` |
| Risk-based Conditional Access | Yes `entra_risk_policies_missing` |
| No standing admin access (PIM, just in time, approval for the top roles) | Yes `entra_pim_not_used`, `entra_pim_activation_no_approval` |
| Few admins, at least two, cloud-only, no mailbox, still in use | Yes `entra_global_admins_*`, `entra_admin_synced_from_onprem`, `entra_admin_licensed`, `entra_admin_inactive` |
| Emergency access accounts | Yes `entra_no_emergency_access` (excluded from every CA policy; their FIDO2 keys and alerting still need a manual look) |
| Guests out of admin roles, stale guests removed | Yes `entra_privileged_guest`, `entra_stale_guest` |
| Devices: who can join, no local admin rights, LAPS | Yes `entra_device_*`, `entra_users_read_bitlocker_keys` |
| Session and token theft: managed devices, token protection, sign-in frequency | Yes `entra_no_managed_device`, `entra_token_protection_off`, `entra_no_periodic_reauth`, `entra_admin_sign_in_frequency` |
| Restrict app consent and app registration | Yes `entra_user_consent_allowed`, `entra_users_can_consent`, `entra_users_can_register_apps` |
| Service principals: least privilege, certificates over secrets | Yes `entra_app_high_privilege`, `entra_app_management_policy_weak`, `entra_app_secret_long_lived`, `entra_app_credential_expiring` |
| Banned passwords, smart lockout | Yes `entra_banned_passwords_off`, `entra_smart_lockout_weak` |
| External collaboration hardening | Yes `entra_guest_invite_open`, `entra_guest_access_not_restricted`, `entra_cross_tenant_mfa_trust`, `entra_b2b_direct_connect_open` (the guest domain allow list stays manual, see 5.1.6.1) |
| Access reviews | Yes `entra_no_guest_access_review`, `entra_no_admin_access_review` |
| Entitlement management | Yes `entra_access_package_external_no_approval`, `entra_access_package_no_expiry` |
| Workload identity Conditional Access | Yes `entra_no_workload_identity_ca` (apps registered in this tenant only: Conditional Access can't target others) |
| Sign-in / audit log retention, SIEM streaming, alerts | Out (operations, and Azure diagnostic settings need Azure RBAC rather than Graph) |

## Recent attacks, 2023-2026

The attack vectors behind the most cited incidents and research of the last
three years, and what IDWolf checks for each. IDWolf audits configuration, so it
looks for the condition an attack needs, not for the attack itself. Reviewed in
October 2026.

| Attack | When | IDWolf |
|---|---|---|
| **BadSuccessor**: a delegated managed service account (dMSA) made the successor of any account, Windows Server 2025 (Akamai; CVE-2025-53779) | 2025 | Yes `badsuccessor_dmsa_create` (who can create dMSAs in an OU or container), with Live build and update revision of the 2025 DCs setting the severity |
| **Golden dMSA / Golden gMSA**: every managed service account password computed from the KDS root key (Semperis) | 2025 | Deep `kds_root_key_readable` |
| Coercion + NTLM relay to LDAP or AD CS, still the most common path to domain admin (CVE-2025-24054 exploited days after the patch) | 2025-26 | Live `coercion_unfiltered_dc`, `webclient_on_dc`; Yes `adcs_esc8`, `adcs_esc11`, `ldap_signing_not_required`, `ldap_channel_binding_off`; GPO `ntlm_weak_lmcompat`, `webclient_not_disabled` |
| NTLM reflection over SMB (CVE-2025-33073) | 2025 | Partial GPO `smb_signing_not_required`, `smb_client_signing_not_required` (SMB signing is the mitigation); patch level Out |
| AD CS ESC15 (EKUwu, CVE-2024-49019) and ESC16 | 2024-25 | Yes `adcs_esc15`; Live `adcs_esc16` |
| Kerberoasting in ransomware intrusions (Interlock, 2026) | 2026 | Yes `kerberoastable_user`, `privileged_kerberoastable`, `spn_account_rc4` |
| Shadow Credentials | ongoing | Yes `shadow_credentials_present`; Deep `dangerous_ace_anywhere` (write access to `msDS-KeyCredentialLink`) |
| Entra Connect server and sync account as a way into the cloud (Mollema, Black Hat 2025) | 2025 | Partial `entra_connect_app_extra_credentials`, `dcsync_rights` (the sync account is flagged as a Tier 0 credential), `entra_admin_synced_from_onprem` |
| SyncJacking: hard match takes over a synced cloud account (Semperis) | 2025-26 | Partial `entra_admin_synced_from_onprem` (synced admins are what makes it worth doing); Microsoft blocks the re-match in the service since mid-2026 |
| Password spraying, over 99% of observed cloud initial access (Microsoft Digital Defense Report 2026) | 2025-26 | Yes `entra_smart_lockout_weak`, `entra_banned_passwords_off`, `entra_legacy_auth_allowed`, `entra_admins_without_mfa`, `entra_users_not_mfa_capable`; on premises `password_policy_no_lockout`, PQ `pwq_*` |
| Device code phishing (Storm-2372 and later kits) | 2025-26 | Yes `entra_device_code_flow_allowed` |
| Adversary-in-the-middle phishing and token theft | ongoing | Yes `entra_no_phishing_resistant_admins`, `entra_admin_no_phishing_resistant_method`, `entra_token_protection_off`, `entra_admin_sign_in_frequency` |
| OAuth consent phishing and over-privileged apps (Midnight Blizzard, 2024) | 2024-26 | Yes `entra_users_can_consent`, `entra_user_consent_allowed`, `entra_risky_delegated_grant`, `entra_app_high_privilege`, `entra_first_party_sp_credentials` |
| Escalation through service principal ownership (Entra Agent ID flaw, Silverfort) | 2026 | Yes `entra_privileged_app_sp_owner`, `entra_privileged_app_owner`, `entra_sp_in_admin_role` |
| Mass device wipe from a compromised Intune admin (Stryker, reported) | 2026 | Yes `entra_intune_no_multi_admin_approval`, `entra_intune_role_weak_group`. Neither has been verified on a real tenant yet |

Not covered yet:

| Attack | When | Why |
|---|---|---|
| SCCM / MECM misconfigurations (network access account, PXE, site takeover by relay) | 2023-26 | Planned for what AD shows (the System Management container and who can write to it); the rest needs the site server |
| AD CS ESC17: WSUS over HTTPS with a certificate from a weak template (TROOPERS26) | 2026 | Partial `wsus_http` covers WSUS over plain HTTP only |
| Apps still on Azure AD Graph (behind the Actor token flaw, CVE-2025-55241) | 2025 | Planned; the flaw itself was fixed by Microsoft |
| Storm-0558 key theft, CVE-2026-69836, OAuth client ID spoofing, help desk social engineering | 2023-26 | Out: flaws on Microsoft's side, detection rather than configuration, or a process problem |

## Regulations

IDWolf maps each check to the regulatory controls it gives evidence for. The
mapping lives in `lib/Compliance.ps1`. A check gets one or more themes from its
category and from words in its ID. Each control lists the themes that support
it. The regression suite checks that every AD and Entra check maps to all four
frameworks.

This is evidence for the **technical, directory-side part** of a control. A
control with no findings is not a control that is met. Policies, processes,
training, suppliers and every system outside AD and Entra are out of scope.
When none of a control's checks could be evaluated, the report says "Not
evaluated", and when no check covers it, it says "No check". Neither is ever
shown as clean.

| Theme | Typical checks |
|---|---|
| Authentication and credentials | `password_policy_*`, `pwq_*`, `kerberoastable_user`, `asrep_roastable`, `krbtgt_password_old`, `laps_*`, `password_in_description` |
| Multi-factor and strong authentication | `entra_admins_without_mfa`, `entra_no_ca_mfa_admins`, `entra_legacy_auth_allowed`, `entra_weak_auth_methods`, `entra_risk_policies_missing` |
| Privileged access | Privileged Access and Permissions categories, delegation, `adcs_esc*`, `rodc_*`, `entra_pim_*`, `entra_global_admins_*` |
| Identity lifecycle and access rights | Account Hygiene category, guests, `pre_win2000_anonymous`, `gpo_broad_local_group`, app consent and registration, access reviews |
| Secure configuration | Domain Configuration and Host Hardening categories, GPO checks, trusts, DNS |
| Unsupported software and known vulnerabilities | `obsolete_os`, `dc_obsolete_os`, `netlogon_vulnerable_channel`, `smb1_server_enabled`, `spooler_on_dc`, `point_and_print_unsafe`, `functional_level_outdated`, `nopac_unpatched_dc` |
| Cryptography | `*rc4*`, `des_enabled`, `lm_hash_stored`, `ntlm_weak_lmcompat`, `reversible_encryption_*`, signing and channel binding, `adcs_weak_ca_key` |
| Logging and monitoring | `audit_*`, `cmdline_audit_not_enabled`, `powershell_logging_not_enabled` |
| Backup, redundancy and availability | Operational Health category, `recycle_bin_disabled`, `single_dc`, `entra_no_emergency_access`, `entra_sync_stale` |
| Network security | SMB/LDAP signing, `coercion_unfiltered_dc`, `llmnr_enabled`, `mdns_enabled`, `nbtns_enabled_dc`, `webclient_*`, `anonymous_sam_enum`, `dns_*`, `unc_hardening_disabled`, `trust_*`, named locations, cross-tenant access |

### NIS2, Directive (EU) 2022/2555, Art. 21(2)

In Italy, Art. 24 of Legislative Decree 138/2024 transposes Art. 21.

| Point | Requirement | Themes |
|---|---|---|
| (b) | Incident handling | Logging |
| (c) | Business continuity, backup management, disaster recovery | Backup and availability |
| (e) | Security in maintenance, vulnerability handling | Vulnerabilities, configuration, network |
| (g) | Basic cyber hygiene | Configuration, identity lifecycle |
| (h) | Cryptography and encryption | Cryptography |
| (i) | Access control and asset management | Access rights, privileged access, authentication |
| (j) | Multi-factor or continuous authentication | MFA (Entra only: no AD check) |
| (a), (f) | Risk analysis; assessing the effectiveness of measures | Not per check: a scheduled run with `-CompareTo` is evidence for (f) |

### ISO/IEC 27001:2022, Annex A

| Control | Title | Themes |
|---|---|---|
| A.5.15 | Access control | Access rights, privileged access |
| A.5.16 | Identity management | Identity lifecycle |
| A.5.17 | Authentication information | Authentication |
| A.5.18 | Access rights | Access rights, privileged access |
| A.8.2 | Privileged access rights | Privileged access |
| A.8.5 | Secure authentication | Authentication, MFA |
| A.8.8 | Management of technical vulnerabilities | Vulnerabilities |
| A.8.9 | Configuration management | Configuration |
| A.8.13 | Information backup | Backup and availability |
| A.8.14 | Redundancy of information processing facilities | Backup and availability |
| A.8.15 | Logging | Logging |
| A.8.16 | Monitoring activities | Logging |
| A.8.20 | Networks security | Network |
| A.8.24 | Use of cryptography | Cryptography |

Periodic runs support the reviews of A.5.35 and A.5.36, but no single check does.

### DORA, Regulation (EU) 2022/2554

| Article | Requirement | Themes |
|---|---|---|
| 9(2) | ICT security policies and tools for resilience, integrity and confidentiality | Configuration |
| 9(4)(b) | Sound network and infrastructure management | Network, configuration |
| 9(4)(c) | Logical access limited to what is required | Access rights, privileged access |
| 9(4)(d) | Strong authentication, protection of cryptographic keys | Authentication, MFA, cryptography |
| 9(4)(f) | Patches and updates | Vulnerabilities |
| 10(1) | Detection of anomalous activities | Logging |
| 12(1) | Backup, restoration and recovery | Backup and availability |

The detailed access-control and authentication requirements are in the ICT
risk management RTS, Delegated Regulation (EU) 2024/1774. They are not mapped
article by article yet.

### GDPR, Regulation (EU) 2016/679, Art. 32(1)

| Point | Requirement | Themes |
|---|---|---|
| (a) | Pseudonymisation and encryption | Cryptography |
| (b) | Ongoing confidentiality, integrity, availability and resilience | Every theme except cryptography and backup |
| (c) | Timely restoration of availability and access | Backup and availability |
| (d) | Regularly testing and evaluating the measures | Not per check: running IDWolf regularly is the evidence |
## What stays out, on purpose

- **Patch level and most live host state** (MS14-068, MS17-010, firewall, Defender): a directory snapshot does not have it. The exceptions are read over CIM on the DCs when the account has admin rights there: disk space, core services, Spooler, WebClient, NetBIOS per adapter, and the build plus update revision used for noPac (`nopac_unpatched_dc`). PingCastle gets some of it by touching every DC; IDWolf stays read-only from one snapshot.
- **Password hashes**: only through the hashless DSInternals report, never in the snapshot.
- **On-CA settings** (ESC6, ESC7, ESC8, ESC11, ESC16): read on the CA host over CIM when the account has admin rights there, otherwise listed for manual verification. The IIS side of ESC8 (HTTPS, EPA) is not read.
- **Settings made by hand on a DC** instead of by GPO: invisible to the GPO-based checks.
