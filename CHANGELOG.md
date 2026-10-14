# Changelog

## 1.2 - 2026-10-14

Checks: 167 AD (from 166) and 88 Entra (from 86). The Entra snapshot schema goes from 7 to 9;
snapshots from 1.1 still load, and the new checks are listed as "not evaluated" until you
re-collect.

- New AD check `badsuccessor_dmsa_create` (High, T1098): a non-Tier 0 principal can create
  delegated managed service accounts in an OU or container (CreateChild for all classes or for
  dMSAs, GenericAll, WriteDacl, WriteOwner, or ownership), the BadSuccessor technique. It is
  reported only when the domain has a Windows Server 2025 DC: High while one of them is older than
  build 26100.4946 (the August 2025 update, CVE-2025-53779) or its build could not be read,
  Critical for Authenticated Users / Everyone / Domain Users / Domain Computers, Medium once
  every 2025 DC is patched.
- AD collector: new `ouAcls` section, the security descriptors of every OU and of the
  containers just below the domain head, read without `-Deep` by a standard user. Only explicit
  Allow ACEs that grant create or control rights are kept, to keep the snapshot small.
- New Entra check `entra_intune_role_weak_group` (High, T1072): an Intune role that can push
  scripts, apps or configuration to devices, or change Intune roles, is given through a group
  that is not role-assignable or has a dynamic membership. **Not yet verified on a real tenant**:
  the powerful roles are matched by built-in name (Intune Role Administrator, Policy and Profile
  Manager, Application Manager, School Administrator) and, for custom roles, by action names
  taken from the documentation (`Microsoft.Intune_<DeviceConfigurations|MobileApps|
  DeviceManagementScripts|Remediations|Roles>_<Create|Update|Assign>`). Please report a false
  positive or a role it misses.
- New Entra check `entra_intune_no_multi_admin_approval` (High, T1485): no Intune Multi Admin
  Approval policy covers device wipes or scripts, so one compromised Intune admin can wipe or
  run code on every managed device (the attack reported at Stryker in March 2026). **Not yet
  verified on a real tenant**: the policy types are matched from the documentation.
- Entra collector: new `intuneRoles` section (`deviceManagement/roleDefinitions` and their
  assignments, GET only) and the `DeviceManagementRBAC.Read.All` read scope (schema 8), and new
  `intuneApprovalPolicies` section (`deviceManagement/operationApprovalPolicies`, beta, GET only,
  same scope; schema 9). Of the approval policies only the type, platform and number of approver
  groups are kept, not the name. A tenant without an Intune licence records a collection error
  and both checks show as "not evaluated". The groups the Intune roles are given to are read like
  the other gating groups (visibility, dynamic rule, role-assignable flag, owners).
- AI step: two new parts of the answer. `known_exploitation` lists the findings that match
  attack vectors used in publicly known attacks of the last few years; the prompt now carries
  IDWolf's own list of the fired checks tied to recent attacks (the README "Recent attacks"
  table), and the model is told not to invent incidents or CVE numbers. `compromise_assessment`
  says whether the findings can be chained into full compromise of the domain or the Entra
  tenant (likely / possible / unlikely), from what starting access, with up to four chains and
  the link that breaks each. Both are shown in the AI section of the report; items citing checks
  that didn't fire are dropped, as for the other parts.
- Default outputs go to an `output` folder under the current directory: snapshots, reports,
  password-quality reports, BloodHound zips and packages, when you don't give a path. The menu
  and the analyzer wizard also offer the snapshots they find in `output`. Explicit paths work as
  before.
- `examples\`: synthetic snapshots and deterministic reports rebuilt (the demo with `-Deep` and
  password quality: 206 findings, since the demo has no Windows Server 2025 DC and the regression
  adds one for BadSuccessor; the Entra tenant: 89). The AI files and the lab report still come
  from 1.0: refreshing them needs the Gemini key and the lab domain.
- README: the report GIF moved to the top, the comparison table has an ADScan column and a
  "Report" row, and a new "Recent attacks" table lists the vectors behind the main incidents and
  research of 2023-2026 with the checks for each.
- README: "Limitations" renamed "Known Limitations". The AD CS item now says ESC6/7/8/11/16
  are read on the CA host when the collector has admin rights there (manual check only for a
  CA that could not be read), and the CIS item explains why Manual and Out items aren't covered.
- COVERAGE: tool-by-tool comparisons with other repositories removed. Their useful rows moved
  into the attack-technique table, a generic DC health table and the Entra "Beyond CIS" table.
  New "Recent attacks, 2023-2026" section, with what isn't covered yet (SCCM, ESC17, apps on
  Azure AD Graph).
- Tests: 534 assertions. Reference results: demo 193, partial 183, `-Deep` 198, the Entra tenant 89.

## 1.1 - 2026-10-12

Checks: 166 AD (from 136) and 86 Entra (from 75). Snapshots from 1.0 still load: the checks that need
the new collector fields are listed as "not evaluated" until you re-collect. The Entra snapshot
schema goes from 5 to 7.

- New check `trust_inactive` (PingCastle `T-Inactive`): an external or forest trust whose
  object has not changed for 180 days (a live trust rotates its password every 30). The
  collector now records `whenChanged` on each trust; older snapshots list the check as
  "not evaluated".
- New check `schema_java_objects` (PingCastle `S-JavaSchema`): RFC 2713 Java classes present
  in the schema. The collector records which of them exist (`domain.javaSchemaClasses`);
  older snapshots list the check as "not evaluated".
- New check `dns_zone_create_child` (PingCastle `A-DnsZoneAUCreateChild`): Authenticated
  Users, Everyone, Anonymous, Domain Users or Domain Computers can create records in an
  AD-integrated zone (ADIDNS spoofing). The collector reads each zone's security descriptor
  (`createChildSids`) on both the RPC and the LDAP path; older snapshots list the check as
  "not evaluated".
- New check `smartcard_password_not_rotated` (PingCastle `A-SmartCardPwdRotation`): an
  enabled smart-card-only account whose NT hash is older than `-PasswordMaxAgeDays`. The
  collector records the domain setting `msDS-ExpirePasswordsOnSmartCardOnlyAccounts`
  (`domain.smartcardPwdRotation`), shown in the finding.
- New check `schema_class_poss_superior` (PingCastle `S-ADRegistrationSchema`): a schema
  class that inherits from container and has `user` or `computer` in possSuperiors, so any
  account can create a container and objects inside it (msExchStorageGroup,
  CVE-2021-34470). The collector records those classes (`domain.possSuperiorClasses`);
  older snapshots list the check as "not evaluated".
- `anonymous_sam_enum` now also reports null-session settings opened by a GPO:
  `RestrictAnonymous = 0`, `EveryoneIncludesAnonymous = 1`, `RestrictNullSessAccess = 0`,
  anonymous shares and anonymous pipes beyond the DC defaults (netlogon, samr, lsarpc).
- New check `mdns_enabled`: no GPO sets `Dnscache\Parameters\EnableMDNS` to 0 (mDNS
  poisoning, next to `llmnr_enabled`).
- New check `webclient_not_disabled`: no GPO disables the WebClient service (WebDAV
  coercion to HTTP and relay to LDAP). The collector now reads the GPO System Services
  settings (`[Service General Setting]`, `serviceStart` per GPO); `spooler_on_dc` uses them
  too. Older snapshots list `webclient_not_disabled` as "not evaluated".
- New check `kds_root_key_readable` (Golden gMSA, `-Deep`): a non-Tier 0 principal can
  read a KDS root key (GenericAll, GenericRead, ReadProperty, or WriteDacl / WriteOwner to
  grant itself the right) and so compute every gMSA password. The collector reads only the
  permissions of the root keys (`kdsRootKeyAcls`), never the key data.
- New check `webclient_on_dc`: the WebClient (WebDAV) service is installed and not disabled
  on a DC, read live over CIM next to the Print Spooler (High when running, Medium when
  only startable). Older snapshots list it as "not evaluated".
- New check `nbtns_enabled_dc`: NetBIOS over TCP/IP on (or left "from DHCP", which is on
  with a static address) on a DC network adapter, read live over CIM
  (`Win32_NetworkAdapterConfiguration`, `netbiosAdapters` per DC).
- When some DCs answer the CIM queries and others refuse them (access denied), the collector
  now names those DCs on screen, and `dc_low_disk`, `dc_service_stopped`, `webclient_on_dc`
  and `nbtns_enabled_dc` are listed as "only partly evaluated" with the DCs that were not
  read, instead of looking clean for them.
- New check `nopac_unpatched_dc` (CVE-2021-42278 / 42287): the DC build and update revision
  are older than the November 2021 cumulative update (Server 2016, 2019, 2022 and the
  2004/20H2 builds; later builds count as fixed). Critical when the machine account quota
  is above 0. The collector reads the build over CIM and the update revision (`UBR`) with
  one registry read through `StdRegProv`. DCs whose patch level the build can't prove
  (2012 R2 and older, or no update revision) are named in "not evaluated", never treated
  as patched.
- Safety review: `Invoke-CimMethod` is allowed only as a registry read
  (`-ClassName StdRegProv` with a literal Get*/Enum* method); the regression checks that a
  `SetDWORDValue` call fails the review.
- COVERAGE: the CVE-2021-42278/42287 row was labelled Certifried; Certifried is
  CVE-2022-26923. Both now have their own row.
- COVERAGE: new **Live** legend entry (read over CIM on the DCs or CA hosts at collection
  time) used for every check that reads live state; null sessions, mDNS, NetBIOS, WebClient
  and noPac added to the reference tables and the compliance themes; S-DC-NotUpdated is
  now Partial (noPac fix only).
- New checks `adcs_esc6`, `adcs_esc7`, `adcs_esc8`, `adcs_esc11`, `adcs_esc16`, read on the
  CA host over CIM: policy `EditFlags` (EDITF_ATTRIBUTESUBJECTALTNAME2), the CA security
  descriptor (Manage CA / Issue and Manage Certificates outside Tier 0; Critical for broad
  principals), Web Enrollment or CES installed (`Win32_ServerFeature`; HTTPS and EPA are not
  read), `InterfaceFlags` without IF_ENFORCEENCRYPTICERTREQUEST, and the SID extension in
  `DisableExtensionList`. Each CA gets `caRegistry` in the snapshot. `adcs_manual_checks`
  now appears only for CAs that could not be read, and those CAs are named in "not
  evaluated". Installed roles are trusted only with English role names; otherwise ESC8 is
  "not evaluated". The safety review also allows `GetBinaryValue` (the CA permissions).
- New check `coercion_unfiltered_dc` (PetitPotam, DFSCoerce, MS-EVEN): read live on each
  DC, without calling any RPC interface. The collector reads the state of the EFS, DFS
  Namespace and EventLog services and looks for the interface UUIDs in the persistent RPC
  filters (BFE filter store, `rpcFilterInterfaces`; `$null` when it can't be read, which is
  never taken as filtered). MS-EFSR always counts as open, since LSASS serves it over
  lsarpc. High when a relay target is open (LDAP signing or channel binding not enforced,
  ESC8 or ESC11 on a CA), Medium otherwise.
- Ten new GPO checks from the ADcheck gap analysis, looked for in every GPO template:
  `always_install_elevated` (Critical when the user side is set too), `gpo_autologon_password`
  (Winlogon DefaultPassword as a registry value or a Group Policy Preferences registry item),
  `wsus_http`, `rdp_nla_disabled`, `rdp_restricted_admin`, and the domain-wide
  `credential_guard_not_configured`, `app_control_missing` (no AppLocker rules or WDAC
  policy), `force_logoff_disabled`, `ipv6_dhcpv6_takeover` (mitm6; Medium when a relay
  target is open) and `wsh_enabled`.
- Collector: the user-side `User\registry.pol` of each GPO is read too (`USER\...` keys,
  `userPolicyRead`); a Winlogon DefaultPassword set by a GPO is stored masked; the SYSVOL scan
  records Group Policy Preferences `Registry.xml` files that write DefaultPassword (path only,
  `autologonFiles`). Older snapshots list `gpo_autologon_password` as "not evaluated".
- New check `altsecid_weak_mapping` (ESC14, data side): an account whose
  `altSecurityIdentities` holds a weak explicit certificate mapping (subject only, issuer +
  subject, or RFC822 e-mail). High on Tier 0 accounts or when StrongCertificateBindingEnforcement
  is relaxed by GPO, Critical with both. The collector now reads `altSecurityIdentities` and
  keeps only the mapping types (`altSecIdTypes`), never the issuer, subject or e-mail.
- Roadmap: MSSQL service accounts are covered by the Kerberoasting checks; no separate check.
- New check `sysvol_writable`: a non-Tier 0 principal can write to the NETLOGON scripts
  folder or the SYSVOL Policies folder (code execution on every computer in scope). The
  collector reads the NTFS permissions of those two folders (`folderAcls`, `Get-Acl`, added to
  the safety review's reviewed list); older snapshots list the check as "not evaluated".
- `trust_rc4` now shows how long ago the trust object (and its key) last changed.
- PrivExchange (Exchange groups with WriteDacl on the domain head) is confirmed as covered by
  `dangerous_ace_tier0`, with a regression assertion. The ADcheck / cheat sheet section of
  the roadmap is closed; what is left is listed under "Not planned" with the reason.
  Demo gives 192 findings, partial 182, `-Deep` 197.
- EntraFalcon gap analysis (comparison in `COVERAGE.md`). Four new Entra checks:
  `entra_ca_excluded_group_weak` (a group excluded from an enabled Conditional Access policy
  that is public, dynamic on a user-influenced attribute, or owned by non-admins),
  `entra_privileged_group_owner` (a group holding an admin role, active or eligible, owned by
  a non-admin, a guest or a service principal), `entra_connect_app_extra_credentials` (the
  ConnectSyncProvisioning app with more than one certificate or a secret) and
  `entra_sp_lookalike_name` (mixed scripts, full-width or invisible characters in a service
  principal name; the detail gives positions and code points, never a rewritten name, so the
  AI pseudonymizer still catches it).
- Entra collector, schema 6: reads the groups behind Conditional Access exclusions and
  inclusions and behind admin roles (visibility, dynamic rule, owners; never members), and
  the `includeGroups` of each policy. Group names are registered in the Entra pseudonymizer.
  Older snapshots list the two group checks as "not evaluated". The Entra tenant gives 79
  findings, now asserted by the regression (it was not before).
- Six more Entra checks from the EntraFalcon gap analysis: `entra_pim_role_settings_weak`
  (activation without MFA or authentication context, longer than 8 hours, permanent eligible
  or active assignments allowed; one finding listing the roles per issue),
  `entra_scoped_admin_outside_ca` (admins with an administrative-unit-scoped role while the
  admin MFA policies only target roles), `entra_privileged_app_sp_owner` (a service principal
  or managed identity owning a privileged app), `entra_privileged_app_inactive` (privileged app
  with no sign-in for 180 days), `entra_app_instance_lock_off` (multi-tenant app with
  credentials and no App instance property lock) and `entra_access_package_grants_admin`
  (self-request without approval granting a role-holding group or an Entra role).
  `entra_privileged_group_owner` now also counts PIM for Groups eligible owners.
- Entra collector, schema 7: PIM rules of the 14 privileged roles (`pimRules`), role
  assignments with their scope (`roleAssignments`, no P2 needed), owners by type for service
  principals in admin roles too, service principal sign-in activity (beta report,
  `spSignIns`), the sign-in audience and instance lock of each app, the resources each access
  package grants (`accessPackageGrants`) and PIM for Groups eligibility of role-holding groups.
  New read-only scope: PrivilegedEligibilitySchedule.Read.AzureADGroup (needs consent once;
  without it the group owner check is listed as partly evaluated). The Entra tenant gives 85.
- The default Gemini model is now `gemini-3.8-flash` (generally available; still overridable
  with `-Model` and in the launcher).
- Encrypted packages: the launcher asks for a password when it packages a collection (12
  characters or more, typed twice; Enter keeps a plain zip) and writes an `.idwolf` file: the
  zip encrypted with AES-256-CBC, key from PBKDF2 (SHA-256, 600,000 rounds, or SHA-1 with
  1,300,000 on .NET older than 4.7.2), HMAC-SHA256 over the whole file checked before
  decrypting. `IDWolf.ps1` recognizes it by its header, asks for the password or takes
  `-BundlePassword` (a SecureString, never plain text), and decrypts in memory. Plain zips
  still work as before.
- Internal identifiers renamed from MooseAD to IDWolf: `$script:IDWolfVersion`,
  `Show-IDWolfBanner`, `Get-IDWolfReportCss`, the report's `filterIDWolfTable` and the
  `idwolf_*` temp folders of the tests. Snapshots tagged `ADSheep` or `MooseAD` still load.
- New check `wpad_not_disabled`: no GPO sets WinHttp `DisableWpad = 1` or disables the
  WinHttpAutoProxySvc service (WPAD poisoning, next to the LLMNR / mDNS / NBT-NS checks).
- New Entra check `entra_app_scoped_admin_privileged`: Application or Cloud Application
  Administrator scoped to a single app that holds an admin role or a tenant-takeover
  permission. Demo gives 193 findings, partial 183, `-Deep` 198; the Entra tenant gives 86.
- New report look ("keycap" theme), the default for the AD and the Entra report: paper
  background, ink borders and hard shadows, severity counters and pills as coloured keys
  (red, coral, amber, beige), monospace labels, warm palette in the charts and the
  attack-path map. Both reports now share one stylesheet (`Get-IDWolfThemeCss` in
  `Reporting.ps1`). Still self-contained: system font stacks, no web fonts or CDN. Long
  chart legends wrap instead of running under the next chart.

## 1.0 - Initial release
