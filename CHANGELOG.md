# Changelog

## 1.7 - 2026-10-23

- New AD checks (3): `dsrm_logon_behavior` (High) flags a DC where DsrmAdminLogonBehavior = 2, so
  the DSRM local administrator can log on while the DC runs normally (Tier 0 persistence; read
  over CIM, needs admin on the DCs); `tombstone_lifetime_low` (Low) flags a tombstone lifetime
  below 180 days (short recovery/backup window); `privileged_logon_unrestricted` (Medium) flags
  Tier 0 accounts that log on with a reusable password, i.e. not in Protected Users and not
  required to use a smart card. The collector records `domain.tombstoneLifetime` and per-DC
  `dsrmAdminLogonBehavior`.
- Report header: when the AI step ran, the top line also shows the model used and how long
  Gemini took (retries and the defensive fallback included), e.g. `... analysis 2.8s &middot; AI
  gemini-3.8-flash in 12.4s`. Nothing is added when no AI step ran.
- Collector: gentle pacing. `-Gentle` (or `-ThrottleMs <n>`) pauses between the heavy reads
  and every few hundred per-object reads, so a large, busy or closely-monitored domain is read
  more slowly and evenly: lighter on the DC and kinder to rate-based monitoring of a sanctioned
  scan. It only changes the pace (same objects, still read-only over ADWS) and is recorded in
  `meta.options` (`gentle`, `throttleMs`). The launcher offers it on an AD run and in the
  default settings.
- Four more AD checks: `azuread_sso_key_old` (Medium, High past a year) flags an Entra Seamless SSO
  computer account (`AZUREADSSOACC$`) whose Kerberos key hasn't been rolled over in 30 days
  (`SsoKeyMaxAgeDays`), the key behind a Silver Ticket for any synced user;
  `cloud_kerberos_trust_key_old` (Medium) flags a Windows Hello cloud Kerberos trust account
  (`krbtgt_AzureAD`) past the krbtgt rotation age; `kerberos_ticket_lifetime_long` (Low) flags a
  domain Kerberos policy with ticket, renewal or service-ticket lifetimes above the defaults
  (10 h, 7 days, 600 min) or unlimited; `ntlm_not_restricted` (Low) flags DCs where NTLM is
  neither audited nor restricted (the first step of any NTLM phase-out). The collector reads the
  `[Kerberos Policy]` section of each GPO's security template (`gpo.gpos[].kerberosPolicy`); an
  older snapshot without it lists the lifetime check as *not evaluated*.
- `AZUREADSSOACC$` is no longer reported as a stale computer: it never logs on by design.
- `dangerous_ace_tier0` on the domain head for Exchange Windows Permissions, Exchange Trusted
  Subsystem or Organization Management now says it is the PrivExchange path and how to remove it
  (Exchange's split-permissions setup, or the published fix).
- New Entra checks (2, snapshot schema 11): `entra_sync_hard_match_takeover` (Medium; Low when
  only soft match is open) flags a synced tenant where on-premises accounts can be matched onto
  existing cloud accounts (BlockCloudObjectTakeoverThroughHardMatch / BlockSoftMatch off, the
  SyncJacking precondition); `entra_tap_weak` (Low; Medium past 8 hours) flags a Temporary Access
  Pass policy that allows reusable passes or a long maximum lifetime. The Entra collector reads
  both from endpoints it already used (GET only). Schema 10 snapshots list them as *not
  evaluated*.
- AD attack-path map: a dark **Any domain user** entry box for what any account can start from
  (Kerberoasting / AS-REP roasting a Tier 0 account, enrolling a vulnerable template, coercion and
  relay to the CA, noPac with a machine account quota above zero, rights given to Authenticated
  Users / Domain Users / Everyone, a breached or empty Tier 0 password from the password report).
  Members of a source group are one step behind it, and a Tier 0 password shared with a normal
  account is a step from that account. New kinds on the map: AD CS on the CA (ESC6/7/8/10/11/16/17),
  weak certificate mappings on Tier 0, BadSuccessor, Golden gMSA (only when a gMSA is Tier 0),
  privileged SID history, SID filtering off, operator groups, DnsAdmins, RODC caches, GPO scripts
  from a share, GPP passwords, writable SYSVOL, LAPS readers and the SCCM container; the ones the
  finding alone doesn't prove are dashed.
- Entra report: a new attack-path map toward the admin roles (owners of privileged groups, apps
  and service principals, scoped application administrators, access packages any user can
  request, admins without MFA), drawn like the AD one.
- Not added: a check on partner (DAP / GDAP) relationships. Microsoft Graph exposes them only to
  the partner tenant, not to the customer, so a read-only customer-side collector can't see them.
- Password quality: two duplicate-password clusters of the same size no longer share one Object
  ("3 accounts"), which made `-CompareTo` and the SIEM `finding_id` mix them up. The Object now
  names the cluster's alphabetically first account, e.g. `3 accounts incl. svc_app`. Findings
  of this check get a new `finding_id` once, so the first comparison against a 1.6 run shows
  them as resolved and new.
- The demo now gives 216 findings (26/79/82/29; 221 deep, 205 partial, 224 with the example
  password report) and the Entra tenant 95.

## 1.6 - 2026-10-21

- AI step, reasoning: the model now works in three passes (as an intruder from every realistic
  starting point and across categories; as a reviewer trying to break each chain against the
  findings; as a defender planning from the chains that survived) and returns only the
  defensive result. Each chain in the compromise assessment lists its links, what each gives,
  whether a finding shows it or it is assumed (with the assumption), a confidence and the link
  whose fix breaks it; new `rejected_chains` and `verify_next` (what to check by hand). IDWolf
  checks what comes back: a link cannot be "shown" by a check that didn't fire, and a chain with
  assumed links cannot be high confidence. The report shows all of it.
- AI step, input: the checks that couldn't be evaluated are sent too (ids and titles only), so a
  collection gap is never read as a clean link. The instructions cover Entra as well as AD.
- If Gemini refuses the instructions on safety grounds (`SAFETY`, `PROHIBITED_CONTENT`...), one
  retry with a defensive-only variant, saved as `<report>_ai_prompt_defensive.txt` and noted in
  the report.
- The prompt file (`<report>_ai_prompt.txt`, `-AiDryRun`) is now one self-contained text, the
  instructions then the input, to paste whole into another model's chat; the answer is the same
  JSON. It replaces the `=== SYSTEM ===` / `=== USER ===` layout.
- No temperature is sent any more: Gemini 3 is tuned for its default (1.0), and Google warns that
  lower values can make it loop.
- Launcher: default settings, under the new `[S] Settings` menu. Set once (DC, deep, password
  quality, tenant, device-code sign-in, what to do after collecting, AI step, model, attempts)
  and kept apart from the remembered answers in `wizard.json`. Each collection asks whether to
  use them: yes skips the questions and opens the settings screen with them (a change there is
  for that run only), no asks as before. Repeating the last run doesn't ask. The analyzer
  wizard (option 6) offers their AI step, model and attempts in place of its AI question.
- Launcher: `[C] Forget remembered choices` moved to `[S]`, option 2. It now keeps the default
  settings.
- Fix: in the Entra report the AI text kept tokens such as `UPN-3`, `APP-2` or `CAPOLICY-1`
  instead of the real names; de-tokenization now covers every prefix the map knows.

## 1.5 - 2026-10-19

- Session log: the launcher, and the analyzer wizard on its own, write a transcript to
  `output\idwolf_<timestamp>.log` (`idwolf_analysis_...` for the wizard alone) with every
  question, the answer given and all the console output of the collector and the analyzer. Only
  at an interactive console; one log per session; hidden prompts leave nothing in it.
  `Start-Transcript` / `Stop-Transcript` join the safety review's list.
- Started from an elevated window (`C:\Windows\System32`), the launcher and the analyzer wizard
  work from the IDWolf folder, so snapshots and reports no longer land in
  `C:\Windows\System32\output`. `Set-Location` joins the safety review's list.
- Analyzer wizard: the snapshot list is newest first; the Gemini key prompt is hidden (it was
  echoed); switching AiMode to `send` on the review screen now asks the model, key and attempts,
  and the review shows the model / attempts only when they apply and refuses an unknown AiMode.
- Connection diagnostics (`lib\Connection.ps1`, no RSAT needed): the DNS servers of the
  collecting machine, the DNS lookup of the domain, the DC locator record
  (`_ldap._tcp.dc._msdcs.<domain>`), an LDAP bind with the DC and site that answered, the DC's
  address, and a TCP connect (closed at once, nothing sent) to the ports a collection uses, each
  with its time in ms. The launcher shows them before every AD collection, again when the DC is
  changed on the settings screen, and on its own under the new menu entry `[D]`. The collector
  prints one line when all is well and the full table when a port it needs is closed or the
  domain can't be reached, and records them in `meta.connection` together with the DC that
  served the AD cmdlets (`rootDSE.dnsHostName`) and its first ADWS answer time. The report shows
  them under Details, *Collection and connection*, and the DC in its header; older snapshots
  say they have only the server name. `Resolve-DnsName` joins the safety review's list.
- Choosing the domain controller: `Start-IDWolf.ps1 -Server` (alias `-DomainController`, as on
  the collector), and the AD collections ask for it with `L` listing every DC of the domain
  (one LDAP query of the Sites container: site, PDC / GC / RODC) with its ADWS connect time;
  the settings screen opens the same list. `Collect-ADSnapshot.ps1 -ListDomainControllers` prints
  it and exits, and its guided setup takes `L` too. `Export-PasswordQuality.ps1 -Server`
  replicates from that DC instead of the PDC; the launcher passes the chosen DC to it.
- LDAPS: the LDAP reads IDWolf makes itself (the diagnostics' bind, the DC list, the launcher's
  rights check) use 389 as before, and LDAPS on 636 when 389 does not answer and 636 does (a
  firewall that lets only LDAPS through), also when the serverless bind fails and the locator's
  DC answers only on 636. The console, `meta.connection.diagnostics.ldap` (`protocol`, `port`)
  and the report say which was used. The DC's certificate is checked by Windows; a refused one
  fails the bind with a hint, it is never ignored. With neither port answering, no bind is tried
  (no 20 s wait). New `Open-LdapRootDse` in `lib\Connection.ps1`. The collection itself still
  goes over ADWS.
- `Edit-RunSettings` (`lib\Wizard.ps1`) takes `-Pickers`: a setting edited through a scriptblock
  (the DC list) instead of a typed answer.

## 1.4 - 2026-10-16

- Launcher, AD collections (1 and 3): before the settings screen it shows what the collecting
  account (or `-Credential`) can do: elevated session, Domain Admins / Enterprise Admins (token
  groups), replication (DCSync) rights on the domain head, and the checks those rights will leave
  "not evaluated", named from the catalog's `Needs` and grouped by reason. Read-only LDAP through
  .NET (`Get-CollectorRights`, `lib\Wizard.ps1`), no RSAT needed; an unreachable domain is shown
  as "not read" with LDAP's own message. Admin groups that UAC keeps as deny-only in a window that
  is not elevated count as filtered, not as rights.
- Launcher, on start: on a domain controller in a window that is not elevated it says that even
  a Domain Admin collects like a standard user there, how to start it as administrator, and
  offers to quit (it never restarts itself: the safety review forbids starting processes). Not
  elevated without RSAT, it notes that an AD collection can't install RSAT from that window.
- New check `sccm_system_management_writable` (High; Critical for Authenticated Users, Domain
  Users or Domain Computers): a principal that is neither Tier 0 nor a site server (a computer
  account, or a group of computer accounts only) can write to the SCCM / MECM System Management
  container, so it can publish a rogue management point. The detail lists the site servers with
  rights there and the published management points. The collector reads that container's ACL
  and its management points (section `sccm`; no container means no SCCM, not a gap). It is its
  own read, so a failed domain head ACL no longer hides it; older snapshots list it as "not
  evaluated".
- New check `adcs_esc17` (High): a GPO points Windows Update at WSUS over HTTPS and a published
  template lets low-privileged users enroll with a supplied subject for server authentication
  (or any purpose), without approval: anyone can get a trusted certificate for the WSUS name.
  Read from data already collected (GPO templates, AD CS templates).
- The demo gives 195 findings (25 Critical, 77 High, 67 Medium, 26 Low), 203 with the example
  password report; `partial` 185, `-Deep` 200; 169 AD checks.
- New Entra check `entra_app_azure_ad_graph` (Low): an app registration that requests
  permissions on the retired Azure AD Graph, or a service principal granted some there
  (application permissions or delegated consents; Microsoft's own apps left out). One finding
  per app. The collector now reads `requiredResourceAccess` (counts only), the Azure AD Graph
  grants of each service principal and the resource of each delegated grant.
- New Entra check `entra_catalog_role_privileged_group` (High): a non-admin, guest or service
  principal who is catalog owner or access package manager of an entitlement catalog holding a
  group with an admin role, or its assignment manager while a package of the catalog already
  grants that group. The collector reads the catalogs (resources, packages) and the catalog role
  assignments (`EntitlementManagement.Read.All`, already requested). Catalog names are
  pseudonymized for the AI step.
- Entra snapshots move to schema 10; older ones list both checks as "not evaluated". The
  synthetic tenant gives 93 findings (4 Critical, 21 High, 27 Medium, 41 Low), 90 Entra checks.
- Launcher menu reordered: 1 full AD run, 2 full Entra run, then the single steps (3 AD
  collection, 4 password quality, 5 Entra collection, 6 analysis, 7 package). "Add AI summary"
  is gone: the analysis (6) already asks for the AI step and also opens encrypted `.idwolf`
  packages, which the old option refused. A remembered last run from before (5 or 8) is read
  as 1 or 2.
- Launcher, single collections (3 and 5): the same questions and settings screen as a full run
  (output path, deep collection / tenant, device code, the DC on a workgroup PC), with "Then"
  set to stop. The snapshot stays pending, so the next start offers to analyze or package it;
  "stop" in a full run now does the same. Before, option 3 started the collector's own setup
  and failed on a workgroup PC, where it never asked for a DC.
- Launcher, AI step on the settings screen: skip (`-SkipLLM`, so a long run never stops at the
  end on "send to Gemini?"), ask (the confirmation before sending) or dry-run (the prompt only,
  `<report>_ai_prompt.txt`). Model and attempts show only for ask.
- Launcher: clearing the DC with "-" on the settings screen of a workgroup PC cancels the run
  with a message; before, the old DC was still used.
- Password-quality reports from another domain: the launcher names reports
  `pwq_<domain>_<timestamp>.json`, and the wizard and the package option offer only reports of
  the snapshot's domain (read from the report, not its name), newest first. `IDWolf.ps1` refuses
  a report whose domain differs from the snapshot's (`-PasswordQualityFile` or inside a
  package); a report that does not know its domain is accepted with a warning.
- Analyzer wizard: when a snapshot newer than the last analyzed one is in the folder or in
  `.\output`, "same settings again?" offers that one instead.
- Launcher and analyzer wizard: answers are remembered between runs and offered as defaults,
  saved after each answer so a Ctrl+C half way loses nothing. On start the launcher offers to
  pick up a snapshot that was collected but never analyzed or packaged, or to repeat the last
  full run (option 1 or 2) with the same answers; `[C]` deletes what was remembered. The
  analyzer wizard offers the last snapshot with the same settings, and compares against the
  report of the last run. The file (`%LOCALAPPDATA%\IDWolf\wizard.json`, new `lib\Wizard.ps1`)
  takes keys from a fixed list only: never a password, an API key or directory data.
- Launcher, full runs (1 and 2): every question is asked up front, password quality and what to
  do after collecting included, then one settings screen lists all the answers. Change one by
  its number, Q cancels, Enter starts; nothing is collected before that. Repeating the last run
  goes straight to that screen.
- After an interactive analysis, the launcher and the wizard ask whether to open the report in
  the default browser. `Invoke-Item` joins the safety review's list, allowed in
  `lib\Wizard.ps1` only, which opens nothing but the `.html` the run has just written. Runs
  with `-Snapshot`, piped input and the scheduled script never ask.
- Report: the HTML opens on a **Dashboard** tab, and the per-check blocks and tables move to a
  **Details** tab. The dashboard has a score ring with the grade and the counts by severity, then
  the Gemini section and the attack-path map (both collapsible, open by default), one card per
  framework (NIS2, ISO 27001, DORA, GDPR) with the share of evaluated checks that came out clean
  and a bar per control, one tile per category, the six top risks (worst severity, then most
  objects, then catalog order) linked to their check, and the charts. Not-evaluated checks are
  counted apart on the cards, never as clean. Same layout for the Entra report, which now shares
  the AD report's scripts (`Get-IDWolfReportScript`). Printing, and a browser without scripts,
  show both tabs. The score formula moves under "How the score is computed".
- `tests\New-ReportGif.ps1` renders both tabs and has slides for the new dashboard cards.
- `examples\demo_report.html` re-rendered with the new layout (findings and CSV unchanged).
  `entra_report.html` and the lab report keep the 1.3 layout for now.

## 1.3 - 2026-10-15

- AI step: the reply text is now joined from every part Gemini returns (thinking models can split
  it over several parts, and only the first was read, so the JSON came out cut short). When the
  reply still isn't clean JSON, the error shows Gemini's `finishReason` and says what to do on
  `MAX_TOKENS` or an early stop.
- Report: each check's details have an "Attack it enables" line in place of the bare MITRE
  link: the ATT&CK technique with its name, and for the checks in the "Recent attacks" table
  the attack seen in public incidents (the same list the AI step gets, now kept in
  `Reporting.ps1`). The regression asserts that every MITRE ID in the catalogs has a name.
- Analyzer wizard: choosing `[G] send` no longer acts like `-SendToAI`. It skipped the step that
  shows the `_ai_prompt.txt` path and asks before sending; now the text can be checked first, as
  from the menu. `-SendToAI` on the command line still sends without asking.
- Launcher: the splash screen of `Start-IDWolf.ps1` shows the version next to the name. It is
  read from `$script:IDWolfVersion` in `IDWolf.ps1`, so there is still only one place to bump it.
- Banner: the box is closed on the right and shows the repository link.
- `examples\lab_report.html` and `lab_report.gif` rebuilt from a `-Deep` collection of the lab
  (BadSuccessor evaluated) with a fresh Gemini reply: the AI section shows the least access
  needed and the starting point of each chain. `demo_report.html` and `entra_report.html`
  re-rendered for the "Attack it enables" line (findings, CSV and JSON Lines unchanged).

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
- AI step: each chain of the compromise assessment has its own starting point, and the
  top-level one is the least access among the chains (it could say "any domain user" for a
  chain that starts from a specific account). An HTTP 503 now suggests a smaller model
  (`-Model gemini-3.5-flash-lite`); the README says so too.
- `examples\lab_report.html` and `lab_report.gif` rebuilt from a 1.2 run on the lab domain
  (populated with Vulnerable-AD and the `tests/lab/` scripts) with the Gemini summary; the GIF
  has two more slides, for the compromise verdict and the recent attack vectors. README: the lab
  testing is now stated next to the GIF and in Testing.
- Default outputs go to an `output` folder under the current directory: snapshots, reports,
  password-quality reports, BloodHound zips and packages, when you don't give a path. The menu
  and the analyzer wizard also offer the snapshots they find in `output`. Explicit paths work as
  before.
- `examples\`: synthetic snapshots and deterministic reports rebuilt (the demo with `-Deep` and
  password quality: 206 findings, since the demo has no Windows Server 2025 DC and the regression
  adds one for BadSuccessor; the Entra tenant: 89). The demo AI files still come
  from 1.0.
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
