# AD checks. To add one: a catalog entry below, then Add-Finding from the
# right section of Invoke-ADHygieneChecks.

# --------------------------------------------------------------------------
# Catalog. Severity is the default; a check can raise or lower it per object.
# Needs lists the snapshot sections a check depends on: if one is missing the
# check is reported as "not evaluated", not as clean.
# --------------------------------------------------------------------------
$script:CheckCatalog = [ordered]@{
    # ---------------- Kerberos ----------------
    krbtgt_password_old = @{ Category = 'Kerberos'; Severity = 'High'; Mitre = 'T1558.001'; Needs = @('users')
        Title = 'krbtgt password not rotated'
        Description = 'The krbtgt key signs every TGT in the domain. Until it is rotated twice, any Golden Ticket forged with a previously stolen key stays valid, including after an incident is considered closed.'
        Remediation = 'Rotate the krbtgt password twice, waiting for full replication (and at least the maximum TGT lifetime, 10h by default) between the two resets. Use Microsoft''s New-KrbtgtKeys.ps1 or an equivalent procedure, then schedule a recurring rotation (e.g. every 180 days).' }
    rodc_krbtgt_password_old = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1558.001'; Needs = @('users')
        Title = 'RODC krbtgt account not rotated'
        Description = 'Each RODC has its own krbtgt_NNNNN account. A stale key extends the impact of a compromised branch-office RODC.'
        Remediation = 'Rotate the RODC krbtgt_NNNNN account with the same double-reset procedure.' }
    azuread_sso_key_old = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1558.002'; Needs = @('computers')
        Title = 'Seamless SSO key (AZUREADSSOACC$) not rolled over'
        Description = 'With Entra Seamless SSO, the AZUREADSSOACC$ computer account holds the Kerberos key that Entra ID uses to accept on-premises tickets. Whoever has read that key (DCSync, an old backup) can forge a ticket for any synced user and sign in to the cloud as them, MFA rules for trusted networks included. The key never changes by itself.'
        Remediation = 'Roll over the Seamless SSO decryption key (Update-AzureADSSOForest from the Entra Connect server) at least every 30 days, as Microsoft recommends, and protect the AZUREADSSOACC$ object like a Tier 0 account. If Seamless SSO is no longer used, turn it off in Entra Connect and delete the account.' }
    cloud_kerberos_trust_key_old = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1558.001'; Needs = @('users')
        Title = 'Cloud Kerberos trust key (krbtgt_AzureAD) not rotated'
        Description = 'The krbtgt_AzureAD account (Entra Kerberos server object, used by Windows Hello for Business cloud Kerberos trust and FIDO2 sign-in to on-premises resources) holds the key Entra ID uses to issue partial TGTs for this domain. Like the RODC krbtgt keys, a stolen copy keeps working until it is rotated.'
        Remediation = 'Rotate the key with Set-AzureADKerberosServer -RotateServerKey (AzureADHybridAuthenticationManagement module) on a regular schedule, like krbtgt.' }
    privileged_kerberoastable = @{ Category = 'Kerberos'; Severity = 'Critical'; Mitre = 'T1558.003'; Needs = @('users', 'groups')
        Title = 'Privileged account with SPN (Kerberoastable)'
        Description = 'Any authenticated user can request a service ticket for an account with a servicePrincipalName and crack it offline. When that account is Tier 0, a cracked password means domain compromise.'
        Remediation = 'Remove the SPN from the privileged account, or move the service to a gMSA. Privileged identities should never run services.' }
    kerberoastable_user = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1558.003'; Needs = @('users')
        Title = 'User account with SPN (Kerberoastable)'
        Description = 'Service account whose ticket can be requested and cracked offline by any domain user. Risk grows with password age and weak encryption types.'
        Remediation = 'Migrate the service to a gMSA. If not possible, set a random password of 25+ characters, enforce AES only (msDS-SupportedEncryptionTypes = 24) and rotate it regularly.' }
    spn_account_rc4 = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1558.003'; Needs = @('users')
        Title = 'SPN account without AES-only encryption'
        Description = 'An SPN account whose msDS-SupportedEncryptionTypes is unset or lacks AES can receive RC4-encrypted service tickets, which crack orders of magnitude faster than AES.'
        Remediation = 'Set msDS-SupportedEncryptionTypes to 24 (AES128+AES256) after verifying the service supports AES, then reset the password so AES keys are generated.' }
    asrep_roastable = @{ Category = 'Kerberos'; Severity = 'High'; Mitre = 'T1558.004'; Needs = @('users')
        Title = 'Kerberos pre-authentication disabled (AS-REP roastable)'
        Description = 'With DONT_REQ_PREAUTH set, anyone who can reach a DC (no credentials needed) can request an AS-REP for the account and crack it offline.'
        Remediation = 'Clear "Do not require Kerberos preauthentication" unless a documented legacy dependency exists; if it does, enforce a long random password.' }
    unconstrained_delegation = @{ Category = 'Kerberos'; Severity = 'High'; Mitre = 'T1558'; Needs = @('users', 'computers')
        Title = 'Unconstrained delegation on non-DC principal'
        Description = 'Hosts trusted for unconstrained delegation cache the TGT of every user that authenticates to them. Combined with coercion (e.g. printer bug, PetitPotam) this yields a DC TGT and full domain compromise.'
        Remediation = 'Replace with constrained or resource-based constrained delegation. Add Tier 0 accounts to Protected Users or mark them "sensitive and cannot be delegated".' }
    constrained_delegation_protocol_transition = @{ Category = 'Kerberos'; Severity = 'High'; Mitre = 'T1550.003'; Needs = @('users', 'computers')
        Title = 'Constrained delegation with protocol transition'
        Description = 'TRUSTED_TO_AUTH_FOR_DELEGATION lets the account obtain a ticket for any user (including admins) to the listed services without that user ever authenticating (S4U2Self + S4U2Proxy). The service part of the SPN is not protected, so any service on the target host is reachable.'
        Remediation = 'Use Kerberos-only constrained delegation where possible, restrict the target list, and protect the source account as Tier 0 when the targets are sensitive.' }
    constrained_delegation = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1550.003'; Needs = @('users', 'computers')
        Title = 'Constrained delegation configured'
        Description = 'The account can impersonate users to the listed services. Critical when the targets are domain controllers.'
        Remediation = 'Review the business need and target list. Delegation to DC services (ldap, cifs, host) is equivalent to domain admin.' }
    rbcd_configured = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1550.003'; Needs = @('users', 'computers', 'rbcd')
        Title = 'Resource-based constrained delegation (RBCD) configured'
        Description = 'msDS-AllowedToActOnBehalfOfOtherIdentity lets the listed principals impersonate any user to this object. Often left behind by attacks (e.g. via MachineAccountQuota + relay).'
        Remediation = 'Verify each allowed principal is expected. Clear the attribute if unknown. Any RBCD on a domain controller must be treated as an active compromise indicator.' }
    delegation_orphan_spn = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1558.003'; Needs = @('users', 'computers')
        Title = 'Constrained delegation to an SPN no account holds (SPN-jacking)'
        Description = 'An account is allowed to delegate (msDS-AllowedToDelegateTo) to a service on a host of this domain, but no user, service account or computer in the snapshot holds that SPN or that host name. Whoever can write a servicePrincipalName (WriteSPN, or a computer created through the machine account quota) can register the orphan SPN on an account they control. The delegating service then obtains tickets for any user to that account, and the unprotected service name in the ticket can be rewritten to reach any service on the attacker''s host (ghost SPN-jacking).'
        Remediation = 'Remove the stale entry from msDS-AllowedToDelegateTo (it usually points to a decommissioned server), or recreate the target with its SPN. Restrict who can write servicePrincipalName and set ms-DS-MachineAccountQuota to 0.' }
    privileged_account_delegable = @{ Category = 'Kerberos'; Severity = 'High'; Mitre = 'T1558'; Needs = @('users', 'groups')
        Title = 'Privileged account can be delegated'
        Description = 'Tier 0 account neither marked "sensitive and cannot be delegated" nor in Protected Users: its credentials can be captured and replayed through any delegation-enabled host it touches.'
        Remediation = 'Add the account to Protected Users (after testing: it disables NTLM, DES/RC4 and delegation for it) or set NOT_DELEGATED.' }
    des_enabled = @{ Category = 'Kerberos'; Severity = 'High'; Mitre = 'T1558'; Needs = @('users', 'computers')
        Title = 'DES Kerberos encryption enabled'
        Description = 'DES keys are trivially brute-forceable. Enabled via USE_DES_KEY_ONLY or msDS-SupportedEncryptionTypes.'
        Remediation = 'Clear USE_DES_KEY_ONLY and the DES bits, then reset the password.' }
    auth_policy_silo_unused = @{ Category = 'Privileged Access'; Severity = 'Low'; Mitre = 'T1078.002'; Needs = @('domain.authPolicySilos')
        Title = 'No authentication policy silo in use'
        Description = 'The domain defines no authentication policy silos. Silos (2012R2+) confine Tier 0 accounts so their TGTs can only be used from designated hosts and enforce Protected-Users-style restrictions, limiting credential theft and lateral movement. They are a key Tier 0 containment control and are unused here.'
        Remediation = 'Create an authentication policy and silo for Tier 0 accounts and admin workstations, pilot it, then assign the Tier 0 accounts. Combine with Protected Users.' }
    protected_users_empty = @{ Category = 'Kerberos'; Severity = 'Medium'; Mitre = 'T1550'; Needs = @('groups')
        Title = 'Protected Users group is empty'
        Description = 'Protected Users gives privileged accounts non-configurable protections (no NTLM, no delegation, no RC4/DES, 4h TGT). It is unused.'
        Remediation = 'Add Tier 0 human accounts to Protected Users after a pilot. Do not add service accounts or computer accounts.' }

    # ---------------- Privileged access ----------------
    privileged_group_oversized = @{ Category = 'Privileged Access'; Severity = 'Medium'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Too many Domain Admins'
        Description = 'Every Domain Admin is a direct path to the domain. A large group usually means privileges used for daily administration instead of delegated roles.'
        Remediation = 'Reduce to break-glass and a few dedicated Tier 0 accounts. Move day-to-day tasks to delegated groups with least privilege.' }
    schema_enterprise_admins_populated = @{ Category = 'Privileged Access'; Severity = 'Medium'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Schema / Enterprise Admins not empty'
        Description = 'Microsoft guidance is to keep Schema Admins and Enterprise Admins empty and populate them only for the duration of a change.'
        Remediation = 'Remove permanent members and use a just-in-time procedure to add them when needed.' }
    operator_groups_populated = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Built-in operator group populated'
        Description = 'Account, Server, Print and Backup Operators can log on to DCs and have rights (service control, backup of NTDS.dit, driver loading, modifying most accounts) that lead to domain admin. They are Tier 0 in practice.'
        Remediation = 'Empty these groups and replace them with narrowly delegated permissions.' }
    rodc_tier0_unprotected = @{ Category = 'Privileged Access'; Severity = 'Medium'; Mitre = 'T1207'; Needs = @('domainControllers', 'groups')
        Title = 'Tier 0 accounts not protected from RODC credential caching'
        Description = 'A read-only domain controller exists, but the Denied RODC Password Replication Group no longer contains the key privileged principals (Domain Admins, Enterprise Admins, krbtgt). A compromised or stolen RODC could then cache and expose those credentials.'
        Remediation = 'Keep Domain Admins, Enterprise Admins, krbtgt and the other default protected groups in the Denied RODC Password Replication Group, and keep the Allowed group minimal.' }
    rodc_prp_too_broad = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1003'; Needs = @('domainControllers', 'groups', 'rodcPolicy')
        Title = 'RODC allowed to cache privileged or domain-wide credentials'
        Description = 'The password replication policy of a read-only domain controller (msDS-RevealOnDemandGroup) allows a Tier 0 principal or a domain-wide group (Domain Users, Domain Computers, Authenticated Users, Everyone) to be cached, or its denied list (msDS-NeverRevealGroup) no longer holds the Denied RODC Password Replication Group. An RODC sits in a less protected site: whoever compromises it, or administers it through managedBy, extracts every cached credential and can forge tickets with the RODC krbtgt key for the accounts the policy allows (RODC golden ticket, Kerberos key list).'
        Remediation = 'Limit the Allowed list of each RODC to the users and computers of its site, never Tier 0 and never a domain-wide group, and keep the Denied RODC Password Replication Group in its denied list.' }
    rodc_tier0_revealed = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1003'; Needs = @('domainControllers', 'groups', 'rodcPolicy')
        Title = 'Tier 0 credentials cached on a read-only domain controller'
        Description = 'msDS-RevealedList of an RODC shows that the password of a Tier 0 account has been replicated to it. Anyone who gets local admin or the disk of that RODC can extract the hash and use it against the whole domain. When the RODC is administered (managedBy) by a principal that is not Tier 0, that principal is already one step from domain admin.'
        Remediation = 'Reset the password of every Tier 0 account listed (twice for krbtgt-like accounts), fix the password replication policy so it cannot happen again, and keep RODC administration (managedBy) out of reach of non-Tier 0 principals.' }
    dnsadmins_populated = @{ Category = 'Privileged Access'; Severity = 'Medium'; Mitre = ''; Needs = @('users', 'groups')
        Title = 'DnsAdmins populated'
        Description = 'DnsAdmins members can configure the DNS service running on DCs; historically this allowed loading an arbitrary DLL as SYSTEM on a DC. Treat as Tier 0.'
        Remediation = 'Keep DnsAdmins empty or restricted to Tier 0 accounts.' }
    privileged_inactive = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Inactive privileged account still enabled'
        Description = 'An enabled privileged account nobody uses is an unmonitored credential with full rights.'
        Remediation = 'Disable and remove from privileged groups after confirming with the owner. Keep break-glass accounts documented and monitored.' }
    privileged_password_old = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Privileged account password not changed'
        Description = 'An old password on a Tier 0 account increases exposure to reuse, past leaks and offline cracking of previously captured hashes.'
        Remediation = 'Reset the password and enforce rotation (or smart card / passwordless) for privileged accounts.' }
    privileged_password_never_expires = @{ Category = 'Privileged Access'; Severity = 'Medium'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Privileged account with password never expires'
        Description = 'DONT_EXPIRE_PASSWORD on a Tier 0 account removes the only built-in guarantee that its password is ever changed.'
        Remediation = 'Clear the flag, or document the exception (break-glass) with compensating controls.' }
    privileged_logon_unrestricted = @{ Category = 'Privileged Access'; Severity = 'Medium'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Privileged account logs on with a reusable password'
        Description = 'An enabled Tier 0 account is neither in Protected Users nor required to log on with a smart card, so it authenticates with a reusable password (NTLM/Kerberos RC4 or AES long-term key) that can be phished, sprayed or replayed. Tier 0 logons should be bound to a smart card and/or Protected Users.'
        Remediation = 'Add Tier 0 human accounts to Protected Users (after a pilot: it disables NTLM, DES/RC4 and delegation) and/or set "smart card is required for interactive logon". Keep break-glass accounts documented with compensating controls.' }
    privileged_disabled_member = @{ Category = 'Privileged Access'; Severity = 'Low'; Mitre = 'T1078.002'; Needs = @('users', 'groups')
        Title = 'Disabled account in privileged group'
        Description = 'A disabled account keeps its group memberships: re-enabling it (by anyone with that right) instantly restores Tier 0 access.'
        Remediation = 'Remove disabled accounts from privileged groups.' }
    privileged_computer_member = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1078.002'; Needs = @('computers', 'groups')
        Title = 'Computer account in privileged group'
        Description = 'SYSTEM on that host acts as a Tier 0 principal: compromising the machine compromises the domain.'
        Remediation = 'Remove the computer account from the group and grant only the specific rights required.' }
    privileged_foreign_member = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1078.002'; Needs = @('groups')
        Title = 'Foreign or unresolved principal in privileged group'
        Description = 'A principal from another domain or forest (or one that cannot be resolved) holds Tier 0 rights here: the security of this domain then depends on the other one.'
        Remediation = 'Remove cross-domain members from privileged groups, or treat the trusted domain as part of the same Tier 0.' }
    hidden_primary_group = @{ Category = 'Privileged Access'; Severity = 'High'; Mitre = 'T1098'; Needs = @('users', 'computers')
        Title = 'Non-standard primaryGroupID'
        Description = 'Membership through primaryGroupID is not stored in the group''s member attribute, so it is invisible in most consoles and reviews. A classic persistence trick when set to a privileged group.'
        Remediation = 'Set primaryGroupID back to Domain Users (513) / Domain Computers (515) and review how it was changed.' }
    orphaned_admincount = @{ Category = 'Privileged Access'; Severity = 'Low'; Mitre = ''; Needs = @('users', 'groups')
        Title = 'Orphaned adminCount=1'
        Description = 'The account was protected by AdminSDHolder in the past but is no longer privileged. Inheritance stays disabled, so it keeps an ACL that nobody reviews, and it may reveal former admin accounts.'
        Remediation = 'Clear adminCount and re-enable ACL inheritance on the object.' }
    builtin_administrator_hygiene = @{ Category = 'Privileged Access'; Severity = 'Medium'; Mitre = 'T1078.002'; Needs = @('users')
        Title = 'Built-in Administrator (RID 500) hygiene'
        Description = 'The RID 500 account cannot be locked out and is a known target. It should be a vaulted break-glass account, not used day to day.'
        Remediation = 'Vault the password, rotate it after each use, and alert on every logon of this account.' }

    # ---------------- Account hygiene ----------------
    password_not_required = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1078.002'; Needs = @('users')
        Title = 'Password not required (PASSWD_NOTREQD)'
        Description = 'The account may have, or be set to, an empty password regardless of domain policy.'
        Remediation = 'Clear PASSWD_NOTREQD (Set-ADAccountControl -PasswordNotRequired $false) and set a compliant password.' }
    reversible_encryption_account = @{ Category = 'Account Hygiene'; Severity = 'High'; Mitre = 'T1556.005'; Needs = @('users')
        Title = 'Password stored with reversible encryption'
        Description = 'The cleartext password is recoverable by anyone able to read the NTDS database (e.g. via DCSync).'
        Remediation = 'Clear the flag and reset the password.' }
    altsecid_weak_mapping = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1649'; Needs = @('users', 'users.altSecId')
        Title = 'Weak explicit certificate mapping on an account (ESC14)'
        Description = 'altSecurityIdentities maps a certificate to the account by subject, issuer + subject or e-mail (RFC822) only. Whoever gets a certificate with that subject or e-mail, which is often easy to request, can authenticate as the account. Full strong certificate binding enforcement rejects these weak mappings for Kerberos; when it is relaxed by GPO, they work again. High on Tier 0 accounts.'
        Remediation = 'Replace the mapping with a strong one (X509:<I>issuer<SR>serial, <SKI> or <SHA1-PUKEY>), or remove it, and keep StrongCertificateBindingEnforcement = 2 on the DCs.' }
    unix_password_present = @{ Category = 'Account Hygiene'; Severity = 'High'; Mitre = 'T1552'; Needs = @('users')
        Title = 'UNIX password attribute populated'
        Description = 'The account has a userPassword or unixUserPassword attribute set. These attributes are often world-readable or weakly protected and can store a recoverable or hashed credential, a classic forgotten exposure from NIS/identity-management integrations. The collector records only that a value exists, never the value.'
        Remediation = 'Clear userPassword / unixUserPassword, and move UNIX identity integration to a mechanism that does not store a readable secret in the directory.' }
    password_in_description = @{ Category = 'Account Hygiene'; Severity = 'High'; Mitre = 'T1552'; Needs = @('users')
        Title = 'Possible password in description'
        Description = 'The description attribute is readable by every authenticated user. The collector masked the value.'
        Remediation = 'Remove the credential from the description and reset the password: consider it disclosed.' }
    circular_group_nesting = @{ Category = 'Account Hygiene'; Severity = 'Low'; Mitre = ''; Needs = @('groups')
        Title = 'Circular group nesting'
        Description = 'Two or more groups are nested into each other in a cycle. Circular nesting makes effective membership hard to reason about and review, hides who really has access, and can confuse tools and access reviews.'
        Remediation = 'Break the cycle: remove the nesting link that is not needed so the group hierarchy is a tree.' }
    inactive_user = @{ Category = 'Account Hygiene'; Severity = 'Low'; Mitre = 'T1078.002'; Needs = @('users')
        Title = 'Enabled user inactive'
        Description = 'Unused enabled accounts are valid credentials nobody would notice being used.'
        Remediation = 'Disable after owner confirmation, then delete after a retention period.' }
    never_logged_on_user = @{ Category = 'Account Hygiene'; Severity = 'Low'; Mitre = 'T1078.002'; Needs = @('users')
        Title = 'Enabled user never logged on'
        Description = 'Account created long ago and never used: often an onboarding leftover with an initial password known to several people.'
        Remediation = 'Disable or delete.' }
    smartcard_password_not_rotated = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1550.002'; Needs = @('users')
        Title = 'Smart-card-only account whose password is never rotated'
        Description = 'A smart-card-only account still has an NT hash, derived from a random password set when the flag was enabled. Users never change it, so whoever steals that hash once can pass-the-hash (or get the NTLM fallback through PKINIT) for years.'
        Remediation = 'Turn on automatic rotation (domain functional level 2016: msDS-ExpirePasswordsOnSmartCardOnlyAccounts, "Enable rolling of expiring NTLM secrets") or reset the hash by toggling "Smart card is required for interactive logon" off and on.' }
    password_never_expires = @{ Category = 'Account Hygiene'; Severity = 'Low'; Mitre = 'T1078.002'; Needs = @('users')
        Title = 'Password never expires'
        Description = 'Typical of service accounts whose passwords are never changed.'
        Remediation = 'Migrate services to gMSA; for humans, clear the flag.' }
    guest_enabled = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1078.001'; Needs = @('users')
        Title = 'Guest account enabled'
        Description = 'The built-in Guest account (RID 501) is enabled.'
        Remediation = 'Disable the Guest account.' }
    sid_history = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1134.005'; Needs = @('users', 'computers', 'groups')
        Title = 'sIDHistory populated'
        Description = 'sIDHistory adds the listed SIDs to the logon token. Legitimate after a migration, a persistence technique otherwise. A SID of this same domain, or of a privileged group, is never legitimate.'
        Remediation = 'Clear sIDHistory once the migration is complete and resource ACLs have been re-permissioned.' }
    stale_computer = @{ Category = 'Account Hygiene'; Severity = 'Low'; Mitre = 'T1078.002'; Needs = @('computers')
        Title = 'Stale computer account'
        Description = 'Enabled computer account with no recent logon. Its password no longer rotates and it clutters inventory and LAPS coverage.'
        Remediation = 'Disable, move to a quarantine OU, and delete after the retention period.' }
    obsolete_os = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1210'; Needs = @('computers')
        Title = 'Unsupported operating system'
        Description = 'Enabled computer running an operating system out of vendor support: no security updates.'
        Remediation = 'Upgrade or decommission; if it must stay, isolate it and restrict what can authenticate to it.' }
    laps_not_deployed = @{ Category = 'Account Hygiene'; Severity = 'High'; Mitre = 'T1550.002'; Needs = @('domain.lapsSchema')
        Title = 'LAPS not deployed'
        Description = 'Neither legacy LAPS nor Windows LAPS schema attributes exist: local administrator passwords are likely identical across machines, enabling lateral movement with a single hash.'
        Remediation = 'Deploy Windows LAPS (built into current Windows) and back up passwords to AD with encryption.' }
    laps_missing = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1550.002'; Needs = @('computers')
        Title = 'Computer without LAPS password'
        Description = 'Enabled Windows computer with no LAPS expiration timestamp: LAPS policy is not applied to it.'
        Remediation = 'Check GPO/Intune scope and client-side processing for this machine.' }
    laps_stale = @{ Category = 'Account Hygiene'; Severity = 'Low'; Mitre = 'T1550.002'; Needs = @('computers')
        Title = 'LAPS password overdue'
        Description = 'The LAPS expiration time is well in the past: the client is no longer rotating the local admin password.'
        Remediation = 'Investigate the client (offline, broken GPO processing, removed from policy scope).' }
    machine_account_quota = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1136.002'; Needs = @('domain.machineAccountQuota')
        Title = 'Users can join computers to the domain'
        Description = 'ms-DS-MachineAccountQuota > 0 lets any user create computer accounts, a key building block of relay and RBCD attacks.'
        Remediation = 'Set ms-DS-MachineAccountQuota to 0 and delegate domain join to a dedicated group.' }
    precreated_computer_account = @{ Category = 'Account Hygiene'; Severity = 'Medium'; Mitre = 'T1078.002'; Needs = @('computers')
        Title = 'Computer account with password not required'
        Description = 'An enabled computer account with PASSWD_NOTREQD can be joined or taken over with the predictable default machine password (usually the lowercase account name). Pre-created or pre-staged computer objects left in this state let an attacker who knows the name authenticate as the machine and set its password.'
        Remediation = 'Clear PASSWD_NOTREQD, complete or remove the pre-staged account, and reset the computer password. Delegate pre-staging to a controlled process.' }

    # ---------------- Domain configuration ----------------
    password_policy_short = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1110'; Needs = @('domain.passwordPolicy')
        Title = 'Short minimum password length'
        Description = 'Default Domain Policy minimum length below the configured threshold.'
        Remediation = 'Raise the minimum length (14+ for users; longer or passwordless for admins) and add banned-password filtering.' }
    password_policy_no_complexity = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1110'; Needs = @('domain.passwordPolicy')
        Title = 'Password complexity disabled with short passwords'
        Description = 'Complexity is disabled and the minimum length is not long enough to compensate.'
        Remediation = 'Enable complexity, or move to long passphrases (14+) with banned-password filtering.' }
    password_policy_no_lockout = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1110.003'; Needs = @('domain.passwordPolicy')
        Title = 'No account lockout'
        Description = 'Lockout threshold is 0: online password spraying is unlimited.'
        Remediation = 'Set a lockout threshold (e.g. 10) with a short duration, and monitor 4625/4771 events for spraying.' }
    reversible_encryption_policy = @{ Category = 'Domain Configuration'; Severity = 'Critical'; Mitre = 'T1556.005'; Needs = @('domain.passwordPolicy')
        Title = 'Reversible encryption enabled in password policy'
        Description = 'Every account covered by this policy stores a recoverable cleartext password.'
        Remediation = 'Disable reversible encryption in the policy and reset the passwords of all affected accounts.' }
    password_policy_min_age_zero = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = 'T1110'; Needs = @('domain.passwordPolicy')
        Title = 'Minimum password age is zero'
        Description = 'A minimum password age of 0 lets a user change the password repeatedly in quick succession, cycling past the password history to return to a known value and defeating history enforcement.'
        Remediation = 'Set a minimum password age of at least 1 day so password history cannot be flushed in a single session.' }
    password_policy_history_weak = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = 'T1110'; Needs = @('domain.passwordPolicy')
        Title = 'Short password history'
        Description = 'The password history count is below the recommended 24. A short history lets users rotate back to a recently used (possibly compromised) password.'
        Remediation = 'Set the enforced password history to 24 previous passwords.' }
    password_policy_max_age = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1110'; Needs = @('domain.passwordPolicy')
        Title = 'Password maximum age never expires or is too long'
        Description = 'The default domain policy either never expires passwords (maximum age 0) or allows an excessively long lifetime. A password that never changes stays valid indefinitely after any past exposure or offline crack.'
        Remediation = 'Set a maximum password age (for example 365 days with long passphrases, or shorter with standard complexity), or adopt a documented passwordless / long-passphrase strategy instead of "never expires".' }
    fgpp_weak = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1110'; Needs = @('domain.fineGrainedPolicies')
        Title = 'Weak fine-grained password policy'
        Description = 'A Password Settings Object is weaker than the configured baseline. Worse when it applies to privileged principals.'
        Remediation = 'Align the PSO with the baseline or narrow its scope.' }
    dc_password_old = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1207'; Needs = @('domainControllers', 'computers')
        Title = 'Domain controller machine password not rotated'
        Description = 'A domain controller normally rotates its machine account password about every 30 days. A much older pwdLastSet means automatic rotation is disabled or the DC is not healthy, which keeps an old DC key valid far longer than it should (relevant to Golden/Silver and DC-key attacks).'
        Remediation = 'Investigate why the DC is not rotating its machine password (DisablePasswordChange, replication or health issues) and restore normal rotation.' }
    dc_subnet_missing = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = ''; Needs = @('sites')
        Title = 'No subnets declared in Active Directory Sites'
        Description = 'With no subnets defined, clients cannot be mapped to a site: they may authenticate against any DC (including a remote or RODC), and site-aware security and locality are lost. It is also a sign of an incompletely managed directory.'
        Remediation = 'Declare every network subnet under Sites and Services and associate it with the correct site.' }
    sysvol_frs = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = ''; Needs = @('sysvolReplication')
        Title = 'SYSVOL still replicated by FRS'
        Description = 'SYSVOL is replicated by the deprecated File Replication Service instead of DFSR. FRS is unsupported on current Windows Server, blocks raising the functional level, and its failure modes can leave GPOs and logon scripts inconsistent across DCs.'
        Remediation = 'Migrate SYSVOL replication from FRS to DFSR (dfsrmig), then raise the functional level.' }
    functional_level_outdated = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = ''; Needs = @()
        Title = 'Outdated domain functional level'
        Description = 'Functional levels below 2016 miss security features such as automatic NTLM secret rolling for smart-card-only accounts and PAM features.'
        Remediation = 'Raise the domain and forest functional level once all DCs run a supported OS.' }
    recycle_bin_disabled = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = ''; Needs = @('domain.recycleBin')
        Title = 'AD Recycle Bin not enabled'
        Description = 'Deleted objects cannot be restored with their attributes and group memberships, which slows recovery after an incident or an error.'
        Remediation = 'Enable-ADOptionalFeature ''Recycle Bin Feature''.' }
    tombstone_lifetime_low = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = ''; Needs = @('domain.tombstoneLifetime')
        Title = 'Tombstone lifetime below 180 days'
        Description = 'The tombstone lifetime sets how long a deleted object (and an AD backup) stays restorable. Below 180 days the recovery window is short: a backup older than it can no longer be used for an authoritative restore, which hurts recovery after ransomware or a bad change. An unset value falls back to the legacy 60-day default.'
        Remediation = 'Set tombstoneLifetime on CN=Directory Service,CN=Windows NT,CN=Services,<config NC> to at least 180 days (the modern default).' }
    anonymous_ldap_enabled = @{ Category = 'Domain Configuration'; Severity = 'High'; Mitre = 'T1087.002'; Needs = @('domain.dsHeuristics')
        Title = 'Anonymous LDAP operations allowed'
        Description = 'dSHeuristics 7th character is 2: anonymous users can perform LDAP operations and enumerate the directory.'
        Remediation = 'Reset the 7th character of dSHeuristics to 0.' }
    single_dc = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = ''; Needs = @('domainControllers')
        Title = 'Single domain controller'
        Description = 'Only one DC: no redundancy and a harder, riskier recovery.'
        Remediation = 'Deploy at least two writable DCs.' }
    dc_obsolete_os = @{ Category = 'Domain Configuration'; Severity = 'High'; Mitre = 'T1210'; Needs = @('domainControllers')
        Title = 'Domain controller on old operating system'
        Description = 'Domain controller running an OS that is out of support or close to end of support.'
        Remediation = 'Plan the DC replacement: DCs are the most exposed Tier 0 assets.' }
    trust_sid_filtering_disabled = @{ Category = 'Domain Configuration'; Severity = 'High'; Mitre = 'T1134.005'; Needs = @('trusts')
        Title = 'Trust without SID filtering'
        Description = 'SIDs coming from the trusted side are not filtered: an admin of the other domain can forge sIDHistory with privileged SIDs of this domain.'
        Remediation = 'Enable quarantine on external trusts (netdom trust /quarantine:yes) and disable SID history on forest trusts unless required by a migration.' }
    trust_tgt_delegation = @{ Category = 'Domain Configuration'; Severity = 'High'; Mitre = 'T1558'; Needs = @('trusts')
        Title = 'TGT delegation enabled across forest trust'
        Description = 'Unconstrained delegation hosts in the other forest can capture TGTs of this forest''s users.'
        Remediation = 'Disable TGT delegation across the trust (netdom trust /EnableTGTDelegation:No).' }
    trust_no_selective_auth = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = ''; Needs = @('trusts')
        Title = 'Inbound trust without selective authentication'
        Description = 'All users of the trusted domain can authenticate to any resource here.'
        Remediation = 'Consider selective authentication for external/forest trusts with third parties.' }
    trust_rc4 = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1558'; Needs = @('trusts')
        Title = 'Trust uses RC4'
        Description = 'The trust key uses RC4 instead of AES for inter-realm tickets.'
        Remediation = 'Enable AES on both sides of the trust and reset the trust password.' }
    schema_class_poss_superior = @{ Category = 'Domain Configuration'; Severity = 'High'; Mitre = 'T1136.002'; Needs = @('domain.possSuperiors')
        Title = 'Schema class lets any user or computer create containers'
        Description = 'A schema class inherits from container and lists user or computer in possSuperiors. Any account (or any computer, which a user can create through the machine account quota) can add an object of that class under itself and then create users or computers inside it without restriction. msExchStorageGroup is the known case (CVE-2021-34470) and stays exploitable after Exchange is uninstalled.'
        Remediation = 'Remove user and computer from possSuperiors of the class (schema change, Schema Admins). For msExchStorageGroup apply the Exchange CVE-2021-34470 update or the published schema fix script.' }
    schema_java_objects = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = ''; Needs = @('domain.javaSchema')
        Title = 'Java object classes present in the schema'
        Description = 'The schema contains the RFC 2713 Java classes (javaSerializedObject, javaObject...), usually left by an old LDAP/Unix integration. They let a client store serialized Java objects in the directory, which a vulnerable Java application can deserialize.'
        Remediation = 'Check that no application uses these classes. Schema classes cannot be deleted, but they can be deactivated (defunct); make sure nobody can create objects of these classes (default security descriptor and ACLs).' }
    trust_inactive = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = ''; Needs = @('trusts', 'trusts.whenChanged')
        Title = 'Trust that looks unused'
        Description = 'The trust object (and so its password, which rotates every 30 days on a live trust) has not changed for months. The other domain is probably gone or the trust forgotten, yet it still extends authentication to a domain nobody maintains.'
        Remediation = 'Confirm with the owner of the other domain that the trust is still needed. If not, remove it (netdom trust /remove or Active Directory Domains and Trusts).' }

    # ---------------- DNS (AD-adjacent service) ----------------
    dns_insecure_updates = @{ Category = 'Domain Configuration'; Severity = 'High'; Mitre = 'T1557'; Needs = @('dns')
        Title = 'DNS zone allows non-secure dynamic updates'
        Description = 'An AD zone accepting non-secure dynamic updates lets any host (even unauthenticated) create or overwrite records, enabling spoofing of services and name-based poisoning.'
        Remediation = 'Set the zone dynamic update policy to "Secure only" for AD-integrated zones.' }
    dns_zone_transfer_allowed = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1590'; Needs = @('dns', 'dnsTransfer')
        Title = 'DNS zone transfer allowed to any server'
        Description = 'The zone allows zone transfer to any server, which hands an attacker the full list of hosts and services for reconnaissance.'
        Remediation = 'Restrict zone transfers to named secondary servers, or disable them where AD replication is used.' }
    dns_zone_create_child = @{ Category = 'Domain Configuration'; Severity = 'Medium'; Mitre = 'T1557'; Needs = @('dns', 'dnsZoneAcl')
        Title = 'Any user can create records in a DNS zone'
        Description = 'Broad principals (Authenticated Users by default) can create child objects in the AD-integrated zone, so any domain account can register a name that does not exist yet (WPAD, a mistyped server, a wildcard) and redirect traffic to itself (ADIDNS spoofing).'
        Remediation = 'Remove the Create all child objects right of Authenticated Users (or Everyone, Domain Users, Domain Computers) on the zone. Let DHCP register records with a dedicated account, and pre-create the names clients need.' }
    dns_scavenging_disabled = @{ Category = 'Domain Configuration'; Severity = 'Low'; Mitre = ''; Needs = @('dns')
        Title = 'DNS aging/scavenging disabled'
        Description = 'Without aging/scavenging, stale records accumulate; an attacker can claim an abandoned name that still resolves for clients.'
        Remediation = 'Enable aging and scavenging on the zone with sensible refresh/no-refresh intervals.' }
    dns_dangerous_record = @{ Category = 'Domain Configuration'; Severity = 'High'; Mitre = 'T1557'; Needs = @('dns')
        Title = 'Dangerous DNS record (wildcard / WPAD / ISATAP)'
        Description = 'A wildcard, WPAD or ISATAP record lets an attacker redirect proxy or tunnel traffic. WPAD in particular is a classic credential-interception path; a wildcard answers every unknown name.'
        Remediation = 'Remove the record unless explicitly required, and use the DNS global query block list for WPAD and ISATAP.' }

    # ---------------- Operational Health (AD-adjacent) ----------------
    fsmo_holder_invalid = @{ Category = 'Operational Health'; Severity = 'High'; Mitre = ''; Needs = @('health', 'health.fsmo')
        Title = 'FSMO role held by a server that is not a DC'
        Description = 'An operations master role points to a server that is no longer a domain controller (usually one that was removed without moving its roles). Password changes, new objects or schema updates depending on that role will fail.'
        Remediation = 'Move the role to a healthy DC (Move-ADDirectoryServerOperationMasterRole), or seize it if the old DC is gone for good, then run a metadata cleanup.' }
    dc_unreachable = @{ Category = 'Operational Health'; Severity = 'Medium'; Mitre = ''; Needs = @('health', 'health.dcReachability')
        Title = 'Domain controller not answering'
        Description = 'A DC registered in AD did not answer an LDAP query (through ADWS) from the machine that ran the collection. It may be down, firewalled, or a leftover that was never cleaned up.'
        Remediation = 'Check the DC and its ADWS service (TCP 9389). If it was decommissioned, remove it with a metadata cleanup.' }
    dc_time_skew = @{ Category = 'Operational Health'; Severity = 'Medium'; Mitre = ''; Needs = @('health', 'health.dcTime', 'health.time')
        Title = 'Domain controllers'' clocks disagree'
        Description = 'The clocks of the DCs differ by more than a minute. Kerberos rejects tickets beyond 5 minutes of skew, so logons start failing in ways that are hard to diagnose.'
        Remediation = 'Make the PDC emulator of the forest root sync with a reliable NTP source and let every other DC follow the domain hierarchy (w32tm /config /syncfromflags:domhier on the others).' }
    dc_low_disk = @{ Category = 'Operational Health'; Severity = 'Medium'; Mitre = ''; Needs = @('health', 'health.dcState', 'health.dcStatePartial')
        Title = 'Low disk space on a domain controller'
        Description = 'The system drive of a DC is nearly full. When the disk holding NTDS.dit fills up, AD stops accepting changes and the DC can stop working.'
        Remediation = 'Free space or extend the volume; keep at least 10% (and several GB) free on the DCs.' }
    dc_service_stopped = @{ Category = 'Operational Health'; Severity = 'High'; Mitre = ''; Needs = @('health', 'health.dcState', 'health.dcStatePartial')
        Title = 'Core service stopped on a domain controller'
        Description = 'A service the DC depends on (NTDS, ADWS, KDC, Netlogon, DNS, DFSR, W32Time...) is set to start but isn''t running.'
        Remediation = 'Find out why it stopped (event logs), start it, and check replication and logons afterwards.' }
    replication_failures = @{ Category = 'Operational Health'; Severity = 'Medium'; Mitre = ''; Needs = @('health', 'health.replication')
        Title = 'Active Directory replication failing'
        Description = 'A domain controller reports consecutive replication failures with a partner. Broken replication means security changes (password resets, group changes, disables) do not propagate, so a compromised or stale DC can keep serving old state, and recovery is harder.'
        Remediation = 'Investigate the failing replication link (repadmin /showrepl, DNS, time, firewall) and restore healthy replication.' }
    replication_stale = @{ Category = 'Operational Health'; Severity = 'Medium'; Mitre = ''; Needs = @('health', 'health.replication')
        Title = 'Active Directory replication stale'
        Description = 'A replication partner has not had a successful replication in over a day. Even without hard errors, stale replication delays the propagation of security-relevant changes across DCs.'
        Remediation = 'Check the replication topology and connectivity; force and verify replication (repadmin /syncall).' }
    ad_backup_overdue = @{ Category = 'Operational Health'; Severity = 'High'; Mitre = ''; Needs = @('health', 'health.backup')
        Title = 'Active Directory backup overdue'
        Description = 'The last successful system-state / AD backup of the domain naming context is older than the expected window. Without a recent backup, recovery from ransomware or a bad change (or an authoritative restore) is not possible within objective.'
        Remediation = 'Restore a working, tested backup schedule for the domain controllers (system state), and store copies offline.' }
    dsrm_logon_behavior = @{ Category = 'Operational Health'; Severity = 'High'; Mitre = 'T1078.003'; Needs = @('health', 'health.dcState', 'health.dcStatePartial', 'health.dsrm')
        Title = 'DSRM administrator allowed to log on'
        Description = 'DsrmAdminLogonBehavior is 2 on a domain controller: the Directory Services Restore Mode local administrator (a password that never expires and is not managed by AD) can log on while the DC runs normally. It is a classic Tier 0 persistence foothold that survives a domain password reset.'
        Remediation = 'Set HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior to 0 (or 1) on the DCs, and rotate the DSRM password (for example with ntdsutil "set dsrm password").' }
    dhcp_on_dc = @{ Category = 'Operational Health'; Severity = 'Medium'; Mitre = 'T1557'; Needs = @('health')
        Title = 'DHCP server running on a domain controller'
        Description = 'An authorized DHCP server is also a domain controller. DHCP on a DC runs dynamic DNS registration as the DC machine account (the DnsUpdateProxy / record-ownership problem) and widens the DC attack surface; it is a long-standing Microsoft anti-pattern.'
        Remediation = 'Move the DHCP role off the domain controllers to dedicated member servers.' }

    # ---------------- Permissions ----------------
    dcsync_rights = @{ Category = 'Permissions'; Severity = 'Critical'; Mitre = 'T1003.006'; Needs = @('acl.DomainRoot')
        Title = 'Non-default principal with DCSync rights'
        Description = 'Replicating Directory Changes All on the domain head lets the principal retrieve every password hash, including krbtgt.'
        Remediation = 'Remove the right unless it belongs to a documented synchronization account; protect any such account as Tier 0.' }
    sync_laps_rights = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1555'; Needs = @('acl.DomainRoot')
        Title = 'Non-default principal can read confidential attributes through DirSync'
        Description = 'The principal holds DS-Replication-Get-Changes together with DS-Replication-Get-Changes-In-Filtered-Set on the domain head, without Get-Changes-All. With the DirSync control it can read confidential and RODC-filtered attributes of every object, including legacy LAPS passwords (ms-Mcs-AdmPwd) and BitLocker material, without any read right on the objects themselves (BloodHound SyncLAPSPassword).'
        Remediation = 'Remove both extended rights unless the principal is a documented synchronization or backup product, and protect any such account as Tier 0.' }
    dangerous_ace_tier0 = @{ Category = 'Permissions'; Severity = 'Critical'; Mitre = 'T1098'; Needs = @('acl')
        Title = 'Dangerous permission on Tier 0 object'
        Description = 'A non-default principal holds control rights (GenericAll, WriteDacl, WriteOwner, GenericWrite, member / SPN / key credential writes, forced password reset) on the domain head, AdminSDHolder, the Domain Controllers OU or a privileged group.'
        Remediation = 'Remove the ACE. For AdminSDHolder, SDProp will propagate the fix to all protected accounts within 60 minutes.' }
    nonstandard_owner_tier0 = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1098'; Needs = @('acl')
        Title = 'Non-default owner of Tier 0 object'
        Description = 'The owner of an object can always rewrite its ACL.'
        Remediation = 'Set the owner back to Domain Admins.' }
    gpp_cpassword = @{ Category = 'Permissions'; Severity = 'Critical'; Mitre = 'T1552.006'; Needs = @('sysvol')
        Title = 'Group Policy Preferences password in SYSVOL'
        Description = 'cpassword values are encrypted with a key Microsoft published (MS14-025): any domain user can read SYSVOL and decrypt them.'
        Remediation = 'Delete the preference item, remove the XML, and change the password of the referenced account everywhere it is used.' }
    sysvol_writable = @{ Category = 'Permissions'; Severity = 'Critical'; Mitre = 'T1484.001'; Needs = @('sysvol', 'sysvol.acl')
        Title = 'NETLOGON or SYSVOL Policies folder writable by non-Tier 0 principals'
        Description = 'A principal outside Tier 0 can write to the NETLOGON scripts folder or the SYSVOL Policies folder. Logon scripts and GPO files there run on every computer and for every user in scope, so write access is code execution across the domain, DCs included.'
        Remediation = 'Remove the write, modify or full control entries for that principal from the folder (and check the files below it), keeping the defaults: Administrators, SYSTEM, Server Operators, CREATOR OWNER and read-only for Authenticated Users.' }
    sysvol_script_secrets = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1552.001'; Needs = @('sysvol')
        Title = 'Possible credential in a SYSVOL logon script'
        Description = 'A script in SYSVOL (bat/cmd/ps1/vbs) contains a password-like string. SYSVOL is readable by every authenticated user, so any credential embedded in a logon or deployment script is exposed domain-wide. The collector records only the file path, never the content.'
        Remediation = 'Remove the credential from the script (use a gMSA, LAPS, or a secret store), then rotate the exposed password.' }
    dangerous_ace_anywhere = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1098'; Needs = @('deepAcls')
        Title = 'Dangerous permission held by a non-privileged principal'
        Description = 'A non-privileged principal holds a control right (GenericAll, WriteDacl, WriteOwner, GenericWrite, member/SPN/key-credential write, forced password reset) over a user, computer, group or OU. This is a delegation path to whatever that object controls. Found only with a deep ACL sweep.'
        Remediation = 'Remove the ACE or scope the delegation to the minimum needed. Prioritize ACEs over Tier 0 or over objects that lead to Tier 0.' }
    kds_root_key_readable = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1003'; Needs = @('deepAcls', 'kdsRootKeys')
        Title = 'Non-Tier 0 principal can read a KDS root key (Golden gMSA)'
        Description = 'A principal outside Tier 0 can read a KDS root key, or can grant itself that right. With the root key and a few public attributes it can compute the password of every gMSA and dMSA in the forest, offline and for the lifetime of the key (Golden gMSA). Rotating the gMSA passwords does not help.'
        Remediation = 'Remove the ACE from the root key (CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services in the Configuration partition); by default only Domain Admins, Enterprise Admins and SYSTEM have access. If a non-admin may already have read it, create a new root key and move the gMSAs to it.' }
    badsuccessor_dmsa_create = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1098'; Needs = @('acl', 'ouAcls')
        Title = 'Non-Tier 0 principal can create dMSAs (BadSuccessor)'
        Description = 'A principal outside Tier 0 can create objects in an OU or container (CreateChild for all classes or for msDS-DelegatedManagedServiceAccount, GenericAll, WriteDacl, WriteOwner, or ownership). With a Windows Server 2025 DC in the domain it can create a delegated managed service account, mark it as the successor of any account (a Domain Admin, krbtgt) and authenticate with that account''s privileges and keys (BadSuccessor). The August 2025 update (CVE-2025-53779, build 26100.4946) requires a two-sided link, which closes the direct takeover, but the right to create dMSAs should still belong to Tier 0 only. Reported only when a Windows Server 2025 DC is present: High while one is unpatched or its patch level could not be read, Medium once all are patched.'
        Remediation = 'Install the August 2025 cumulative update (or later) on every Windows Server 2025 DC. Remove CreateChild (all classes or dMSA), GenericAll, WriteDacl and WriteOwner from non-Tier 0 principals on OUs and containers, scope delegations to the object classes really needed (user, group, computer), and give ownership of OUs back to Domain Admins. Akamai''s Get-BadSuccessorOUPermissions.ps1 lists the same rights.' }
    sccm_system_management_writable = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1072'; Needs = @('sccm')
        Title = 'Non-site-server principal can write to the SCCM System Management container'
        Description = 'SCCM / MECM site servers publish their sites and management points in CN=System Management,CN=System, and clients use what is published there to find a management point. A principal that is neither Tier 0 nor a site server (a computer account, or a group of computer accounts only) can create or change objects there: it can publish a rogue management point that clients will contact, and collect their authentication or the network access account. Site servers themselves hold Full Control by design, so the detail lists them: they control every client of the site and belong in Tier 0 when DCs or admin workstations are among those clients.'
        Remediation = 'Remove the write, create, WriteDacl and WriteOwner rights of everyone but the site server computer accounts (or a group that contains only them) and Tier 0 from the System Management container; give each site server Full Control as Microsoft documents, nothing more. Protect the site servers and the SCCM admins at the tier of the most sensitive client they manage.' }
    laps_readers = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1098'; Needs = @('deepAcls')
        Title = 'Non-Tier 0 principal can read LAPS passwords'
        Description = 'A principal that is not Tier 0 holds rights to read the local administrator password (ms-Mcs-AdmPwd or msLAPS-Password) on one or more computers, via GenericAll, All Extended Rights, or a read delegation on the LAPS attribute. Reading a LAPS password gives local admin on that machine, a lateral-movement step. Found only with a deep ACL sweep.'
        Remediation = 'Scope LAPS read rights (msLAPS / ms-Mcs-AdmPwd) to the dedicated admin tier for each machine set; remove broad or non-Tier 0 readers.' }
    pre_win2000_anonymous = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1087'; Needs = @('preWin2000')
        Title = 'Pre-Windows 2000 Compatible Access includes Anonymous/Everyone'
        Description = 'The Pre-Windows 2000 Compatible Access group grants broad read of the directory. With Anonymous Logon or Everyone as a member, an unauthenticated attacker can enumerate accounts and groups.'
        Remediation = 'Remove Anonymous Logon (S-1-5-7) and Everyone (S-1-1-0) from the group once no legacy system depends on it.' }

    gmsa_password_readable = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1649'; Needs = @('users', 'groups')
        Title = 'gMSA password readable by a non-Tier 0 principal'
        Description = 'msDS-GroupMSAMembership (PrincipalsAllowedToRetrieveManagedPassword) lets the listed principals retrieve the managed password of this group managed service account. When that principal is not Tier 0, anyone who controls it can recover the gMSA credential and impersonate the service (BloodHound ReadGMSAPassword edge).'
        Remediation = 'Restrict PrincipalsAllowedToRetrieveManagedPassword to the specific host or Tier-matched group that runs the service. Remove broad or non-Tier 0 principals.' }
    shadow_credentials_present = @{ Category = 'Permissions'; Severity = 'High'; Mitre = 'T1556.003'; Needs = @('users')
        Title = 'Key credential set on a privileged account (possible Shadow Credentials)'
        Description = 'The privileged account has one or more msDS-KeyCredentialLink entries. A key credential allows PKINIT/NGC logon with an attacker-held private key, a common persistence and takeover technique (Shadow Credentials / Whisker). Windows Hello for Business and Azure AD join set this legitimately, so each entry on a Tier 0 account must be confirmed.'
        Remediation = 'Verify every key credential on the account against the expected device/registration. Remove unexpected entries and review who holds the write-to-key-credential right on the object.' }

    # ---------------- AD CS (certificate services) ----------------
    adcs_esc1 = @{ Category = 'Certificate Services'; Severity = 'Critical'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Template allows requester-supplied subject with client-auth (ESC1)'
        Description = 'A published template lets a low-privileged enroller supply an arbitrary Subject Alternative Name, issues a certificate usable for client authentication, and requires neither manager approval nor an enrollment agent signature. Anyone who can enroll can obtain a certificate as any account, including a domain admin.'
        Remediation = 'Remove ENROLLEE_SUPPLIES_SUBJECT, or require manager approval, or restrict enrollment to a trusted group. Re-issue affected templates.' }
    adcs_esc2 = @{ Category = 'Certificate Services'; Severity = 'Critical'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Template with Any Purpose or no EKU enrollable by low-privileged users (ESC2)'
        Description = 'A published template grants the Any Purpose EKU (or no EKU at all, a subordinate-CA-equivalent certificate) to low-privileged enrollers with no approval. The resulting certificate can be used for almost anything, including impersonation.'
        Remediation = 'Constrain the template EKUs to what the use case needs, require approval, and restrict enrollment.' }
    adcs_esc3 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Enrollment Agent template enrollable by low-privileged users (ESC3)'
        Description = 'A published template grants the Certificate Request Agent EKU with no approval to low-privileged enrollers. An enrollment agent certificate can request certificates on behalf of other users.'
        Remediation = 'Restrict enrollment-agent templates to a dedicated trusted group and require manager approval.' }
    adcs_esc4 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Certificate template with a dangerous ACL (ESC4)'
        Description = 'A non-privileged principal can modify the template object itself (WriteDacl, WriteOwner, WriteProperty, GenericWrite, GenericAll, Owner). Whoever controls the template can turn it into an ESC1-style template on demand.'
        Remediation = 'Remove write permissions on certificate templates for non-administrators; the template DACL should match a known-good baseline.' }
    adcs_esc9 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Template without the SID security extension (ESC9)'
        Description = 'The template sets CT_FLAG_NO_SECURITY_EXTENSION (msPKI-Enrollment-Flag 0x80000), so the issued certificate omits the szOID_NTDS_CA_SECURITY_EXT SID binding. Combined with an account whose UPN or mapping can be changed, an attacker can obtain a certificate that authenticates as another user even with strong certificate mapping enforced. The template is published, enrollable by low-privileged users and requires no manager approval.'
        Remediation = 'Clear CT_FLAG_NO_SECURITY_EXTENSION on the template unless a documented interoperability need exists, enforce strong certificate mapping (KB5014754 Full enforcement) and restrict enrollment.' }
    adcs_esc17 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1557'; Needs = @('adcs', 'gpo')
        Title = 'WSUS over HTTPS and a template that issues server certificates for any name (ESC17)'
        Description = 'A GPO points Windows Update at a WSUS server over HTTPS, and a published certificate template lets low-privileged users enroll with a subject they supply, for server authentication (or any purpose), without approval. Anyone in that population can get a certificate for the WSUS host name that every client trusts, put themselves in the path (an ADIDNS record, ARP or DHCP spoofing) and serve updates that run as SYSTEM: HTTPS no longer protects WSUS (ESC17, TROOPERS26).'
        Remediation = 'Remove ENROLLEE_SUPPLIES_SUBJECT from the template, or restrict its enrollment to the servers that need it, or require manager approval. Issue the WSUS certificate from a template that builds the subject from AD. Keep ADIDNS record creation restricted so the WSUS name cannot be taken over.' }
    adcs_esc15 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Schema v1 template with requester-supplied subject (ESC15 / EKUwu, CVE-2024-49019)'
        Description = 'A schema version 1 certificate template published and enrollable by low-privileged users allows the requester to supply the subject. On v1 templates the application policies are not fixed, so a requester can inject an arbitrary application policy (for example Client Authentication) into the request and obtain a certificate usable for authentication, even when the template EKUs do not grant it.'
        Remediation = 'Replace v1 templates with v2+ equivalents, remove ENROLLEE_SUPPLIES_SUBJECT, require manager approval, restrict enrollment, and apply the November 2024 AD CS updates.' }
    adcs_esc13 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Template with an issuance policy linked to a group (ESC13)'
        Description = 'The template carries an issuance policy (msPKI-Certificate-Policy) whose OID is linked to an AD group via msDS-OIDToGroupLink. A certificate from this template grants the holder the rights of that group for the certificate lifetime. When the template is enrollable by low-privileged users and the linked group is privileged, enrolling is a direct privilege escalation.'
        Remediation = 'Remove the msDS-OIDToGroupLink on the issuance-policy OID, or restrict enrollment on the template to trusted principals. Review why a certificate issuance policy is bound to a group.' }
    adcs_esc5 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs', 'adcs.pkiAcls')
        Title = 'Non-privileged principal controls an AD CS object (ESC5)'
        Description = 'A principal outside Tier 0 holds control rights (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty, or ownership) on a PKI object in the Configuration partition: the Public Key Services container and its Certificate Templates, Enrollment Services, Certification Authorities, AIA, CDP and OID containers, the NTAuthCertificates store, a CA object, or the computer account of a CA. Control of these objects means adding a trusted root or an NTAuth CA, publishing a vulnerable template, or taking over the CA host: each one ends in certificates for any account.'
        Remediation = 'Remove the ACE or the ownership. PKI objects in the Configuration partition and the CA servers are Tier 0: only Enterprise Admins, Domain Admins of the forest root and the CA computer accounts should hold write rights there.' }
    adcs_low_priv_enroll = @{ Category = 'Certificate Services'; Severity = 'Medium'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'Client-auth template enrollable by all users'
        Description = 'A published template that allows client authentication can be enrolled by Domain Users / Authenticated Users. Not exploitable on its own, but it is the surface every ESC technique builds on, and worth reviewing.'
        Remediation = 'Restrict enrollment to the groups that actually need each template.' }
    adcs_ca_cert_expiring = @{ Category = 'Certificate Services'; Severity = 'Medium'; Mitre = ''; Needs = @('adcs')
        Title = 'CA certificate expiring or expired'
        Description = 'A CA certificate is close to expiry or already expired. Expiry disrupts every certificate the CA issues (auth, VPN, LDAPS).'
        Remediation = 'Plan CA certificate renewal well ahead; expiry of an issuing or root CA is a major outage.' }
    adcs_weak_ca_key = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'CA certificate uses a weak key or signature'
        Description = 'The CA certificate has an RSA key shorter than 2048 bits or is signed with SHA-1. A weak CA key or signature undermines every certificate the CA issues, including those used for authentication.'
        Remediation = 'Re-key the CA with a 3072-bit (or stronger) RSA key and a SHA-256 signature, then reissue subordinate and end-entity certificates. Plan this as a CA migration.' }
    adcs_esc6 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs', 'adcs.caRegistry')
        Title = 'CA accepts a requester-supplied SAN on any request (ESC6)'
        Description = 'EDITF_ATTRIBUTESUBJECTALTNAME2 is set in the CA policy module: every request may add a subject alternative name, so any template a user can enroll in becomes an ESC1. Since the 2022 strong-mapping updates it still leads to impersonation when the SID extension is missing (ESC16) or certificate mapping is weak (ESC10).'
        Remediation = 'certutil -config "<CA>" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then restart CertSvc. Check that no template needs it.' }
    adcs_esc7 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs', 'adcs.caRegistry')
        Title = 'Non-Tier 0 principal can manage the CA (ESC7)'
        Description = 'A principal outside Tier 0 holds Manage CA or Issue and Manage Certificates on the CA. Manage CA can turn on ESC6 or enable any template; Issue and Manage Certificates can approve a pending request for a domain admin certificate.'
        Remediation = 'Remove the right from the CA security settings (certsrv.msc > Properties > Security), and keep CA administration in Tier 0.' }
    adcs_esc8 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1557.001'; Needs = @('adcs', 'adcs.caRegistry', 'adcs.caWebEnrollment')
        Title = 'Web enrollment on the CA (ESC8 NTLM relay)'
        Description = 'Certification Authority Web Enrollment or the Certificate Enrollment Web Service is installed on the CA. Over HTTP, or HTTPS without Extended Protection for Authentication, a coerced DC authentication can be relayed to it for a DC certificate and domain takeover (PetitPotam + ESC8). IDWolf cannot read the IIS settings, so HTTPS and EPA must be confirmed by hand.'
        Remediation = 'Remove web enrollment if it is not needed. Otherwise require HTTPS, enable Extended Protection for Authentication and disable NTLM on the CertSrv / CES sites.' }
    adcs_esc11 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1557.001'; Needs = @('adcs', 'adcs.caRegistry')
        Title = 'CA does not require encrypted RPC requests (ESC11)'
        Description = 'IF_ENFORCEENCRYPTICERTREQUEST is not set in InterfaceFlags, so certificate requests over RPC (ICPR) can be sent without packet privacy and an NTLM authentication can be relayed to the CA, like ESC8 over RPC.'
        Remediation = 'certutil -config "<CA>" -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST, then restart CertSvc (check old clients first).' }
    adcs_esc16 = @{ Category = 'Certificate Services'; Severity = 'High'; Mitre = 'T1649'; Needs = @('adcs', 'adcs.caRegistry')
        Title = 'CA no longer adds the SID security extension (ESC16)'
        Description = 'The CA policy module lists 1.3.6.1.4.1.311.25.2 in DisableExtensionList, so no certificate carries the requester SID. Strong certificate mapping then falls back to the weak UPN / DNS mapping for every template, which re-opens ESC9/ESC10-style impersonation CA-wide.'
        Remediation = 'certutil -config "<CA>" -setreg policy\DisableExtensionList -1.3.6.1.4.1.311.25.2, restart CertSvc, and keep StrongCertificateBindingEnforcement = 2 on the DCs.' }
    adcs_manual_checks = @{ Category = 'Certificate Services'; Severity = 'Low'; Mitre = 'T1649'; Needs = @('adcs')
        Title = 'AD CS checks not verified on the CA (ESC6/ESC7/ESC8/ESC11/ESC16)'
        Description = 'Some AD CS weaknesses are not visible in LDAP: EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (ESC6), CA role delegation (ESC7), HTTP/NTLM web enrollment relay (ESC8), RPC enrollment without IF_ENFORCEENCRYPTICERTREQUEST (ESC11, NTLM relay to ICPR), and the SID security extension disabled CA-wide (ESC16). IDWolf flags that a CA exists so these are verified manually or with a dedicated tool.'
        Remediation = 'On each CA: certutil -getreg policy\\EditFlags (ESC6 = EDITF_ATTRIBUTESUBJECTALTNAME2 set); review Manage CA / Issue and Manage Certificates delegation (ESC7); disable HTTP web enrollment or enforce EPA/HTTPS (ESC8); certutil -getreg CA\\InterfaceFlags must include IF_ENFORCEENCRYPTICERTREQUEST (ESC11); certutil -getreg policy\\DisableExtensionList must not list 1.3.6.1.4.1.311.25.2 (ESC16).' }
}

$script:SeverityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }

# --------------------------------------------------------------------------
# ACL helpers
# --------------------------------------------------------------------------
$script:EmptyGuid = '00000000-0000-0000-0000-000000000000'
$script:AdGuids = @{
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'member'
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'msDS-KeyCredentialLink'
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'servicePrincipalName'
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'msDS-AllowedToActOnBehalfOfOtherIdentity'
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1' = 'gPLink'
    # From Adalanche's edge list: each is a takeover on its own.
    '00fbf30c-91fe-11d1-aebc-0000f80367c1' = 'altSecurityIdentities'   # map an attacker certificate to the account (ESC14)
    'bf9679a8-0de6-11d0-a285-00aa003049e2' = 'scriptPath'              # logon script runs as the user
    'bf967a05-0de6-11d0-a285-00aa003049e2' = 'profilePath'             # roaming profile on an attacker share
    'bf967a68-0de6-11d0-a285-00aa003049e2' = 'userAccountControl'      # e.g. turn off pre-auth, then AS-REP roast
    # Property set that holds msDS-AllowedToActOnBehalfOfOtherIdentity: write it, configure RBCD (BloodHound WriteAccountRestrictions).
    '4c164200-20c0-11d0-a768-00aa003049e2' = 'User-Account-Restrictions'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    'bf967aba-0de6-11d0-a285-00aa003049e2' = 'user objects'
    'bf967a9c-0de6-11d0-a285-00aa003049e2' = 'group objects'
    'bf967a86-0de6-11d0-a285-00aa003049e2' = 'computer objects'
    '4828cc14-1437-45bc-9b07-ad6f015e5f28' = 'inetOrgPerson objects'
    'ce206244-5827-4a86-ba1c-1c0c386c1b64' = 'msDS-ManagedServiceAccount objects'
    '7b8b558a-93a5-4af7-adca-e017e67f1057' = 'msDS-GroupManagedServiceAccount objects'
    '0feb936f-47b3-49f2-9386-1dedc2c23765' = 'msDS-DelegatedManagedServiceAccount objects'
}
$script:DangerousWriteProps = @('bf9679c0-0de6-11d0-a285-00aa003049e2', '5b47d60f-6090-40b2-9f37-2a4de88f3063', 'f3a64788-5306-11d1-a9c5-0000f80367c1', '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79', 'f30e3bbe-9ff0-11d1-b603-0000f80367c1',
    '00fbf30c-91fe-11d1-aebc-0000f80367c1', 'bf9679a8-0de6-11d0-a285-00aa003049e2', 'bf967a05-0de6-11d0-a285-00aa003049e2', 'bf967a68-0de6-11d0-a285-00aa003049e2',
    '4c164200-20c0-11d0-a768-00aa003049e2')
$script:DangerousExtRights = @('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '00299570-246d-11d0-a768-00aa006e0529')

function Get-DefaultAclPrincipals {
    param($Index)
    $d = $Index.DomainSid; $r = $Index.RootSid
    return @(
        'S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0', 'S-1-5-10',
        "$d-512", "$d-516", "$d-521", "$d-526",
        "$r-519", "$r-498", "$r-527"
    )
}

# SIDs that are expected to hold rights: directory defaults plus everything Tier 0.
function Get-Tier0SidSet {
    param($Index, $PrivMap)
    $set = @{}
    foreach ($s in (Get-DefaultAclPrincipals $Index)) { $set[$s] = $true }
    foreach ($s in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-9', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-551', 'S-1-5-32-550')) { $set[$s] = $true }
    foreach ($rid in @(512, 516, 518, 519, 520, 521, 526, 527)) { $set["$($Index.DomainSid)-$rid"] = $true; $set["$($Index.RootSid)-$rid"] = $true }
    if ($PrivMap) {
        foreach ($rec in $PrivMap.Principals.Values) { if ($rec.Principal -and $rec.Principal.sid) { $set[$rec.Principal.sid] = $true } }
        foreach ($e in $PrivMap.Groups.Values) { if ($e.Group -and $e.Group.sid) { $set[$e.Group.sid] = $true } }
    }
    return $set
}

function Get-GuidName {
    param([string]$Guid)
    if (-not $Guid -or $Guid -eq $script:EmptyGuid) { return 'all' }
    $n = $script:AdGuids[$Guid.ToLower()]
    if ($n) { return $n }
    return $Guid
}

# Returns a short label of what makes the ACE dangerous, or $null.
function Get-AceDanger {
    param($Ace)
    if ($Ace.accessType -ne 'Allow') { return $null }
    $rights = "$($Ace.rights)"
    $ot = "$($Ace.objectType)".ToLower()
    $labels = New-Object System.Collections.Generic.List[string]
    foreach ($r in @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite')) {
        if ($rights -match "\b$r\b") { $labels.Add($r) }
    }
    if ($rights -match '\bWriteProperty\b' -and ($ot -eq $script:EmptyGuid -or $ot -eq '' -or $script:DangerousWriteProps -contains $ot)) {
        $labels.Add("WriteProperty($(Get-GuidName $ot))")
    }
    if ($rights -match '\bExtendedRight\b' -and ($ot -eq $script:EmptyGuid -or $ot -eq '' -or $script:DangerousExtRights -contains $ot)) {
        $labels.Add("ExtendedRight($(Get-GuidName $ot))")
    }
    if ($rights -match '\bSelf\b' -and $ot -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2') {
        $labels.Add('Self(member)')
    }
    if ($labels.Count -eq 0) { return $null }
    return ($labels -join ', ')
}

# True when the ACE applies to the object itself (not only to children).
function Test-AceAppliesToSelf {
    param($Ace)
    return @('None', 'All', 'SelfAndChildren') -contains "$($Ace.inheritanceType)"
}

# --------------------------------------------------------------------------
# Findings plumbing
# --------------------------------------------------------------------------
function Add-Finding {
    param(
        [string]$Type, [string]$Object, [string]$ObjectType = '', [string]$ObjectDn = '',
        [string]$Detail, [string]$Severity = ''
    )
    $meta = $script:CheckCatalog[$Type]
    if (-not $meta) { throw "Unknown check type: $Type" }
    if (-not $Severity) { $Severity = $meta.Severity }
    $script:Findings.Add([PSCustomObject]@{
            Severity   = $Severity
            Type       = $Type
            Title      = $meta.Title
            Category   = $meta.Category
            Object     = $Object
            ObjectType = $ObjectType
            ObjectDn   = $ObjectDn
            Detail     = $Detail
            Mitre      = $meta.Mitre
        })
}

function Get-NotEvaluatedChecks {
    param($Index, $Snapshot)
    $result = New-Object System.Collections.Generic.List[object]
    $failed = @($Index.CollectionErrorSections.Keys)
    $skipped = @()
    if ($Snapshot.meta.options.skipSysvol) { $skipped += 'sysvol' }
    if ($Snapshot.meta.options.skipAcl) { $skipped += 'acl' }
    # Sections this run didn't gather at all (skipped, or no -Deep).
    $absentReasons = @{}
    if (-not $Snapshot.meta.options.deep) { $absentReasons['deepAcls'] = "requires -Deep collection (privileged, full ACL sweep)" }
    elseif (-not $Snapshot.PSObject.Properties['kdsRootKeyAcls']) { $absentReasons['kdsRootKeys'] = 'snapshot from an older collector (no KDS root key permissions): re-collect with -Deep' }
    if (-not $Snapshot.meta.options.skipAcl -and -not $Snapshot.PSObject.Properties['ouAcls']) { $absentReasons['ouAcls'] = 'snapshot from an older collector (no OU and container permissions): re-collect' }
    # Its own read, independent of the Tier 0 ACLs: only -SkipAcl or an older collector leave it out.
    if ($Snapshot.meta.options.skipAcl) { $absentReasons['sccm'] = 'ACL collection skipped (-SkipAcl)' }
    elseif (-not $Snapshot.PSObject.Properties['sccm']) { $absentReasons['sccm'] = 'snapshot from an older collector (no SCCM System Management container): re-collect' }
    if ($null -eq $Snapshot.preWin2000) { $absentReasons['preWin2000'] = 'Pre-Windows 2000 group could not be read' }
    # No AD CS at all is not a gap; skipping it or failing to read it is.
    if ($Snapshot.meta.options.skipAdcs) { $absentReasons['adcs'] = 'AD CS collection skipped (-SkipAdcs)' }
    elseif ((-not $Snapshot.adcs -or -not $Snapshot.adcs.collected) -and -not ($Snapshot.adcs.notDeployed)) {
        $absentReasons['adcs'] = 'AD CS could not be read'
    }
    elseif ($Snapshot.adcs.collected -and -not $Snapshot.adcs.PSObject.Properties['pkiAcls']) { $absentReasons['adcs.pkiAcls'] = 'snapshot from an older collector (no ACLs of the PKI objects): re-collect' }
    if ($Snapshot.adcs -and $Snapshot.adcs.collected) {
        $cas = @($Snapshot.adcs.enrollmentServices | Where-Object { $_ })
        $caNoReg = @($cas | Where-Object { -not $_.PSObject.Properties['caRegistry'] -or -not $_.caRegistry -or $_.caRegistry.error })
        if ($caNoReg.Count -gt 0) {
            $absentReasons['adcs.caRegistry'] = "CA settings not read on $(@($caNoReg | ForEach-Object { if ($_.PSObject.Properties['caRegistry'] -and $_.caRegistry -and $_.caRegistry.error) { "$($_.name) ($($_.caRegistry.error))" } else { "$($_.name) (older collector)" } }) -join ', ') (needs admin rights on the CA host)"
        }
        $caNoWeb = @($cas | Where-Object { $_.PSObject.Properties['caRegistry'] -and $_.caRegistry -and -not $_.caRegistry.error -and $null -eq $_.caRegistry.webEnrollment })
        if ($caNoWeb.Count -gt 0) {
            $absentReasons['adcs.caWebEnrollment'] = "installed CA roles could not be identified on $(@($caNoWeb | ForEach-Object { $_.name }) -join ', ') (non-English server or no role information): check web enrollment by hand"
        }
    }
    # Only an RODC has a password replication policy; without one there is nothing to read.
    if (@($Snapshot.domainControllers | Where-Object { $_ -and $_.isReadOnly -and -not $_.PSObject.Properties['rodcPolicy'] }).Count -gt 0) {
        $absentReasons['rodcPolicy'] = 'snapshot from an older collector (no RODC password replication policy): re-collect'
    }
    if ($Snapshot.meta.options.skipGpo) { $absentReasons['gpo'] = 'GPO collection skipped (-SkipGpo)' }
    elseif (-not $Snapshot.gpo -or -not $Snapshot.gpo.collected) { $absentReasons['gpo'] = 'GPO security templates could not be read from SYSVOL' }
    elseif (-not $Snapshot.gpo.PSObject.Properties['execution']) { $absentReasons['gpo.execution'] = 'snapshot from an older collector (no GPO scripts, tasks or local groups): re-collect' }
    if (@($Snapshot.users | Where-Object { $_ -and -not $_.PSObject.Properties['altSecIdTypes'] }).Count -gt 0) {
        $absentReasons['users.altSecId'] = 'snapshot from an older collector (no certificate mappings): re-collect'
    }
    if ($Snapshot.sysvol -and $Snapshot.sysvol.scanned -and -not $Snapshot.sysvol.PSObject.Properties['folderAcls']) {
        $absentReasons['sysvol.acl'] = 'snapshot from an older collector (no NETLOGON / Policies folder permissions): re-collect'
    }
    if ($Snapshot.sysvol -and $Snapshot.sysvol.scanned -and -not $Snapshot.sysvol.PSObject.Properties['autologonFiles']) {
        $absentReasons['sysvol.autologon'] = 'snapshot from an older collector (no Group Policy Preferences autologon scan): re-collect'
    }
    if ($Snapshot.gpo -and $Snapshot.gpo.collected -and @($Snapshot.gpo.gpos | Where-Object { $_ -and $_.PSObject.Properties['kerberosPolicy'] }).Count -eq 0) {
        $absentReasons['gpo.kerberos'] = 'snapshot from an older collector (no Kerberos policy from the GPO security templates): re-collect'
    }
    if ($Snapshot.gpo -and $Snapshot.gpo.collected -and @($Snapshot.gpo.gpos | Where-Object { $_ -and -not $_.PSObject.Properties['serviceStart'] }).Count -gt 0) {
        $absentReasons['gpo.services'] = 'snapshot from an older collector (no GPO service startup settings): re-collect'
    }
    if ($Snapshot.meta.options.skipDns) { $absentReasons['dns'] = 'DNS collection skipped (-SkipDns)' }
    elseif (-not $Snapshot.dns -or -not $Snapshot.dns.collected) { $absentReasons['dns'] = 'DNS not collected (DnsServer module or RPC unavailable)' }
    elseif ("$($Snapshot.dns.source)" -eq 'ldap') { $absentReasons['dnsTransfer'] = 'DNS zones read over LDAP (no DNS RPC rights): the zone transfer setting is only in the DNS server registry; collect as DnsAdmins/admin to evaluate it' }
    if ($Snapshot.dns.collected -and @($Snapshot.dns.zones | Where-Object { $_ -and $_.isAdIntegrated -and -not $_.PSObject.Properties['createChildSids'] }).Count -gt 0) {
        $absentReasons['dnsZoneAcl'] = 'snapshot from an older collector (no DNS zone permissions): re-collect'
    }
    if ($Snapshot.meta.options.skipHealth) { $absentReasons['health'] = 'operational health collection skipped (-SkipHealth)' }
    elseif (-not $Snapshot.health -or -not $Snapshot.health.collected) { $absentReasons['health'] = 'operational health not collected (replication/DHCP/backup metadata unavailable)' }
    else {
        foreach ($s in 'fsmo', 'dcReachability', 'dcTime', 'dcState') {
            if (-not $Snapshot.health.PSObject.Properties[$s]) { $absentReasons["health.$s"] = 'snapshot from an older collector: re-collect' }
        }
        if (@($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error -and -not $_.PSObject.Properties['webClientStartMode'] }).Count -gt 0) {
            $absentReasons['health.webClient'] = 'snapshot from an older collector (no WebClient service state on the DCs): re-collect'
        }
        if (@($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error -and -not $_.PSObject.Properties['dsrmAdminLogonBehavior'] }).Count -gt 0) {
            $absentReasons['health.dsrm'] = 'snapshot from an older collector (no DSRM admin logon behavior on the DCs): re-collect'
        }
        if (@($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error -and -not $_.PSObject.Properties['coercionServices'] }).Count -gt 0) {
            $absentReasons['health.coercion'] = 'snapshot from an older collector (no coercion services or RPC filters on the DCs): re-collect'
        }
        if (@($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error -and -not $_.PSObject.Properties['netbiosAdapters'] }).Count -gt 0) {
            $absentReasons['health.netbios'] = 'snapshot from an older collector (no NetBIOS adapter settings on the DCs): re-collect'
        }
        if (@($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error -and -not $_.PSObject.Properties['osBuild'] }).Count -gt 0) {
            $absentReasons['health.osBuild'] = 'snapshot from an older collector (no DC build and update revision): re-collect'
        }
        else {
            $noBuild = @($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error } | Where-Object { $null -eq (Get-NoPacStatus $_) })
            if ($noBuild.Count -gt 0) {
                $absentReasons['health.osBuildUnknown'] = "patch level could not be verified on $(@($noBuild | ForEach-Object { "$($_.dc) (build $($_.osBuild)$(if ($null -ne $_.osUbr) { ".$($_.osUbr)" } else { ', no update revision' }))" }) -join ', '): check by hand that the November 2021 updates (or later) are installed"
            }
        }
        # Some DCs read, some refused (unreachable DCs have their own finding): the live checks
        # only cover part of the DCs, which must not look like a clean result for the others.
        $dcRead = @($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error })
        $dcDenied = @($Snapshot.health.dcState | Where-Object { $_ -and $_.error -and "$($_.error)" -ne 'not reachable' })
        if ($dcRead.Count -gt 0 -and $dcDenied.Count -gt 0) {
            $absentReasons['health.dcStatePartial'] = "only partly evaluated: could not read $(@($dcDenied | ForEach-Object { "$($_.dc) ($($_.error))" }) -join ', ') (needs admin rights on each DC)"
        }
    }
    if (@($Snapshot.trusts | Where-Object { $_ -and -not $_.PSObject.Properties['whenChanged'] }).Count -gt 0) {
        $absentReasons['trusts.whenChanged'] = 'snapshot from an older collector (no trust object change date): re-collect'
    }
    if (-not $Snapshot.domain.PSObject.Properties['possSuperiorClasses']) { $absentReasons['domain.possSuperiors'] = 'snapshot from an older collector (no schema possSuperiors probe): re-collect' }
    if (-not $Snapshot.domain.PSObject.Properties['javaSchemaClasses']) { $absentReasons['domain.javaSchema'] = 'snapshot from an older collector (no Java schema probe): re-collect' }
    if ($null -eq $Snapshot.domain.subnetCount) { $absentReasons['sites'] = 'Sites/subnets could not be read from the Configuration partition' }
    if (-not $Snapshot.domain.sysvolReplication) { $absentReasons['sysvolReplication'] = 'SYSVOL replication engine could not be determined' }
    if (-not $Snapshot.passwordQuality) { $absentReasons['passwordQuality'] = 'no password-quality report supplied (run Export-PasswordQuality.ps1, pass -PasswordQualityFile)' }
    # Without a weak-password list DSInternals can't tell a breached password from a good one: the list stays empty.
    elseif ($Snapshot.passwordQuality.PSObject.Properties['weakListUsed'] -and $Snapshot.passwordQuality.weakListUsed -eq $false) {
        $absentReasons['passwordQualityWeakList'] = 'the password-quality report was made without a weak/breached password list (Export-PasswordQuality.ps1 -WeakPasswordsFile): no breached password could be found, so nothing here means clean'
    }
    # One bad GPO or a missing NTAuth object shouldn't sink every GPO or AD CS
    # check: for these, only the section-level "collected" flag counts.
    $containerNeeds = @('adcs', 'gpo', 'health')
    foreach ($type in $script:CheckCatalog.Keys) {
        $meta = $script:CheckCatalog[$type]
        $reasons = @()
        foreach ($need in $meta.Needs) {
            foreach ($f in $failed) {
                if ($f -eq $need) { $reasons += "collection of '$f' failed: $($Index.CollectionErrorSections[$f])" }
                elseif ($f.StartsWith("$need.") -and $containerNeeds -notcontains $need) { $reasons += "collection of '$f' failed: $($Index.CollectionErrorSections[$f])" }
            }
            foreach ($s in $skipped) {
                if ($need -eq $s -or $need.StartsWith("$s.")) { $reasons += "section '$s' skipped at collection time" }
            }
            if ($absentReasons.ContainsKey($need)) { $reasons += $absentReasons[$need] }
        }
        if ($reasons.Count -gt 0) {
            $result.Add([PSCustomObject]@{ Type = $type; Title = $meta.Title; Reason = (($reasons | Select-Object -Unique) -join '; ') })
        }
    }
    return $result
}

# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
function Invoke-ADHygieneChecks {
    param($Snapshot, $Index, $PrivMap, [hashtable]$Config)

    $script:Findings = New-Object System.Collections.Generic.List[object]
    $dom = $Index.DomainSid

    $enabledUsers = @($Index.Users | Where-Object { $_.enabled })
    $humanUsers = @($enabledUsers | Where-Object { $_.kind -eq 'user' })

    # ======================= Kerberos =======================
    $krbtgt = $Index.BySid["$dom-502"]
    if ($krbtgt) {
        $age = Get-AgeDays $krbtgt.pwdLastSet
        if ($null -eq $age -or $age -gt $Config.KrbtgtMaxAgeDays) {
            $sev = if ($null -eq $age -or $age -gt $Config.KrbtgtCriticalDays) { 'Critical' } else { 'High' }
            Add-Finding -Type krbtgt_password_old -Object $krbtgt.samAccountName -ObjectType 'user' -ObjectDn $krbtgt.distinguishedName -Severity $sev `
                -Detail "krbtgt password last set $(Format-Age $age) ago (threshold $($Config.KrbtgtMaxAgeDays) days, critical above $($Config.KrbtgtCriticalDays))."
        }
    }
    foreach ($u in @($Index.Users | Where-Object { $_.samAccountName -match '^krbtgt_\d+$' })) {
        $age = Get-AgeDays $u.pwdLastSet
        if ($null -eq $age -or $age -gt $Config.KrbtgtMaxAgeDays) {
            Add-Finding -Type rodc_krbtgt_password_old -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail "RODC krbtgt password last set $(Format-Age $age) ago."
        }
    }
    # Hybrid keys Entra ID holds for this domain: Seamless SSO and cloud Kerberos trust.
    $ssoMax = if ($Config.ContainsKey('SsoKeyMaxAgeDays')) { [int]$Config.SsoKeyMaxAgeDays } else { 30 }
    foreach ($c in @($Index.Computers | Where-Object { "$($_.samAccountName)" -ieq 'AZUREADSSOACC$' })) {
        $age = Get-AgeDays $c.pwdLastSet
        if ($null -eq $age -or $age -gt $ssoMax) {
            $sev = if ($null -eq $age -or $age -gt 365) { 'High' } else { 'Medium' }
            Add-Finding -Type azuread_sso_key_old -Object $c.samAccountName -ObjectType 'computer' -ObjectDn $c.distinguishedName -Severity $sev `
                -Detail "Seamless SSO key last rolled over $(Format-Age $age) ago (Microsoft recommends every $ssoMax days)."
        }
    }
    foreach ($u in @($Index.Users | Where-Object { "$($_.samAccountName)" -ieq 'krbtgt_AzureAD' })) {
        $age = Get-AgeDays $u.pwdLastSet
        if ($null -eq $age -or $age -gt $Config.KrbtgtMaxAgeDays) {
            $sev = if ($null -eq $age -or $age -gt $Config.KrbtgtCriticalDays) { 'High' } else { 'Medium' }
            Add-Finding -Type cloud_kerberos_trust_key_old -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName -Severity $sev `
                -Detail "Entra Kerberos server key last set $(Format-Age $age) ago (threshold $($Config.KrbtgtMaxAgeDays) days)."
        }
    }

    foreach ($u in $humanUsers) {
        if ($u.samAccountName -eq 'krbtgt' -or $u.samAccountName -match '^krbtgt_\d+$') { continue }
        $isPriv = Test-IsPrivileged $PrivMap $u
        $spns = @($u.servicePrincipalNames | Where-Object { $_ })
        $pwdAge = Get-AgeDays $u.pwdLastSet
        $enc = $u.supportedEncryptionTypes

        if ($spns.Count -gt 0) {
            $spnText = ($spns | Select-Object -First 3) -join ', '
            if ($spns.Count -gt 3) { $spnText += " (+$($spns.Count - 3) more)" }
            if ($isPriv) {
                Add-Finding -Type privileged_kerberoastable -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                    -Detail "Member of $(Get-PrivilegedGroupsText $PrivMap $u). SPN: $spnText. Password age: $(Format-Age $pwdAge)."
            }
            else {
                $sev = if ($null -ne $pwdAge -and $pwdAge -gt $Config.PasswordMaxAgeDays) { 'High' } else { 'Medium' }
                Add-Finding -Type kerberoastable_user -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName -Severity $sev `
                    -Detail "SPN: $spnText. Password age: $(Format-Age $pwdAge)$(if ($sev -eq 'High') { " (over $($Config.PasswordMaxAgeDays) days)" })."
            }
            if ($null -eq $enc -or [int64]$enc -eq 0) {
                Add-Finding -Type spn_account_rc4 -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                    -Detail 'msDS-SupportedEncryptionTypes not set: encryption type falls back to domain/DC defaults, RC4 possible.'
            }
            elseif (([int64]$enc -band $script:ENC_AES) -eq 0) {
                Add-Finding -Type spn_account_rc4 -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName -Severity 'High' `
                    -Detail "msDS-SupportedEncryptionTypes = ${enc}: no AES, only RC4/DES tickets."
            }
        }

        if (Test-Uac $u 'DONT_REQ_PREAUTH') {
            $sev = if ($isPriv) { 'Critical' } else { 'High' }
            Add-Finding -Type asrep_roastable -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName -Severity $sev `
                -Detail "Pre-authentication disabled$(if ($isPriv) { " on a privileged account ($(Get-PrivilegedGroupsText $PrivMap $u))" }). Password age: $(Format-Age $pwdAge)."
        }
    }

    # sMSAs with an SPN can have a human-set password (vulnerable-AD does
    # exactly that), so they are Kerberoastable. gMSAs are not.
    foreach ($m in @($Index.Users | Where-Object { $_.enabled -and $_.kind -eq 'msa' -and $_.isGroupManaged -ne $true })) {
        $spns = @($m.servicePrincipalNames | Where-Object { $_ })
        if ($spns.Count -eq 0) { continue }
        $spnText = ($spns | Select-Object -First 3) -join ', '
        if ($spns.Count -gt 3) { $spnText += " (+$($spns.Count - 3) more)" }
        if (Test-IsPrivileged $PrivMap $m) {
            Add-Finding -Type privileged_kerberoastable -Object $m.samAccountName -ObjectType 'msa' -ObjectDn $m.distinguishedName `
                -Detail "Standalone MSA in $(Get-PrivilegedGroupsText $PrivMap $m). SPN: $spnText."
        }
        else {
            Add-Finding -Type kerberoastable_user -Object $m.samAccountName -ObjectType 'msa' -ObjectDn $m.distinguishedName `
                -Detail "Standalone managed service account (sMSA) with SPN and a settable password. SPN: $spnText."
        }
        $enc = $m.supportedEncryptionTypes
        if ($null -eq $enc -or [int64]$enc -eq 0 -or ([int64]$enc -band $script:ENC_AES) -eq 0) {
            Add-Finding -Type spn_account_rc4 -Object $m.samAccountName -ObjectType 'msa' -ObjectDn $m.distinguishedName `
                -Detail "sMSA msDS-SupportedEncryptionTypes = $(if ($null -eq $enc) { 'not set' } else { $enc }): RC4 possible."
        }
    }

    # Every SPN and host name in the snapshot, to spot delegation targets nobody holds (SPN-jacking).
    # A computer answers for every service class on its host names (HOST/ covers cifs/, http/...).
    $domSuffix = ".$("$($Snapshot.domain.dnsRoot)".ToLower())"
    $knownSpns = @{}; $knownHosts = @{}
    foreach ($o in @($Index.Users) + @($Index.Computers)) {
        foreach ($s in @($o.servicePrincipalNames | Where-Object { $_ })) {
            $sl = "$s".ToLower(); $knownSpns[$sl] = $true
            $sp = $sl -split '/'
            if ($sp.Count -ge 2) { $knownSpns["$($sp[0])/$(($sp[1] -split ':')[0])"] = $true }
        }
        if ($o._type -eq 'computer') {
            if ($o.dnsHostName) { $knownHosts["$($o.dnsHostName)".ToLower()] = $true }
            if ($o.samAccountName) { $knownHosts["$($o.samAccountName)".TrimEnd('$').ToLower()] = $true }
        }
    }

    $enabledPrincipals = @($enabledUsers) + @($Index.Computers | Where-Object { $_.enabled })
    foreach ($p in $enabledPrincipals) {
        $ptype = $p._type
        $isDc = ($ptype -eq 'computer' -and $p._isDc)

        if (-not $isDc -and (Test-Uac $p 'TRUSTED_FOR_DELEGATION')) {
            $extra = if ($ptype -eq 'computer' -and $p.operatingSystem) { " OS: $($p.operatingSystem)." } else { '' }
            Add-Finding -Type unconstrained_delegation -Object $p.samAccountName -ObjectType $ptype -ObjectDn $p.distinguishedName `
                -Detail "TRUSTED_FOR_DELEGATION set on a $ptype that is not a domain controller.$extra"
        }

        $targets = @($p.allowedToDelegateTo | Where-Object { $_ })
        if ($targets.Count -gt 0 -and -not $isDc) {
            $dcTargets = @($targets | Where-Object {
                    $hostPart = ($_ -split '/')[1]
                    if ($hostPart) { $hostPart = ($hostPart -split ':')[0].ToLower() }
                    $hostPart -and ($Index.DcHostNames.ContainsKey($hostPart) -or $Index.DcHostNames.ContainsKey(($hostPart -split '\.')[0]))
                })
            $tText = ($targets | Select-Object -First 4) -join ', '
            if ($targets.Count -gt 4) { $tText += " (+$($targets.Count - 4) more)" }
            $dcNote = if ($dcTargets.Count -gt 0) { " Targets include domain controller services: $($dcTargets -join ', ')." } else { '' }
            if (Test-Uac $p 'TRUSTED_TO_AUTH_FOR_DELEGATION') {
                $sev = if ($dcTargets.Count -gt 0) { 'Critical' } else { 'High' }
                Add-Finding -Type constrained_delegation_protocol_transition -Object $p.samAccountName -ObjectType $ptype -ObjectDn $p.distinguishedName -Severity $sev `
                    -Detail "Protocol transition (any-auth) to: $tText.$dcNote"
            }
            else {
                $sev = if ($dcTargets.Count -gt 0) { 'Critical' } else { 'Medium' }
                Add-Finding -Type constrained_delegation -Object $p.samAccountName -ObjectType $ptype -ObjectDn $p.distinguishedName -Severity $sev `
                    -Detail "Kerberos-only constrained delegation to: $tText.$dcNote"
            }
            # Only hosts of this domain (not of a child): a target elsewhere can't be judged from here.
            $orphans = @($targets | Where-Object {
                    $parts = "$_".ToLower() -split '/'
                    if ($parts.Count -lt 2) { return $false }
                    $h = ($parts[1] -split ':')[0]
                    if (-not $h) { return $false }
                    if ($h.Contains('.') -and -not ($h.EndsWith($domSuffix) -and -not $h.Substring(0, $h.Length - $domSuffix.Length).Contains('.'))) { return $false }
                    -not ($knownSpns.ContainsKey("$_".ToLower()) -or $knownSpns.ContainsKey("$($parts[0])/$h") -or $knownHosts.ContainsKey($h) -or $knownHosts.ContainsKey(($h -split '\.')[0]))
                })
            if ($orphans.Count -gt 0) {
                $t2a = Test-Uac $p 'TRUSTED_TO_AUTH_FOR_DELEGATION'
                $sev = if ($t2a) { 'High' } else { 'Medium' }
                Add-Finding -Type delegation_orphan_spn -Object $p.samAccountName -ObjectType $ptype -ObjectDn $p.distinguishedName -Severity $sev `
                    -Detail "Delegation targets held by no account in the snapshot: $($orphans -join ', ').$(if ($t2a) { ' Protocol transition is enabled: no user ticket is needed to use them.' })"
            }
        }

        $rbcd = @($p.rbcdPrincipals | Where-Object { $_ })
        if ($rbcd.Count -gt 0) {
            $names = @($rbcd | ForEach-Object { $o = $Index.ByDn["$_".ToLower()]; if ($o -and $o.samAccountName) { $o.samAccountName } else { $_ } })
            $sev = if ($isDc) { 'Critical' } else { 'Medium' }
            Add-Finding -Type rbcd_configured -Object $p.samAccountName -ObjectType $ptype -ObjectDn $p.distinguishedName -Severity $sev `
                -Detail "Principals allowed to act on behalf of other identities: $($names -join ', ').$(if ($isDc) { ' Target is a DOMAIN CONTROLLER.' })"
        }

        $enc = $p.supportedEncryptionTypes
        if ((Test-Uac $p 'USE_DES_KEY_ONLY') -or ($null -ne $enc -and ([int64]$enc -band $script:ENC_DES) -ne 0)) {
            Add-Finding -Type des_enabled -Object $p.samAccountName -ObjectType $ptype -ObjectDn $p.distinguishedName `
                -Detail "USE_DES_KEY_ONLY: $(Test-Uac $p 'USE_DES_KEY_ONLY'); msDS-SupportedEncryptionTypes: $(if ($null -eq $enc) { 'not set' } else { $enc })."
        }
    }

    # Privileged accounts that can be delegated
    foreach ($rec in $PrivMap.Principals.Values) {
        $u = $rec.Principal
        if (-not $u -or $u._type -ne 'user' -or $u.kind -ne 'user' -or -not $u.enabled) { continue }
        if ($u.samAccountName -eq 'krbtgt') { continue }
        $inPU = $PrivMap.ProtectedUsersSet.ContainsKey($u.distinguishedName.ToLower())
        if (-not (Test-Uac $u 'NOT_DELEGATED') -and -not $inPU) {
            Add-Finding -Type privileged_account_delegable -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail "Member of $($rec.Groups -join ', '); not in Protected Users and NOT_DELEGATED not set."
        }
    }

    if ($PrivMap.ProtectedUsersGroup) {
        $puCount = @($PrivMap.ProtectedUsersSet.Keys).Count
        if ($puCount -eq 0 -and $PrivMap.Principals.Count -gt 0) {
            Add-Finding -Type protected_users_empty -Object $PrivMap.ProtectedUsersGroup.name -ObjectType 'group' -ObjectDn $PrivMap.ProtectedUsersGroup.distinguishedName `
                -Detail "Protected Users has no members while $($PrivMap.Principals.Count) principal(s) hold Tier 0 group membership."
        }
    }

    # ======================= Privileged access =======================
    if ($PrivMap.Groups.Contains('DomainAdmins')) {
        $da = $PrivMap.Groups['DomainAdmins']
        $daUsers = @($da.Members | Where-Object { $_.Principal -and $_.Type -eq 'user' -and $_.Principal.enabled } | ForEach-Object { $_.Principal.samAccountName } | Select-Object -Unique)
        if ($daUsers.Count -gt $Config.MaxDomainAdmins) {
            Add-Finding -Type privileged_group_oversized -Object $da.Group.name -ObjectType 'group' -ObjectDn $da.Group.distinguishedName `
                -Detail "$($daUsers.Count) enabled effective members (threshold $($Config.MaxDomainAdmins)): $($daUsers -join ', ')."
        }
    }

    $groupMemberChecks = @(
        @{ Keys = @('SchemaAdmins', 'EnterpriseAdmins'); Type = 'schema_enterprise_admins_populated' }
        @{ Keys = @('AccountOperators', 'ServerOperators', 'PrintOperators', 'BackupOperators'); Type = 'operator_groups_populated' }
        @{ Keys = @('DnsAdmins'); Type = 'dnsadmins_populated' }
    )
    foreach ($gc in $groupMemberChecks) {
        foreach ($k in $gc.Keys) {
            if (-not $PrivMap.Groups.Contains($k)) { continue }
            $entry = $PrivMap.Groups[$k]
            $seen = @{}
            foreach ($m in $entry.Members) {
                if ($seen.ContainsKey($m.Dn.ToLower())) { continue }
                $seen[$m.Dn.ToLower()] = $true
                $name = if ($m.Principal -and $m.Principal.samAccountName) { $m.Principal.samAccountName } elseif ($m.Principal -and $m.Principal.name) { $m.Principal.name } else { $m.Dn }
                $state = if ($m.Principal -and $null -ne $m.Principal.enabled) { if ($m.Principal.enabled) { 'enabled' } else { 'disabled' } } else { 'n/a' }
                Add-Finding -Type $gc.Type -Object $name -ObjectType $m.Type -ObjectDn $m.Dn `
                    -Detail "Member of $($entry.Def.Label) via: $($m.Path). Account $state."
            }
        }
    }

    foreach ($rec in $PrivMap.Principals.Values) {
        $p = $rec.Principal
        $groupsText = $rec.Groups -join ', '
        if (-not $p -or $rec.Type -eq 'foreign' -or $rec.Type -eq 'unresolved') {
            # In a child domain the forest root's Enterprise Admins is a default member of the builtin
            # Administrators, through a foreign security principal. That is expected, not a finding.
            if ($p -and $rec.Type -eq 'foreign' -and $Index.RootSid -and $Index.RootSid -ne $Index.DomainSid -and "$($p.sid)" -eq "$($Index.RootSid)-519") { continue }
            $label = if ($p -and $p.name) { $p.name } else { $rec.Dn }
            Add-Finding -Type privileged_foreign_member -Object $label -ObjectType $rec.Type -ObjectDn $rec.Dn `
                -Detail "Member of $groupsText via: $($rec.Paths -join ' | ')."
            continue
        }
        if ($rec.Type -eq 'computer') {
            if (-not $p._isDc) {
                Add-Finding -Type privileged_computer_member -Object $p.samAccountName -ObjectType 'computer' -ObjectDn $p.distinguishedName `
                    -Detail "Member of $groupsText via: $($rec.Paths -join ' | ')."
            }
            continue
        }
        if (-not $p.enabled) {
            Add-Finding -Type privileged_disabled_member -Object $p.samAccountName -ObjectType 'user' -ObjectDn $p.distinguishedName `
                -Detail "Disabled, still member of $groupsText."
            continue
        }
        if ($p.kind -ne 'user') { continue }   # gMSA/sMSA: managed passwords, logon not interactive

        $lastLogon = Get-AgeDays $p.lastLogonTimestamp
        $created = Get-AgeDays $p.whenCreated
        if (($null -eq $lastLogon -and ($null -eq $created -or $created -gt $Config.PrivInactiveDays)) -or ($null -ne $lastLogon -and $lastLogon -gt $Config.PrivInactiveDays)) {
            Add-Finding -Type privileged_inactive -Object $p.samAccountName -ObjectType 'user' -ObjectDn $p.distinguishedName `
                -Detail "Last logon: $(Format-Age $lastLogon)$(if ($null -ne $lastLogon) { ' ago' }) (threshold $($Config.PrivInactiveDays) days). Member of $groupsText."
        }
        $pwdAge = Get-AgeDays $p.pwdLastSet
        if ($null -ne $pwdAge -and $pwdAge -gt $Config.PasswordMaxAgeDays) {
            Add-Finding -Type privileged_password_old -Object $p.samAccountName -ObjectType 'user' -ObjectDn $p.distinguishedName `
                -Detail "Password last set $pwdAge days ago (threshold $($Config.PasswordMaxAgeDays)). Member of $groupsText."
        }
        if (Test-Uac $p 'DONT_EXPIRE_PASSWORD') {
            Add-Finding -Type privileged_password_never_expires -Object $p.samAccountName -ObjectType 'user' -ObjectDn $p.distinguishedName `
                -Detail "Member of $groupsText."
        }
        # Tier 0 logon not bound to a smart card nor to Protected Users: a reusable password.
        if (-not $PrivMap.ProtectedUsersSet.ContainsKey($p.distinguishedName.ToLower()) -and -not (Test-Uac $p 'SMARTCARD_REQUIRED')) {
            Add-Finding -Type privileged_logon_unrestricted -Object $p.samAccountName -ObjectType 'user' -ObjectDn $p.distinguishedName `
                -Detail "Member of $groupsText; not in Protected Users and smart-card logon not required (authenticates with a reusable password)."
        }
    }

    # Non-standard primaryGroupID
    $privRids = @{}
    foreach ($entry in $PrivMap.Groups.Values) {
        if ($entry.Group.sid -and $entry.Group.sid.StartsWith("$dom-")) { $privRids[(Get-RidFromSid $entry.Group.sid)] = $entry.Def.Label }
    }
    foreach ($p in @($Index.Users) + @($Index.Computers)) {
        if ($null -eq $p.primaryGroupId) { continue }
        $pg = [int64]$p.primaryGroupId
        if ($script:NormalPrimaryGroupRids -contains $pg) { continue }
        if ($p.sid -eq "$dom-500" -and $pg -eq 513) { continue }
        $g = $Index.BySid["$dom-$pg"]
        $gName = if ($g) { $g.name } else { "RID $pg" }
        $sev = if ($privRids.ContainsKey($pg)) { 'Critical' } else { 'High' }
        Add-Finding -Type hidden_primary_group -Object $p.samAccountName -ObjectType $p._type -ObjectDn $p.distinguishedName -Severity $sev `
            -Detail "primaryGroupID = $pg ($gName)$(if ($sev -eq 'Critical') { ': privileged group membership not visible in the member attribute' })."
    }

    # Orphaned adminCount
    foreach ($u in $Index.Users) {
        if ([int]$u.adminCount -ne 1) { continue }
        if ($u.samAccountName -eq 'krbtgt' -or $u.samAccountName -match '^krbtgt_\d+$') { continue }
        if (Test-IsPrivileged $PrivMap $u) { continue }
        Add-Finding -Type orphaned_admincount -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
            -Detail "adminCount=1 but not an effective member of any protected group. Enabled: $($u.enabled)."
    }

    # RID 500
    $scRotation = if (-not $Snapshot.domain.PSObject.Properties['smartcardPwdRotation'] -or $null -eq $Snapshot.domain.smartcardPwdRotation) { 'unknown' }
    elseif ($Snapshot.domain.smartcardPwdRotation) { 'on' } else { 'off' }
    foreach ($u in @($enabledUsers | Where-Object { Test-Uac $_ 'SMARTCARD_REQUIRED' })) {
        $pa = Get-AgeDays $u.pwdLastSet
        if ($null -ne $pa -and $pa -gt $Config.PasswordMaxAgeDays) {
            Add-Finding -Type smartcard_password_not_rotated -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail "Smart card required; password (NT hash) last set $(Format-Age $pa) ago (threshold $($Config.PasswordMaxAgeDays) days). Domain automatic rotation: $scRotation."
        }
    }

    $rid500 = $Index.BySid["$dom-500"]
    if ($rid500 -and $rid500.enabled) {
        $issues = @()
        $ll = Get-AgeDays $rid500.lastLogonTimestamp
        $pa = Get-AgeDays $rid500.pwdLastSet
        if ($null -ne $ll -and $ll -le $Config.BuiltinAdminRecentDays) { $issues += "used $ll days ago (routine use suspected)" }
        if ($null -ne $pa -and $pa -gt $Config.PasswordMaxAgeDays) { $issues += "password $pa days old" }
        if ($issues.Count -gt 0) {
            Add-Finding -Type builtin_administrator_hygiene -Object $rid500.samAccountName -ObjectType 'user' -ObjectDn $rid500.distinguishedName `
                -Detail ("RID 500 account: " + ($issues -join '; ') + '.')
        }
    }

    # ======================= Account hygiene =======================
    # Strong certificate binding relaxed by GPO (0 or 1): weak explicit mappings are honoured again.
    $scbLoose = $null
    if ($Snapshot.gpo -and $Snapshot.gpo.collected -and (Get-Command Get-EffectiveGpoOrder -ErrorAction SilentlyContinue)) {
        $scb = Get-RegInt (Get-EffectiveRegValue (Get-EffectiveGpoOrder $Snapshot.gpo) 'MACHINE\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement')
        if ($null -ne $scb -and $scb -lt 2) { $scbLoose = "$scb" }
    }
    foreach ($u in $Index.Users) {
        if ($u.descriptionSuspicious) {
            Add-Finding -Type password_in_description -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail "Description (masked): '$($u.description)'. Enabled: $($u.enabled)."
        }
        if ($u.PSObject.Properties['altSecIdTypes']) {
            $weak = @(@($u.altSecIdTypes) | Where-Object { @('IssuerSubject', 'SubjectOnly', 'RFC822') -contains "$_" } | Select-Object -Unique)
            if ($weak.Count) {
                $sev = if ($scbLoose) { if (Test-IsPrivileged $PrivMap $u) { 'Critical' } else { 'High' } } elseif (Test-IsPrivileged $PrivMap $u) { 'High' } else { 'Medium' }
                Add-Finding -Type altsecid_weak_mapping -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName -Severity $sev `
                    -Detail "Weak altSecurityIdentities mapping(s): $($weak -join ', ') (values not collected).$(if (Test-IsPrivileged $PrivMap $u) { ' Tier 0 account.' })$(if ($scbLoose) { " StrongCertificateBindingEnforcement = $scbLoose by GPO, so the mapping is honoured." })"
            }
        }
        if ($u.hasUnixPassword) {
            Add-Finding -Type unix_password_present -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail "userPassword / unixUserPassword attribute is populated (value not collected). Enabled: $($u.enabled)."
        }
    }
    foreach ($c in $Index.Computers) {
        if ($c.descriptionSuspicious) {
            Add-Finding -Type password_in_description -Object $c.samAccountName -ObjectType 'computer' -ObjectDn $c.distinguishedName `
                -Detail "Description (masked): '$($c.description)'. Enabled: $($c.enabled)."
        }
    }

    foreach ($u in $humanUsers) {
        if ($u.samAccountName -eq 'krbtgt' -or $u.samAccountName -match '^krbtgt_\d+$') { continue }
        $isPriv = Test-IsPrivileged $PrivMap $u
        if (Test-Uac $u 'PASSWD_NOTREQD') {
            $sev = if ($isPriv) { 'High' } else { 'Medium' }
            Add-Finding -Type password_not_required -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName -Severity $sev `
                -Detail "PASSWD_NOTREQD set$(if ($isPriv) { ' on a privileged account' })."
        }
        if (Test-Uac $u 'ENCRYPTED_TEXT_PWD_ALLOWED') {
            Add-Finding -Type reversible_encryption_account -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail 'ENCRYPTED_TEXT_PWD_ALLOWED set.'
        }
        if ($isPriv) { continue }   # privileged accounts have their own, stricter checks
        $ll = Get-AgeDays $u.lastLogonTimestamp
        $created = Get-AgeDays $u.whenCreated
        if ($null -eq $ll) {
            if ($null -ne $created -and $created -gt $Config.NeverLoggedOnGraceDays) {
                Add-Finding -Type never_logged_on_user -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                    -Detail "Created $created days ago, no logon recorded."
            }
        }
        elseif ($ll -gt $Config.InactiveDays) {
            Add-Finding -Type inactive_user -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail "Last logon $ll days ago (threshold $($Config.InactiveDays))."
        }
        if (Test-Uac $u 'DONT_EXPIRE_PASSWORD') {
            Add-Finding -Type password_never_expires -Object $u.samAccountName -ObjectType 'user' -ObjectDn $u.distinguishedName `
                -Detail "Password age: $(Format-Age (Get-AgeDays $u.pwdLastSet))."
        }
    }

    $guest = $Index.BySid["$dom-501"]
    if ($guest -and $guest.enabled) {
        Add-Finding -Type guest_enabled -Object $guest.samAccountName -ObjectType 'user' -ObjectDn $guest.distinguishedName -Detail 'Built-in Guest (RID 501) is enabled.'
    }

    $privilegedSidSet = @{ 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-549' = 'Server Operators'; 'S-1-5-32-551' = 'Backup Operators' }
    foreach ($rid in @(500, 512, 516, 518, 519, 520, 526, 527)) {
        $privilegedSidSet["$dom-$rid"] = "RID $rid"
        $privilegedSidSet["$($Index.RootSid)-$rid"] = "RID $rid"
    }
    foreach ($p in @($Index.Users) + @($Index.Computers) + @($Index.Groups)) {
        $sh = @($p.sidHistory | Where-Object { $_ })
        if ($sh.Count -eq 0) { continue }
        $reasons = @()
        foreach ($s in $sh) {
            if ($privilegedSidSet.ContainsKey($s)) { $reasons += "$s is a privileged SID ($($privilegedSidSet[$s]))" }
            elseif ($s.StartsWith("$dom-")) { $reasons += "$s belongs to this same domain" }
        }
        $sev = if ($reasons.Count -gt 0) { 'Critical' } else { 'Medium' }
        $label = if ($p.samAccountName) { $p.samAccountName } else { $p.name }
        $detail = "sIDHistory: $($sh -join ', ')."
        if ($reasons.Count -gt 0) { $detail += ' ' + ($reasons -join '; ') + '.' }
        Add-Finding -Type sid_history -Object $label -ObjectType $p._type -ObjectDn $p.distinguishedName -Severity $sev -Detail $detail
    }

    # Computers
    $obsoleteRegex = '(?i)Windows (XP|Vista|7|8(\.1)?)\b|Windows 2000|Server 2003|Server 2008|Server 2012'
    $lapsDeployed = [bool]($Snapshot.domain.lapsLegacySchema -or $Snapshot.domain.lapsV2Schema)
    if (-not $lapsDeployed -and $null -ne $Snapshot.domain.lapsLegacySchema -and -not $Index.CollectionErrorSections.ContainsKey('domain.lapsSchema')) {
        Add-Finding -Type laps_not_deployed -Object $Snapshot.domain.dnsRoot -ObjectType 'domain' -ObjectDn $Snapshot.domain.distinguishedName `
            -Detail 'Neither ms-Mcs-AdmPwdExpirationTime (legacy LAPS) nor msLAPS-PasswordExpirationTime (Windows LAPS) exists in the schema.'
    }
    foreach ($c in @($Index.Computers | Where-Object { $_.enabled -and -not $_._isDc })) {
        if (Test-Uac $c 'PASSWD_NOTREQD') {
            Add-Finding -Type precreated_computer_account -Object $c.samAccountName -ObjectType 'computer' -ObjectDn $c.distinguishedName `
                -Detail "PASSWD_NOTREQD set on an enabled computer account (predictable default machine password). OS: $($c.operatingSystem)."
        }
        $ll = Get-AgeDays $c.lastLogonTimestamp
        $created = Get-AgeDays $c.whenCreated
        $stale = ($null -ne $ll -and $ll -gt $Config.StaleComputerDays) -or ($null -eq $ll -and $null -ne $created -and $created -gt $Config.StaleComputerDays)
        # The Seamless SSO account never logs on; deleting it as stale breaks SSO (azuread_sso_key_old covers it).
        if ($stale -and "$($c.samAccountName)" -ine 'AZUREADSSOACC$') {
            Add-Finding -Type stale_computer -Object $c.samAccountName -ObjectType 'computer' -ObjectDn $c.distinguishedName `
                -Detail "Last logon: $(Format-Age $ll)$(if ($null -ne $ll) { ' ago' }) (threshold $($Config.StaleComputerDays) days). OS: $($c.operatingSystem)."
        }
        if ($c.operatingSystem -and $c.operatingSystem -match $obsoleteRegex) {
            $sev = if ($c.operatingSystem -match '(?i)server') { 'High' } else { 'Medium' }
            Add-Finding -Type obsolete_os -Object $c.samAccountName -ObjectType 'computer' -ObjectDn $c.distinguishedName -Severity $sev `
                -Detail "$($c.operatingSystem) $($c.osVersion)$(if ($stale) { ' (also stale)' })."
        }
        if ($lapsDeployed -and $c.operatingSystem -match '(?i)windows' -and -not $stale) {
            $exp = if ($c.lapsV2Expiry) { $c.lapsV2Expiry } else { $c.lapsLegacyExpiry }
            if (-not $exp) {
                Add-Finding -Type laps_missing -Object $c.samAccountName -ObjectType 'computer' -ObjectDn $c.distinguishedName `
                    -Detail "No LAPS expiration timestamp. OS: $($c.operatingSystem)."
            }
            else {
                $overdue = Get-AgeDays $exp
                if ($null -ne $overdue -and $overdue -gt $Config.LapsOverdueDays) {
                    Add-Finding -Type laps_stale -Object $c.samAccountName -ObjectType 'computer' -ObjectDn $c.distinguishedName `
                        -Detail "LAPS password expired $overdue days ago and was not rotated."
                }
            }
        }
    }

    if ($Snapshot.domain.PSObject.Properties['possSuperiorClasses'] -and $null -ne $Snapshot.domain.possSuperiorClasses -and -not $Index.CollectionErrorSections.ContainsKey('domain.possSuperiors')) {
        foreach ($cls in @($Snapshot.domain.possSuperiorClasses | Where-Object { $_ -and $_.inheritsContainer } | Sort-Object { "$($_.name)" })) {
            $cve = if ("$($cls.name)" -eq 'msExchStorageGroup') { ' Known as CVE-2021-34470.' } else { '' }
            Add-Finding -Type schema_class_poss_superior -Object "$($cls.name)" -ObjectType 'schemaclass' `
                -Detail "possSuperiors includes $(@($cls.possSuperiors) -join ' and '); inherits from $(@($cls.subClassChain) -join ' > ').$cve"
        }
    }
    if ($Snapshot.domain.PSObject.Properties['javaSchemaClasses'] -and $null -ne $Snapshot.domain.javaSchemaClasses -and -not $Index.CollectionErrorSections.ContainsKey('domain.javaSchema')) {
        $jc = @($Snapshot.domain.javaSchemaClasses | Where-Object { $_ } | Sort-Object)
        if ($jc.Count -gt 0) {
            Add-Finding -Type schema_java_objects -Object $Snapshot.domain.dnsRoot -ObjectType 'domain' -ObjectDn $Snapshot.domain.distinguishedName `
                -Detail "Java classes in the schema: $($jc -join ', ')."
        }
    }
    if ($null -ne $Snapshot.domain.machineAccountQuota -and [int]$Snapshot.domain.machineAccountQuota -gt 0) {
        Add-Finding -Type machine_account_quota -Object $Snapshot.domain.dnsRoot -ObjectType 'domain' -ObjectDn $Snapshot.domain.distinguishedName `
            -Detail "ms-DS-MachineAccountQuota = $($Snapshot.domain.machineAccountQuota)."
    }
    if ($null -ne $Snapshot.domain.authPolicySiloCount -and [int]$Snapshot.domain.authPolicySiloCount -eq 0 -and $PrivMap.Principals.Count -gt 0) {
        Add-Finding -Type auth_policy_silo_unused -Object $Snapshot.domain.dnsRoot -ObjectType 'domain' -ObjectDn $Snapshot.domain.distinguishedName `
            -Detail "No authentication policy silo defined while $($PrivMap.Principals.Count) Tier 0 principal(s) exist."
    }

    # ======================= Domain configuration =======================
    $pp = $Snapshot.domain.passwordPolicy
    $domObj = $Snapshot.domain.dnsRoot; $domDn = $Snapshot.domain.distinguishedName
    if ($pp) {
        if ([int]$pp.minPasswordLength -lt $Config.MinPasswordLength) {
            $sev = if ([int]$pp.minPasswordLength -lt 8) { 'High' } else { 'Medium' }
            Add-Finding -Type password_policy_short -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn -Severity $sev `
                -Detail "Minimum length $($pp.minPasswordLength) (baseline $($Config.MinPasswordLength))."
        }
        if (-not $pp.complexityEnabled -and [int]$pp.minPasswordLength -lt 14) {
            Add-Finding -Type password_policy_no_complexity -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn `
                -Detail "Complexity disabled, minimum length $($pp.minPasswordLength)."
        }
        if ([int]$pp.lockoutThreshold -eq 0) {
            Add-Finding -Type password_policy_no_lockout -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn -Detail 'Lockout threshold = 0.'
        }
        if ($pp.reversibleEncryptionEnabled) {
            Add-Finding -Type reversible_encryption_policy -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn -Detail 'ReversibleEncryptionEnabled = True in the default domain policy.'
        }
        $histMin = if ($Config.PasswordHistoryMin) { [int]$Config.PasswordHistoryMin } else { 24 }
        if ($null -ne $pp.minPasswordAgeDays -and [int]$pp.minPasswordAgeDays -eq 0) {
            Add-Finding -Type password_policy_min_age_zero -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn -Detail 'Minimum password age = 0 days: password history can be flushed by rapid successive changes.'
        }
        if ($null -ne $pp.passwordHistoryCount -and [int]$pp.passwordHistoryCount -lt $histMin) {
            Add-Finding -Type password_policy_history_weak -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn -Detail "Enforced password history = $($pp.passwordHistoryCount) (baseline $histMin)."
        }
        if ($null -ne $pp.maxPasswordAgeDays) {
            $maxAge = [int]$pp.maxPasswordAgeDays
            if ($maxAge -eq 0) {
                Add-Finding -Type password_policy_max_age -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn -Detail 'Maximum password age = 0: passwords never expire domain-wide.'
            }
            elseif ($maxAge -gt 365) {
                Add-Finding -Type password_policy_max_age -Object 'Default Domain Policy' -ObjectType 'policy' -ObjectDn $domDn -Detail "Maximum password age = $maxAge days (over 365)."
            }
        }
    }
    $privGroupDns = @{}
    foreach ($entry in $PrivMap.Groups.Values) { $privGroupDns[$entry.Group.distinguishedName.ToLower()] = $entry.Def.Label }
    foreach ($f in @($Snapshot.domain.fineGrainedPolicies | Where-Object { $_ })) {
        if ($f.reversibleEncryptionEnabled) {
            Add-Finding -Type reversible_encryption_policy -Object $f.name -ObjectType 'fgpp' -Detail "Fine-grained policy with reversible encryption, applies to: $(@($f.appliesTo) -join '; ')."
        }
        if ([int]$f.minPasswordLength -lt $Config.MinPasswordLength) {
            $privTargets = @(@($f.appliesTo) | Where-Object { $_ -and ($privGroupDns.ContainsKey($_.ToLower()) -or $PrivMap.Principals.ContainsKey($_.ToLower())) })
            $sev = if ($privTargets.Count -gt 0) { 'High' } else { 'Medium' }
            Add-Finding -Type fgpp_weak -Object $f.name -ObjectType 'fgpp' -Severity $sev `
                -Detail "Minimum length $($f.minPasswordLength) (baseline $($Config.MinPasswordLength)), precedence $($f.precedence).$(if ($privTargets.Count -gt 0) { " Applies to privileged principals: $($privTargets -join '; ')." })"
        }
    }

    if ($Snapshot.domain.domainMode -match '(\d{4})') {
        if ([int]$Matches[1] -lt 2016) {
            Add-Finding -Type functional_level_outdated -Object $domObj -ObjectType 'domain' -ObjectDn $domDn `
                -Detail "Domain mode: $($Snapshot.domain.domainMode); forest mode: $($Snapshot.domain.forestMode)."
        }
    }
    if ($Snapshot.domain.recycleBinEnabled -eq $false) {
        Add-Finding -Type recycle_bin_disabled -Object $domObj -ObjectType 'domain' -ObjectDn $domDn -Detail 'Recycle Bin Feature has no enabled scope.'
    }
    # Tombstone lifetime: unset means the legacy 60-day default; below 180 the recovery window
    # (and the usable age of a backup) is short.
    if ($Snapshot.domain.PSObject.Properties['tombstoneLifetime']) {
        $tsl = if ($null -eq $Snapshot.domain.tombstoneLifetime) { 60 } else { [int]$Snapshot.domain.tombstoneLifetime }
        if ($tsl -lt 180) {
            Add-Finding -Type tombstone_lifetime_low -Object $domObj -ObjectType 'domain' -ObjectDn $domDn `
                -Detail "tombstoneLifetime = $(if ($null -eq $Snapshot.domain.tombstoneLifetime) { 'not set (defaults to 60)' } else { $tsl }) days (recommended >= 180)."
        }
    }
    $dsh = "$($Snapshot.domain.dsHeuristics)"
    if ($dsh.Length -ge 7 -and $dsh[6] -eq '2') {
        Add-Finding -Type anonymous_ldap_enabled -Object $domObj -ObjectType 'domain' -Detail "dSHeuristics = '$dsh'."
    }

    $dcList = @($Snapshot.domainControllers | Where-Object { $_ })
    $writableDcs = @($dcList | Where-Object { -not $_.isReadOnly })
    if ($dcList.Count -gt 0 -and $writableDcs.Count -eq 1) {
        Add-Finding -Type single_dc -Object $writableDcs[0].name -ObjectType 'dc' -ObjectDn $writableDcs[0].computerDN -Detail 'Only one writable domain controller.'
    }
    foreach ($dc in $dcList) {
        $os = "$($dc.operatingSystem)"
        if ($os -match '(?i)200[038]|2012') {
            Add-Finding -Type dc_obsolete_os -Object $dc.name -ObjectType 'dc' -ObjectDn $dc.computerDN -Severity 'Critical' -Detail "${os}: out of support."
        }
        elseif ($os -match '(?i)2016') {
            Add-Finding -Type dc_obsolete_os -Object $dc.name -ObjectType 'dc' -ObjectDn $dc.computerDN -Severity 'Low' -Detail "${os}: extended support ends January 2027, plan replacement."
        }
    }

    # DC machine password rotation.
    foreach ($dcc in @($Index.Computers | Where-Object { $_._isDc -and $_.enabled })) {
        $age = Get-AgeDays $dcc.pwdLastSet
        if ($null -ne $age -and $age -gt $Config.DcPasswordMaxAgeDays) {
            Add-Finding -Type dc_password_old -Object $dcc.samAccountName -ObjectType 'computer' -ObjectDn $dcc.distinguishedName `
                -Detail "DC machine password last set $age days ago (expected rotation ~30 days, threshold $($Config.DcPasswordMaxAgeDays))."
        }
    }

    # Subnets declared in Sites and Services.
    if ($null -ne $Snapshot.domain.subnetCount -and [int]$Snapshot.domain.subnetCount -eq 0) {
        Add-Finding -Type dc_subnet_missing -Object $domObj -ObjectType 'domain' -ObjectDn $domDn -Detail 'No subnet objects are declared under Sites and Services.'
    }

    # SYSVOL replication engine.
    if ("$($Snapshot.domain.sysvolReplication)" -eq 'FRS') {
        Add-Finding -Type sysvol_frs -Object $domObj -ObjectType 'domain' -ObjectDn $domDn -Detail 'SYSVOL is still replicated by FRS (no DFSR content set found). Migrate to DFSR.'
    }

    # Tier 0 kept out of RODC caches (only matters if there is an RODC).
    if (@($dcList | Where-Object { $_.isReadOnly }).Count -gt 0) {
        $denied = $Index.BySid["$dom-572"]
        if ($denied -and $denied._type -eq 'group') {
            $deniedDns = @{}
            foreach ($mm in @($denied.members | Where-Object { $_ })) { $d = Get-DnString $mm; if ($d) { $deniedDns[$d.ToLower()] = $true } }
            $mustProtect = @('512', '519', '518', '502') | ForEach-Object { $Index.BySid["$dom-$_"] } | Where-Object { $_ -and $_.distinguishedName }
            $missing = @($mustProtect | Where-Object { -not $deniedDns.ContainsKey($_.distinguishedName.ToLower()) } | ForEach-Object { $_.samAccountName })
            if ($missing.Count -gt 0) {
                Add-Finding -Type rodc_tier0_unprotected -Object 'Denied RODC Password Replication Group' -ObjectType 'group' -ObjectDn $denied.distinguishedName `
                    -Detail "RODC present; these Tier 0 principals are not in the Denied RODC Password Replication Group: $($missing -join ', ')."
            }
        }
    }

    # Per-RODC password replication policy, cached credentials and who administers it.
    $rodcTier0 = Get-Tier0SidSet $Index $PrivMap
    $broadSids = @{ 'S-1-5-11' = 'Authenticated Users'; 'S-1-1-0' = 'Everyone'; 'S-1-5-32-545' = 'Users'; "$dom-513" = 'Domain Users'; "$dom-515" = 'Domain Computers' }
    $nameOfDn = {
        param([string]$Dn)
        $o = $Index.ByDn[$Dn.ToLower()]
        if ($o -and $o.samAccountName) { return "$($o.samAccountName)" }
        if ($o -and $o.name) { return "$($o.name)" }
        return (($Dn -split ',')[0] -replace '^..=', '')
    }
    # Tier 0 (by SID, by DN for the privileged map) or a domain-wide group. FSPs carry their SID in the CN.
    $classify = {
        param([string]$Dn)
        $o = $Index.ByDn[$Dn.ToLower()]
        $sid = if ($o -and $o.sid) { "$($o.sid)" } elseif ($Dn -match '^CN=(S-1-[0-9-]+),') { $Matches[1] } else { '' }
        if ($sid -and $broadSids.ContainsKey($sid)) { return 'broad' }
        if (($sid -and $rodcTier0.ContainsKey($sid)) -or $PrivMap.Principals.ContainsKey($Dn.ToLower())) { return 'tier0' }
        return ''
    }
    foreach ($rodc in @($dcList | Where-Object { $_.isReadOnly -and $_.rodcPolicy })) {
        $pol = $rodc.rodcPolicy
        $rodcObj = if ($rodc.computerDN) { $Index.ByDn["$($rodc.computerDN)".ToLower()] } else { $null }
        $mgr = "$($pol.managedBy)"
        $mgrNote = ''; $mgrUnsafe = $false
        if ($mgr) {
            $mgrClass = & $classify $mgr
            $mgrUnsafe = ($mgrClass -ne 'tier0')
            $mgrNote = " Administered (managedBy) by $(& $nameOfDn $mgr)$(if ($mgrUnsafe) { ', not Tier 0' })."
        }
        $issues = @()
        foreach ($a in @($pol.allowed | Where-Object { $_ })) {
            $cls = & $classify "$a"
            if ($cls -eq 'broad') { $issues += "allowed list contains the domain-wide group $(& $nameOfDn "$a")" }
            elseif ($cls -eq 'tier0') { $issues += "allowed list contains the Tier 0 principal $(& $nameOfDn "$a")" }
        }
        $deniedRodc = $Index.BySid["$dom-572"]
        if ($deniedRodc -and $deniedRodc.distinguishedName -and @($pol.denied | Where-Object { "$_" -ieq $deniedRodc.distinguishedName }).Count -eq 0) {
            $issues += 'denied list does not contain the Denied RODC Password Replication Group'
        }
        if ($issues.Count -gt 0) {
            Add-Finding -Type rodc_prp_too_broad -Object $rodc.name -ObjectType 'dc' -ObjectDn $rodc.computerDN `
                -Detail "RODC $($rodc.name): $($issues -join '; ').$mgrNote"
        }
        $revealed = @(@($pol.revealed | Where-Object { $_ }) | Where-Object {
                ($null -eq $rodcObj -or "$_" -ine $rodcObj.distinguishedName) -and (& $classify "$_") -eq 'tier0'
            } | ForEach-Object { & $nameOfDn "$_" } | Select-Object -Unique)
        if ($revealed.Count -gt 0) {
            $sev = if ($mgrUnsafe) { 'Critical' } else { 'High' }
            Add-Finding -Type rodc_tier0_revealed -Object $rodc.name -ObjectType 'dc' -ObjectDn $rodc.computerDN -Severity $sev `
                -Detail "Password of Tier 0 account(s) cached on RODC $($rodc.name): $($revealed -join ', ').$mgrNote"
        }
    }

    foreach ($t in @($Snapshot.trusts | Where-Object { $_ })) {
        if ($t.intraForest) { continue }
        $inbound = @('Inbound', 'BiDirectional') -contains "$($t.direction)"
        $attrs = [int]$t.trustAttributes
        if ($t.forestTransitive) {
            if (($attrs -band $script:TRUST_TREAT_AS_EXTERNAL) -ne 0 -and $inbound) {
                Add-Finding -Type trust_sid_filtering_disabled -Object $t.name -ObjectType 'trust' `
                    -Detail "Forest trust ($($t.direction)) with SID history enabled (TREAT_AS_EXTERNAL): SIDs with RID >= 1000 from the other forest are accepted."
            }
            if ($t.tgtDelegation -or ($attrs -band $script:TRUST_ENABLE_TGT_DELEGATION) -ne 0) {
                Add-Finding -Type trust_tgt_delegation -Object $t.name -ObjectType 'trust' -Detail "Forest trust ($($t.direction)) with TGT delegation enabled."
            }
        }
        elseif ($inbound -and -not $t.sidFilteringQuarantined) {
            Add-Finding -Type trust_sid_filtering_disabled -Object $t.name -ObjectType 'trust' -Detail "External trust ($($t.direction)) without quarantine (SID filtering)."
        }
        if ($inbound -and -not $t.selectiveAuthentication) {
            Add-Finding -Type trust_no_selective_auth -Object $t.name -ObjectType 'trust' -Detail "$($t.direction) $(if ($t.forestTransitive) { 'forest' } else { 'external' }) trust, forest-wide authentication."
        }
        if ($t.usesRC4Encryption -or -not $t.usesAESKeys) {
            $keyAge = if ($t.PSObject.Properties['whenChanged']) { Get-AgeDays $t.whenChanged } else { $null }
            Add-Finding -Type trust_rc4 -Object $t.name -ObjectType 'trust' -Detail "UsesRC4Encryption: $($t.usesRC4Encryption); UsesAESKeys: $($t.usesAESKeys).$(if ($null -ne $keyAge) { " Trust object (and key) last changed $(Format-Age $keyAge) ago." })"
        }
        $tAge = if ($t.PSObject.Properties['whenChanged']) { Get-AgeDays $t.whenChanged } else { $null }
        if ($null -ne $tAge -and $tAge -gt $script:TRUST_INACTIVE_DAYS) {
            Add-Finding -Type trust_inactive -Object $t.name -ObjectType 'trust' `
                -Detail "$($t.direction) trust object last changed $(Format-Age $tAge) ago (threshold $($script:TRUST_INACTIVE_DAYS) days): the trust password should have rotated."
        }
    }

    # ======================= Permissions =======================
    $defaultAcl = Get-DefaultAclPrincipals $Index
    $defaultOwners = @("$dom-512", "$($Index.RootSid)-519", 'S-1-5-32-544', 'S-1-5-18')
    # Account Operators holds GenericAll on every group that AdminSDHolder doesn't protect, from the
    # default security descriptor of the group class. Group Policy Creator Owners (RID 520) is one
    # of them and is also an ACL target, so that ACE is expected there, not a delegation.
    $gpco = $Index.BySid["$dom-520"]
    $gpcoDefaultDn = if ($gpco -and $gpco.distinguishedName -and [int]$gpco.adminCount -ne 1) { "$($gpco.distinguishedName)".ToLower() } else { '' }
    foreach ($acl in @($Snapshot.acls | Where-Object { $_ })) {
        if ($acl.ownerSid -and $defaultOwners -notcontains $acl.ownerSid) {
            Add-Finding -Type nonstandard_owner_tier0 -Object $acl.ownerName -ObjectType 'acl' -ObjectDn $acl.distinguishedName `
                -Detail "Owner of $($acl.target) is $($acl.ownerName) ($($acl.ownerSid))."
        }

        # One finding per principal and target.
        $perPrincipal = [ordered]@{}
        foreach ($ace in @($acl.aces | Where-Object { $_ })) {
            if ($defaultAcl -contains $ace.sid) { continue }
            $danger = Get-AceDanger $ace
            if (-not $danger) { continue }
            if ($gpcoDefaultDn -and $ace.sid -eq 'S-1-5-32-548' -and -not $ace.isInherited -and $danger -eq 'GenericAll' -and "$($acl.distinguishedName)".ToLower() -eq $gpcoDefaultDn) { continue }
            if (-not $perPrincipal.Contains($ace.sid)) { $perPrincipal[$ace.sid] = [PSCustomObject]@{ Name = $ace.name; Items = New-Object System.Collections.Generic.List[object] } }
            $perPrincipal[$ace.sid].Items.Add([PSCustomObject]@{ Ace = $ace; Danger = $danger })
        }

        foreach ($sid in $perPrincipal.Keys) {
            $entry = $perPrincipal[$sid]
            $name = if ($entry.Name) { $entry.Name } else { $sid }
            $isSync = $name -match '(?i)(^|\\)(MSOL_|AAD_|Sync_)'
            # Exchange's default WriteDacl on the domain head: the PrivExchange path to DCSync.
            $exNote = if ($name -match '(?i)(^|\\)(Exchange Windows Permissions|Exchange Trusted Subsystem|Organization Management)$') { ' Exchange group: without split permissions it can grant itself DCSync (PrivExchange); remove the ACE with Exchange''s split-permissions setup or the published fix.' } else { '' }

            if ($acl.target -eq 'DomainRoot') {
                $dcsyncItems = @($entry.Items | Where-Object {
                        (Test-AceAppliesToSelf $_.Ace) -and ($_.Danger -match 'GenericAll|DS-Replication-Get-Changes-All|ExtendedRight\(all\)')
                    })
                if ($dcsyncItems.Count -gt 0) {
                    $sev = if ($isSync) { 'High' } else { 'Critical' }
                    $note = if ($isSync) { ' Looks like an Entra Connect / sync account: expected, but it is a Tier 0 credential and must be protected as such.' } else { '' }
                    Add-Finding -Type dcsync_rights -Object $name -ObjectType 'acl' -ObjectDn $acl.distinguishedName -Severity $sev `
                        -Detail "Rights on domain head: $((@($dcsyncItems | ForEach-Object { $_.Danger }) | Select-Object -Unique) -join '; ').$note"
                }
                $other = @($entry.Items | Where-Object { $dcsyncItems -notcontains $_ -and $_.Danger -notmatch '^ExtendedRight\(DS-Replication-Get-Changes-All\)$' })
                if ($isSync) { $other = @($other | Where-Object { $_.Danger -notmatch 'ExtendedRight' }) }
                if ($other.Count -eq 0) { continue }
                $parts = @($other | ForEach-Object {
                        $scope = if (Test-AceAppliesToSelf $_.Ace) { 'domain head' } else { "descendant $(Get-GuidName $_.Ace.inheritedObjectType)" }
                        "$($_.Danger) on $scope"
                    } | Select-Object -Unique)
                $selfApplies = @($other | Where-Object { Test-AceAppliesToSelf $_.Ace }).Count -gt 0
                $sev = if ($selfApplies) { 'Critical' } else { 'High' }
                Add-Finding -Type dangerous_ace_tier0 -Object $name -ObjectType 'acl' -ObjectDn $acl.distinguishedName -Severity $sev `
                    -Detail "Target: DomainRoot. $($parts -join '; ').$exNote"
            }
            else {
                $parts = @($entry.Items | ForEach-Object { $_.Danger } | Select-Object -Unique)
                Add-Finding -Type dangerous_ace_tier0 -Object $name -ObjectType 'acl' -ObjectDn $acl.distinguishedName `
                    -Detail "Target: $($acl.target). $($parts -join '; ')."
            }
        }
    }

    # Get-Changes + Get-Changes-In-Filtered-Set without Get-Changes-All: DirSync reads of confidential
    # attributes (LAPS). With Get-Changes-All it is DCSync, reported above.
    $guidGc = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; $guidGca = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; $guidFiltered = '89e95b76-444d-4c62-991a-0facbeda640c'
    foreach ($acl in @($Snapshot.acls | Where-Object { $_ -and $_.target -eq 'DomainRoot' })) {
        $rightsBySid = [ordered]@{}
        foreach ($ace in @($acl.aces | Where-Object { $_ })) {
            if ($ace.accessType -ne 'Allow' -or $defaultAcl -contains $ace.sid -or -not (Test-AceAppliesToSelf $ace)) { continue }
            $rights = "$($ace.rights)"; $ot = "$($ace.objectType)".ToLower()
            $all = ($rights -match '\bGenericAll\b') -or ($rights -match '\bExtendedRight\b' -and ($ot -eq '' -or $ot -eq $script:EmptyGuid))
            if (-not $rightsBySid.Contains($ace.sid)) { $rightsBySid[$ace.sid] = [PSCustomObject]@{ Name = $ace.name; Set = @{} } }
            $set = $rightsBySid[$ace.sid].Set
            if ($all) { $set[$guidGc] = $true; $set[$guidGca] = $true; $set[$guidFiltered] = $true }
            elseif ($rights -match '\bExtendedRight\b') { $set[$ot] = $true }
        }
        foreach ($sid in $rightsBySid.Keys) {
            $e = $rightsBySid[$sid]
            if ($e.Set.ContainsKey($guidGca) -or -not ($e.Set.ContainsKey($guidGc) -and $e.Set.ContainsKey($guidFiltered))) { continue }
            $name = if ($e.Name) { $e.Name } else { $sid }
            Add-Finding -Type sync_laps_rights -Object $name -ObjectType 'acl' -ObjectDn $acl.distinguishedName `
                -Detail "Holds DS-Replication-Get-Changes and DS-Replication-Get-Changes-In-Filtered-Set on the domain head$(if ($Snapshot.domain.lapsLegacySchema) { '; legacy LAPS is deployed, so its passwords are readable' })."
        }
    }

    if ($Snapshot.sysvol -and $Snapshot.sysvol.scanned) {
        foreach ($f in @($Snapshot.sysvol.cpasswordFiles | Where-Object { $_ })) {
            $gpo = if ($f -match '\{[0-9A-Fa-f\-]{36}\}') { $Matches[0] } else { '' }
            Add-Finding -Type gpp_cpassword -Object $(if ($gpo) { "GPO $gpo" } else { $f }) -ObjectType 'gpo' -Detail "cpassword found in $f"
        }
        $t0 = Get-Tier0SidSet $Index $PrivMap
        foreach ($fa in @($Snapshot.sysvol.folderAcls | Where-Object { $_ })) {
            $w = [ordered]@{}
            foreach ($a in @($fa.aces | Where-Object { $_ -and "$($_.accessType)" -eq 'Allow' -and "$($_.rights)" -match 'FullControl|Modify|Write|CreateFiles|AppendData|ChangePermissions|TakeOwnership' })) {
                if ($t0.ContainsKey("$($a.sid)")) { continue }
                $n = if ($a.name) { "$($a.name)" } else { "$($a.sid)" }
                $w[$n] = "$($a.rights)"
            }
            if ($w.Count) {
                Add-Finding -Type sysvol_writable -Object "$($fa.folder)" -ObjectType 'file' `
                    -Detail "Write access for: $(@($w.Keys | ForEach-Object { "$_ ($($w[$_]))" }) -join '; '). Folder: $($fa.path)"
            }
        }
        foreach ($f in @($Snapshot.sysvol.scriptSecretFiles | Where-Object { $_ })) {
            Add-Finding -Type sysvol_script_secrets -Object (($f -split '[\\/]')[-1]) -ObjectType 'file' -Detail "Password-like string in SYSVOL script: $f"
        }
    }

    # ======================= gMSA password exposure & Shadow Credentials =======================
    $tier0Sids = Get-Tier0SidSet $Index $PrivMap
    foreach ($m in @($Index.Users | Where-Object { $_.kind -eq 'msa' -and $_.isGroupManaged -eq $true })) {
        $readers = @($m.gmsaReadPrincipals | Where-Object { $_ })
        if ($readers.Count -eq 0) { continue }
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($dn in $readers) {
            $p = $Index.ByDn["$dn".ToLower()]
            $sid = if ($p) { $p.sid } else { $null }
            if ($sid -and $tier0Sids.ContainsKey($sid)) { continue }
            $name = if ($p -and $p.samAccountName) { $p.samAccountName } elseif ($p -and $p.name) { $p.name } else { ($dn -split ',')[0] -replace '^..=', '' }
            if (-not $bad.Contains($name)) { $bad.Add($name) }
        }
        if ($bad.Count -gt 0) {
            $isPriv = Test-IsPrivileged $PrivMap $m
            $sev = if ($isPriv) { 'Critical' } else { 'High' }
            Add-Finding -Type gmsa_password_readable -Object $m.samAccountName -ObjectType 'msa' -ObjectDn $m.distinguishedName -Severity $sev `
                -Detail "Password retrievable by non-Tier 0 principal(s): $($bad -join ', ')$(if ($isPriv) { ' (the gMSA itself holds privileged rights)' })."
        }
    }
    foreach ($rec in $PrivMap.Principals.Values) {
        $p = $rec.Principal
        if (-not $p -or $p._type -ne 'user' -or $p.kind -ne 'user' -or -not $p.distinguishedName) { continue }
        $kc = 0; try { $kc = [int]$p.keyCredentialCount } catch { $kc = 0 }
        if ($kc -gt 0) {
            Add-Finding -Type shadow_credentials_present -Object $p.samAccountName -ObjectType 'user' -ObjectDn $p.distinguishedName `
                -Detail "$kc key credential(s) on a Tier 0 account (member of $($rec.Groups -join ', ')). Confirm each against an expected Windows Hello / device registration, or treat as Shadow Credentials persistence."
        }
    }

    # Each group runs on its own: odd data from a real domain costs a warning, not the report.
    $subChecks = [ordered]@{
        PreWin2000    = { Invoke-PreWin2000Check -Snapshot $Snapshot }
        DeepAcl       = { Invoke-DeepAclChecks -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap }
        BadSuccessor  = { Invoke-BadSuccessorCheck -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap }
        AdCs          = { Invoke-AdcsChecks -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap }
        Dns           = { Invoke-DnsChecks -Snapshot $Snapshot }
        Sccm          = { Invoke-SccmChecks -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap }
        GroupNesting  = { Invoke-GroupNestingCheck -Index $Index }
        Gpo           = { if (Get-Command Invoke-GpoChecks -ErrorAction SilentlyContinue) { Invoke-GpoChecks -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap } }
        PasswordQuality = { if (Get-Command Invoke-PasswordQualityChecks -ErrorAction SilentlyContinue) { Invoke-PasswordQualityChecks -Snapshot $Snapshot } }
        LapsReaders   = { Invoke-LapsReaderCheck -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap }
        Health        = { Invoke-HealthChecks -Snapshot $Snapshot -Index $Index }
    }
    foreach ($name in $subChecks.Keys) {
        try { & $subChecks[$name] }
        catch { Write-Warning "Check group '$name' failed and was skipped: $($_.Exception.Message)" }
    }

    return (Sort-FindingsStable -Findings $script:Findings -Catalog $script:CheckCatalog)
}

# Position of a check in the catalogs (AD, then Entra): the tie-breaker that
# keeps sorted lists in the same order on PS 5.1 and 7, whose Sort-Object
# break ties differently.
function Get-CheckPosition {
    param([string]$Type)
    $total = @($script:CheckCatalog.Keys).Count + $(if ($script:EntraCheckCatalog) { @($script:EntraCheckCatalog.Keys).Count } else { 0 })
    if (-not $script:CheckPositions -or $script:CheckPositions.Count -ne $total) {
        $script:CheckPositions = @{}; $i = 0
        foreach ($k in @($script:CheckCatalog.Keys) + @(if ($script:EntraCheckCatalog) { $script:EntraCheckCatalog.Keys })) { if (-not $script:CheckPositions.ContainsKey("$k")) { $script:CheckPositions["$k"] = $i }; $i++ }
    }
    if ($script:CheckPositions.ContainsKey($Type)) { return $script:CheckPositions[$Type] }
    return 99999
}

# Findings in a fixed order: catalog position of the check, then object. PS 7
# randomizes hashtable order per process, so without this the CSV, the JSON
# Lines and the AI prompt changed order from one run of the same snapshot to
# the next. Ordinal keys: the same order on every machine and culture.
function Sort-FindingsStable {
    param($Findings, $Catalog)
    $items = @($Findings | Where-Object { $_ })
    if ($items.Count -lt 2) { return $items }
    $pos = @{}; $i = 0
    foreach ($k in $Catalog.Keys) { $pos["$k"] = $i; $i++ }
    # Only the keys are sorted: [Array]::Sort(keys, items) from PowerShell sorts
    # a copy of the items. Each key ends with the item's index.
    $keys = New-Object 'System.Collections.Generic.List[string]'
    for ($n = 0; $n -lt $items.Count; $n++) {
        $p = if ($pos.ContainsKey("$($items[$n].Type)")) { $pos["$($items[$n].Type)"] } else { 9999 }
        $keys.Add(('{0:D4}|{1}|{2}|{3}|{4:D6}' -f $p, "$($items[$n].Type)", "$($items[$n].Object)".ToLowerInvariant(), "$($items[$n].Object)", $n))
    }
    $keys.Sort([StringComparer]::Ordinal)
    # Unrolled on purpose: callers collect with @().
    foreach ($k in $keys) { $items[[int]$k.Substring($k.Length - 6)] }
}

# --------------------------------------------------------------------------
# Pre-Windows 2000 Compatible Access
# --------------------------------------------------------------------------
function Invoke-GroupNestingCheck {
    param($Index)
    $groups = @($Index.Groups)
    if ($groups.Count -eq 0) { return }
    $adj = @{}
    foreach ($g in $groups) {
        if (-not $g.distinguishedName) { continue }
        $dn = $g.distinguishedName.ToLower()
        $adj[$dn] = New-Object System.Collections.Generic.List[string]
        foreach ($m in @($g.members | Where-Object { $_ })) {
            $md = Get-DnString $m
            if (-not $md) { continue }
            $md = $md.ToLower()
            $mo = $Index.ByDn[$md]
            if ($mo -and $mo._type -eq 'group') { $adj[$dn].Add($md) }
        }
    }
    $reach = @{}
    foreach ($n in $adj.Keys) {
        $seen = @{}; $stack = New-Object System.Collections.Generic.Stack[string]
        foreach ($x in $adj[$n]) { $stack.Push($x) }
        while ($stack.Count -gt 0) {
            $c = $stack.Pop()
            if ($seen.ContainsKey($c)) { continue }
            $seen[$c] = $true
            if ($adj.ContainsKey($c)) { foreach ($x in $adj[$c]) { if (-not $seen.ContainsKey($x)) { $stack.Push($x) } } }
        }
        $reach[$n] = $seen
    }
    $done = @{}
    foreach ($n in ($adj.Keys | Sort-Object)) {
        if ($done.ContainsKey($n)) { continue }
        if (-not $reach[$n].ContainsKey($n)) { continue }
        $comp = New-Object System.Collections.Generic.List[string]
        $comp.Add($n)
        foreach ($m in $adj.Keys) {
            if ($m -eq $n) { continue }
            if ($reach[$n].ContainsKey($m) -and $reach[$m].ContainsKey($n)) { $comp.Add($m) }
        }
        foreach ($c in $comp) { $done[$c] = $true }
        if ($comp.Count -ge 2) {
            $names = @($comp | ForEach-Object { $o = $Index.ByDn[$_]; if ($o -and $o.name) { $o.name } else { $_ } } | Sort-Object)
            Add-Finding -Type circular_group_nesting -Object ($names | Select-Object -First 1) -ObjectType 'group' `
                -Detail "Groups in a nesting cycle: $($names -join ', ')."
        }
    }
}

function Invoke-LapsReaderCheck {
    param($Snapshot, $Index, $PrivMap)
    $lapsGuids = @($Snapshot.domain.lapsAttrGuids | Where-Object { $_ } | ForEach-Object { "$_".ToLower() })
    if ($lapsGuids.Count -eq 0) { return }
    $deep = @($Snapshot.deepAcls | Where-Object { $_ -and "$($_.objectClass)" -match '(?i)computer' })
    if ($deep.Count -eq 0) { return }
    $tier0 = Get-Tier0SidSet $Index $PrivMap
    $default = @(Get-DefaultAclPrincipals $Index)
    $byReader = [ordered]@{}
    foreach ($acl in $deep) {
        foreach ($ace in @($acl.aces | Where-Object { $_ })) {
            if ("$($ace.accessType)" -ne 'Allow') { continue }
            $sid = "$($ace.sid)"
            if (-not $sid -or $tier0.ContainsKey($sid) -or $default -contains $sid -or $sid -in @('S-1-5-18', 'S-1-5-10')) { continue }
            $rights = "$($ace.rights)"; $ot = "$($ace.objectType)".ToLower()
            $can = $false
            if ($rights -match '\bGenericAll\b') { $can = $true }
            elseif ($rights -match '\bReadProperty\b' -and $lapsGuids -contains $ot) { $can = $true }
            elseif ($rights -match '\bExtendedRight\b' -and ($ot -eq $script:EmptyGuid -or $ot -eq '' -or $lapsGuids -contains $ot)) { $can = $true }
            if (-not $can) { continue }
            if (-not $byReader.Contains($sid)) { $byReader[$sid] = [PSCustomObject]@{ Name = $ace.name; Computers = (New-Object System.Collections.Generic.HashSet[string]) } }
            [void]$byReader[$sid].Computers.Add($acl.distinguishedName)
        }
    }
    foreach ($sid in $byReader.Keys) {
        $r = $byReader[$sid]
        $n = if ($r.Name) { $r.Name } else { $sid }
        Add-Finding -Type laps_readers -Object $n -ObjectType 'acl' `
            -Detail "Non-Tier 0 principal can read the LAPS password of $($r.Computers.Count) computer(s)."
    }
}

# First fixed update revision per build for noPac (November 2021 cumulative updates).
$script:NoPacFixedUbr = @{ 14393 = 4770; 17763 = 2300; 19041 = 1348; 19042 = 1348; 19043 = 1348; 20348 = 350 }
# $true patched, $false vulnerable, $null when the build alone can't tell (2012 R2 and older
# have no update revision; the update revision could not be read).
function Get-NoPacStatus {
    param($DcState)
    $b = 0
    if (-not [int]::TryParse("$($DcState.osBuild)", [ref]$b) -or $b -le 0) { return $null }
    if ($b -gt 20348) { return $true }
    if (-not $script:NoPacFixedUbr.ContainsKey($b) -or $null -eq $DcState.osUbr) { return $null }
    return ([int]$DcState.osUbr -ge $script:NoPacFixedUbr[$b])
}

function Invoke-HealthChecks {
    param($Snapshot, $Index)
    $h = $Snapshot.health
    if (-not $h -or -not $h.collected) { return }
    foreach ($r in @($h.replication | Where-Object { $_ })) {
        if ([int]$r.consecutiveFailures -gt 0) {
            Add-Finding -Type replication_failures -Object "$($r.server)" -ObjectType 'dc' `
                -Detail "$($r.consecutiveFailures) consecutive replication failure(s) with partner $($r.partner)."
        }
        else {
            $age = Get-AgeDays $r.lastSuccessUtc
            if ($null -eq $age -or $age -ge 1) {
                Add-Finding -Type replication_stale -Object "$($r.server)" -ObjectType 'dc' `
                    -Detail "Last successful replication with $($r.partner): $(Format-Age $age)$(if ($null -ne $age) { ' ago' })."
            }
        }
    }
    $bAge = Get-AgeDays $h.lastBackupUtc
    if ($null -ne $bAge -and $bAge -gt 7) {
        Add-Finding -Type ad_backup_overdue -Object $Snapshot.domain.dnsRoot -ObjectType 'domain' -ObjectDn $Snapshot.domain.distinguishedName `
            -Detail "Last AD backup of the domain naming context was $bAge days ago (threshold 7)."
    }
    $dcHosts = @{}
    foreach ($c in @($Index.Computers | Where-Object { $_._isDc })) {
        if ($c.dnsHostName) { $dcHosts["$($c.dnsHostName)".ToLower()] = $true }
        if ($c.samAccountName) { $dcHosts["$("$($c.samAccountName)".TrimEnd('$'))".ToLower()] = $true }
    }
    foreach ($d in @($h.dhcpServers | Where-Object { $_ })) {
        $dn = "$($d.name)".ToLower()
        $short = ($dn -split '\.')[0]
        if ($dcHosts.ContainsKey($dn) -or $dcHosts.ContainsKey($short)) {
            Add-Finding -Type dhcp_on_dc -Object "$($d.name)" -ObjectType 'dc' -Detail "Authorized DHCP server $($d.name) ($($d.ip)) is a domain controller."
        }
    }

    # FSMO roles must sit on a current DC. Forest roles only count in the forest root.
    if ($h.PSObject.Properties['fsmo'] -and $h.fsmo) {
        $known = @{}
        foreach ($d in @($Snapshot.domainControllers | Where-Object { $_ })) { $known["$($d.hostName)".ToLower()] = $true; $known["$($d.name)".ToLower()] = $true }
        $roles = @('PDCEmulator', 'RIDMaster', 'InfrastructureMaster'); if ($h.forestRoot) { $roles += 'SchemaMaster', 'DomainNamingMaster' }
        foreach ($r in $roles) {
            $holder = "$($h.fsmo.$r)"; $hl = $holder.ToLower()
            if (-not $holder) {
                Add-Finding -Type fsmo_holder_invalid -Object $r -ObjectType 'fsmo' -Detail "AD reports no holder for $r."
            }
            elseif (-not ($known.ContainsKey($hl) -or $known.ContainsKey(($hl -split '\.')[0]))) {
                Add-Finding -Type fsmo_holder_invalid -Object $r -ObjectType 'fsmo' -Detail "$r is held by $holder, which is not one of the current domain controllers."
            }
        }
    }
    foreach ($r in @($h.dcReachability | Where-Object { $_ -and -not $_.reachable })) {
        Add-Finding -Type dc_unreachable -Object "$($r.dc)" -ObjectType 'dc' -Detail "No LDAP answer from the collecting machine: $($r.error)"
    }
    # Only the spread between DCs matters: the collecting machine's own clock cancels out.
    $offs = @($h.dcTime | Where-Object { $_ -and $null -ne $_.offsetSeconds })
    if ($offs.Count -ge 2) {
        $sorted = @($offs | Sort-Object { [double]$_.offsetSeconds })
        $spread = [Math]::Round([double]$sorted[-1].offsetSeconds - [double]$sorted[0].offsetSeconds, 1)
        if ($spread -gt 60) {
            $sev = if ($spread -gt 300) { 'High' } else { 'Medium' }
            Add-Finding -Type dc_time_skew -Object 'domain controllers' -ObjectType 'dc' -Severity $sev `
                -Detail "Clocks differ by $spread s between $($sorted[0].dc) and $($sorted[-1].dc) (Kerberos fails beyond 300 s)."
        }
    }
    # Coercion: interfaces behind running services, minus those an RPC filter mentions.
    $relay = @()
    if ($Snapshot.gpo -and $Snapshot.gpo.collected) {
        $gOrder = Get-EffectiveGpoOrder $Snapshot.gpo
        $li = Get-RegInt (Get-EffectiveRegValue $gOrder 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity')
        $lcb = Get-RegInt (Get-EffectiveRegValue $gOrder 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding')
        if ($null -eq $li -or $li -lt 2) { $relay += 'LDAP signing not required' }
        if ($null -eq $lcb -or $lcb -lt 2) { $relay += 'LDAPS channel binding not enforced' }
    }
    foreach ($ca in @($Snapshot.adcs.enrollmentServices | Where-Object { $_ -and $_.PSObject.Properties['caRegistry'] -and $_.caRegistry -and -not $_.caRegistry.error })) {
        if ($ca.caRegistry.webEnrollment -or $ca.caRegistry.enrollmentWebService) { $relay += "AD CS web enrollment on $($ca.name) (ESC8)" }
        if ($null -ne $ca.caRegistry.interfaceFlags -and ([int64]$ca.caRegistry.interfaceFlags -band 0x200) -eq 0) { $relay += "AD CS RPC enrollment on $($ca.name) (ESC11)" }
    }
    foreach ($s in @($h.dcState | Where-Object { $_ -and -not $_.error -and $_.PSObject.Properties['coercionServices'] -and $_.coercionServices })) {
        $svc = $s.coercionServices
        $open = @()
        # MS-EFSR is also served by LSASS over \pipe\lsarpc, so the EFS service state doesn't close it.
        $open += "MS-EFSR (EFS service $(Get-Member2 $svc 'EFS'))"
        if ("$(Get-Member2 $svc 'Dfs')" -match '/Running$') { $open += 'MS-DFSNM (DFS Namespace running)' }
        if ("$(Get-Member2 $svc 'EventLog')" -match '/Running$') { $open += 'MS-EVEN (EventLog running)' }
        # Assigned in a branch, not from an if-expression: an empty array would come out as $null.
        $filtered = $null
        if ($s.PSObject.Properties['rpcFilterInterfaces'] -and $null -ne $s.rpcFilterInterfaces) { $filtered = @($s.rpcFilterInterfaces | ForEach-Object { "$_" }) }
        if ($null -ne $filtered) { $open = @($open | Where-Object { $filtered -notcontains (($_ -split ' ')[0]) }) }
        if (-not $open.Count) { continue }
        $fText = if ($null -eq $filtered) { 'RPC filters could not be read (verify any filter deployed by hand)' } elseif ($filtered.Count) { "RPC filters found for $($filtered -join ', ')" } else { 'no RPC filter for these interfaces' }
        $rText = if ($relay.Count) { " Relay targets open: $(($relay | Select-Object -Unique) -join '; ')." } else { '' }
        Add-Finding -Type coercion_unfiltered_dc -Object "$($s.dc)" -ObjectType 'dc' -Severity $(if ($relay.Count) { 'High' } else { 'Medium' }) `
            -Detail "Open: $($open -join ', '); $fText.$rText"
    }
    # noPac: build + update revision older than the fix.
    $maq = $Snapshot.domain.machineAccountQuota
    foreach ($s in @($h.dcState | Where-Object { $_ -and -not $_.error -and $_.PSObject.Properties['osBuild'] })) {
        if ((Get-NoPacStatus $s) -ne $false) { continue }
        $open = $null -ne $maq -and [int]$maq -gt 0
        Add-Finding -Type nopac_unpatched_dc -Object "$($s.dc)" -ObjectType 'dc' -Severity $(if ($open) { 'Critical' } else { 'High' }) `
            -Detail "Build $($s.osBuild).$($s.osUbr), fixed from $($s.osBuild).$($script:NoPacFixedUbr[[int]$s.osBuild]). Machine account quota: $(if ($null -eq $maq) { 'unknown' } else { $maq })$(if ($open) { ', so any user can exploit it' })."
    }
    # NetBIOS over TCP/IP on DC adapters: 2 is the only "off"; 0 (from DHCP) means on with a static IP.
    foreach ($s in @($h.dcState | Where-Object { $_ -and -not $_.error -and $_.PSObject.Properties['netbiosAdapters'] -and $null -ne $_.netbiosAdapters })) {
        $on = @(@($s.netbiosAdapters) | Where-Object { $_ -and $null -ne $_.netbiosOption -and [int]$_.netbiosOption -ne 2 } |
                ForEach-Object { "$($_.adapter) ($(if ([int]$_.netbiosOption -eq 1) { 'enabled' } else { 'default: from DHCP' }))" })
        if ($on.Count) { Add-Finding -Type nbtns_enabled_dc -Object "$($s.dc)" -ObjectType 'dc' -Detail "NetBIOS over TCP/IP on: $($on -join '; ')." }
    }
    # WebClient on DCs, live state (Running is worse than an idle Manual service).
    foreach ($s in @($h.dcState | Where-Object { $_ -and -not $_.error -and $_.PSObject.Properties['webClientStartMode'] -and $_.webClientStartMode })) {
        $wm = "$($s.webClientStartMode)"
        if ($wm -eq 'absent' -or $wm -eq 'Disabled') { continue }
        $sev = if ("$($s.webClientState)" -eq 'Running') { 'High' } else { 'Medium' }
        Add-Finding -Type webclient_on_dc -Object "$($s.dc)" -ObjectType 'dc' -Severity $sev -Detail "WebClient service: start mode $wm, state $($s.webClientState)."
    }
    # DSRM administrator logon behavior (2 = can log on while the DC runs normally): Tier 0 persistence.
    foreach ($s in @($h.dcState | Where-Object { $_ -and -not $_.error -and $_.PSObject.Properties['dsrmAdminLogonBehavior'] -and $null -ne $_.dsrmAdminLogonBehavior })) {
        if ([int]$s.dsrmAdminLogonBehavior -eq 2) {
            Add-Finding -Type dsrm_logon_behavior -Object "$($s.dc)" -ObjectType 'dc' -Detail 'DsrmAdminLogonBehavior = 2: the DSRM local administrator can log on while the DC runs normally.'
        }
    }
    foreach ($s in @($h.dcState | Where-Object { $_ -and -not $_.error })) {
        if ($null -ne $s.freeGB -and $s.sizeGB) {
            $free = [double]$s.freeGB; $pct = [Math]::Round(100 * $free / [double]$s.sizeGB, 1)
            if ($free -lt 2) { $sev = 'High' } elseif ($free -lt 6 -or $pct -lt 10) { $sev = 'Medium' } else { $sev = '' }
            if ($sev) { Add-Finding -Type dc_low_disk -Object "$($s.dc)" -ObjectType 'dc' -Severity $sev -Detail "$($s.systemDrive) has $free GB free of $($s.sizeGB) GB ($pct%)." }
        }
        $stopped = @($s.stoppedServices | Where-Object { $_ })
        if ($stopped.Count) { Add-Finding -Type dc_service_stopped -Object "$($s.dc)" -ObjectType 'dc' -Detail "Not running: $($stopped -join ', ')." }
    }
}

function Invoke-DnsChecks {
    param($Snapshot)
    $dns = $Snapshot.dns
    if (-not $dns -or -not $dns.collected) { return }
    $dom = "$($Snapshot.domain.sid)"
    $broad = @(@('S-1-1-0', 'Everyone'), @('S-1-5-7', 'Anonymous Logon'), @('S-1-5-11', 'Authenticated Users'), @("$dom-513", 'Domain Users'), @("$dom-515", 'Domain Computers'))
    foreach ($z in @($dns.zones | Where-Object { $_ })) {
        if ($z.isAdIntegrated -and $z.PSObject.Properties['createChildSids'] -and $null -ne $z.createChildSids) {
            $cc = @($z.createChildSids | Where-Object { $_ } | ForEach-Object { "$_" })
            $who = @($broad | Where-Object { $cc -contains $_[0] } | ForEach-Object { $_[1] })
            if ($who.Count -gt 0) {
                Add-Finding -Type dns_zone_create_child -Object $z.name -ObjectType 'dnszone' -Detail "Create child objects (new DNS records) granted to: $($who -join ', ')."
            }
        }
        $du = "$($z.dynamicUpdate)"
        if ($du -match '(?i)nonsecure') {
            Add-Finding -Type dns_insecure_updates -Object $z.name -ObjectType 'dnszone' -Detail "DynamicUpdate = $du."
        }
        if ("$($z.secureSecondaries)" -match '(?i)TransferToAnyServer|TransferAnyServer') {
            Add-Finding -Type dns_zone_transfer_allowed -Object $z.name -ObjectType 'dnszone' -Detail "SecureSecondaries = $($z.secureSecondaries)."
        }
        if ($z.agingEnabled -eq $false) {
            Add-Finding -Type dns_scavenging_disabled -Object $z.name -ObjectType 'dnszone' -Detail 'Aging/scavenging not enabled on the zone.'
        }
    }
    foreach ($r in @($dns.dangerousRecords | Where-Object { $_ })) {
        $nm = "$($r.name)".ToLower()
        $sev = if ($nm -eq 'wpad' -or $nm -eq '*') { 'High' } else { 'Medium' }
        Add-Finding -Type dns_dangerous_record -Object "$($r.name) ($($r.zone))" -ObjectType 'dnsrecord' -Severity $sev -Detail "$($r.type) record '$($r.name)' in zone $($r.zone)."
    }
}

function Invoke-PreWin2000Check {
    param($Snapshot)
    $g = $Snapshot.preWin2000
    if (-not $g) { return }
    $bad = @($g.members | Where-Object { $_ } | Where-Object {
            # Anonymous and Everyone show up as ForeignSecurityPrincipals DNs.
            $_ -match 'S-1-5-7\b' -or $_ -match 'S-1-1-0\b'
        })
    if ($bad.Count -gt 0) {
        Add-Finding -Type pre_win2000_anonymous -Object $g.name -ObjectType 'group' -ObjectDn $g.distinguishedName `
            -Detail "Members include Anonymous Logon or Everyone: $($bad -join ', ')."
    }
}

# --------------------------------------------------------------------------
# -Deep only: dangerous ACEs held by non-privileged principals, on any object.
# --------------------------------------------------------------------------
function Invoke-DeepAclChecks {
    param($Snapshot, $Index, $PrivMap)
    $deep = @($Snapshot.deepAcls | Where-Object { $_ })
    $default = @(Get-DefaultAclPrincipals $Index)
    # Tier 0 holding rights is expected.
    $privSids = @{}
    foreach ($rec in $PrivMap.Principals.Values) { if ($rec.Principal -and $rec.Principal.sid) { $privSids[$rec.Principal.sid] = $true } }
    foreach ($entry in $PrivMap.Groups.Values) { if ($entry.Group.sid) { $privSids[$entry.Group.sid] = $true } }

    # Golden gMSA: reading the key (or being able to grant it) is enough, inherited or not.
    $kdsReaders = [ordered]@{}
    foreach ($acl in @($Snapshot.kdsRootKeyAcls | Where-Object { $_ })) {
        foreach ($ace in @($acl.aces | Where-Object { $_ -and "$($_.accessType)" -eq 'Allow' })) {
            if ($default -contains $ace.sid -or $privSids.ContainsKey($ace.sid)) { continue }
            $r = "$($ace.rights)"
            $full = $r -match 'GenericAll|GenericRead|WriteDacl|WriteOwner'
            $read = $r -match 'ReadProperty' -and "$($ace.objectType)" -eq '00000000-0000-0000-0000-000000000000'
            if (-not ($full -or $read)) { continue }
            if (-not $kdsReaders.Contains($ace.sid)) { $kdsReaders[$ace.sid] = [PSCustomObject]@{ Name = $(if ($ace.name) { $ace.name } else { $ace.sid }); Keys = New-Object System.Collections.Generic.List[string]; Rights = New-Object System.Collections.Generic.List[string] } }
            $kn = "$($acl.target)" -replace '^kds:', ''
            if (-not $kdsReaders[$ace.sid].Keys.Contains($kn)) { $kdsReaders[$ace.sid].Keys.Add($kn) }
            foreach ($one in ($r -split ',\s*')) { if ($one -match 'GenericAll|GenericRead|WriteDacl|WriteOwner|ReadProperty' -and -not $kdsReaders[$ace.sid].Rights.Contains($one)) { $kdsReaders[$ace.sid].Rights.Add($one) } }
        }
    }
    foreach ($sid in $kdsReaders.Keys) {
        $kr = $kdsReaders[$sid]
        $sev = if ($kr.Name -match '(?i)authenticated users|everyone|domain users|domain computers') { 'Critical' } else { 'High' }
        Add-Finding -Type kds_root_key_readable -Object $kr.Name -ObjectType 'acl' -Severity $sev `
            -Detail "$($kr.Rights -join ', ') on KDS root key(s): $(($kr.Keys | Sort-Object) -join ', ')."
    }

    if ($deep.Count -eq 0) { return }
    # Everyone-style principals: any control right they hold is worth a look.
    $dom = $Index.DomainSid

    foreach ($acl in $deep) {
        $targetDn = $acl.distinguishedName
        # Tier 0 objects have their own checks.
        $per = [ordered]@{}
        foreach ($ace in @($acl.aces | Where-Object { $_ })) {
            if ($ace.isInherited) { continue }
            if ($default -contains $ace.sid) { continue }
            if ($privSids.ContainsKey($ace.sid)) { continue }
            if ($ace.sid -eq $acl.ownerSid) { continue }
            # Self rights on the object's own account are normal.
            if ($ace.sid -eq 'S-1-5-10') { continue }
            $danger = Get-AceDanger $ace
            if (-not $danger) { continue }
            if (-not (Test-AceAppliesToSelf $ace)) { continue }
            if (-not $per.Contains($ace.sid)) { $per[$ace.sid] = [PSCustomObject]@{ Name = $ace.name; Items = New-Object System.Collections.Generic.List[string] } }
            if (-not $per[$ace.sid].Items.Contains($danger)) { $per[$ace.sid].Items.Add($danger) }
        }
        foreach ($sid in $per.Keys) {
            $name = if ($per[$sid].Name) { $per[$sid].Name } else { $sid }
            $victim = $Index.ByDn[$targetDn.ToLower()]
            $victimName = if ($victim) { if ($victim.samAccountName) { $victim.samAccountName } else { $victim.name } } else { ($targetDn -split ',')[0] -replace '^..=', '' }
            $sev = if ($name -match '(?i)authenticated users|everyone|domain users|domain computers') { 'Critical' } else { 'High' }
            Add-Finding -Type dangerous_ace_anywhere -Object $name -ObjectType 'acl' -ObjectDn $targetDn -Severity $sev `
                -Detail "$(($per[$sid].Items | Select-Object -Unique) -join ', ') over $($acl.objectClass) '$victimName'."
        }
    }
}

# --------------------------------------------------------------------------
# BadSuccessor: who can create a dMSA in an OU or container. Only a Windows
# Server 2025 DC honours the dMSA successor link, so without one it is silent.
# --------------------------------------------------------------------------
$script:DmsaClassGuid = '0feb936f-47b3-49f2-9386-1dedc2c23765'
# First fixed update revision of build 26100 (August 2025 cumulative update, CVE-2025-53779).
$script:BadSuccessorFixedUbr = 4946
# organizationalUnit, container: an inherit-only ACE scoped to these still reaches child containers.
$script:ContainerClassGuids = @('bf967aa5-0de6-11d0-a285-00aa003049e2', 'bf967a8b-0de6-11d0-a285-00aa003049e2')

function Invoke-BadSuccessorCheck {
    param($Snapshot, $Index, $PrivMap)
    if (-not $Snapshot.PSObject.Properties['ouAcls']) { return }
    $state = @{}
    foreach ($s in @($Snapshot.health.dcState | Where-Object { $_ -and -not $_.error })) { $state["$($s.dc)".ToLower()] = $s }
    $dc2025 = New-Object System.Collections.Generic.List[object]
    foreach ($dc in @($Snapshot.domainControllers | Where-Object { $_ })) {
        $s = $state["$($dc.hostName)".ToLower()]
        $b = 0
        if ($s) { [void][int]::TryParse("$($s.osBuild)", [ref]$b) }
        if ("$($dc.operatingSystem)" -notmatch '2025' -and $b -lt 26100) { continue }
        # $true patched, $false vulnerable, $null when the live build could not be read.
        $patched = $null
        if ($b -gt 26100) { $patched = $true }
        elseif ($b -eq 26100 -and $null -ne $s.osUbr) { $patched = ([int]$s.osUbr -ge $script:BadSuccessorFixedUbr) }
        $text = if ($patched -eq $true) { 'patched' } elseif ($patched -eq $false) { "build $b.$($s.osUbr), not patched" } else { 'patch level not read' }
        $dc2025.Add([PSCustomObject]@{ Name = "$($dc.name)"; Patched = $patched; Text = $text })
    }
    if ($dc2025.Count -eq 0) { return }
    $allPatched = @($dc2025 | Where-Object { $_.Patched -ne $true }).Count -eq 0
    $dcText = "Windows Server 2025 DC(s): $(@($dc2025 | ForEach-Object { "$($_.Name) ($($_.Text))" }) -join ', ')."

    $tier0 = Get-Tier0SidSet $Index $PrivMap
    $per = [ordered]@{}
    $targets = @($Snapshot.acls | Where-Object { $_ -and $_.target -eq 'DomainRoot' }) + @($Snapshot.ouAcls | Where-Object { $_ })
    foreach ($acl in $targets) {
        $hits = New-Object System.Collections.Generic.List[object]
        if ($acl.ownerSid -and -not $tier0.ContainsKey("$($acl.ownerSid)")) {
            $hits.Add([PSCustomObject]@{ Sid = "$($acl.ownerSid)"; Name = "$($acl.ownerName)"; Right = 'owner' })
        }
        foreach ($ace in @($acl.aces | Where-Object { $_ })) {
            if ("$($ace.accessType)" -ne 'Allow' -or $ace.isInherited) { continue }
            if ($tier0.ContainsKey("$($ace.sid)")) { continue }
            $iot = "$($ace.inheritedObjectType)".ToLower()
            if (-not (Test-AceAppliesToSelf $ace) -and $iot -and $iot -ne $script:EmptyGuid -and $script:ContainerClassGuids -notcontains $iot) { continue }
            $r = "$($ace.rights)"
            $ot = "$($ace.objectType)".ToLower()
            $labels = @()
            foreach ($x in 'GenericAll', 'WriteDacl', 'WriteOwner') { if ($r -match "\b$x\b") { $labels += $x } }
            if ($r -match '\bCreateChild\b' -and ($ot -eq '' -or $ot -eq $script:EmptyGuid)) { $labels += 'CreateChild(all)' }
            elseif ($r -match '\bCreateChild\b' -and $ot -eq $script:DmsaClassGuid) { $labels += 'CreateChild(dMSA)' }
            foreach ($l in $labels) { $hits.Add([PSCustomObject]@{ Sid = "$($ace.sid)"; Name = "$($ace.name)"; Right = $l }) }
        }
        foreach ($h in $hits) {
            if (-not $per.Contains($h.Sid)) { $per[$h.Sid] = [PSCustomObject]@{ Name = $(if ($h.Name) { $h.Name } else { $h.Sid }); Where = [ordered]@{} } }
            $dn = "$($acl.distinguishedName)"
            if (-not $per[$h.Sid].Where.Contains($dn)) { $per[$h.Sid].Where[$dn] = New-Object System.Collections.Generic.List[string] }
            if (-not $per[$h.Sid].Where[$dn].Contains($h.Right)) { $per[$h.Sid].Where[$dn].Add($h.Right) }
        }
    }
    foreach ($sid in $per.Keys) {
        $p = $per[$sid]
        $broad = $p.Name -match '(?i)authenticated users|everyone|domain users|domain computers'
        $sev = if ($allPatched) { 'Medium' } elseif ($broad) { 'Critical' } else { 'High' }
        $parts = @($p.Where.Keys | ForEach-Object { "$($p.Where[$_] -join ', ') on $_" })
        $more = if ($parts.Count -gt 8) { "; and $($parts.Count - 8) more container(s)" } else { '' }
        Add-Finding -Type badsuccessor_dmsa_create -Object $p.Name -ObjectType 'acl' -Severity $sev `
            -Detail "$(@($parts | Select-Object -First 8) -join '; ')$more. $dcText"
    }
}

# --------------------------------------------------------------------------
# SCCM / MECM: who can write to the System Management container. Site servers (computer
# accounts, or groups whose members are all computer accounts) hold Full Control by design.
# --------------------------------------------------------------------------
function Invoke-SccmChecks {
    param($Snapshot, $Index, $PrivMap)
    if (-not $Snapshot.PSObject.Properties['sccm'] -or -not $Snapshot.sccm -or -not $Snapshot.sccm.present -or -not $Snapshot.sccm.acl) { return }
    $acl = $Snapshot.sccm.acl
    $tier0 = Get-Tier0SidSet $Index $PrivMap
    $isSiteServer = {
        param([string]$Sid)
        $o = $Index.BySid[$Sid]
        if (-not $o) { return $false }
        if ($o._type -eq 'computer') { return $true }
        # Domain Computers is all computer accounts too, but it is every machine, not the site servers.
        if ($o._type -ne 'group' -or "$($o.sid)" -match '-515$') { return $false }
        $m = @(Get-EffectiveMembers $Index $o)
        return ($m.Count -gt 0 -and @($m | Where-Object { $_.Type -ne 'computer' }).Count -eq 0)
    }
    $siteServers = New-Object System.Collections.Generic.List[string]
    $per = [ordered]@{}
    $add = {
        param([string]$Sid, [string]$Name, [string]$Right)
        if (-not $per.Contains($Sid)) { $per[$Sid] = [PSCustomObject]@{ Name = $(if ($Name) { $Name } else { $Sid }); Rights = New-Object System.Collections.Generic.List[string] } }
        if (-not $per[$Sid].Rights.Contains($Right)) { $per[$Sid].Rights.Add($Right) }
    }
    if ($acl.ownerSid -and -not $tier0.ContainsKey("$($acl.ownerSid)") -and -not (& $isSiteServer "$($acl.ownerSid)")) { & $add "$($acl.ownerSid)" "$($acl.ownerName)" 'owner' }
    foreach ($ace in @($acl.aces | Where-Object { $_ -and "$($_.accessType)" -eq 'Allow' })) {
        $sid = "$($ace.sid)"
        if ($tier0.ContainsKey($sid)) { continue }
        $r = "$($ace.rights)"
        $labels = @()
        foreach ($x in 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner') { if ($r -match "\b$x\b") { $labels += $x } }
        if ($r -match '\bCreateChild\b') { $labels += 'CreateChild' }
        if ($r -match '\bWriteProperty\b') { $labels += 'WriteProperty' }
        if (-not $labels.Count) { continue }
        if (& $isSiteServer $sid) {
            $n = if ($ace.name) { "$($ace.name)" } else { $sid }
            if (-not $siteServers.Contains($n)) { $siteServers.Add($n) }
            continue
        }
        foreach ($l in $labels) { & $add $sid "$($ace.name)" $l }
    }
    $mps = @($Snapshot.sccm.managementPoints | Where-Object { $_ })
    $context = "Site servers with rights there: $(if ($siteServers.Count) { $siteServers.ToArray() -join ', ' } else { 'none found' }). Management points published: $(if ($mps.Count) { @($mps | ForEach-Object { "$($_.host) (site $($_.siteCode))" }) -join ', ' } else { 'none' })."
    foreach ($sid in $per.Keys) {
        $p = $per[$sid]
        $broad = $p.Name -match '(?i)authenticated users|everyone|domain users|domain computers'
        Add-Finding -Type sccm_system_management_writable -Object $p.Name -ObjectType 'acl' -ObjectDn "$($acl.distinguishedName)" -Severity $(if ($broad) { 'Critical' } else { 'High' }) `
            -Detail "$($p.Rights.ToArray() -join ', ') on CN=System Management. $context"
    }
}

# --------------------------------------------------------------------------
# AD CS template misconfigurations.
# --------------------------------------------------------------------------
# EKU / application-policy OIDs.
$script:EkuClientAuth = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')  # client auth, PKINIT, smartcard logon, anyPurpose(as-well)
$script:EkuAnyPurpose = '2.5.29.37.0'
$script:EkuEnrollmentAgent = '1.3.6.1.4.1.311.20.2.1'
# msPKI-Certificate-Name-Flag / Enrollment-Flag bits.
$script:CT_ENROLLEE_SUPPLIES_SUBJECT = 0x1
$script:CT_PEND_ALL_REQUESTS = 0x2   # manager approval
$script:CT_NO_SECURITY_EXTENSION = 0x80000   # msPKI-Enrollment-Flag: omit szOID_NTDS_CA_SECURITY_EXT (ESC9)
# Enroll / AutoEnroll extended-right GUIDs.
$script:EnrollRightGuids = @('0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2', '00000000-0000-0000-0000-000000000000')
# Low-privilege enrollers.
function Get-LowPrivEnrollSids {
    param($DomainSid)
    return @('S-1-5-11', 'S-1-1-0', 'S-1-5-32-545', "$DomainSid-513", "$DomainSid-515")
}

function Test-TemplateLowPrivEnroll {
    param($Template, $LowPrivSids)
    foreach ($ace in @($Template.aces | Where-Object { $_ })) {
        if ($ace.accessType -ne 'Allow') { continue }
        if ($LowPrivSids -notcontains $ace.sid) { continue }
        $rights = "$($ace.rights)"
        $ot = "$($ace.objectType)".ToLower()
        if ($rights -match '\bGenericAll\b') { return $ace.name }
        if ($rights -match '\bExtendedRight\b' -and ($script:EnrollRightGuids -contains $ot)) { return $ace.name }
    }
    return $null
}

function Test-TemplateDangerousAcl {
    param($Template, $LowPrivSids, $PrivSids)
    $hits = @()
    foreach ($ace in @($Template.aces | Where-Object { $_ })) {
        if ($ace.accessType -ne 'Allow') { continue }
        if ($PrivSids.ContainsKey($ace.sid)) { continue }
        if ($ace.sid -in @('S-1-5-18', 'S-1-5-9')) { continue }
        $rights = "$($ace.rights)"
        if ($rights -match '\b(GenericAll|WriteDacl|WriteOwner|WriteProperty|GenericWrite)\b') {
            $hits += "$($ace.name): $rights"
        }
    }
    if ($Template.ownerSid -and -not $PrivSids.ContainsKey($Template.ownerSid) -and $Template.ownerSid -notin @('S-1-5-18')) {
        $hits += "Owner: $($Template.ownerName)"
    }
    return $hits
}

function Test-TemplateHasEku {
    param($Template, [string[]]$Oids)
    $ekus = @($Template.ekus)
    if ($ekus.Count -eq 0) { return $false }
    foreach ($o in $Oids) { if ($ekus -contains $o) { return $true } }
    return $false
}

function Invoke-AdcsChecks {
    param($Snapshot, $Index, $PrivMap)
    $adcs = $Snapshot.adcs
    if (-not $adcs -or -not $adcs.collected) { return }
    # Issuance-policy OID -> group link map and the Tier 0 set, for ESC13.
    $oidToGroup = @{}
    foreach ($l in @($adcs.oidGroupLinks | Where-Object { $_ -and $_.oid })) { $oidToGroup["$($l.oid)"] = $l }
    $tier0 = Get-Tier0SidSet $Index $PrivMap

    # On-CA settings when the collector could read them; a "verify on the CA" note for the rest.
    $unread = @()
    foreach ($ca in @($adcs.enrollmentServices | Where-Object { $_ })) {
        $reg = if ($ca.PSObject.Properties['caRegistry']) { $ca.caRegistry } else { $null }
        if (-not $reg -or $reg.error) { $unread += "$($ca.name)"; continue }
        if ($null -ne $reg.editFlags -and ([int64]$reg.editFlags -band 0x40000) -ne 0) {
            Add-Finding -Type adcs_esc6 -Object "$($ca.name)" -ObjectType 'ca' -Detail "EditFlags = 0x$('{0:X}' -f [int64]$reg.editFlags) includes EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000)."
        }
        if ($null -ne $reg.securityAces) {
            $mgr = [ordered]@{}
            foreach ($a in @($reg.securityAces | Where-Object { $_ -and $_.sid -and -not $tier0.ContainsKey("$($_.sid)") })) {
                $rights = @(); if (([int64]$a.mask -band 1) -ne 0) { $rights += 'Manage CA' }; if (([int64]$a.mask -band 2) -ne 0) { $rights += 'Issue and Manage Certificates' }
                if ($rights.Count) { $mgr["$(if ($a.name) { $a.name } else { $a.sid })"] = $rights -join ' + ' }
            }
            if ($mgr.Count) {
                $broad = @($mgr.Keys | Where-Object { $_ -match '(?i)authenticated users|everyone|domain users|domain computers' }).Count -gt 0
                Add-Finding -Type adcs_esc7 -Object "$($ca.name)" -ObjectType 'ca' -Severity $(if ($broad) { 'Critical' } else { 'High' }) `
                    -Detail "Non-Tier 0 CA officers or managers: $(@($mgr.Keys | ForEach-Object { "$_ ($($mgr[$_]))" }) -join '; ')."
            }
        }
        if ($reg.webEnrollment -or $reg.enrollmentWebService) {
            $what = @(); if ($reg.webEnrollment) { $what += 'Certification Authority Web Enrollment' }; if ($reg.enrollmentWebService) { $what += 'Certificate Enrollment Web Service' }
            Add-Finding -Type adcs_esc8 -Object "$($ca.name)" -ObjectType 'ca' -Detail "Installed on $($ca.dnsHostName): $($what -join ', '). Confirm HTTPS with Extended Protection for Authentication on the site."
        }
        if ($null -ne $reg.interfaceFlags -and ([int64]$reg.interfaceFlags -band 0x200) -eq 0) {
            Add-Finding -Type adcs_esc11 -Object "$($ca.name)" -ObjectType 'ca' -Detail "InterfaceFlags = 0x$('{0:X}' -f [int64]$reg.interfaceFlags) without IF_ENFORCEENCRYPTICERTREQUEST (0x200)."
        }
        if (@($reg.disableExtensionList) -contains '1.3.6.1.4.1.311.25.2') {
            Add-Finding -Type adcs_esc16 -Object "$($ca.name)" -ObjectType 'ca' -Detail 'DisableExtensionList contains 1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT).'
        }
    }
    if ($unread.Count -gt 0) {
        Add-Finding -Type adcs_manual_checks -Object ($unread -join ', ') -ObjectType 'ca' -Detail "The CA settings of $($unread.Count) CA(s) could not be read (needs admin rights on the CA host). ESC6/ESC7/ESC8/ESC11/ESC16 are not in LDAP; verify them on the CA."
    }
    if (@($adcs.enrollmentServices).Count -gt 0) {
        foreach ($ca in $adcs.enrollmentServices) {
            $exp = ConvertTo-UtcDate $ca.caCertExpiry
            if ($exp) {
                $days = [int][Math]::Floor(($exp - $script:RefDate).TotalDays)
                if ($days -lt 180) {
                    $sev = if ($days -lt 0) { 'High' } else { 'Medium' }
                    Add-Finding -Type adcs_ca_cert_expiring -Object $ca.name -ObjectType 'ca' -Severity $sev `
                        -Detail "CA certificate $(if ($days -lt 0) { "expired $([Math]::Abs($days)) days ago" } else { "expires in $days days" }) ($($exp.ToString('yyyy-MM-dd'))). Host: $($ca.dnsHostName)."
                }
            }
            $weak = @()
            if ($ca.caKeySize -and [int]$ca.caKeySize -lt 2048) { $weak += "RSA key $($ca.caKeySize) bits" }
            if ("$($ca.caSigAlg)" -match '(?i)sha1|md5') { $weak += "signature $($ca.caSigAlg)" }
            if ($weak.Count -gt 0) {
                Add-Finding -Type adcs_weak_ca_key -Object $ca.name -ObjectType 'ca' -Detail "CA certificate weakness: $($weak -join ', '). Host: $($ca.dnsHostName)."
            }
        }
    }

    # ESC5: control over the PKI objects themselves. Tier 0, Cert Publishers and the CA computer
    # accounts hold write rights there by default; anyone else is a finding, one per principal.
    $pkiAllowed = @{}
    foreach ($k in $tier0.Keys) { $pkiAllowed[$k] = $true }
    foreach ($s in @("$($Index.DomainSid)-517", "$($Index.RootSid)-517", 'S-1-5-10', 'S-1-3-0')) { $pkiAllowed[$s] = $true }
    $caHosts = @{}; foreach ($ca in @($adcs.enrollmentServices | Where-Object { $_ -and $_.dnsHostName })) { $caHosts["$($ca.dnsHostName)".ToLower()] = $true }
    foreach ($c in @($Index.Computers | Where-Object { $_.dnsHostName -and $caHosts.ContainsKey("$($_.dnsHostName)".ToLower()) })) { if ($c.sid) { $pkiAllowed[$c.sid] = $true } }
    $esc5 = [ordered]@{}
    foreach ($obj in @($adcs.pkiAcls | Where-Object { $_ })) {
        $hits = @()
        if ($obj.ownerSid -and -not $pkiAllowed.ContainsKey("$($obj.ownerSid)")) { $hits += [PSCustomObject]@{ Sid = "$($obj.ownerSid)"; Name = $obj.ownerName; What = 'Owner' } }
        foreach ($ace in @($obj.aces | Where-Object { $_ })) {
            if ($ace.accessType -ne 'Allow' -or $ace.isInherited -or $pkiAllowed.ContainsKey("$($ace.sid)")) { continue }
            $r = @([regex]::Matches("$($ace.rights)", '\b(GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty)\b') | ForEach-Object { $_.Value })
            if ($r.Count -gt 0) { $hits += [PSCustomObject]@{ Sid = "$($ace.sid)"; Name = $ace.name; What = ($r -join '/') } }
        }
        foreach ($h in $hits) {
            if (-not $esc5.Contains($h.Sid)) { $esc5[$h.Sid] = [PSCustomObject]@{ Name = $(if ($h.Name) { $h.Name } else { $h.Sid }); Items = New-Object System.Collections.Generic.List[string] } }
            $item = "$($h.What) on $($obj.target)"
            if (-not $esc5[$h.Sid].Items.Contains($item)) { $esc5[$h.Sid].Items.Add($item) }
        }
    }
    $broadPki = @('S-1-5-11', 'S-1-1-0', 'S-1-5-32-545', "$($Index.DomainSid)-513", "$($Index.DomainSid)-515")
    foreach ($sid in $esc5.Keys) {
        $sev = if ($broadPki -contains $sid) { 'Critical' } else { 'High' }
        Add-Finding -Type adcs_esc5 -Object $esc5[$sid].Name -ObjectType 'acl' -Severity $sev -Detail "Control of PKI objects: $($esc5[$sid].Items -join '; ')."
    }

    $lowPriv = Get-LowPrivEnrollSids $Index.DomainSid
    $privSids = @{}
    foreach ($rid in @(512, 518, 519, 526, 527)) { $privSids["$($Index.DomainSid)-$rid"] = $true; $privSids["$($Index.RootSid)-$rid"] = $true }
    foreach ($s in @('S-1-5-32-544')) { $privSids[$s] = $true }

    foreach ($t in @($adcs.templates | Where-Object { $_ })) {
        $label = if ($t.displayName) { $t.displayName } else { $t.name }
        $enroller = Test-TemplateLowPrivEnroll -Template $t -LowPrivSids $lowPriv
        $noApproval = (([int64]$t.enrollmentFlag -band $script:CT_PEND_ALL_REQUESTS) -eq 0)
        $noRaSig = ([int]$t.raSignature -le 0)
        $suppliesSubject = (([int64]$t.nameFlag -band $script:CT_ENROLLEE_SUPPLIES_SUBJECT) -ne 0)
        $clientAuth = Test-TemplateHasEku -Template $t -Oids $script:EkuClientAuth
        $anyPurpose = ($t.ekus -contains $script:EkuAnyPurpose) -or (@($t.ekus).Count -eq 0)
        $enrollAgent = Test-TemplateHasEku -Template $t -Oids @($script:EkuEnrollmentAgent)
        $noSecExt = (([int64]$t.enrollmentFlag -band $script:CT_NO_SECURITY_EXTENSION) -ne 0)
        $schemaV1 = ([int]$t.schemaVersion -eq 1)

        # ESC4: dangerous ACL on the template, published or not.
        $aclHits = Test-TemplateDangerousAcl -Template $t -LowPrivSids $lowPriv -PrivSids $privSids
        if ($aclHits.Count -gt 0) {
            Add-Finding -Type adcs_esc4 -Object $label -ObjectType 'certtemplate' `
                -Detail "Modifiable by non-administrators: $(($aclHits | Select-Object -First 5) -join '; ')."
        }

        # The enrollment-based ESCs need the template published and open to low-privilege users.
        if (-not $t.published -or -not $enroller) { continue }

        if ($suppliesSubject -and $clientAuth -and $noApproval -and $noRaSig) {
            Add-Finding -Type adcs_esc1 -Object $label -ObjectType 'certtemplate' `
                -Detail "Enrollable by $enroller; ENROLLEE_SUPPLIES_SUBJECT set; client-auth EKU; no manager approval; no enrollment-agent signature."
        }
        elseif ($anyPurpose -and $noApproval) {
            Add-Finding -Type adcs_esc2 -Object $label -ObjectType 'certtemplate' `
                -Detail "Enrollable by $enroller; $(if (@($t.ekus).Count -eq 0) { 'no EKU (SubCA-equivalent)' } else { 'Any Purpose EKU' }); no manager approval."
        }
        elseif ($enrollAgent -and $noApproval) {
            Add-Finding -Type adcs_esc3 -Object $label -ObjectType 'certtemplate' `
                -Detail "Enrollable by $enroller; Certificate Request Agent EKU; no manager approval."
        }
        elseif ($noSecExt -and $clientAuth -and $noApproval) {
            Add-Finding -Type adcs_esc9 -Object $label -ObjectType 'certtemplate' `
                -Detail "Enrollable by $enroller; CT_FLAG_NO_SECURITY_EXTENSION set (no SID binding); client-auth EKU; no manager approval."
        }
        elseif ($schemaV1 -and $suppliesSubject -and $noApproval) {
            Add-Finding -Type adcs_esc15 -Object $label -ObjectType 'certtemplate' `
                -Detail "Schema v1 template enrollable by $enroller; ENROLLEE_SUPPLIES_SUBJECT set; no manager approval: an arbitrary application policy (e.g. client auth) can be injected into the request."
        }
        elseif ($clientAuth) {
            Add-Finding -Type adcs_low_priv_enroll -Object $label -ObjectType 'certtemplate' `
                -Detail "Client-auth template enrollable by $enroller. Review whether such broad enrollment is needed."
        }

        # ESC13: an issuance policy on this template is linked to a group.
        if ($oidToGroup.Count -gt 0) {
            foreach ($pol in @($t.issuancePolicies | Where-Object { $_ })) {
                if (-not $oidToGroup.ContainsKey("$pol")) { continue }
                $gInfo = $oidToGroup["$pol"]
                $gObj = if ($gInfo.groupDn) { $Index.ByDn[("$($gInfo.groupDn)").ToLower()] } else { $null }
                $gName = if ($gObj -and $gObj.name) { $gObj.name } elseif ($gInfo.name) { $gInfo.name } else { (("$($gInfo.groupDn)") -split ',')[0] -replace '^..=', '' }
                $gPriv = ($gObj -and $gObj.sid -and $tier0.ContainsKey($gObj.sid))
                $sev = if ($gPriv) { 'Critical' } else { 'High' }
                Add-Finding -Type adcs_esc13 -Object $label -ObjectType 'certtemplate' -Severity $sev `
                    -Detail "Enrollable by $enroller; issuance policy '$($gInfo.name)' linked to group '$gName'$(if ($gPriv) { ' (privileged)' }): the certificate grants that group's rights."
                break
            }
        }
    }
}

# --------------------------------------------------------------------------
# Accepted risks, a JSON array:
#   [ { "type": "kerberoastable_user", "object": "svc_backup",
#       "reason": "Vendor dependency, CHG-1234", "owner": "IAM team", "expires": "2027-03-31" } ]
# "object": "*" accepts every object of that check. Expired entries are
# ignored and listed, so they can't quietly rot.
# --------------------------------------------------------------------------
function Import-Exceptions {
    param([string]$Path)
    if (-not $Path) { return @() }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Exceptions file not found: $Path" }
    $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path)
    return @($raw | ConvertFrom-Json)
}

function Split-FindingsByException {
    param($Findings, $Exceptions)
    $active = New-Object System.Collections.Generic.List[object]
    $accepted = New-Object System.Collections.Generic.List[object]
    $expired = New-Object System.Collections.Generic.List[object]
    $valid = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Exceptions | Where-Object { $_ })) {
        $exp = ConvertTo-UtcDate $e.expires
        if ($null -ne $exp -and $exp -lt $script:RefDate) { $expired.Add($e) } else { $valid.Add($e) }
    }
    foreach ($f in $Findings) {
        $match = $null
        foreach ($e in $valid) {
            if ($e.type -ne $f.Type) { continue }
            if ($e.object -eq '*' -or $e.object -eq $f.Object -or ($f.ObjectDn -and $e.object -eq $f.ObjectDn)) { $match = $e; break }
        }
        if ($match) {
            $accepted.Add([PSCustomObject]@{ Finding = $f; Exception = $match })
        }
        else { $active.Add($f) }
    }
    # ToArray(): PS 7 throws "Argument types do not match" on @() over a List inside a PSCustomObject.
    return [PSCustomObject]@{ Active = $active.ToArray(); Accepted = $accepted.ToArray(); Expired = $expired.ToArray() }
}

# --------------------------------------------------------------------------
# Score: one weight per triggered check (not per object), at its worst
# severity. 3,000 inactive users shouldn't outweigh one DCSync backdoor.
# --------------------------------------------------------------------------
function Get-HygieneScore {
    # NotEvaluated / Total (checks in the catalog) give the coverage. Below 50% the number
    # only reflects what could be read, so the reports show it as not reliable.
    param($Findings, [int]$NotEvaluated = 0, [int]$Total = 0)
    $weights = @{ Critical = 20; High = 8; Medium = 3; Low = 1 }
    $worstPerType = @{}
    foreach ($f in $Findings) {
        $cur = $worstPerType[$f.Type]
        if (-not $cur -or $script:SeverityRank[$f.Severity] -gt $script:SeverityRank[$cur]) { $worstPerType[$f.Type] = $f.Severity }
    }
    $penalty = 0
    foreach ($s in $worstPerType.Values) { $penalty += $weights[$s] }
    # 100 * e^(-penalty/100): 50 -> 61, 100 -> 37, 200 -> 14. Never quite 0,
    # so bad and catastrophic still rank apart.
    $score = 100.0 * [Math]::Exp(-$penalty / 100.0)
    # The worst problem sets the ceiling: any Critical caps the score at 35 (E),
    # any High at 65 (C). One DCSync backdoor is a compromised domain however
    # tidy the rest is.
    $worst = @($worstPerType.Values | Sort-Object { - $script:SeverityRank[$_] } | Select-Object -First 1)
    $cap = if ($worst -contains 'Critical') { 35 } elseif ($worst -contains 'High') { 65 } else { 100 }
    $score = [Math]::Max(1, [Math]::Round([Math]::Min($score, $cap)))
    $grade = if ($score -ge 85) { 'A' } elseif ($score -ge 70) { 'B' } elseif ($score -ge 55) { 'C' } elseif ($score -ge 40) { 'D' } elseif ($score -ge 25) { 'E' } else { 'F' }
    $coverage = if ($Total -gt 0) { [int][Math]::Round(100.0 * [Math]::Max(0, $Total - $NotEvaluated) / $Total) } else { 100 }
    return [PSCustomObject]@{ Score = [int]$score; Grade = $grade; Penalty = $penalty; ChecksTriggered = $worstPerType.Count; Cap = $cap; Coverage = $coverage; Reliable = ($coverage -ge 50) }
}
