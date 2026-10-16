# Entra ID: catalog, checks, report and the AI helpers, on top of the shared
# report and AI code. The analysis is covered by the synthetic tenant in the
# regression suite; the Graph collector still hasn't met a real tenant.

# Control-plane roles: the cloud's Tier 0.
$script:EntraPrivRoleTemplates = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    'e3973bdf-4987-49ae-837a-ba8e231c7286' = 'Azure DevOps Administrator'
}

# Graph application permissions that amount to tenant takeover.
$script:EntraHighRiskAppRoles = @{
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = 'RoleManagement.ReadWrite.Directory'
    '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = 'Directory.ReadWrite.All'
    '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = 'Application.ReadWrite.All'
    '06b708a9-e830-4db3-a914-8e69da51d44f' = 'AppRoleAssignment.ReadWrite.All'
    '62a82d76-70ea-41e2-9197-370581804d09' = 'Group.ReadWrite.All'
    '741f803b-c850-494e-b5df-cde7c675a1ca' = 'User.ReadWrite.All'
    '50483e42-d915-4231-9639-7fdb7fd190e5' = 'UserAuthenticationMethod.ReadWrite.All'
}

$script:EntraCheckCatalog = [ordered]@{
    entra_security_defaults_off = @{ Category = 'Entra Access Policy'; Severity = 'High'; Mitre = 'T1556.006'; Needs = @('securityDefaults', 'conditionalAccess')
        Title = 'Security defaults off and no MFA enforced by Conditional Access'
        Description = 'Security defaults are disabled and no enabled Conditional Access policy requires MFA. Accounts can sign in with a password alone.'
        Remediation = 'Enable security defaults, or (with Entra ID P1/P2) an enabled CA policy that requires MFA for all users, plus a policy blocking legacy authentication.' }
    entra_admins_without_mfa = @{ Category = 'Entra Identity'; Severity = 'Critical'; Mitre = 'T1078.004'; Needs = @('directoryRoles', 'users', 'mfaRegistration')
        Title = 'Privileged role member without MFA registered'
        Description = 'A member of a control-plane admin role has no MFA method registered. A single phished or sprayed password yields tenant-level control.'
        Remediation = 'Require and register phishing-resistant MFA for every admin; add them to a CA policy that enforces it, and prefer PIM eligible over permanent assignment.' }
    entra_no_ca_mfa_admins = @{ Category = 'Entra Access Policy'; Severity = 'High'; Mitre = 'T1556.006'; Needs = @('conditionalAccess', 'directoryRoles')
        Title = 'No Conditional Access policy enforcing MFA on admins'
        Description = 'No enabled CA policy targets directory roles with an MFA grant control. Admin sign-ins are not guaranteed to be challenged.'
        Remediation = 'Create an enabled CA policy scoped to admin roles requiring MFA (ideally phishing-resistant).' }
    entra_legacy_auth_allowed = @{ Category = 'Entra Access Policy'; Severity = 'High'; Mitre = 'T1110'; Needs = @('conditionalAccess', 'securityDefaults')
        Title = 'Legacy authentication not blocked'
        Description = 'No enabled CA policy blocks legacy authentication protocols (which cannot enforce MFA and are a primary password-spray target), and security defaults are off.'
        Remediation = 'Add an enabled CA policy that blocks legacy authentication for all users.' }
    entra_global_admins_excessive = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('directoryRoles')
        Title = 'Too many Global Administrators'
        Description = 'A large number of standing Global Administrators widens the tenant-takeover surface. Microsoft recommends fewer than five.'
        Remediation = 'Reduce standing Global Admins; move day-to-day work to least-privileged roles and use PIM for just-in-time elevation.' }
    entra_global_admins_too_few = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = ''; Needs = @('directoryRoles')
        Title = 'Fewer than two Global Administrators'
        Description = 'With a single Global Admin there is no break-glass redundancy: losing that account can lock the tenant out.'
        Remediation = 'Maintain at least two, including a cloud-only emergency-access account excluded from CA, with a long stored password and monitored sign-ins.' }
    entra_privileged_guest = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1078.004'; Needs = @('directoryRoles', 'users')
        Title = 'Guest account in a privileged role'
        Description = 'An external (guest) identity holds an admin role: the security of the tenant then depends on an account managed outside it.'
        Remediation = 'Remove guests from privileged roles; if unavoidable, convert to a member account governed by tenant policy and PIM.' }
    entra_users_can_register_apps = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1098.001'; Needs = @('authorizationPolicy')
        Title = 'All users can register applications'
        Description = 'The authorization policy lets any user create app registrations / service principals, a common consent-phishing and persistence vector.'
        Remediation = 'Set "Users can register applications" to No; delegate app registration to a controlled group.' }
    entra_users_can_consent = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1528'; Needs = @('consentPolicy')
        Title = 'Admin consent workflow not enabled'
        Description = 'Without an admin consent workflow, user consent settings are the only guardrail against illicit-consent (OAuth) attacks.'
        Remediation = 'Restrict user consent to verified publishers / low-risk permissions and enable the admin consent request workflow.' }
    entra_guest_invite_open = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1136.003'; Needs = @('authorizationPolicy')
        Title = 'Non-admins can invite guests'
        Description = 'Regular members (or even guests) can invite external users, so the external population grows without anyone deciding it should.'
        Remediation = 'Let only admins and the Guest Inviter role send invitations (CIS 5.1.6.3).' }
    entra_stale_guest = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('users', 'signInActivity')
        Title = 'Stale guest account'
        Description = 'An enabled guest has not signed in for a long time. Unused external identities are unmonitored standing access.'
        Remediation = 'Review and remove stale guests; use access reviews to expire external access automatically.' }
    entra_app_high_privilege = @{ Category = 'Entra Applications'; Severity = 'Critical'; Mitre = 'T1098.001'; Needs = @('servicePrincipals')
        Title = 'Service principal with tenant-takeover permission'
        Description = 'A service principal holds a high-risk application permission (e.g. RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All). A compromise of its credential is equivalent to Global Admin.'
        Remediation = 'Confirm the app truly needs the permission; remove it otherwise. Protect the credential as Tier 0, prefer certificate credentials and workload identity CA.' }
    entra_app_credential_expiring = @{ Category = 'Entra Applications'; Severity = 'Low'; Mitre = ''; Needs = @('applications')
        Title = 'Application credential expired or expiring'
        Description = 'An app registration has a secret or certificate that is expired or close to expiry, which causes outages and, when expired secrets linger, leaves stale credentials configured.'
        Remediation = 'Rotate before expiry, remove unused credentials, and prefer certificates over client secrets.' }
    entra_report_only_ca_stale = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('conditionalAccess')
        Title = 'Conditional Access policy left in report-only / disabled'
        Description = 'A CA policy is disabled or has been in report-only mode: report-only policies are a testing state, not enforcement, and are easy to forget.'
        Remediation = 'Promote validated report-only policies to enabled, or remove policies that are no longer needed.' }

    # ---- Schema 2 (CIS M365 sections 1 and 5, Microsoft guidance) ----
    entra_admin_synced_from_onprem = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1078.004'; Needs = @('directoryRoles', 'users')
        Title = 'Admin account synchronized from on-premises AD'
        Description = 'A privileged role member is synced from on-premises Active Directory. Whoever controls that domain, or the sync server, can take over the account and with it the tenant.'
        Remediation = 'Give Entra admin roles to cloud-only accounts, separate from the on-premises identity (CIS 1.1.1).' }
    entra_pim_not_used = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('pim', 'directoryRoles')
        Title = 'Standing admin access (PIM not used)'
        Description = 'Admin roles are held permanently instead of being activated just in time. A stolen admin session or token is immediately tenant-level access.'
        Remediation = 'Make admin roles eligible in PIM with MFA and approval on activation. Keep permanent Global Admin only for the two emergency access accounts (CIS 5.3.1).' }
    entra_no_phishing_resistant_admins = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1556.006'; Needs = @('conditionalAccess', 'caDetails')
        Title = 'Admins not required to use phishing-resistant MFA'
        Description = 'No enabled Conditional Access policy requires the phishing-resistant authentication strength for admin roles. Push or OTP MFA can still be phished with an adversary-in-the-middle kit.'
        Remediation = 'Require the "Phishing-resistant MFA" authentication strength (FIDO2, Windows Hello, certificate) for all admin roles (CIS 5.2.2.5).' }
    entra_device_code_flow_allowed = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1528'; Needs = @('conditionalAccess', 'caDetails')
        Title = 'Device code flow not blocked'
        Description = 'No enabled Conditional Access policy blocks the device code authentication flow, a favourite of current phishing campaigns: the victim types a code and hands over a token.'
        Remediation = 'Block the device code flow for everyone, with a narrow exception for the devices that really need it (CIS 5.2.2.12).' }
    entra_risk_policies_missing = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('conditionalAccess', 'caDetails')
        Title = 'No user-risk / sign-in-risk Conditional Access'
        Description = 'No enabled Conditional Access policy reacts to Entra ID Protection risk. Leaked credentials and risky sign-ins are detected but nothing happens.'
        Remediation = 'With Entra ID P2, require a secure password change for high user risk and MFA for medium/high sign-in risk (CIS 5.2.2.6, 5.2.2.7).' }
    entra_admin_sign_in_frequency = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1550.001'; Needs = @('conditionalAccess', 'caDetails')
        Title = 'Admin sessions not limited'
        Description = 'No enabled Conditional Access policy limits how long an admin session lasts or stops the browser from keeping it. A stolen admin session stays useful for its full lifetime.'
        Remediation = 'Set a sign-in frequency (for example 4 hours) and a non-persistent browser session for admin roles (CIS 5.2.2.4).' }
    entra_weak_auth_methods = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1111'; Needs = @('authenticationMethods')
        Title = 'Weak authentication methods enabled'
        Description = 'SMS, voice call or email one-time codes are enabled. They can be intercepted (SIM swap, mailbox compromise) and are not phishing resistant.'
        Remediation = 'Disable SMS, voice and email OTP in the authentication methods policy once users have Authenticator or passkeys (CIS 5.2.3.5, 5.2.3.7).' }
    entra_users_can_create_tenants = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('authorizationPolicy')
        Title = 'Users can create tenants'
        Description = 'Any user can create a new Entra tenant. The creator becomes its Global Admin, outside your policies and monitoring.'
        Remediation = 'Set "Restrict non-admin users from creating tenants" to Yes (CIS 5.1.2.3).' }
    entra_user_consent_allowed = @{ Category = 'Entra Applications'; Severity = 'Medium'; Mitre = 'T1528'; Needs = @('authorizationPolicy')
        Title = 'Users can consent to applications'
        Description = 'Users can grant third-party apps access to company data on their own. This is how illicit-consent (OAuth) phishing gets persistent access without a password.'
        Remediation = 'Set user consent to "Do not allow" and route requests through the admin consent workflow (CIS 5.1.5.1, 5.1.5.2).' }
    entra_guest_access_not_restricted = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1087.004'; Needs = @('authorizationPolicy')
        Title = 'Guest access to the directory not restricted'
        Description = 'Guests can browse users and groups in the directory, which helps an external account map the organisation.'
        Remediation = 'Set guest user access to "restricted to properties and memberships of their own directory objects" (CIS 5.1.6.2).' }
    entra_banned_passwords_off = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1110.003'; Needs = @('passwordSettings')
        Title = 'Custom banned password list not enforced'
        Description = 'Only the global banned list is used. Passwords built on the company name, products or city are still accepted and are the first ones sprayed.'
        Remediation = 'Enable the custom banned password list with organisation-specific words (CIS 5.2.3.2), and Password Protection on-premises for hybrid tenants.' }
    entra_smart_lockout_weak = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1110.001'; Needs = @('passwordSettings')
        Title = 'Smart lockout weaker than baseline'
        Description = 'The smart lockout threshold is above 10 attempts or the lockout lasts under 60 seconds, so online guessing is cheaper than it should be.'
        Remediation = 'Keep the lockout threshold at 10 or less and the lockout duration at 60 seconds or more (CIS 5.2.3.8, 5.2.3.9).' }
    entra_users_can_create_security_groups = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('authorizationPolicy')
        Title = 'Users can create security groups'
        Description = 'Any user can create security groups. Groups that nobody owns or reviews end up granting access to apps and data.'
        Remediation = 'Set "Users can create security groups in Azure portals, API or PowerShell" to No (CIS 5.1.3.1).' }
    entra_no_periodic_reauth = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1550.001'; Needs = @('conditionalAccess', 'caDetails')
        Title = 'No periodic reauthentication for all users'
        Description = 'No enabled Conditional Access policy sets a sign-in frequency for everyone, so a stolen session or token keeps working for as long as it lives.'
        Remediation = 'Add a Conditional Access policy with a sign-in frequency for all users (CIS 5.2.2.13).' }
    entra_sign_in_risk_not_blocked = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('conditionalAccess', 'caDetails')
        Title = 'Medium and high sign-in risk not blocked'
        Description = 'No enabled Conditional Access policy blocks sign-ins that Entra ID Protection rates medium or high risk; at best they get an MFA prompt.'
        Remediation = 'With Entra ID P2, block medium and high sign-in risk (CIS 5.2.2.8), with an exclusion for the emergency access accounts.' }
    # ---- Schema 3 (rest of CIS M365 v7 that Graph can read) ----
    entra_admin_inactive = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('directoryRoles', 'users', 'signInActivity')
        Title = 'Inactive admin account'
        Description = 'An enabled member of an admin role has not signed in for months. Nobody notices when an unused admin account starts being used by someone else.'
        Remediation = 'Remove the role, or disable the account. Prefer eligible PIM assignments, which expire on their own.' }
    entra_no_emergency_access = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = ''; Needs = @('conditionalAccess', 'caDetails3')
        Title = 'No emergency access account excluded from Conditional Access'
        Description = 'No user or group is excluded from every enabled Conditional Access policy. A broken policy or an MFA outage can then lock every admin out of the tenant.'
        Remediation = 'Create two cloud-only emergency access accounts with Global Admin, exclude them from Conditional Access, protect them with FIDO2 keys and alert on every sign-in (CIS 1.1.2).' }
    entra_admin_licensed = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = 'T1566'; Needs = @('directoryRoles', 'users', 'licenses', 'caDetails3')
        Title = 'Admin account licensed for mailbox and productivity apps'
        Description = 'An admin account has Exchange, SharePoint or Teams. Reading mail and browsing with an admin account is how admin sessions get phished.'
        Remediation = 'Keep admin accounts separate and give them no productivity licence, or only Entra ID P1/P2 (CIS 1.1.4).' }
    entra_per_user_mfa_admins = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = ''; Needs = @('perUserMfa')
        Title = 'Legacy per-user MFA still in use'
        Description = 'Some admin accounts still use the old per-user MFA setting. It bypasses Conditional Access logic and makes the real policy hard to reason about.'
        Remediation = 'Move MFA to Conditional Access and switch per-user MFA off (CIS 5.1.2.1). IDWolf checks admin accounts only.' }
    entra_users_not_mfa_capable = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('users', 'mfaRegistration', 'mfaCapable')
        Title = 'Members not capable of MFA'
        Description = 'Enabled member accounts have no MFA method registered. When MFA is enforced they either get locked out or, worse, an attacker registers a method first.'
        Remediation = 'Require registration for everyone, protect the registration itself with Conditional Access, and follow up on the accounts listed (CIS 5.2.3.4).' }
    entra_password_expiry_set = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('domains')
        Title = 'Password expiration still configured'
        Description = 'A domain makes passwords expire. Forced changes push people to predictable patterns (Spring2026!, Summer2026!), which are exactly what gets sprayed.'
        Remediation = 'Set passwords to never expire and rely on MFA, banned passwords and leaked-credential detection instead (CIS 1.3.1).' }
    entra_idle_timeout_missing = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('idleTimeout')
        Title = 'No idle session timeout for Microsoft 365 web apps'
        Description = 'Browser sessions on Microsoft 365 web apps never time out, so an unattended or shared machine stays signed in.'
        Remediation = 'Enable idle session timeout (for example 3 hours) for unmanaged devices (CIS 1.3.2).' }
    entra_ca_not_available = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('licenses')
        Title = 'Conditional Access not available (no Entra ID P1/P2 licence)'
        Description = 'The tenant has no Entra ID P1 or P2 plan and no Conditional Access policy, so Conditional Access, risk-based policies and managed-device rules cannot be used. Security defaults are the only built-in MFA protection. The checks that need Conditional Access were skipped instead of reporting one "no policy" finding each.'
        Remediation = 'Keep security defaults on. If the tenant holds more than test data, license Entra ID P1 (or P2 for risk-based policies and PIM) and build the Conditional Access baseline.' }
    entra_kmsi_shown = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('branding')
        Title = '"Stay signed in?" prompt shown'
        Description = 'Users are offered to stay signed in, which keeps long-lived sessions on shared and personal machines.'
        Remediation = 'Hide the "Stay signed in?" option in company branding (CIS 5.1.2.5).' }
    entra_users_can_create_m365_groups = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('groupCreation')
        Title = 'Users can create Microsoft 365 groups'
        Description = 'Anyone can create Microsoft 365 groups, each with its own mailbox, site and team, and nobody reviews who is in them.'
        Remediation = 'Restrict Microsoft 365 group creation to a designated group (CIS 5.1.3.4).' }
    entra_device_join_unrestricted = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1098.005'; Needs = @('deviceRegistration')
        Title = 'Any user can join devices to Entra ID'
        Description = 'Every user can Entra-join a device. A stolen account can register an attacker machine, which then counts as a corporate device.'
        Remediation = 'Allow device join only for a selected group (CIS 5.1.4.1).' }
    entra_device_quota_high = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1098.005'; Needs = @('deviceRegistration')
        Title = 'High device limit per user'
        Description = 'Each user can register many devices, so a compromised account can enrol several attacker machines before anyone notices.'
        Remediation = 'Keep the maximum number of devices per user at 10 or less (CIS 5.1.4.2).' }
    entra_device_join_ga_local_admin = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('deviceRegistration')
        Title = 'Global Admins become local admins on joined devices'
        Description = 'Global Administrators are added to the local Administrators group of every Entra-joined device, so their credentials end up on ordinary workstations.'
        Remediation = 'Turn off "Global administrator role is added as local administrator on the device" (CIS 5.1.4.3).' }
    entra_device_join_user_local_admin = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1078.003'; Needs = @('deviceRegistration')
        Title = 'Users become local admins on the devices they join'
        Description = 'Whoever joins a device becomes its local administrator: installed tools, disabled defences, harvested credentials are one click away.'
        Remediation = 'Set "Registering user is added as local administrator" to None (CIS 5.1.4.4).' }
    entra_device_laps_off = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1550.002'; Needs = @('deviceRegistration')
        Title = 'Windows LAPS not enabled for Entra-joined devices'
        Description = 'Local admin passwords on Entra-joined devices are not rotated by LAPS, so the same password can open many machines.'
        Remediation = 'Enable Microsoft Entra LAPS and push the LAPS policy through Intune (CIS 5.1.4.5).' }
    entra_users_read_bitlocker_keys = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('authorizationPolicy', 'caDetails3')
        Title = 'Users can read their own BitLocker keys'
        Description = 'Users can recover the BitLocker keys of their devices themselves. Whoever holds their account holds the disk too.'
        Remediation = 'Restrict users from recovering BitLocker keys; route recovery through the help desk (CIS 5.1.4.6).' }
    entra_password_hash_sync_off = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('onPremSync')
        Title = 'Password hash sync off in a synced tenant'
        Description = 'The tenant syncs from on-premises AD without password hash sync, so Entra ID Protection cannot detect leaked credentials and there is no fallback if federation fails.'
        Remediation = 'Enable password hash synchronization in Entra Connect (CIS 5.1.8.1).' }
    entra_no_managed_device = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('conditionalAccess', 'caDetails3')
        Title = 'No Conditional Access requiring a managed device'
        Description = 'No enabled policy requires a compliant or hybrid-joined device. A stolen password plus MFA fatigue works from any laptop in the world.'
        Remediation = 'Require a compliant or hybrid-joined device for all users (CIS 5.2.2.9).' }
    entra_security_info_registration = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1098.005'; Needs = @('conditionalAccess', 'caDetails3')
        Title = 'MFA registration not protected'
        Description = 'No enabled policy protects the registration of security info. Whoever has a password first can register their own MFA method.'
        Remediation = 'Require a managed device (or a trusted location) to register security info (CIS 5.2.2.10).' }
    entra_intune_enrollment_reauth = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('conditionalAccess', 'caDetails3')
        Title = 'Intune enrollment doesn''t require a fresh sign-in'
        Description = 'Enrolling a device in Intune can reuse an existing session, so a stolen token is enough to enrol an attacker device.'
        Remediation = 'Set sign-in frequency to "every time" for the Microsoft Intune Enrollment app (CIS 5.2.2.11).' }
    entra_no_trusted_locations = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('namedLocations')
        Title = 'No trusted named locations'
        Description = 'No named location is marked as trusted, so Conditional Access and risk detection can''t tell office networks from anywhere else.'
        Remediation = 'Define your office egress IPs as trusted named locations and use them in policies (CIS 5.2.2.14).' }
    entra_no_geo_restriction = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('conditionalAccess', 'caDetails3', 'namedLocations')
        Title = 'No geographic access restriction'
        Description = 'No enabled policy blocks sign-ins from countries you don''t operate in, so sprayed passwords work from anywhere.'
        Remediation = 'Block sign-ins from countries outside your footprint with a country named location (CIS 5.2.2.15).' }
    entra_token_protection_off = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1550.001'; Needs = @('conditionalAccess', 'caDetails3', 'caTokenProtection')
        Title = 'Token protection not enforced'
        Description = 'No enabled policy binds session tokens to the device. Tokens stolen by infostealers or adversary-in-the-middle kits can be replayed elsewhere.'
        Remediation = 'Enforce token protection for supported apps, starting with admins (CIS 5.2.2.16).' }
    entra_auth_transfer_allowed = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1528'; Needs = @('conditionalAccess', 'caDetails')
        Title = 'Authentication transfer not blocked'
        Description = 'No enabled policy blocks authentication transfer, which moves a signed-in session from one device to another (desktop to phone).'
        Remediation = 'Block authentication transfer for all users (CIS 5.2.2.17).' }
    entra_authenticator_context_off = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1621'; Needs = @('authenticatorSettings')
        Title = 'Authenticator prompts lack app name and location'
        Description = 'Push notifications don''t show which app and where the sign-in comes from, so users approve MFA prompts they didn''t start (MFA fatigue).'
        Remediation = 'Show the application name and the geographic location in Microsoft Authenticator notifications (CIS 5.2.3.1).' }
    entra_system_preferred_mfa_off = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('authenticatorSettings')
        Title = 'System-preferred MFA not enabled'
        Description = 'Users are prompted with whatever method they picked, often SMS, instead of the strongest one they have registered.'
        Remediation = 'Enable system-preferred multifactor authentication (CIS 5.2.3.6).' }
    entra_authenticator_lite_on = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = ''; Needs = @('authenticatorSettings')
        Title = 'Authenticator Lite (companion apps) allowed'
        Description = 'MFA can be approved inside Outlook mobile and other companion apps, with fewer protections than the full Authenticator app.'
        Remediation = 'Disable Microsoft Authenticator on companion applications (CIS 5.2.3.10).' }
    entra_no_guest_access_review = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('accessReviews')
        Title = 'No access review for guests'
        Description = 'Guest access is never reviewed, so partners keep access long after the project ended.'
        Remediation = 'Create a recurring access review of guest users (CIS 5.3.2).' }
    entra_no_admin_access_review = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('accessReviews')
        Title = 'No access review for admin roles'
        Description = 'Admin role assignments are never reviewed, so they pile up and nobody remembers why someone has them.'
        Remediation = 'Create a recurring access review of privileged role assignments in PIM (CIS 5.3.3).' }
    entra_pim_activation_no_approval = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('pimPolicies')
        Title = 'Top admin roles activate without approval'
        Description = 'Global Administrator or Privileged Role Administrator can be activated in PIM without anyone approving it, so a stolen eligible account becomes a Global Admin on its own.'
        Remediation = 'Require approval to activate Global Administrator and Privileged Role Administrator (CIS 5.3.4, 5.3.5).' }
    entra_app_management_policy_weak = @{ Category = 'Entra Applications'; Severity = 'Low'; Mitre = 'T1552.001'; Needs = @('appManagementPolicy')
        Title = 'No tenant-wide rules for app credentials'
        Description = 'Nothing stops new client secrets, custom secrets or long-lived credentials on app registrations, so weak credentials keep appearing.'
        Remediation = 'Enable the default app management policy: block password addition and custom passwords, cap secret and certificate lifetimes at 180 days (CIS 5.1.5.3 to 5.1.5.6).' }
    # ---- Schema 4 (beyond CIS: non-human identities, hybrid, consent) ----
    entra_risky_delegated_grant = @{ Category = 'Entra Applications'; Severity = 'High'; Mitre = 'T1528'; Needs = @('oauthGrants', 'servicePrincipals')
        Title = 'Third-party app with risky delegated permissions'
        Description = 'An app from another tenant has been granted delegated permissions to read or write mail, files or the directory on behalf of users. That is what an illicit-consent (OAuth) phishing campaign leaves behind, and it survives a password reset.'
        Remediation = 'Check who the app belongs to and why it needs this. If nobody can vouch for it, revoke the grant and disable the service principal, then look at the sign-in and audit logs for the app.' }
    entra_pim_role_settings_weak = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('pimPolicies', 'schema7')
        Title = 'Weak PIM settings on privileged roles'
        Description = 'PIM settings of privileged roles let an admin activate without MFA or an authentication context, keep the role active for more than 8 hours, or receive eligible or active assignments that never expire. Each of these turns just-in-time access back into standing access for whoever holds the account.'
        Remediation = 'For every privileged role in PIM: require MFA (or an authentication context bound to phishing-resistant MFA) and a justification on activation, keep the activation at 8 hours or less, and require an end date on eligible and active assignments (except the emergency access accounts).' }
    entra_scoped_admin_outside_ca = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('roleAssignments', 'conditionalAccess', 'caDetails', 'schema7')
        Title = 'Admins with a scoped role are outside the admin Conditional Access policies'
        Description = 'Some privileged roles are assigned with a scope (an administrative unit or a single object). Conditional Access policies that target directory roles only apply to tenant-wide assignments, and no enabled policy requires MFA from all users, so these admins sign in without the admin protections.'
        Remediation = 'Target admins with a group (or all users) rather than only roles, or add the scoped admins to the admin policies explicitly.' }
    entra_privileged_app_sp_owner = @{ Category = 'Entra Applications'; Severity = 'High'; Mitre = 'T1098.001'; Needs = @('servicePrincipals', 'appOwners', 'schema7')
        Title = 'Service principal owns a privileged application'
        Description = 'A service principal or managed identity owns an app that holds an admin role or a tenant-takeover permission. Whoever controls the owner (its credentials, the code or the Azure resource behind a managed identity) can add a credential to the privileged app and act as it.'
        Remediation = 'Remove service principals from the owners of privileged apps; give ownership to a small set of admins of the same tier, or none.' }
    entra_privileged_app_inactive = @{ Category = 'Entra Applications'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('servicePrincipals', 'spSignIns', 'schema7')
        Title = 'Privileged application not used for months'
        Description = 'A service principal with an admin role or a tenant-takeover permission has not signed in for more than 180 days. Its permissions and credentials are attack surface nobody uses or watches.'
        Remediation = 'Confirm with the owner that the app is still needed; if not, remove its permissions and credentials, then delete it.' }
    entra_app_instance_lock_off = @{ Category = 'Entra Applications'; Severity = 'Low'; Mitre = 'T1098.001'; Needs = @('applications', 'schema7')
        Title = 'Multi-tenant app without App instance property lock'
        Description = 'A multi-tenant app registration with credentials does not lock the sensitive properties of its service principals. In a tenant where the app is installed, someone with rights on the service principal can add a credential to it and use the permissions granted there.'
        Remediation = 'Enable App instance property lock for all properties (servicePrincipalLockConfiguration) on multi-tenant apps.' }
    entra_access_package_grants_admin = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1098.003'; Needs = @('accessPackages', 'accessPackageGrants', 'groups', 'schema7')
        Title = 'Access package grants admin access through self-request without approval'
        Description = 'An access package that a broad population can request for itself, without approval, grants a privileged Entra role or membership of a group that holds one. Any account in that population gets admin rights by asking.'
        Remediation = 'Require approval (by admins of the same tier) on that policy, restrict who can request it, or remove the privileged resource from the package.' }
    entra_app_scoped_admin_privileged = @{ Category = 'Entra Applications'; Severity = 'High'; Mitre = 'T1098.001'; Needs = @('roleAssignments', 'servicePrincipals', 'schema7')
        Title = 'App administrator scoped to a privileged application'
        Description = 'Application Administrator or Cloud Application Administrator is assigned with the scope of a single app, and that app holds an admin role or a tenant-takeover permission. The scoped admin can add a credential to the app and act with its permissions: a delegated "just this app" role that is in fact tenant takeover.'
        Remediation = 'Remove the scoped assignment, or move the privileged permission out of that app; treat whoever manages a privileged app as an admin of the same tier.' }
    entra_ca_excluded_group_weak = @{ Category = 'Entra Access Policy'; Severity = 'High'; Mitre = 'T1556.009'; Needs = @('conditionalAccess', 'groups', 'schema6')
        Title = 'Conditional Access exclusion group anyone can get into'
        Description = 'A group excluded from an enabled Conditional Access policy is a public Microsoft 365 group (anyone can join), a dynamic group whose rule uses attributes a user or guest can influence, or a group owned by non-admins (who can add anyone). Getting into that group switches the policy off for that account, MFA included.'
        Remediation = 'Exclude only dedicated, role-assignable or admin-owned security groups (for example the emergency access accounts), make the group private and assigned, remove non-admin owners, and review the exclusion with an access review.' }
    entra_privileged_group_owner = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1098.003'; Needs = @('directoryRoles', 'groups', 'schema6', 'pimForGroups')
        Title = 'Group holding an admin role owned by a non-admin'
        Description = 'A group that holds a privileged Entra role (active or eligible) has an owner who is not an admin, or a guest or service principal as owner. The owner can add any account, including their own, to the group and so take the role.'
        Remediation = 'Remove those owners: groups that hold roles should be owned by admins of the same tier only (or by nobody, managed through PIM for Groups), and the group must be role-assignable.' }
    entra_connect_app_extra_credentials = @{ Category = 'Entra Applications'; Severity = 'High'; Mitre = 'T1098.001'; Needs = @('applications')
        Title = 'Entra Connect application with extra credentials'
        Description = 'The ConnectSyncProvisioning application that Entra Connect Sync uses to write to the tenant has more than one certificate, or a client secret. Entra Connect manages a single certificate itself; an extra credential lets someone else act as the sync engine (Directory Synchronization Accounts rights), a known persistence path.'
        Remediation = 'Keep only the certificate Entra Connect rotates itself, remove other certificates and every secret, and find out who added them.' }
    entra_sp_lookalike_name = @{ Category = 'Entra Applications'; Severity = 'Medium'; Mitre = 'T1036'; Needs = @('servicePrincipals')
        Title = 'Service principal name with look-alike characters'
        Description = 'A service principal name mixes Latin letters with look-alike letters from another script (Cyrillic, Greek, full-width) or hides invisible characters. That is how consent-phishing apps pose as Microsoft or a trusted vendor in consent prompts and in the admin portal.'
        Remediation = 'Check who published the app and what it was granted; if it is not a known app, revoke its grants and delete the service principal.' }
    entra_privileged_app_owner = @{ Category = 'Entra Applications'; Severity = 'High'; Mitre = 'T1098.001'; Needs = @('servicePrincipals', 'appOwners', 'schema4')
        Title = 'Regular user owns an app with tenant-takeover permissions'
        Description = 'A user who is not an admin owns an app (or its service principal) holding permissions such as RoleManagement.ReadWrite.Directory. An owner can add a secret and act as the app, so that user is effectively a Global Admin.'
        Remediation = 'Remove user owners from privileged apps, or treat those owners as Tier 0 (admin roles, phishing-resistant MFA, PIM).' }
    entra_first_party_sp_credentials = @{ Category = 'Entra Applications'; Severity = 'High'; Mitre = 'T1098.001'; Needs = @('servicePrincipals')
        Title = 'Credential added to a Microsoft first-party app'
        Description = 'A service principal of a Microsoft-owned application has a secret or certificate added in this tenant. Microsoft apps don''t need that; it is a known persistence technique (seen in the SolarWinds intrusion) because these apps carry broad trusted permissions.'
        Remediation = 'Find out who added it (audit log, "Add service principal credentials"), remove the credential, and investigate the sign-ins that used it.' }
    entra_sp_in_admin_role = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1098.003'; Needs = @('directoryRoles', 'schema4')
        Title = 'Service principal in an admin role'
        Description = 'An application holds an Entra admin role. Its secret or certificate is now a Tier 0 credential, usually stored somewhere much less protected than an admin account.'
        Remediation = 'Replace the role with the narrowest Graph application permission that does the job, or protect the app as Tier 0 (certificate only, owners limited, workload identity Conditional Access).' }
    entra_admin_password_old = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('directoryRoles', 'users', 'schema4')
        Title = 'Admin password not changed in over a year'
        Description = 'An admin account still uses a password set more than a year ago. Old passwords have had more time to be phished, reused or leaked.'
        Remediation = 'Move admins to passwordless (FIDO2, Windows Hello); until then, rotate the password and make sure leaked-credential detection is on.' }
    entra_admin_no_phishing_resistant_method = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = 'T1556.006'; Needs = @('directoryRoles', 'users', 'mfaRegistration', 'schema4')
        Title = 'Admin without a phishing-resistant method registered'
        Description = 'An admin has no FIDO2 key, passkey, Windows Hello or certificate registered, so a phishing-resistant MFA policy can''t even be enforced for them.'
        Remediation = 'Register a FIDO2 key or passkey for every admin, then require the phishing-resistant authentication strength.' }
    entra_sync_stale = @{ Category = 'Entra Identity'; Severity = 'Medium'; Mitre = ''; Needs = @('organization', 'schema4')
        Title = 'Directory sync has stopped'
        Description = 'The tenant syncs from on-premises AD but the last sync is over a day old. Disabled or deleted accounts on-premises stay active in the cloud until it resumes.'
        Remediation = 'Check the Entra Connect (or Cloud Sync) server and its service, and Entra Connect Health.' }
    entra_cross_tenant_mfa_trust = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1199'; Needs = @('crossTenant')
        Title = 'MFA or device claims trusted from any tenant'
        Description = 'The default cross-tenant settings accept MFA (or device compliance) done in any other tenant. Your policies then rely on how well every external tenant protects its accounts.'
        Remediation = 'Keep the default inbound trust off and trust MFA only from specific partner tenants you have vetted.' }
    entra_app_insecure_redirect = @{ Category = 'Entra Applications'; Severity = 'Low'; Mitre = 'T1528'; Needs = @('applications', 'schema4')
        Title = 'App with an insecure redirect URI'
        Description = 'An app registration sends tokens to a plain-HTTP or wildcard address. Whoever can answer on that address can collect tokens.'
        Remediation = 'Use HTTPS redirect URIs on domains you control, no wildcards; remove addresses that are no longer used.' }
    entra_federated_domain = @{ Category = 'Entra Access Policy'; Severity = 'Low'; Mitre = 'T1606.002'; Needs = @('domains', 'schema4')
        Title = 'Federated domain'
        Description = 'Sign-ins for this domain are handled by an on-premises identity provider (AD FS or similar). Its token-signing key can mint tokens for any user (Golden SAML), so it is Tier 0. Trusting its MFA claim makes that worse.'
        Remediation = 'Move to managed authentication (password hash sync or cloud authentication) if you can. Otherwise protect the federation servers as Tier 0 and set federatedIdpMfaBehavior to rejectMfaByFederatedIdp so Entra does the MFA.' }
    entra_app_secret_long_lived = @{ Category = 'Entra Applications'; Severity = 'Low'; Mitre = 'T1552.001'; Needs = @('applications')
        Title = 'Application secret valid for too long'
        Description = 'An app registration has a client secret valid for more than the allowed lifetime. Long-lived secrets end up in scripts and config files and outlive the people who knew about them.'
        Remediation = 'Prefer certificates or managed identities; keep client secrets to 180 days or less (CIS 5.1.5.4) and rotate them.' }
    # ---- Schema 5 ----
    entra_b2b_direct_connect_open = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1199'; Needs = @('crossTenant', 'schema5')
        Title = 'B2B direct connect open to every tenant'
        Description = 'The default cross-tenant settings allow B2B direct connect (Teams shared channels) with any external tenant. Those users reach your shared channels without a guest account, so they never show up in your directory, your guest reviews or your Conditional Access. Microsoft ships it blocked.'
        Remediation = 'Set B2B direct connect back to blocked in the default cross-tenant settings and allow it only for named partner organizations.' }
    entra_access_package_external_no_approval = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1098'; Needs = @('accessPackages', 'schema5')
        Title = 'External users can get an access package without approval'
        Description = 'An entitlement management policy lets external users request an access package and get it straight away. With "all external users", anyone with a Microsoft account can sign up for the groups, apps and sites in that package.'
        Remediation = 'Require approval (by a sponsor or the package owner) for external requests, limit the policy to specific connected organizations, and set an expiry.' }
    entra_access_package_no_expiry = @{ Category = 'Entra Identity'; Severity = 'Low'; Mitre = 'T1078.004'; Needs = @('accessPackages', 'schema5')
        Title = 'Access package assignments never expire and are never reviewed'
        Description = 'Access granted through this package lasts forever and no access review checks it. People keep it after they change role or the project ends.'
        Remediation = 'Set an expiry on the assignment policy (for example 180 or 365 days) or turn on periodic access reviews for it.' }
    # ---- Schema 8 ----
    entra_intune_role_weak_group = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1072'; Needs = @('intuneRoles', 'groups', 'schema8')
        Title = 'Intune role that can run code on devices given through an unprotected group'
        Description = 'An Intune role that can push scripts, apps or configuration to managed devices, or change Intune roles, is assigned to a group that is not role-assignable or has a dynamic membership. Groups Administrators, User Administrators, Intune Administrators and the group''s owners can add members to such a group, and a member can run code as SYSTEM on every device in scope, admin workstations included.'
        Remediation = 'Give powerful Intune roles only to role-assignable groups managed by admins of the same tier (or through PIM for Groups), keep their membership assigned rather than dynamic, and narrow the scope tags and scope groups of the assignment.' }
    # ---- Schema 9 ----
    entra_intune_no_multi_admin_approval = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1485'; Needs = @('intuneRoles', 'intuneApprovalPolicies', 'schema9')
        Title = 'Intune device wipes or scripts need no second admin (Multi Admin Approval)'
        Description = 'No Intune Multi Admin Approval policy covers device wipes or scripts. One compromised Intune or Global Administrator can then factory-reset every managed device, or run code as SYSTEM on all of them, in a single action: in March 2026 the attack on Stryker was reported to have wiped tens of thousands of devices this way. The policy types are matched by name from the documentation and have not yet been verified on a real tenant.'
        Remediation = 'In Intune admin center > Tenant administration > Multi Admin Approval, create access policies for device wipe (and retire/delete), scripts, apps and Intune roles, with an approver group of admins other than the requester. Protect the Multi Admin Approval settings themselves with an access policy as well.' }
    # ---- Schema 10 ----
    entra_app_azure_ad_graph = @{ Category = 'Entra Applications'; Severity = 'Low'; Mitre = ''; Needs = @('applications', 'servicePrincipals', 'schema10')
        Title = 'App still holds permissions on the retired Azure AD Graph'
        Description = 'An app registration requests permissions on Azure AD Graph (graph.windows.net, resource 00000002-0000-0000-c000-000000000000), or a service principal was granted some. Microsoft has retired that API: the app either already fails or depends on something that is going away, and permission reviews built on Microsoft Graph do not show what it was allowed to do there (Directory.ReadWrite.All on Azure AD Graph is as strong as on Microsoft Graph).'
        Remediation = 'Ask the owner to move the app to Microsoft Graph. Then remove the Azure AD Graph entries from its API permissions and revoke the grants (application permissions and delegated consents) on the Windows Azure Active Directory service principal; delete the app if nobody claims it.' }
    entra_catalog_role_privileged_group = @{ Category = 'Entra Identity'; Severity = 'High'; Mitre = 'T1098.003'; Needs = @('entitlementCatalogs', 'catalogRoles', 'accessPackageGrants', 'groups', 'directoryRoles', 'schema10')
        Title = 'Non-admin manages an entitlement catalog that holds an admin group'
        Description = 'An entitlement management catalog holds a group that has a privileged Entra role (active or eligible), and someone who is not an admin is its catalog owner or access package manager (they can put the group in an access package and assign it, to themselves too), or its access package assignment manager while a package of the catalog already hands out the group. Through the catalog they can make themselves a member of the group and take the role.'
        Remediation = 'Keep groups that hold admin roles out of catalogs managed by non-admins: move them to a catalog whose owners and managers are admins of the same tier, or remove those catalog roles. Treat catalog roles on such a catalog as Tier 0.' }
    entra_no_workload_identity_ca = @{ Category = 'Entra Access Policy'; Severity = 'Medium'; Mitre = 'T1078.004'; Needs = @('conditionalAccess', 'servicePrincipals', 'directoryRoles', 'schema5')
        Title = 'Privileged apps without workload identity Conditional Access'
        Description = 'Apps registered in this tenant hold admin roles or tenant-wide permissions, and no Conditional Access policy covers service principals. A stolen secret or certificate for those apps works from anywhere on the internet.'
        Remediation = 'With Workload Identities Premium, add a Conditional Access policy that targets those service principals and blocks sign-ins outside your known locations (and high service principal risk). Without the licence, move them to certificates and managed identities and watch their sign-ins.' }
}

# Built-in authentication strength for phishing-resistant MFA.
$script:EntraPhishResistantStrength = '00000000-0000-0000-0000-000000000004'
# guestUserRoleId values: same as members, limited (default), restricted.
$script:EntraGuestRoles = @{ 'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'same as members'; '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'limited (default)'; '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'restricted' }

function Add-EntraFinding {
    param([string]$Type, [string]$Object, [string]$ObjectType = '', [string]$ObjectDn = '', [string]$Detail, [string]$Severity = '')
    $meta = $script:EntraCheckCatalog[$Type]
    if (-not $meta) { throw "Unknown Entra check type: $Type" }
    if (-not $Severity) { $Severity = $meta.Severity }
    $script:Findings.Add([PSCustomObject]@{
            Severity = $Severity; Type = $Type; Title = $meta.Title; Category = $meta.Category
            Object = $Object; ObjectType = $ObjectType; ObjectDn = $ObjectDn; Detail = $Detail; Mitre = $meta.Mitre
        })
}

function Get-EntraNotEvaluated {
    param($Snapshot)
    $result = New-Object System.Collections.Generic.List[object]
    $failed = @{}
    foreach ($e in @($Snapshot.meta.collectionErrors | Where-Object { $_ })) { $failed[$e.section] = $e.message }
    # Sections an older collector never gathered: not evaluated, not clean.
    $absent = @{}
    $sv = [int]"0$($Snapshot.meta.schemaVersion)"
    $reCollect = 'snapshot from an older collector: re-collect'
    if ($sv -lt 2) { $absent['caDetails'] = "$reCollect (no Conditional Access details)" }
    if ($sv -lt 3) { foreach ($s in 'caDetails3', 'mfaCapable', 'caTokenProtection') { $absent[$s] = $reCollect } }
    if ($sv -lt 4) { $absent['schema4'] = $reCollect }
    if ($sv -lt 5) { $absent['schema5'] = $reCollect }
    if ($sv -lt 6) { $absent['schema6'] = "$reCollect (no groups behind Conditional Access exclusions and admin roles)" }
    if ($sv -lt 7) { $absent['schema7'] = "$reCollect (no PIM rules, scoped role assignments, app owners by type, app sign-ins or access package resources)" }
    if ($sv -lt 7) { $absent['pimForGroups'] = "$reCollect (no PIM for Groups eligibility)" }
    if ($sv -lt 8) { $absent['schema8'] = "$reCollect (no Intune roles)" }
    if ($sv -lt 9) { $absent['schema9'] = "$reCollect (no Intune Multi Admin Approval policies)" }
    if ($sv -lt 10) { $absent['schema10'] = "$reCollect (no Azure AD Graph permissions, entitlement catalogs or catalog roles)" }
    foreach ($s in 'authenticationMethods', 'passwordSettings', 'pim', 'pimPolicies', 'authenticatorSettings', 'groupCreation', 'deviceRegistration',
        'appManagementPolicy', 'domains', 'idleTimeout', 'branding', 'onPremSync', 'accessReviews', 'namedLocations', 'licenses', 'perUserMfa', 'oauthGrants', 'crossTenant', 'accessPackages', 'intuneRoles', 'intuneApprovalPolicies') {
        if (-not $Snapshot.PSObject.Properties[$s]) { $absent[$s] = "'$s' not in this snapshot ($reCollect)" }
    }
    foreach ($type in $script:EntraCheckCatalog.Keys) {
        $meta = $script:EntraCheckCatalog[$type]
        $reasons = @()
        foreach ($need in $meta.Needs) {
            foreach ($f in $failed.Keys) { if ($f -eq $need -or $f.StartsWith("$need.")) { $reasons += "collection of '$f' failed: $($failed[$f])" } }
            if ($absent.ContainsKey($need)) { $reasons += $absent[$need] }
        }
        if ($reasons.Count -gt 0) { $result.Add([PSCustomObject]@{ Type = $type; Title = $meta.Title; Reason = (($reasons | Select-Object -Unique) -join '; ') }) }
    }
    return $result
}

# MFA comes either from the 'mfa' control or from an authentication strength.
function Test-CaGrantsMfa { param($p) (@($p.grantControls) -contains 'mfa') -or [bool]"$($p.authStrengthId)" }
function Test-CaRequiresMfaForAdmins {
    param($Snapshot)
    foreach ($p in @($Snapshot.conditionalAccess | Where-Object { $_ })) {
        if ("$($p.state)" -ne 'enabled') { continue }
        if (-not (Test-CaGrantsMfa $p)) { continue }
        $roles = @($p.includeRoles)
        $usersAll = (@($p.includeUsers) -contains 'All')
        if ($roles.Count -gt 0 -or $usersAll) { return $true }
    }
    return $false
}
function Test-CaRequiresMfaAll {
    param($Snapshot)
    foreach ($p in @($Snapshot.conditionalAccess | Where-Object { $_ })) {
        if ("$($p.state)" -ne 'enabled') { continue }
        if (-not (Test-CaGrantsMfa $p)) { continue }
        if (@($p.includeUsers) -contains 'All') { return $true }
    }
    return $false
}
function Test-CaBlocksLegacyAuth {
    param($Snapshot)
    foreach ($p in @($Snapshot.conditionalAccess | Where-Object { $_ })) {
        if ("$($p.state)" -ne 'enabled') { continue }
        if (@($p.grantControls) -notcontains 'block') { continue }
        $types = @($p.clientAppTypes)
        if ($types -contains 'exchangeActiveSync' -or $types -contains 'other') { return $true }
    }
    return $false
}

function Invoke-EntraChecks {
    param($Snapshot, [hashtable]$Config)
    $script:Findings = New-Object System.Collections.Generic.List[object]
    $usersById = @{}; foreach ($u in @($Snapshot.users | Where-Object { $_ })) { $usersById[$u.id] = $u }
    # Sections that failed to collect: their checks must stay silent (they're listed as not evaluated).
    $failedSections = @{}; foreach ($e in @($Snapshot.meta.collectionErrors | Where-Object { $_ })) { $failedSections["$($e.section)"] = $true }
    $sv = [int]"0$($Snapshot.meta.schemaVersion)"
    $sdOn = ($Snapshot.securityDefaults -eq $true)
    $caMfaAll = Test-CaRequiresMfaAll $Snapshot
    $caMfaAdmins = $caMfaAll -or (Test-CaRequiresMfaForAdmins $Snapshot)
    # With no Conditional Access data every "no enabled policy does X" check would fire.
    $caData = -not $failedSections.ContainsKey('conditionalAccess')
    $sdOk = -not $failedSections.ContainsKey('securityDefaults')
    # A tenant with no Entra ID P1/P2 plan and no policy can't use Conditional Access at all: one note
    # instead of ~25 "no policy does X" findings nobody can act on. Security defaults stay checked.
    $licOk = [bool]$Snapshot.PSObject.Properties['licenses'] -and -not $failedSections.ContainsKey('licenses')
    $hasPremium = @($Snapshot.licenses | Where-Object { $_ } | ForEach-Object { @($_.plans) } | Where-Object { "$_" -match '^AAD_PREMIUM' }).Count -gt 0
    $noCaLicence = $caData -and $licOk -and -not $hasPremium -and -not @($Snapshot.conditionalAccess | Where-Object { $_ }).Count
    $caOk = $caData -and -not $noCaLicence
    if ($noCaLicence) {
        Add-EntraFinding -Type entra_ca_not_available -Object 'tenant' -ObjectType 'tenant' -Detail "No Entra ID P1/P2 plan in the subscriptions and no Conditional Access policy; security defaults $(if ($sdOn) { 'are on' } else { 'are off' })."
    }

    # ---- Access policy baseline ----
    if ($caData -and $sdOk -and -not $sdOn -and -not $caMfaAll) {
        Add-EntraFinding -Type entra_security_defaults_off -Object $(if ($Snapshot.org) { $Snapshot.org.displayName } else { 'tenant' }) -ObjectType 'tenant' `
            -Detail "Security defaults disabled and no enabled CA policy requires MFA for all users."
    }
    if ($caData -and -not $failedSections.ContainsKey('directoryRoles') -and -not $sdOn -and -not $caMfaAdmins) {
        Add-EntraFinding -Type entra_no_ca_mfa_admins -Object 'admin roles' -ObjectType 'policy' -Detail 'No enabled CA policy with an MFA grant control targets admin roles or all users.'
    }
    if ($caData -and $sdOk -and -not $sdOn -and -not (Test-CaBlocksLegacyAuth $Snapshot)) {
        Add-EntraFinding -Type entra_legacy_auth_allowed -Object 'tenant' -ObjectType 'policy' -Detail 'No enabled CA policy blocks legacy authentication.'
    }
    foreach ($p in @($Snapshot.conditionalAccess | Where-Object { $_ })) {
        if ("$($p.state)" -eq 'disabled' -or "$($p.state)" -eq 'enabledForReportingButNotEnforced') {
            Add-EntraFinding -Type entra_report_only_ca_stale -Object $p.displayName -ObjectType 'capolicy' -ObjectDn $p.id -Detail "Policy state: $($p.state)."
        }
    }

    if ($Snapshot.authorizationPolicy) {
        if ($Snapshot.authorizationPolicy.allowedToCreateApps) {
            Add-EntraFinding -Type entra_users_can_register_apps -Object 'authorizationPolicy' -ObjectType 'policy' -Detail 'defaultUserRolePermissions.allowedToCreateApps = true.'
        }
        # CIS wants admins and Guest Inviters only ('adminsAndGuestInviters' or 'none').
        $inv = "$($Snapshot.authorizationPolicy.allowInvitesFrom)"
        if ($inv -match '(?i)^(everyone|adminsGuestInvitersAndAllMembers)$') {
            $who = if ($inv -match '(?i)everyone') { 'everyone, guests included' } else { 'every member' }
            Add-EntraFinding -Type entra_guest_invite_open -Object 'authorizationPolicy' -ObjectType 'policy' -Detail "allowInvitesFrom = $inv ($who)."
        }
    }
    if ($Snapshot.consentPolicy -and -not $Snapshot.consentPolicy.adminConsentRequestEnabled) {
        Add-EntraFinding -Type entra_users_can_consent -Object 'adminConsentRequestPolicy' -ObjectType 'policy' -Detail 'Admin consent request workflow is not enabled.'
    }

    # ---- Privileged roles ----
    $privMembers = @{}   # userId -> list of role names
    foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ })) {
        $rn = if ($script:EntraPrivRoleTemplates.ContainsKey("$($r.roleTemplateId)")) { $script:EntraPrivRoleTemplates["$($r.roleTemplateId)"] } else { $null }
        if (-not $rn) { continue }
        foreach ($mid in @($r.members)) {
            if (-not $privMembers.ContainsKey($mid)) { $privMembers[$mid] = New-Object System.Collections.Generic.List[string] }
            if (-not $privMembers[$mid].Contains($rn)) { $privMembers[$mid].Add($rn) }
        }
    }
    $mfaKnown = @($Snapshot.users | Where-Object { $_ -and $null -ne $_.mfaRegistered }).Count -gt 0
    foreach ($uid in $privMembers.Keys) {
        $u = $usersById[$uid]
        $label = if ($u) { $u.upn } else { $uid }
        $rolesText = ($privMembers[$uid] -join ', ')
        if ($u -and $u.userType -eq 'Guest') {
            Add-EntraFinding -Type entra_privileged_guest -Object $label -ObjectType 'user' -ObjectDn $uid -Detail "Guest holds: $rolesText."
        }
        if ($mfaKnown -and $u -and $u.mfaRegistered -eq $false -and $u.enabled) {
            Add-EntraFinding -Type entra_admins_without_mfa -Object $label -ObjectType 'user' -ObjectDn $uid -Detail "No MFA method registered. Roles: $rolesText."
        }
    }
    $ga = @($Snapshot.directoryRoles | Where-Object { $_ -and "$($_.roleTemplateId)" -eq '62e90394-69f5-4237-9190-012177145e10' } | Select-Object -First 1)
    if ($ga.Count -gt 0) {
        $gaCount = @($ga[0].members).Count
        if ($gaCount -gt $Config.MaxGlobalAdmins) {
            Add-EntraFinding -Type entra_global_admins_excessive -Object 'Global Administrator' -ObjectType 'role' -Detail "$gaCount Global Administrators (recommended < $($Config.MaxGlobalAdmins + 1))."
        }
        elseif ($gaCount -lt 2) {
            Add-EntraFinding -Type entra_global_admins_too_few -Object 'Global Administrator' -ObjectType 'role' -Detail "$gaCount Global Administrator(s): no break-glass redundancy."
        }
    }

    # ---- Guests ----
    # Without sign-in data every guest would look like it never signed in.
    $guests = if ($failedSections.ContainsKey('signInActivity')) { @() } else { @($Snapshot.users | Where-Object { $_ -and $_.userType -eq 'Guest' -and $_.enabled }) }
    foreach ($u in $guests) {
        $ll = $null
        try { if ($u.lastSignIn) { $ll = [int][Math]::Floor(($script:RefDate - ([datetime]$u.lastSignIn).ToUniversalTime()).TotalDays) } } catch { }
        $created = $null
        try { if ($u.createdDateTime) { $created = [int][Math]::Floor(($script:RefDate - ([datetime]$u.createdDateTime).ToUniversalTime()).TotalDays) } } catch { }
        if (($null -eq $ll -and $null -ne $created -and $created -gt $Config.StaleGuestDays) -or ($null -ne $ll -and $ll -gt $Config.StaleGuestDays)) {
            Add-EntraFinding -Type entra_stale_guest -Object $u.upn -ObjectType 'user' -ObjectDn $u.id -Detail "Guest, last sign-in: $(if ($null -ne $ll) { "$ll days ago" } else { 'never' }) (threshold $($Config.StaleGuestDays))."
        }
    }

    # ---- Applications / service principals ----
    foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ })) {
        $risk = @($sp.appRoleIds | Where-Object { $script:EntraHighRiskAppRoles.ContainsKey("$_") } | ForEach-Object { $script:EntraHighRiskAppRoles["$_"] } | Select-Object -Unique)
        if ($risk.Count -gt 0) {
            Add-EntraFinding -Type entra_app_high_privilege -Object $sp.displayName -ObjectType 'serviceprincipal' -ObjectDn $sp.id -Detail "Application permissions: $($risk -join ', ')."
        }
    }
    foreach ($app in @($Snapshot.applications | Where-Object { $_ })) {
        $creds = @(@($app.passwordCred) + @($app.keyCred) | Where-Object { $_ })
        foreach ($c in $creds) {
            try {
                # UTC either way: PS 7 reads the JSON date as a DateTime, PS 5.1 as a string.
                $cu = ConvertTo-UtcDate $c
                if (-not $cu) { continue }
                $days = [int][Math]::Floor(($cu - $script:RefDate).TotalDays)
                if ($days -lt $Config.SecretExpiringDays) {
                    Add-EntraFinding -Type entra_app_credential_expiring -Object $app.displayName -ObjectType 'application' -ObjectDn $app.id `
                        -Detail "$(if ($days -lt 0) { "credential expired $([Math]::Abs($days)) days ago" } else { "credential expires in $days days" }) ($($cu.ToString('yyyy-MM-dd')))."
                    break
                }
            }
            catch { }
        }
    }

    # ---- Schema 2 checks ----
    $maxStanding = if ($Config.ContainsKey('MaxStandingAdmins')) { $Config.MaxStandingAdmins } else { 2 }
    $maxSecretDays = if ($Config.ContainsKey('MaxSecretLifetimeDays')) { $Config.MaxSecretLifetimeDays } else { 180 }

    foreach ($uid in $privMembers.Keys) {
        $u = $usersById[$uid]
        if ($u -and $u.onPremSync -and $u.enabled) {
            Add-EntraFinding -Type entra_admin_synced_from_onprem -Object $u.upn -ObjectType 'user' -ObjectDn $uid -Detail "Synced from on-premises AD. Roles: $($privMembers[$uid] -join ', ')."
        }
    }

    # Permanent admin assignments. Two are fine: the emergency access accounts.
    if ($Snapshot.pim) {
        $privRoleIds = @($script:EntraPrivRoleTemplates.Keys)
        $who = @($Snapshot.pim.active | Where-Object { $_ -and $privRoleIds -contains "$($_.roleDefinitionId)" -and "$($_.assignmentType)" -eq 'Assigned' -and -not $_.endDateTime } |
            ForEach-Object { "$($_.principalId)" } | Select-Object -Unique)
        if ($who.Count -gt $maxStanding) {
            $names = @($who | ForEach-Object { if ($usersById[$_]) { $usersById[$_].upn } else { $_ } })
            $more = if ($names.Count -gt 8) { " (+$($names.Count - 8) more)" } else { '' }
            Add-EntraFinding -Type entra_pim_not_used -Object 'admin roles' -ObjectType 'role' `
                -Detail "$($who.Count) principals hold admin roles permanently (expected at most $maxStanding emergency accounts); $(@($Snapshot.pim.eligible | Where-Object { $_ }).Count) eligible assignments in PIM. Permanent: $(($names | Select-Object -First 8) -join ', ')$more."
        }
    }

    # Conditional Access details only exist in schema 2 snapshots.
    if ($caOk -and [int]"0$($Snapshot.meta.schemaVersion)" -ge 2) {
        $enabledCa = @($Snapshot.conditionalAccess | Where-Object { $_ -and "$($_.state)" -eq 'enabled' })
        $forAdmins = @($enabledCa | Where-Object { @($_.includeRoles | Where-Object { $_ }).Count -gt 0 -or @($_.includeUsers) -contains 'All' })
        if (-not @($forAdmins | Where-Object { "$($_.authStrengthId)" -eq $script:EntraPhishResistantStrength }).Count) {
            Add-EntraFinding -Type entra_no_phishing_resistant_admins -Object 'admin roles' -ObjectType 'policy' -Detail 'No enabled CA policy for admin roles requires the phishing-resistant MFA strength.'
        }
        if (-not @($enabledCa | Where-Object { "$($_.transferMethods)" -match 'deviceCodeFlow' -and @($_.grantControls) -contains 'block' }).Count) {
            Add-EntraFinding -Type entra_device_code_flow_allowed -Object 'tenant' -ObjectType 'policy' -Detail 'No enabled CA policy blocks the device code flow.'
        }
        if (-not @($enabledCa | Where-Object { "$($_.transferMethods)" -match 'authenticationTransfer' -and @($_.grantControls) -contains 'block' }).Count) {
            Add-EntraFinding -Type entra_auth_transfer_allowed -Object 'tenant' -ObjectType 'policy' -Detail 'No enabled CA policy blocks authentication transfer.'
        }
        $missing = @()
        if (-not @($enabledCa | Where-Object { @($_.userRiskLevels | Where-Object { $_ }).Count }).Count) { $missing += 'user risk' }
        if (-not @($enabledCa | Where-Object { @($_.signInRiskLevels | Where-Object { $_ }).Count }).Count) { $missing += 'sign-in risk' }
        if ($missing.Count) {
            Add-EntraFinding -Type entra_risk_policies_missing -Object 'tenant' -ObjectType 'policy' -Detail "No enabled CA policy on $($missing -join ' or ')."
        }
        # CIS 5.2.2.4 wants both a sign-in frequency and a non-persistent browser (the latter is in schema 3).
        $adminGaps = @()
        if (-not @($forAdmins | Where-Object { $_.signInFrequency }).Count) { $adminGaps += 'a sign-in frequency' }
        if ($sv -ge 3 -and -not @($forAdmins | Where-Object { "$($_.persistentBrowser)" -eq 'never' }).Count) { $adminGaps += 'a non-persistent browser session' }
        if ($adminGaps.Count) {
            Add-EntraFinding -Type entra_admin_sign_in_frequency -Object 'admin roles' -ObjectType 'policy' -Detail "No enabled CA policy for admin roles sets $($adminGaps -join ' or ')."
        }
        if (-not @($enabledCa | Where-Object { @($_.includeUsers) -contains 'All' -and $_.signInFrequency }).Count) {
            Add-EntraFinding -Type entra_no_periodic_reauth -Object 'all users' -ObjectType 'policy' -Detail 'No enabled CA policy for all users sets a sign-in frequency.'
        }
        $blocksRisk = @($enabledCa | Where-Object { @($_.grantControls) -contains 'block' -and @($_.signInRiskLevels) -contains 'high' -and @($_.signInRiskLevels) -contains 'medium' })
        if (-not $blocksRisk.Count) {
            Add-EntraFinding -Type entra_sign_in_risk_not_blocked -Object 'tenant' -ObjectType 'policy' -Detail 'No enabled CA policy blocks medium and high sign-in risk.'
        }
    }

    if ($Snapshot.authenticationMethods) {
        $weak = @($Snapshot.authenticationMethods | Where-Object { $_ -and @('sms', 'voice', 'email') -contains "$($_.id)".ToLower() -and "$($_.state)" -eq 'enabled' } | ForEach-Object { "$($_.id)" })
        if ($weak.Count) {
            Add-EntraFinding -Type entra_weak_auth_methods -Object 'authenticationMethodsPolicy' -ObjectType 'policy' -Detail "Enabled: $($weak -join ', ')."
        }
    }

    $ap = $Snapshot.authorizationPolicy
    if ($ap) {
        if ($ap.allowedToCreateSecurityGroups -eq $true) {
            Add-EntraFinding -Type entra_users_can_create_security_groups -Object 'authorizationPolicy' -ObjectType 'policy' -Detail 'defaultUserRolePermissions.allowedToCreateSecurityGroups = true.'
        }
        if ($ap.allowedToCreateTenants -eq $true) {
            Add-EntraFinding -Type entra_users_can_create_tenants -Object 'authorizationPolicy' -ObjectType 'policy' -Detail 'defaultUserRolePermissions.allowedToCreateTenants = true.'
        }
        $grants = @($ap.permissionGrantPolicies | ForEach-Object { "$_" })
        if ($grants -match 'microsoft-user-default-legacy') {
            Add-EntraFinding -Type entra_user_consent_allowed -Object 'authorizationPolicy' -ObjectType 'policy' -Detail 'Users can consent to any app, for any permission it asks.'
        }
        elseif ($grants -match 'microsoft-user-default-low') {
            Add-EntraFinding -Type entra_user_consent_allowed -Object 'authorizationPolicy' -ObjectType 'policy' -Severity 'Low' -Detail 'Users can consent to apps from verified publishers for low-impact permissions.'
        }
        $gr = "$($ap.guestUserRoleId)"
        if ($gr -and $gr -ne '2af84b1e-32c8-42b7-82bc-daa82404023b') {
            $sev = if ($gr -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') { 'Medium' } else { 'Low' }
            $what = if ($script:EntraGuestRoles.ContainsKey($gr)) { $script:EntraGuestRoles[$gr] } else { $gr }
            Add-EntraFinding -Type entra_guest_access_not_restricted -Object 'authorizationPolicy' -ObjectType 'policy' -Severity $sev -Detail "Guest user access: $what."
        }
    }

    # No setting object = Microsoft defaults: no custom banned list, lockout 10 / 60 s.
    $pw = $Snapshot.passwordSettings
    if ($pw) {
        if ($pw.enableBannedPasswordCheck -ne $true -or [int]"0$($pw.bannedPasswordCount)" -eq 0) {
            Add-EntraFinding -Type entra_banned_passwords_off -Object 'Password Rule Settings' -ObjectType 'policy' -Detail "Custom banned list enforced: $([bool]($pw.enableBannedPasswordCheck -eq $true)); entries: $([int]"0$($pw.bannedPasswordCount)")."
        }
        $thr = if ($null -ne $pw.lockoutThreshold) { [int]$pw.lockoutThreshold } else { 10 }
        $dur = if ($null -ne $pw.lockoutDurationInSeconds) { [int]$pw.lockoutDurationInSeconds } else { 60 }
        if ($thr -gt 10 -or $dur -lt 60) {
            Add-EntraFinding -Type entra_smart_lockout_weak -Object 'Password Rule Settings' -ObjectType 'policy' -Detail "Lockout threshold $thr, duration $dur s (baseline: 10 or less, 60 s or more)."
        }
    }

    foreach ($app in @($Snapshot.applications | Where-Object { $_ })) {
        foreach ($s in @($app.secrets | Where-Object { $_ -and $_.start -and $_.end })) {
            try {
                $life = [int](([datetime]$s.end) - ([datetime]$s.start)).TotalDays
                if ($life -gt $maxSecretDays) {
                    Add-EntraFinding -Type entra_app_secret_long_lived -Object $app.displayName -ObjectType 'application' -ObjectDn $app.id -Detail "Client secret valid for $life days (limit $maxSecretDays)."
                    break
                }
            }
            catch { }
        }
    }

    # ---- Schema 3 ----
    $cfg = { param($k, $d) if ($Config.ContainsKey($k)) { $Config[$k] } else { $d } }
    $have = { param($s) [bool]$Snapshot.PSObject.Properties[$s] -and -not $failedSections.ContainsKey($s) }
    $ageDays = { param($d) try { if ($d) { [int][Math]::Floor(($script:RefDate - ([datetime]$d).ToUniversalTime()).TotalDays) } else { $null } } catch { $null } }
    $upnOf = { param($id) if ($usersById[$id]) { $usersById[$id].upn } else { $id } }

    # Admins who stopped signing in (or never did, on an old account).
    if (-not $failedSections.ContainsKey('signInActivity')) {
        $limit = & $cfg 'AdminInactiveDays' 90
        foreach ($uid in $privMembers.Keys) {
            $u = $usersById[$uid]
            if (-not $u -or -not $u.enabled) { continue }
            $ll = & $ageDays $u.lastSignIn; $created = & $ageDays $u.createdDateTime
            if (($null -ne $ll -and $ll -gt $limit) -or ($null -eq $ll -and $null -ne $created -and $created -gt $limit)) {
                Add-EntraFinding -Type entra_admin_inactive -Object $u.upn -ObjectType 'user' -ObjectDn $uid `
                    -Detail "Last sign-in: $(if ($null -ne $ll) { "$ll days ago" } else { 'never' }) (threshold $limit). Roles: $($privMembers[$uid] -join ', ')."
            }
        }
    }

    if ($sv -ge 3) {
        $en = @($Snapshot.conditionalAccess | Where-Object { $_ -and "$($_.state)" -eq 'enabled' })

        # Emergency access: someone must be excluded from every enabled policy.
        if ($en.Count) {
            $common = $null
            foreach ($p in $en) {
                $ex = @(@($p.excludeUsers) + @($p.excludeGroups) | Where-Object { $_ } | ForEach-Object { "$_" })
                $common = if ($null -eq $common) { $ex } else { @($common | Where-Object { $ex -contains $_ }) }
            }
            if (-not @($common).Count) {
                Add-EntraFinding -Type entra_no_emergency_access -Object 'Conditional Access' -ObjectType 'policy' -Detail "No user or group is excluded from all $($en.Count) enabled policies."
            }
        }

        $managed = { param($p) @($p.grantControls) -contains 'compliantDevice' -or @($p.grantControls) -contains 'domainJoinedDevice' }
        if ($caOk -and -not @($en | Where-Object { @($_.includeUsers) -contains 'All' -and (& $managed $_) }).Count) {
            Add-EntraFinding -Type entra_no_managed_device -Object 'all users' -ObjectType 'policy' -Detail 'No enabled CA policy for all users requires a compliant or hybrid-joined device.'
        }
        if ($caOk -and -not @($en | Where-Object { @($_.includeUserActions) -contains 'urn:user:registersecurityinfo' -and ((& $managed $_) -or @($_.grantControls) -contains 'block') }).Count) {
            Add-EntraFinding -Type entra_security_info_registration -Object 'security info registration' -ObjectType 'policy' -Detail 'No enabled CA policy protects the "register security information" action.'
        }
        if ($caOk -and -not @($en | Where-Object { @($_.includeApplications) -contains 'd4ebce55-015a-49b5-a083-c84d1797ae8c' -and "$($_.signInFrequencyInterval)" -eq 'everyTime' }).Count) {
            Add-EntraFinding -Type entra_intune_enrollment_reauth -Object 'Microsoft Intune Enrollment' -ObjectType 'policy' -Detail 'No enabled CA policy sets sign-in frequency "every time" for Intune enrollment.'
        }
        if ($caOk -and -not $failedSections.ContainsKey('caTokenProtection') -and -not @($en | Where-Object { $_.tokenProtection -eq $true }).Count) {
            Add-EntraFinding -Type entra_token_protection_off -Object 'tenant' -ObjectType 'policy' -Detail 'No enabled CA policy enforces token protection.'
        }
        if ($caOk -and (& $have 'namedLocations')) {
            $countries = @($Snapshot.namedLocations | Where-Object { $_ -and $_.type -eq 'country' } | ForEach-Object { "$($_.id)" })
            $geo = @($en | Where-Object { @($_.grantControls) -contains 'block' -and @(@(@($_.includeLocations) + @($_.excludeLocations)) | Where-Object { $countries -contains "$_" }).Count })
            if (-not $geo.Count) {
                Add-EntraFinding -Type entra_no_geo_restriction -Object 'tenant' -ObjectType 'policy' -Detail "No enabled block policy uses a country location ($($countries.Count) country location(s) defined)."
            }
        }

        # Admin accounts with mailbox, SharePoint or Teams.
        if (& $have 'licenses') {
            $skuById = @{}; foreach ($s in @($Snapshot.licenses | Where-Object { $_ })) { $skuById["$($s.skuId)"] = $s }
            foreach ($uid in $privMembers.Keys) {
                $u = $usersById[$uid]
                if (-not $u -or -not $u.enabled -or $u.userType -eq 'Guest') { continue }
                $prod = @($u.licenses | ForEach-Object { $s = $skuById["$_"]; if ($s -and @($s.plans | Where-Object { "$_" -match '^(EXCHANGE_S_|SHAREPOINT|TEAMS|MCOSTANDARD|OFFICESUBSCRIPTION)' }).Count) { $s.name } } | Select-Object -Unique)
                if ($prod.Count) {
                    Add-EntraFinding -Type entra_admin_licensed -Object $u.upn -ObjectType 'user' -ObjectDn $uid -Detail "Licences with mail / productivity apps: $($prod -join ', '). Roles: $($privMembers[$uid] -join ', ')."
                }
            }
        }

        # Members who can't do MFA: one finding with a sample, not one per user.
        if (-not $failedSections.ContainsKey('mfaRegistration')) {
            $nc = @($Snapshot.users | Where-Object { $_ -and $_.enabled -and $_.userType -eq 'Member' -and $_.mfaCapable -eq $false })
            if ($nc.Count) {
                $more = if ($nc.Count -gt 10) { " (+$($nc.Count - 10) more)" } else { '' }
                Add-EntraFinding -Type entra_users_not_mfa_capable -Object "$($nc.Count) users" -ObjectType 'users' -Detail "Not MFA capable: $((@($nc | Select-Object -First 10) | ForEach-Object { $_.upn }) -join ', ')$more."
            }
        }

        if ($ap -and $ap.allowedToReadBitlockerKeys -eq $true) {
            Add-EntraFinding -Type entra_users_read_bitlocker_keys -Object 'authorizationPolicy' -ObjectType 'policy' -Detail 'defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice = true.'
        }
    }

    if (& $have 'perUserMfa') {
        foreach ($p in @($Snapshot.perUserMfa.PSObject.Properties)) {
            if ("$($p.Value)" -match '^(?i)(enabled|enforced)$') {
                Add-EntraFinding -Type entra_per_user_mfa_admins -Object (& $upnOf $p.Name) -ObjectType 'user' -ObjectDn $p.Name -Detail "Per-user MFA: $($p.Value)."
            }
        }
    }

    if (& $have 'domains') {
        foreach ($d in @($Snapshot.domains | Where-Object { $_ -and $_.isVerified -and "$($_.authenticationType)" -eq 'Managed' })) {
            if ($null -ne $d.passwordValidityDays -and [int64]$d.passwordValidityDays -lt 2147483647) {
                Add-EntraFinding -Type entra_password_expiry_set -Object $d.id -ObjectType 'domain' -Detail "Passwords expire after $($d.passwordValidityDays) days."
            }
        }
    }
    if ((& $have 'idleTimeout') -and $Snapshot.idleTimeout -and [int]$Snapshot.idleTimeout.policyCount -eq 0) {
        Add-EntraFinding -Type entra_idle_timeout_missing -Object 'tenant' -ObjectType 'policy' -Detail 'No activity-based timeout policy.'
    }
    if ((& $have 'branding') -and $Snapshot.branding -and -not $Snapshot.branding.hideKeepMeSignedIn) {
        Add-EntraFinding -Type entra_kmsi_shown -Object 'company branding' -ObjectType 'policy' -Detail $(if ($Snapshot.branding.configured) { 'Branding is set, "Stay signed in?" is not hidden.' } else { 'No company branding: the prompt is shown by default.' })
    }
    if ((& $have 'groupCreation') -and $Snapshot.groupCreation -and $Snapshot.groupCreation.m365GroupCreationAllowed) {
        Add-EntraFinding -Type entra_users_can_create_m365_groups -Object 'Group.Unified' -ObjectType 'policy' -Detail 'EnableGroupCreation is on (or not set).'
    }

    $dr = $Snapshot.deviceRegistration
    if ((& $have 'deviceRegistration') -and $dr) {
        if ("$($dr.joinAllowedFor)" -eq 'all') {
            Add-EntraFinding -Type entra_device_join_unrestricted -Object 'deviceRegistrationPolicy' -ObjectType 'policy' -Detail 'All users can join devices to Entra ID.'
        }
        $maxDev = & $cfg 'MaxDevicesPerUser' 10
        if ($null -ne $dr.userDeviceQuota -and [int]$dr.userDeviceQuota -gt $maxDev) {
            Add-EntraFinding -Type entra_device_quota_high -Object 'deviceRegistrationPolicy' -ObjectType 'policy' -Detail "Up to $($dr.userDeviceQuota) devices per user (baseline $maxDev)."
        }
        if ($dr.globalAdminsAreLocalAdmins -eq $true) {
            Add-EntraFinding -Type entra_device_join_ga_local_admin -Object 'deviceRegistrationPolicy' -ObjectType 'policy' -Detail 'Global Administrators are added as local admins on join.'
        }
        if ("$($dr.registeringUsersLocalAdmin)" -in 'all', 'selected') {
            $sev = if ("$($dr.registeringUsersLocalAdmin)" -eq 'all') { 'Medium' } else { 'Low' }
            Add-EntraFinding -Type entra_device_join_user_local_admin -Object 'deviceRegistrationPolicy' -ObjectType 'policy' -Severity $sev -Detail "Registering users made local admin: $($dr.registeringUsersLocalAdmin)."
        }
        if ($dr.lapsEnabled -ne $true) {
            Add-EntraFinding -Type entra_device_laps_off -Object 'deviceRegistrationPolicy' -ObjectType 'policy' -Detail 'Microsoft Entra LAPS is not enabled.'
        }
    }

    $ps = $Snapshot.onPremSync
    if ((& $have 'onPremSync') -and $ps -and $ps.syncEnabled -and $ps.passwordHashSync -eq $false) {
        Add-EntraFinding -Type entra_password_hash_sync_off -Object 'Entra Connect' -ObjectType 'sync' -Detail 'Directory sync is on, password hash sync is off.'
    }

    if ($caOk -and (& $have 'namedLocations') -and -not @($Snapshot.namedLocations | Where-Object { $_ -and $_.isTrusted }).Count) {
        Add-EntraFinding -Type entra_no_trusted_locations -Object 'named locations' -ObjectType 'policy' -Detail "$(@($Snapshot.namedLocations | Where-Object { $_ }).Count) named location(s), none trusted."
    }

    $as = $Snapshot.authenticatorSettings
    if ((& $have 'authenticatorSettings') -and $as) {
        $on = "$($as.authenticatorState)" -eq 'enabled'
        if ($on -and ("$($as.showAppName)" -ne 'enabled' -or "$($as.showLocation)" -ne 'enabled')) {
            Add-EntraFinding -Type entra_authenticator_context_off -Object 'Microsoft Authenticator' -ObjectType 'policy' -Detail "App name: $($as.showAppName); location: $($as.showLocation)."
        }
        if ("$($as.systemPreferred)" -ne 'enabled') {
            Add-EntraFinding -Type entra_system_preferred_mfa_off -Object 'authenticationMethodsPolicy' -ObjectType 'policy' -Detail "System-preferred MFA: $(if ($as.systemPreferred) { $as.systemPreferred } else { 'not set' })."
        }
        if ($on -and "$($as.companionApp)" -ne 'disabled') {
            Add-EntraFinding -Type entra_authenticator_lite_on -Object 'Microsoft Authenticator' -ObjectType 'policy' -Detail "Companion apps: $(if ($as.companionApp) { $as.companionApp } else { 'default' })."
        }
    }

    if (& $have 'accessReviews') {
        $live = @($Snapshot.accessReviews | Where-Object { $_ -and "$($_.status)" -notmatch '(?i)completed|deleted' })
        if (-not @($live | Where-Object { "$($_.scope)" -match "(?i)userType eq 'Guest'|guest" }).Count) {
            Add-EntraFinding -Type entra_no_guest_access_review -Object 'access reviews' -ObjectType 'policy' -Detail "$($live.Count) active review(s), none covering guests."
        }
        if (-not @($live | Where-Object { "$($_.scope)" -match '(?i)roleDefinition|roleManagement|directoryRole' }).Count) {
            Add-EntraFinding -Type entra_no_admin_access_review -Object 'access reviews' -ObjectType 'policy' -Detail "$($live.Count) active review(s), none covering admin roles."
        }
    }

    if ((& $have 'pimPolicies') -and $Snapshot.pimPolicies) {
        $names = @{ '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'; 'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator' }
        $noApproval = @($Snapshot.pimPolicies.PSObject.Properties | Where-Object { $_.Value -eq $false } | ForEach-Object { if ($names[$_.Name]) { $names[$_.Name] } else { $_.Name } })
        if ($noApproval.Count) {
            Add-EntraFinding -Type entra_pim_activation_no_approval -Object 'PIM' -ObjectType 'policy' -Detail "Activation without approval: $($noApproval -join ', ')."
        }
    }

    # ---- Schema 4 ----
    $msTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
    $spById = @{}; foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ })) { $spById["$($sp.id)"] = $sp }
    $tenantId = "$($Snapshot.meta.tenantId)"

    # Delegated grants to apps from other tenants that reach mail, files or the directory.
    if (& $have 'oauthGrants') {
        $riskyScopes = 'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite', 'Files.Read.All', 'Files.ReadWrite.All', 'Sites.Read.All', 'Sites.ReadWrite.All',
        'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'User.ReadWrite.All', 'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
        'full_access_as_user', 'EWS.AccessAsUser.All', 'Contacts.ReadWrite', 'Calendars.ReadWrite', 'Notes.ReadWrite.All'
        foreach ($g in @($Snapshot.oauthGrants | Where-Object { $_ } | Group-Object clientId)) {
            $sp = $spById["$($g.Name)"]
            $owner = if ($sp) { "$($sp.appOwnerTenant)" } else { '' }
            if (-not $owner -or $owner -eq $tenantId -or $msTenants -contains $owner) { continue }
            $scopes = @($g.Group | ForEach-Object { "$($_.scope)" -split '\s+' } | Where-Object { $riskyScopes -contains $_ } | Select-Object -Unique)
            if (-not $scopes.Count) { continue }
            $admin = @($g.Group | Where-Object { "$($_.consentType)" -eq 'AllPrincipals' }).Count -gt 0
            $users = @($g.Group | Where-Object { "$($_.consentType)" -eq 'Principal' }).Count
            $who = if ($admin) { 'admin consent for every user' } else { "consented by $users user(s)" }
            Add-EntraFinding -Type entra_risky_delegated_grant -Object $(if ($sp) { $sp.displayName } else { $g.Name }) -ObjectType 'serviceprincipal' -ObjectDn $g.Name `
                -Severity $(if ($admin) { 'High' } else { 'Medium' }) -Detail "App from another tenant, $who`: $($scopes -join ', ')."
        }
    }

    # ---- Groups behind CA exclusions and admin roles (schema 6) ----
    if ($sv -ge 6 -and (& $have 'groups')) {
        $groupsById = @{}; foreach ($g in @($Snapshot.groups | Where-Object { $_ })) { $groupsById["$($g.id)"] = $g }
        # Admins: privileged role members, plus eligible principals of privileged roles.
        $adminIds = @{}; foreach ($k in $privMembers.Keys) { $adminIds["$k"] = $true }
        foreach ($a in @($Snapshot.pim.eligible | Where-Object { $_ })) { if ($script:EntraPrivRoleTemplates.ContainsKey("$($a.roleDefinitionId)")) { $adminIds["$($a.principalId)"] = $true } }
        $ownerIssues = {
            param($g)
            $out = @()
            # PIM for Groups: someone eligible to become owner is an owner in waiting.
            if ($g.PSObject.Properties['pimEligible'] -and $g.pimEligible) {
                foreach ($pe in @($g.pimEligible | Where-Object { $_ -and "$($_.accessId)" -eq 'owner' })) {
                    $peu = $usersById["$($pe.principalId)"]
                    if ($peu -and $peu.userType -eq 'Guest') { $out += "eligible owner guest $($peu.upn)" }
                    elseif (-not $adminIds.ContainsKey("$($pe.principalId)")) { $out += "eligible owner non-admin $(if ($peu) { $peu.upn } else { $pe.principalId })" }
                }
            }
            foreach ($op in @($g.ownerTypes.PSObject.Properties)) {
                $oid = "$($op.Name)"; $ot = "$($op.Value)"
                if ($ot -eq 'servicePrincipal') { $out += "service principal $(if ($spById[$oid]) { $spById[$oid].displayName } else { $oid })"; continue }
                $ou = $usersById[$oid]
                if ($ou -and $ou.userType -eq 'Guest') { $out += "guest $($ou.upn)"; continue }
                if (-not $adminIds.ContainsKey($oid)) { $out += "non-admin $(if ($ou) { $ou.upn } else { $oid })" }
            }
            $out
        }
        # Attributes a user or a guest can influence (self-service, invitation, profile).
        $softAttr = '(?i)user\.(displayName|mail|otherMails|userPrincipalName|mailNickname|proxyAddresses|givenName|surname)\b'
        $exclByGroup = [ordered]@{}
        foreach ($p in @($Snapshot.conditionalAccess | Where-Object { $_ -and "$($_.state)" -eq 'enabled' })) {
            foreach ($gid in @($p.excludeGroups | Where-Object { $_ })) {
                if (-not $exclByGroup.Contains("$gid")) { $exclByGroup["$gid"] = New-Object System.Collections.Generic.List[string] }
                $exclByGroup["$gid"].Add("$($p.displayName)")
            }
        }
        foreach ($gid in $exclByGroup.Keys) {
            $g = $groupsById[$gid]
            if (-not $g) { continue }
            $why = @()
            if ($g.unified -and "$($g.visibility)" -eq 'Public') { $why += 'public Microsoft 365 group (anyone can join)' }
            if ($g.dynamic -and "$($g.membershipRule)" -match $softAttr) { $why += "dynamic rule on an attribute users or guests can influence ($($Matches[1]))" }
            $oi = @(& $ownerIssues $g)
            if ($oi.Count) { $why += "owners: $($oi -join ', ')" }
            if ($why.Count) {
                Add-EntraFinding -Type entra_ca_excluded_group_weak -Object $g.displayName -ObjectType 'group' -ObjectDn $gid `
                    -Detail "Excluded from: $(@($exclByGroup[$gid]) -join ', '). $($why -join '; ')."
            }
        }
        # Groups holding a privileged role, active (role member) or eligible (PIM).
        $roleOfGroup = [ordered]@{}
        foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ -and $_.memberTypes })) {
            $rn = if ($script:EntraPrivRoleTemplates.ContainsKey("$($r.roleTemplateId)")) { $script:EntraPrivRoleTemplates["$($r.roleTemplateId)"] } else { $null }
            if (-not $rn) { continue }
            foreach ($m in @($r.memberTypes.PSObject.Properties | Where-Object { "$($_.Value)" -eq 'group' })) {
                if (-not $roleOfGroup.Contains("$($m.Name)")) { $roleOfGroup["$($m.Name)"] = New-Object System.Collections.Generic.List[string] }
                if (-not $roleOfGroup["$($m.Name)"].Contains($rn)) { $roleOfGroup["$($m.Name)"].Add($rn) }
            }
        }
        foreach ($a in @($Snapshot.pim.active) + @($Snapshot.pim.eligible) | Where-Object { $_ -and $groupsById.ContainsKey("$($_.principalId)") }) {
            $rn = $script:EntraPrivRoleTemplates["$($a.roleDefinitionId)"]
            if (-not $rn) { continue }
            $label = if ("$($a.assignmentType)" -eq 'Eligible') { "$rn (eligible)" } else { $rn }
            if (-not $roleOfGroup.Contains("$($a.principalId)")) { $roleOfGroup["$($a.principalId)"] = New-Object System.Collections.Generic.List[string] }
            if (-not $roleOfGroup["$($a.principalId)"].Contains($label) -and -not $roleOfGroup["$($a.principalId)"].Contains($rn)) { $roleOfGroup["$($a.principalId)"].Add($label) }
        }
        foreach ($gid in $roleOfGroup.Keys) {
            $g = $groupsById[$gid]
            if (-not $g) { continue }
            $oi = @(& $ownerIssues $g)
            if ($oi.Count) {
                Add-EntraFinding -Type entra_privileged_group_owner -Object $g.displayName -ObjectType 'group' -ObjectDn $gid `
                    -Detail "Holds: $(@($roleOfGroup[$gid]) -join ', '). Owners who can add themselves: $($oi -join ', ').$(if (-not $g.isAssignableToRole) { ' The group is not role-assignable.' })"
            }
        }
    }

    # ---- Schema 7 ----
    if ($sv -ge 7) {
        # Privileged service principals: admin role or tenant-takeover permission.
        $spRoles = @{}
        foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ -and $_.memberTypes })) {
            $rn = $script:EntraPrivRoleTemplates["$($r.roleTemplateId)"]
            if (-not $rn) { continue }
            foreach ($m in @($r.memberTypes.PSObject.Properties | Where-Object { "$($_.Value)" -eq 'servicePrincipal' })) { $spRoles["$($m.Name)"] = @(@($spRoles["$($m.Name)"]) + $rn | Where-Object { $_ }) }
        }
        $privWhy = {
            param($sp)
            $w = @()
            if ($spRoles.ContainsKey("$($sp.id)")) { $w += "role $(@($spRoles["$($sp.id)"]) -join ', ')" }
            $risk = @($sp.appRoleIds | Where-Object { $script:EntraHighRiskAppRoles.ContainsKey("$_") } | ForEach-Object { $script:EntraHighRiskAppRoles["$_"] })
            if ($risk.Count) { $w += "permission $($risk -join ', ')" }
            $w -join '; '
        }

        if ((& $have 'pimPolicies') -and $Snapshot.PSObject.Properties['pimRules'] -and $Snapshot.pimRules) {
            $top = @('62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13')
            $issues = [ordered]@{ 'activation without MFA or authentication context' = @(); 'activation longer than 8 hours' = @(); 'active assignments can be permanent' = @(); 'eligible assignments can be permanent' = @() }
            $severe = $false
            foreach ($rp in @($Snapshot.pimRules.PSObject.Properties)) {
                $rn = if ($script:EntraPrivRoleTemplates.ContainsKey($rp.Name)) { $script:EntraPrivRoleTemplates[$rp.Name] } else { $rp.Name }
                $v = $rp.Value
                if (-not $v.mfa -and -not $v.authContext) { $issues['activation without MFA or authentication context'] += $rn; if ($top -contains $rp.Name) { $severe = $true } }
                $hours = $null; try { if ("$($v.maxActivation)") { $hours = [System.Xml.XmlConvert]::ToTimeSpan("$($v.maxActivation)").TotalHours } } catch { }
                if ($null -ne $hours -and $hours -gt 8) { $issues['activation longer than 8 hours'] += "$rn ($hours h)" }
                if (-not $v.activeExpiryRequired) { $issues['active assignments can be permanent'] += $rn; if ($top -contains $rp.Name) { $severe = $true } }
                if (-not $v.eligibleExpiryRequired) { $issues['eligible assignments can be permanent'] += $rn }
            }
            $parts = @($issues.Keys | Where-Object { @($issues[$_]).Count } | ForEach-Object { "$_`: $(@($issues[$_] | Sort-Object) -join ', ')" })
            if ($parts.Count) {
                Add-EntraFinding -Type entra_pim_role_settings_weak -Object 'PIM role settings' -ObjectType 'policy' -Severity $(if ($severe) { 'Medium' } else { 'Low' }) -Detail "$($parts -join '. ')."
            }
        }

        # Scoped admins: only a gap when the admin MFA comes from role targeting, not from "all users".
        if ($caOk -and (& $have 'roleAssignments') -and -not (Test-CaRequiresMfaAll $Snapshot)) {
            $roleTargeted = @($Snapshot.conditionalAccess | Where-Object { $_ -and "$($_.state)" -eq 'enabled' -and (Test-CaGrantsMfa $_) -and @($_.includeRoles).Count }).Count -gt 0
            if ($roleTargeted) {
                $scoped = [ordered]@{}
                foreach ($a in @($Snapshot.roleAssignments | Where-Object { $_ -and "$($_.directoryScopeId)" -and "$($_.directoryScopeId)" -ne '/' })) {
                    $rn = $script:EntraPrivRoleTemplates["$($a.roleDefinitionId)"]
                    if (-not $rn) { continue }
                    $who = if ($usersById["$($a.principalId)"]) { $usersById["$($a.principalId)"].upn } else { "$($a.principalId)" }
                    $scoped["$who ($rn)"] = $true
                }
                if ($scoped.Count) {
                    Add-EntraFinding -Type entra_scoped_admin_outside_ca -Object 'scoped role assignments' -ObjectType 'policy' -Detail "Scoped privileged assignments not covered by role-targeted policies: $(@($scoped.Keys) -join ', ')."
                }
            }
        }

        # App admins scoped to one app: the scope is the object id of the app registration or of its service principal.
        if (& $have 'roleAssignments') {
            $appAdminRoles = @{ '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'; '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator' }
            $spByAppId = @{}; foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ })) { $spByAppId["$($sp.appId)"] = $sp }
            $appById = @{}; foreach ($ap in @($Snapshot.applications | Where-Object { $_ })) { $appById["$($ap.id)"] = $ap }
            $scopedApp = [ordered]@{}
            foreach ($a in @($Snapshot.roleAssignments | Where-Object { $_ -and $appAdminRoles.ContainsKey("$($_.roleDefinitionId)") -and "$($_.directoryScopeId)" -match '^/[0-9a-fA-F-]{36}$' })) {
                $oid = "$($a.directoryScopeId)".TrimStart('/')
                $target = if ($spById[$oid]) { $spById[$oid] } elseif ($appById[$oid]) { $spByAppId["$($appById[$oid].appId)"] } else { $null }
                if (-not $target) { continue }
                $why = & $privWhy $target
                if (-not $why) { continue }
                $who = if ($usersById["$($a.principalId)"]) { $usersById["$($a.principalId)"].upn } else { "$($a.principalId)" }
                if (-not $scopedApp.Contains("$($target.id)")) { $scopedApp["$($target.id)"] = [PSCustomObject]@{ Sp = $target; Why = $why; Who = New-Object System.Collections.Generic.List[string] } }
                $scopedApp["$($target.id)"].Who.Add("$who ($($appAdminRoles["$($a.roleDefinitionId)"]))")
            }
            foreach ($k in $scopedApp.Keys) {
                $x = $scopedApp[$k]
                Add-EntraFinding -Type entra_app_scoped_admin_privileged -Object $x.Sp.displayName -ObjectType 'serviceprincipal' -ObjectDn $x.Sp.id `
                    -Detail "Scoped app admin(s): $(@($x.Who) -join ', '). The app holds: $($x.Why)."
            }
        }

        if (-not $failedSections.ContainsKey('appOwners')) {
            foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ -and $_.PSObject.Properties['ownerTypes'] -and $_.ownerTypes })) {
                $why = & $privWhy $sp
                if (-not $why) { continue }
                $spOwners = @($sp.ownerTypes.PSObject.Properties | Where-Object { "$($_.Value)" -eq 'servicePrincipal' } | ForEach-Object { if ($spById["$($_.Name)"]) { $spById["$($_.Name)"].displayName } else { $_.Name } })
                if ($spOwners.Count) {
                    Add-EntraFinding -Type entra_privileged_app_sp_owner -Object $sp.displayName -ObjectType 'serviceprincipal' -ObjectDn $sp.id -Detail "Owned by service principal(s): $($spOwners -join ', '). The app holds: $why."
                }
            }
        }

        if ((& $have 'spSignIns') -and $Snapshot.spSignIns) {
            foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ })) {
                $why = & $privWhy $sp
                if (-not $why -or -not $Snapshot.spSignIns.PSObject.Properties["$($sp.appId)"]) { continue }
                $last = & $ageDays $Snapshot.spSignIns."$($sp.appId)"
                if ($null -ne $last -and $last -gt 180) {
                    Add-EntraFinding -Type entra_privileged_app_inactive -Object $sp.displayName -ObjectType 'serviceprincipal' -ObjectDn $sp.id -Detail "Last sign-in $last days ago. Holds: $why."
                }
            }
        }

        foreach ($app in @($Snapshot.applications | Where-Object { $_ -and $_.PSObject.Properties['signInAudience'] })) {
            if ("$($app.signInAudience)" -notmatch 'Multiple|Personal') { continue }
            $creds = @($app.keyCred | Where-Object { $_ }).Count + @($app.passwordCred | Where-Object { $_ }).Count
            if ($creds -gt 0 -and -not $app.instanceLock) {
                Add-EntraFinding -Type entra_app_instance_lock_off -Object $app.displayName -ObjectType 'application' -ObjectDn $app.id -Detail "Sign-in audience $($app.signInAudience), $creds credential(s), App instance property lock not enabled."
            }
        }

        if ((& $have 'accessPackageGrants') -and $Snapshot.accessPackageGrants -and (& $have 'groups')) {
            $roleGroupIds = @{}
            foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ -and $_.memberTypes -and $script:EntraPrivRoleTemplates.ContainsKey("$($_.roleTemplateId)") })) {
                foreach ($m in @($r.memberTypes.PSObject.Properties | Where-Object { "$($_.Value)" -eq 'group' })) { $roleGroupIds["$($m.Name)"] = $true }
            }
            foreach ($a in @($Snapshot.pim.active) + @($Snapshot.pim.eligible) | Where-Object { $_ -and $script:EntraPrivRoleTemplates.ContainsKey("$($_.roleDefinitionId)") }) { $roleGroupIds["$($a.principalId)"] = $true }
            $grpName = @{}; foreach ($g in @($Snapshot.groups | Where-Object { $_ })) { $grpName["$($g.id)"] = $g.displayName }
            foreach ($pol in @($Snapshot.accessPackages | Where-Object { $_ -and $_.selfAddEnabled -and -not $_.approvalRequired -and "$($_.allowedTargetScope)" -match '^all' })) {
                if (-not $pol.PSObject.Properties['accessPackageId'] -or -not $Snapshot.accessPackageGrants.PSObject.Properties["$($pol.accessPackageId)"]) { continue }
                $hits = @()
                foreach ($gr in @($Snapshot.accessPackageGrants."$($pol.accessPackageId)" | Where-Object { $_ })) {
                    if ("$($gr.originSystem)" -eq 'AadGroup' -and $roleGroupIds.ContainsKey("$($gr.scopeOriginId)")) { $hits += "group $(if ($grpName["$($gr.scopeOriginId)"]) { $grpName["$($gr.scopeOriginId)"] } else { $gr.scopeOriginId }) (holds an admin role)" }
                    elseif ("$($gr.originSystem)" -eq 'DirectoryRole') {
                        $rid = @($script:EntraPrivRoleTemplates.Keys | Where-Object { "$($gr.roleOriginId)" -match $_ -or "$($gr.scopeOriginId)" -match $_ })[0]
                        if ($rid) { $hits += "role $($script:EntraPrivRoleTemplates[$rid])" }
                    }
                }
                if ($hits.Count) {
                    Add-EntraFinding -Type entra_access_package_grants_admin -Object $pol.accessPackage -ObjectType 'accesspackage' -ObjectDn $pol.id `
                        -Detail "Policy $($pol.displayName): $($pol.allowedTargetScope) can request it for themselves without approval. Grants: $($hits -join ', ')."
                }
            }
        }
    }

    # Intune roles that reach code execution on devices (or rewrite Intune RBAC), given through
    # a group that non-Tier 0 roles or owners can add members to. The action names are not yet
    # verified against a real tenant.
    if ($sv -ge 8 -and (& $have 'intuneRoles') -and (& $have 'groups')) {
        $powerfulBuiltIn = @('Intune Role Administrator', 'Policy and Profile Manager', 'Application Manager', 'School Administrator')
        $powerfulAction = '^Microsoft\.Intune_(DeviceConfigurations|MobileApps|DeviceManagementScripts|Remediations|Roles)_(Create|Update|Assign)$'
        $grpById = @{}; foreach ($g in @($Snapshot.groups | Where-Object { $_ })) { $grpById["$($g.id)"] = $g }
        foreach ($ia in @($Snapshot.intuneRoles | Where-Object { $_ })) {
            $hits = @(@($ia.actions) | Where-Object { "$_" -match $powerfulAction })
            if (-not ($powerfulBuiltIn -contains "$($ia.roleName)" -and $ia.isBuiltIn) -and -not $hits.Count) { continue }
            foreach ($gid in @($ia.members | Where-Object { $_ })) {
                $g = $grpById["$gid"]
                if (-not $g) { continue }
                $weak = @()
                if (-not $g.isAssignableToRole) { $weak += 'not role-assignable' }
                if ($g.dynamic) { $weak += "dynamic membership ($($g.membershipRule))" }
                if (-not $weak.Count) { continue }
                $owners = @(if ($g.ownerTypes) { $g.ownerTypes.PSObject.Properties }).Count
                $what = if ($ia.isBuiltIn) { 'built-in role' } else { "custom role with $(@($hits | Select-Object -First 3) -join ', ')" }
                Add-EntraFinding -Type entra_intune_role_weak_group -Object "$($ia.roleName): $($g.displayName)" -ObjectType 'intunerole' -ObjectDn $ia.id `
                    -Detail "Assignment $($ia.displayName) ($what) is given to group $($g.displayName): $($weak -join ', '); $owners owner(s). Scope groups: $(if (@($ia.resourceScopes).Count) { @($ia.resourceScopes).Count } else { 'none listed' })."
            }
        }
    }

    # Multi Admin Approval: without it one compromised Intune admin can wipe every device or
    # push a script to all of them. Read only where Intune is (its roles were readable).
    if ($sv -ge 9 -and (& $have 'intuneRoles') -and (& $have 'intuneApprovalPolicies')) {
        $types = @(@($Snapshot.intuneApprovalPolicies) | Where-Object { $_ } | ForEach-Object { "$($_.policyType)" })
        $cover = [ordered]@{ 'device wipe' = '(?i)wipe|deviceAction'; 'scripts' = '(?i)script'; 'apps' = '(?i)^app$'; 'Intune roles' = '(?i)^role' }
        $missing = @(foreach ($k in $cover.Keys) { if (-not @($types | Where-Object { $_ -match $cover[$k] }).Count) { $k } })
        if ($missing -contains 'device wipe' -or $missing -contains 'scripts') {
            $now = if ($types.Count) { "Policies exist for: $((@($types | Sort-Object -Unique)) -join ', ')." } else { 'No approval policy at all.' }
            Add-EntraFinding -Type entra_intune_no_multi_admin_approval -Object 'Intune' -ObjectType 'tenant' `
                -Detail "No Multi Admin Approval for: $($missing -join ', '). $now"
        }
    }

    # ---- Schema 10 ----
    if ($sv -ge 10) {
        # Azure AD Graph: requested by an app registration, or granted to a service principal of
        # this tenant or a third party (application permissions, or delegated consents on the
        # Azure AD Graph service principal). Microsoft's own apps are left out. One finding per app.
        $aadg = [ordered]@{}
        $note = {
            param([string]$Key, [string]$Name, [string]$Id, [string]$Text)
            if (-not $aadg.Contains($Key)) { $aadg[$Key] = [PSCustomObject]@{ Name = $Name; Id = $Id; What = New-Object System.Collections.Generic.List[string] } }
            $aadg[$Key].What.Add($Text)
        }
        if (& $have 'applications') {
            foreach ($app in @($Snapshot.applications | Where-Object { $_ -and $_.PSObject.Properties['aadGraphScopes'] })) {
                $nr = [int]"0$($app.aadGraphRoles)"; $ns = [int]"0$($app.aadGraphScopes)"
                if ($nr -or $ns) { & $note "$($app.appId)" "$($app.displayName)" "$($app.id)" "the app registration requests $nr application and $ns delegated permission(s)" }
            }
        }
        if (& $have 'servicePrincipals') {
            $gsp = "$($Snapshot.aadGraphSpId)"
            $delegated = @{}
            if ($gsp -and (& $have 'oauthGrants')) {
                foreach ($g in @($Snapshot.oauthGrants | Where-Object { $_ -and "$($_.resourceId)" -eq $gsp })) {
                    if (-not $delegated.ContainsKey("$($g.clientId)")) { $delegated["$($g.clientId)"] = New-Object System.Collections.Generic.List[object] }
                    $delegated["$($g.clientId)"].Add($g)
                }
            }
            foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ -and "$($_.id)" -ne $gsp -and $msTenants -notcontains "$($_.appOwnerTenant)" })) {
                $parts = @()
                $nr = [int]"0$($sp.aadGraphRoles)"
                if ($nr) { $parts += "$nr application permission(s) granted" }
                if ($delegated.ContainsKey("$($sp.id)")) {
                    $dg = $delegated["$($sp.id)"]
                    $scopes = @($dg | ForEach-Object { "$($_.scope)" -split '\s+' } | Where-Object { $_ } | Select-Object -Unique)
                    $who = if (@($dg | Where-Object { "$($_.consentType)" -eq 'AllPrincipals' }).Count) { 'admin consent for every user' } else { "consent by $($dg.Count) user(s)" }
                    $parts += "delegated $($scopes -join ', ') ($who)"
                }
                if ($parts.Count) { & $note "$($sp.appId)" "$($sp.displayName)" "$($sp.id)" "the service principal has $($parts -join ' and ')" }
            }
        }
        foreach ($k in $aadg.Keys) {
            $x = $aadg[$k]
            Add-EntraFinding -Type entra_app_azure_ad_graph -Object $x.Name -ObjectType 'application' -ObjectDn $x.Id -Detail "Azure AD Graph: $($x.What.ToArray() -join '; ')."
        }

        # Catalog roles over a catalog that holds a group with an admin role. Owners and access
        # package managers can package any resource of the catalog; assignment managers only hand
        # out existing packages, so they count when a package of the catalog grants the group.
        if ((& $have 'entitlementCatalogs') -and (& $have 'catalogRoles') -and (& $have 'groups') -and $Snapshot.entitlementCatalogs) {
            $catRoleNames = @{ 'ae79f266-94d4-4dab-b730-feca7e132178' = 'Catalog owner'; '7f480852-ebdc-47d4-87de-0d8498384a83' = 'Access package manager'; 'e2182095-804a-4656-ae11-64734e9b7ae5' = 'Access package assignment manager' }
            $privGroupIds = @{}
            foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ -and $_.memberTypes -and $script:EntraPrivRoleTemplates.ContainsKey("$($_.roleTemplateId)") })) {
                foreach ($m in @($r.memberTypes.PSObject.Properties | Where-Object { "$($_.Value)" -eq 'group' })) { $privGroupIds["$($m.Name)"] = $true }
            }
            foreach ($a in @($Snapshot.pim.active) + @($Snapshot.pim.eligible) | Where-Object { $_ -and $script:EntraPrivRoleTemplates.ContainsKey("$($_.roleDefinitionId)") }) { $privGroupIds["$($a.principalId)"] = $true }
            $grpName = @{}; foreach ($g in @($Snapshot.groups | Where-Object { $_ })) { $grpName["$($g.id)"] = "$($g.displayName)" }
            foreach ($cat in @($Snapshot.entitlementCatalogs | Where-Object { $_ })) {
                $held = @(@($cat.resources) | Where-Object { $_ -and "$($_.originSystem)" -eq 'AadGroup' -and $privGroupIds.ContainsKey("$($_.originId)") } | ForEach-Object { "$($_.originId)" } | Select-Object -Unique)
                if (-not $held.Count) { continue }
                $handedOut = @{}
                foreach ($apid in @($cat.accessPackageIds | Where-Object { $_ })) {
                    if (-not $Snapshot.accessPackageGrants -or -not $Snapshot.accessPackageGrants.PSObject.Properties["$apid"]) { continue }
                    foreach ($gr in @($Snapshot.accessPackageGrants."$apid" | Where-Object { $_ -and "$($_.originSystem)" -eq 'AadGroup' })) { $handedOut["$($gr.scopeOriginId)"] = $true }
                }
                foreach ($ra in @($Snapshot.catalogRoles | Where-Object { $_ -and "$($_.appScopeId)" -eq "/AccessPackageCatalog/$($cat.id)" })) {
                    $rn = $catRoleNames["$($ra.roleDefinitionId)"]
                    if (-not $rn) { continue }
                    $reach = if ($rn -eq 'Access package assignment manager') { @($held | Where-Object { $handedOut.ContainsKey($_) }) } else { $held }
                    if (-not @($reach).Count) { continue }
                    $pid2 = "$($ra.principalId)"; $pt = "$($ra.principalType)"
                    $u = $usersById[$pid2]
                    if ($pt -eq 'servicePrincipal') { $name = if ($spById[$pid2]) { "$($spById[$pid2].displayName)" } else { $pid2 }; $kind = 'service principal' }
                    elseif ($pt -eq 'group') { if ($adminIds.ContainsKey($pid2)) { continue }; $name = if ($grpName[$pid2]) { $grpName[$pid2] } else { $pid2 }; $kind = 'group' }
                    elseif ($u -and $u.userType -eq 'Guest') { $name = "$($u.upn)"; $kind = 'guest' }
                    else { if ($adminIds.ContainsKey($pid2)) { continue }; $name = if ($u) { "$($u.upn)" } else { $pid2 }; $kind = 'non-admin' }
                    $groupsText = @($reach | ForEach-Object { if ($grpName[$_]) { $grpName[$_] } else { $_ } }) -join ', '
                    Add-EntraFinding -Type entra_catalog_role_privileged_group -Object "$($cat.displayName): $name" -ObjectType 'catalog' -ObjectDn "$($cat.id)" `
                        -Detail "$rn ($kind $name) on catalog $($cat.displayName), which holds $groupsText (admin role). $(if ($rn -eq 'Access package assignment manager') { 'A package of the catalog already grants it: they can assign it to themselves.' } else { 'They can put it in an access package and assign it, to themselves too.' })"
                }
            }
        }
    }

    # Entra Connect's provisioning app: one self-managed certificate, never a secret.
    foreach ($app in @($Snapshot.applications | Where-Object { $_ -and "$($_.displayName)" -match '^ConnectSyncProvisioning_' })) {
        $nk = @($app.keyCred | Where-Object { $_ }).Count; $np = @($app.passwordCred | Where-Object { $_ }).Count
        if ($nk -gt 1 -or $np -gt 0) {
            Add-EntraFinding -Type entra_connect_app_extra_credentials -Object $app.displayName -ObjectType 'application' -ObjectDn $app.id `
                -Detail "$nk certificate(s) and $np client secret(s) on the Entra Connect provisioning app (expected: one certificate)."
        }
    }

    # Look-alike service principal names: mixed scripts inside a word, full-width letters, invisible characters.
    foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ -and $_.displayName })) {
        $n = "$($sp.displayName)"
        $tricks = @()
        if ($n -match '[\u200B-\u200F\u2060\uFEFF\u00AD]') { $tricks += 'invisible characters' }
        if ($n -match '[\uFF21-\uFF3A\uFF41-\uFF5A]') { $tricks += 'full-width letters' }
        foreach ($w in ($n -split '[\s\-_.]+')) { if ($w -match '[A-Za-z]' -and $w -match '[\p{IsCyrillic}\p{IsGreek}]') { $tricks += 'Latin mixed with Cyrillic or Greek letters'; break } }
        if ($tricks.Count) {
            # Positions and code points only: a rewritten copy of the name would slip past the AI pseudonymizer.
            $odd = @(for ($i = 0; $i -lt $n.Length; $i++) { if ([int]$n[$i] -ge 128) { "{0} (U+{1:X4})" -f ($i + 1), [int]$n[$i] } })
            Add-EntraFinding -Type entra_sp_lookalike_name -Object $sp.displayName -ObjectType 'serviceprincipal' -ObjectDn $sp.id `
                -Detail "$($tricks -join ', ') in the name; non-ASCII characters at position $($odd -join ', ')$(if ($sp.appOwnerTenant) { "; published by tenant $($sp.appOwnerTenant)" })."
        }
    }

    if ($sv -ge 4) {
        # Users owning apps that hold tenant-takeover permissions.
        if (-not $failedSections.ContainsKey('appOwners')) {
            foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ -and $_.PSObject.Properties['owners'] })) {
                $risk = @($sp.appRoleIds | Where-Object { $script:EntraHighRiskAppRoles.ContainsKey("$_") })
                if (-not $risk.Count) { continue }
                $plain = @($sp.owners | Where-Object { $usersById.ContainsKey("$_") -and -not $privMembers.ContainsKey("$_") } | ForEach-Object { $usersById["$_"].upn })
                if ($plain.Count) {
                    Add-EntraFinding -Type entra_privileged_app_owner -Object $sp.displayName -ObjectType 'serviceprincipal' -ObjectDn $sp.id `
                        -Detail "Owned by non-admin user(s): $($plain -join ', '). Permissions: $(($risk | ForEach-Object { $script:EntraHighRiskAppRoles["$_"] }) -join ', ')."
                }
            }
        }

        # Service principals holding admin roles.
        foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ -and $_.memberTypes })) {
            $rn = if ($script:EntraPrivRoleTemplates.ContainsKey("$($r.roleTemplateId)")) { $script:EntraPrivRoleTemplates["$($r.roleTemplateId)"] } else { "$($r.displayName)" }
            foreach ($m in @($r.memberTypes.PSObject.Properties | Where-Object { "$($_.Value)" -eq 'servicePrincipal' })) {
                $name = if ($spById["$($m.Name)"]) { $spById["$($m.Name)"].displayName } else { $m.Name }
                Add-EntraFinding -Type entra_sp_in_admin_role -Object $name -ObjectType 'serviceprincipal' -ObjectDn $m.Name -Detail "Holds the $rn role."
            }
        }

        foreach ($uid in $privMembers.Keys) {
            $u = $usersById[$uid]
            if (-not $u -or -not $u.enabled -or $u.userType -eq 'Guest') { continue }
            $pwAge = & $ageDays $u.lastPasswordChange
            if ($null -ne $pwAge -and $pwAge -gt 365) {
                Add-EntraFinding -Type entra_admin_password_old -Object $u.upn -ObjectType 'user' -ObjectDn $uid -Detail "Password last changed $pwAge days ago. Roles: $($privMembers[$uid] -join ', ')."
            }
            if (-not $failedSections.ContainsKey('mfaRegistration') -and $null -ne $u.mfaMethods) {
                $strong = @($u.mfaMethods | Where-Object { "$_" -match '(?i)fido2|passKey|windowsHelloForBusiness|x509Certificate' })
                if (-not $strong.Count) {
                    Add-EntraFinding -Type entra_admin_no_phishing_resistant_method -Object $u.upn -ObjectType 'user' -ObjectDn $uid `
                        -Detail "Registered: $(if (@($u.mfaMethods).Count) { @($u.mfaMethods) -join ', ' } else { 'nothing' }). Roles: $($privMembers[$uid] -join ', ')."
                }
            }
        }

        if ($Snapshot.org -and $Snapshot.org.onPremisesSyncEnabled) {
            $syncAge = & $ageDays $Snapshot.org.lastSyncUtc
            if ($null -eq $syncAge -or $syncAge -ge 1) {
                Add-EntraFinding -Type entra_sync_stale -Object 'directory sync' -ObjectType 'sync' -Detail "Last sync: $(if ($null -ne $syncAge) { "$syncAge day(s) ago" } else { 'unknown' })."
            }
        }

        foreach ($app in @($Snapshot.applications | Where-Object { $_ })) {
            $bad = @($app.redirectUris | Where-Object { "$_" -match '\*' -or ("$_" -match '^(?i)http://' -and "$_" -notmatch '^(?i)http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)') })
            if ($bad.Count) {
                Add-EntraFinding -Type entra_app_insecure_redirect -Object $app.displayName -ObjectType 'application' -ObjectDn $app.id -Detail "Redirect URI(s): $($bad -join ', ')."
            }
        }

        if (& $have 'domains') {
            foreach ($d in @($Snapshot.domains | Where-Object { $_ -and "$($_.authenticationType)" -eq 'Federated' })) {
                $mb = "$($d.federatedIdpMfaBehavior)"
                $sev = if ($mb -and $mb -ne 'rejectMfaByFederatedIdp') { 'Medium' } else { 'Low' }
                Add-EntraFinding -Type entra_federated_domain -Object $d.id -ObjectType 'domain' -Severity $sev -Detail "Federated; IdP MFA: $(if ($mb) { $mb } else { 'unknown' })."
            }
        }
    }

    # First-party Microsoft apps with a credential added here.
    foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ -and $msTenants -contains "$($_.appOwnerTenant)" })) {
        $n = @(@($sp.passwordCred) + @($sp.keyCred) | Where-Object { $_ }).Count
        if ($n) {
            Add-EntraFinding -Type entra_first_party_sp_credentials -Object $sp.displayName -ObjectType 'serviceprincipal' -ObjectDn $sp.id -Detail "$n credential(s) on a Microsoft-owned app."
        }
    }

    $ct = $Snapshot.crossTenant
    if ((& $have 'crossTenant') -and $ct) {
        $trusted = @(); if ($ct.mfaAccepted) { $trusted += 'MFA' }; if ($ct.compliantDeviceAccepted) { $trusted += 'compliant devices' }; if ($ct.hybridJoinAccepted) { $trusted += 'hybrid-joined devices' }
        if ($trusted.Count) {
            Add-EntraFinding -Type entra_cross_tenant_mfa_trust -Object 'cross-tenant default' -ObjectType 'policy' -Detail "Accepted from any external tenant: $($trusted -join ', ')."
        }
    }

    $amp = $Snapshot.appManagementPolicy
    if ((& $have 'appManagementPolicy') -and $amp) {
        $days = { param($iso) try { [int][System.Xml.XmlConvert]::ToTimeSpan("$iso").TotalDays } catch { $null } }
        $rule = { param($list, $type) @($list | Where-Object { $_ -and "$($_.type)" -eq $type -and "$($_.state)" -eq 'enabled' }) }
        $gaps = @()
        if (-not $amp.isEnabled) { $gaps += 'the policy is off' }
        else {
            # @() around each call: on PS 5.1 a single result has no .Count.
            if (-not @(& $rule $amp.passwordRestrictions 'passwordAddition').Count) { $gaps += 'new client secrets allowed (5.1.5.3)' }
            $pl = @(& $rule $amp.passwordRestrictions 'passwordLifetime'); $pd = if ($pl.Count) { & $days $pl[0].maxLifetime } else { $null }
            if ($null -eq $pd -or $pd -gt 180) { $gaps += 'no 180-day cap on secrets (5.1.5.4)' }
            if (-not @(& $rule $amp.passwordRestrictions 'customPasswordAddition').Count) { $gaps += 'custom secrets allowed (5.1.5.5)' }
            $kl = @(& $rule $amp.keyRestrictions 'asymmetricKeyLifetime'); $kd = if ($kl.Count) { & $days $kl[0].maxLifetime } else { $null }
            if ($null -eq $kd -or $kd -gt 180) { $gaps += 'no 180-day cap on certificates (5.1.5.6)' }
        }
        if ($gaps.Count) {
            Add-EntraFinding -Type entra_app_management_policy_weak -Object 'defaultAppManagementPolicy' -ObjectType 'policy' -Detail "$(($gaps -join '; '))."
        }
    }

    # ---- Schema 5 ----
    if ($sv -ge 5) {
        if ((& $have 'crossTenant') -and $ct) {
            $open = @()
            if ("$($ct.directConnectInbound)" -eq 'allowed') { $open += 'inbound (their users into your shared channels)' }
            if ("$($ct.directConnectOutbound)" -eq 'allowed') { $open += 'outbound (your users into theirs)' }
            if ($open.Count) {
                Add-EntraFinding -Type entra_b2b_direct_connect_open -Object 'cross-tenant default' -ObjectType 'policy' -Detail "B2B direct connect allowed with any tenant: $($open -join ', ')."
            }
        }

        if (& $have 'accessPackages') {
            $external = @{ allExternalUsers = 'High'; allConfiguredConnectedOrganizationUsers = 'Medium'; specificConnectedOrganizationUsers = 'Medium' }
            foreach ($p in @($Snapshot.accessPackages | Where-Object { $_ })) {
                $scope = "$($p.allowedTargetScope)"
                if ($p.selfAddEnabled -and $external.ContainsKey($scope) -and -not $p.approvalRequired) {
                    Add-EntraFinding -Type entra_access_package_external_no_approval -Object $p.accessPackage -ObjectType 'accesspackage' -ObjectDn $p.id -Severity $external[$scope] `
                        -Detail "Policy '$($p.displayName)': requests from $scope, no approval."
                }
                if ("$($p.expirationType)" -eq 'noExpiration' -and -not $p.reviewEnabled) {
                    Add-EntraFinding -Type entra_access_package_no_expiry -Object $p.accessPackage -ObjectType 'accesspackage' -ObjectDn $p.id -Detail "Policy '$($p.displayName)': no expiry, no access review."
                }
            }
        }

        # Workload identity CA only applies to apps registered in this tenant.
        if ($caOk -and -not $failedSections.ContainsKey('servicePrincipals')) {
            $ownTenant = "$($Snapshot.meta.tenantId)"
            $spIndex = @{}; foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ })) { $spIndex["$($sp.id)"] = $sp }
            $own = @($script:Findings | Where-Object { $_.Type -in 'entra_sp_in_admin_role', 'entra_app_high_privilege' -and $spIndex.ContainsKey("$($_.ObjectDn)") } |
                Where-Object { $s = $spIndex["$($_.ObjectDn)"]; $o = "$($s.appOwnerTenant)"; (-not $o -or $o -eq $ownTenant) -and "$($s.type)" -ne 'ManagedIdentity' } |
                ForEach-Object { $_.Object } | Select-Object -Unique)
            $covered = @($Snapshot.conditionalAccess | Where-Object { $_ -and "$($_.state)" -eq 'enabled' -and @($_.includeServicePrincipals | Where-Object { $_ }).Count })
            if ($own.Count -and -not $covered.Count) {
                Add-EntraFinding -Type entra_no_workload_identity_ca -Object 'workload identities' -ObjectType 'policy' `
                    -Detail "No enabled policy targets service principals. Privileged apps of this tenant: $(($own | Select-Object -First 10) -join ', ')$(if ($own.Count -gt 10) { " and $($own.Count - 10) more" })."
            }
        }
    }

    return (Sort-FindingsStable -Findings $script:Findings -Catalog $script:EntraCheckCatalog)
}

# --------------------------------------------------------------------------
# Report (smaller than the AD one, same building blocks)
# --------------------------------------------------------------------------
function Get-EntraChartsRow {
    param($Findings)
    $sevLabels = @('Critical', 'High', 'Medium', 'Low')
    $sevVals = @($sevLabels | ForEach-Object { $s = $_; @($Findings | Where-Object { $_.Severity -eq $s }).Count })
    $sevPie = Get-SvgPieChart -Labels $sevLabels -Values $sevVals -Colors $script:WolfSeverityColors -CenterLabel 'findings'
    $cats = @('Entra Identity', 'Entra Access Policy', 'Entra Applications')
    $catVals = @($cats | ForEach-Object { $c = $_; @($Findings | Where-Object { $_.Category -eq $c }).Count })
    $catPie = Get-SvgPieChart -Labels $cats -Values $catVals -Colors @('#2B2925', '#78726A', '#ABA497') -CenterLabel 'findings'
    return "<div class='chart-row'><div><div class='pie-chart-title'>Findings by severity</div>$sevPie</div><div><div class='pie-chart-title'>Findings by category</div>$catPie</div></div>"
}

# Pies about the tenant itself (not the findings): who is in it and how it is set up. A pie with
# no data is left out, so a tenant that couldn't be read doesn't show empty circles.
function Get-EntraInfoChartsRow {
    param($Snapshot)
    $ramp = $script:WolfCategoryRamp
    $failed = @{}; foreach ($e in @($Snapshot.meta.collectionErrors | Where-Object { $_ })) { $failed["$($e.section)"] = $true }
    $users = @($Snapshot.users | Where-Object { $_ })
    $pies = New-Object System.Collections.Generic.List[string]
    $add = {
        param([string]$Title, [string]$Center, [string[]]$Labels, [int[]]$Values, [string[]]$Colors)
        if (($Values | Measure-Object -Sum).Sum -gt 0) {
            $pies.Add("<div><div class='pie-chart-title'>$(ConvertTo-HtmlSafe $Title)</div>$(Get-SvgPieChart -Labels $Labels -Values $Values -Colors $Colors -CenterLabel $Center)</div>")
        }
    }
    if ($users.Count -and -not $failed.ContainsKey('users')) {
        $disabled = @($users | Where-Object { -not $_.enabled }).Count
        $guests = @($users | Where-Object { $_.enabled -and $_.userType -eq 'Guest' }).Count
        $members = @($users | Where-Object { $_.enabled -and $_.userType -ne 'Guest' }).Count
        & $add 'Users by type' 'users' @('Members', 'Guests', 'Disabled') @($members, $guests, $disabled) @('#2B2925', '#F2B632', '#D3CCBD')
        $synced = @($users | Where-Object { $_.onPremSync }).Count
        & $add 'Users by origin' 'users' @('Cloud-only', 'Synced from on-premises AD') @(($users.Count - $synced), $synced) @('#2B2925', '#8F887C')
        if (-not $failed.ContainsKey('mfaRegistration')) {
            $en = @($users | Where-Object { $_.enabled })
            $reg = @($en | Where-Object { $_.mfaRegistered -eq $true }).Count
            $none = @($en | Where-Object { $_.mfaRegistered -eq $false }).Count
            & $add 'MFA registration (enabled users)' 'users' @('MFA registered', 'No MFA method', 'Unknown') @($reg, $none, ($en.Count - $reg - $none)) @('#2B2925', '#E2372A', '#D3CCBD')
        }
        if (-not $failed.ContainsKey('signInActivity') -and $script:RefDate) {
            $r = 0; $i = 0; $n = 0
            foreach ($u in @($users | Where-Object { $_.enabled })) {
                $age = $null; try { if ($u.lastSignIn) { $age = [int][Math]::Floor(($script:RefDate - ([datetime]$u.lastSignIn).ToUniversalTime()).TotalDays) } } catch { }
                if ($null -eq $age) { $n++ } elseif ($age -gt 90) { $i++ } else { $r++ }
            }
            & $add 'Enabled users by sign-in activity' 'users' @('Signed in within 90d', 'Inactive 90d+', 'Never / unknown') @($r, $i, $n) @('#2B2925', '#8F887C', '#D3CCBD')
        }
    }
    if (-not $failed.ContainsKey('directoryRoles')) {
        $labels = @(); $vals = @()
        foreach ($r in @($Snapshot.directoryRoles | Where-Object { $_ -and $script:EntraPrivRoleTemplates.ContainsKey("$($_.roleTemplateId)") })) {
            $c = @($r.members | Where-Object { $_ }).Count
            if ($c -gt 0) { $labels += $script:EntraPrivRoleTemplates["$($r.roleTemplateId)"]; $vals += $c }
        }
        if ($labels.Count) { & $add 'Privileged role assignments' 'assignments' $labels $vals @($ramp[0..([Math]::Min($labels.Count, $ramp.Count) - 1)]) }
    }
    if (-not $failed.ContainsKey('servicePrincipals')) {
        $own = "$($Snapshot.meta.tenantId)"
        $sps = @($Snapshot.servicePrincipals | Where-Object { $_ })
        $mi = @($sps | Where-Object { "$($_.type)" -eq 'ManagedIdentity' }).Count
        $mine = @($sps | Where-Object { "$($_.type)" -ne 'ManagedIdentity' -and $own -and "$($_.appOwnerTenant)" -eq $own }).Count
        & $add 'Service principals' 'principals' @('Managed identities', 'Owned by this tenant', 'Microsoft / third party') @($mi, $mine, ($sps.Count - $mi - $mine)) @('#78726A', '#2B2925', '#D3CCBD')
    }
    if (-not $pies.Count) { return '' }
    return "<div class='chart-row'>$($pies -join '')</div>"
}

# A few facts about the tenant, from what was collected.
function Get-EntraGlanceHtml {
    param($Snapshot)
    $failed = @{}; foreach ($e in @($Snapshot.meta.collectionErrors | Where-Object { $_ })) { $failed["$($e.section)"] = $true }
    $rows = New-Object System.Collections.Generic.List[string]
    $row = { param([string]$k, [string]$v) $rows.Add("<tr><th style='text-align:left'>$(ConvertTo-HtmlSafe $k)</th><td>$(ConvertTo-HtmlSafe $v)</td></tr>") }
    if ($Snapshot.org) { & $row 'Directory sync' $(if ($Snapshot.org.onPremisesSyncEnabled) { 'enabled (hybrid)' } else { 'cloud only' }) }
    if (-not $failed.ContainsKey('domains') -and @($Snapshot.domains | Where-Object { $_ }).Count) {
        $d = @($Snapshot.domains | Where-Object { $_ })
        & $row 'Domains' "$($d.Count) ($(@($d | Where-Object { $_.isVerified }).Count) verified)"
    }
    if (-not $failed.ContainsKey('securityDefaults') -and $null -ne $Snapshot.securityDefaults) { & $row 'Security defaults' $(if ($Snapshot.securityDefaults -eq $true) { 'on' } else { 'off' }) }
    if (-not $failed.ContainsKey('conditionalAccess')) {
        $ca = @($Snapshot.conditionalAccess | Where-Object { $_ })
        & $row 'Conditional Access policies' "$($ca.Count) ($(@($ca | Where-Object { "$($_.state)" -eq 'enabled' }).Count) enabled)"
    }
    if ([bool]$Snapshot.PSObject.Properties['licenses'] -and -not $failed.ContainsKey('licenses')) {
        $plans = @($Snapshot.licenses | Where-Object { $_ } | ForEach-Object { @($_.plans) })
        $tier = if ($plans -match '^AAD_PREMIUM_P2') { 'P2' } elseif ($plans -match '^AAD_PREMIUM') { 'P1' } else { 'none (free)' }
        & $row 'Entra ID licence' "$tier, $(@($Snapshot.licenses | Where-Object { $_ }).Count) subscription(s)"
    }
    if (-not $failed.ContainsKey('applications') -and [bool]$Snapshot.PSObject.Properties['applications']) { & $row 'App registrations' "$(@($Snapshot.applications | Where-Object { $_ }).Count)" }
    if (-not $rows.Count) { return '' }
    return "<details open><summary><h2>Tenant at a glance</h2></summary><div class='table-wrap'><table>$($rows -join '')</table></div></details>"
}

function ConvertTo-EntraReportHtml {
    param($Snapshot, $Findings, $Score, $NotEvaluated, [string]$ToolVersion, [string]$ElapsedText, $AiResult = $null)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    $sevOrder = @('Critical', 'High', 'Medium', 'Low')
    $counts = @{}; foreach ($s in $sevOrder) { $counts[$s] = @($Findings | Where-Object { $_.Severity -eq $s }).Count }
    $collected = ConvertTo-UtcDate $Snapshot.meta.collectedAtUtc
    $tenant = if ($Snapshot.org) { $Snapshot.org.displayName } else { $Snapshot.meta.tenantId }

    & $w '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<title>IDWolf Entra report - $(& $H $tenant)</title>"
    & $w (Get-IDWolfReportCss)
    & $w "<h1 class=`"title`">$(Get-WolfLogoHtml)<span>IDWolf: Entra ID Hygiene Report</span></h1>"
    & $w "<div class=`"meta`">Tenant <b>$(& $H $tenant)</b> ($(& $H $Snapshot.meta.tenantId)) &middot; snapshot $(& $H $collected.ToString('yyyy-MM-dd HH:mm')) UTC &middot; IDWolf v$ToolVersion &middot; analysis $ElapsedText</div>"
    if ($Snapshot.meta.synthetic) { & $w '<blockquote>Synthetic snapshot for testing. No real tenant data.</blockquote>' }
    & $w (Get-ReportTabsHtml)

    # ---------------- Dashboard ----------------
    & $w '<section id="tab-dashboard" class="tab-pane" role="tabpanel">'
    $kicker = "$(& $H $tenant) &middot; $(@($Snapshot.users).Count) users &middot; $(@($Snapshot.servicePrincipals).Count) service principals"
    & $w (ConvertTo-ScoreHeroHtml -Score $Score -Findings $Findings -CheckTotal $script:EntraCheckCatalog.Count -NotEvaluatedCount @($NotEvaluated).Count -Kicker $kicker)
    if (@($NotEvaluated).Count -gt 0) {
        & $w '<blockquote class="warn"><b>Incomplete coverage.</b> These checks were not evaluated:<ul>'
        foreach ($n in $NotEvaluated) { & $w "<li><code>$($n.Type)</code> $(& $H $n.Title): $(& $H $n.Reason)</li>" }
        & $w '</ul></blockquote>'
    }
    if ($AiResult) { & $w (ConvertTo-AiSectionHtml -AiResult $AiResult) }
    if (Get-Command Get-CheckControls -ErrorAction SilentlyContinue) {
        try { & $w (ConvertTo-FrameworkCardsHtml -Catalog $script:EntraCheckCatalog -Findings $Findings -NotEvaluated $NotEvaluated) }
        catch { Write-Warning "Framework cards skipped: $($_.Exception.Message)" }
    }
    & $w (ConvertTo-CategoryTilesHtml -Catalog $script:EntraCheckCatalog -Findings $Findings -NotEvaluated $NotEvaluated)
    & $w (ConvertTo-TopRisksHtml -Catalog $script:EntraCheckCatalog -Findings $Findings)
    & $w '<details open><summary><h2>Tenant charts</h2></summary>'
    & $w (Get-EntraChartsRow -Findings $Findings)
    & $w (Get-EntraInfoChartsRow -Snapshot $Snapshot)
    & $w '</details>'
    & $w (Get-EntraGlanceHtml -Snapshot $Snapshot)
    & $w '</section>'

    # ---------------- Details ----------------
    & $w '<section id="tab-details" class="tab-pane" role="tabpanel">'
    if (Get-Command ConvertTo-ComplianceHtml -ErrorAction SilentlyContinue) {
        try { & $w (ConvertTo-ComplianceHtml -Catalog $script:EntraCheckCatalog -Findings $Findings -NotEvaluated $NotEvaluated) }
        catch { Write-Warning "Regulatory mapping skipped: $($_.Exception.Message)" }
    }

    & $w '<details open><summary><h2>Findings by check</h2></summary>'
    if (@($Findings).Count -eq 0) { & $w '<p>No findings.</p>' }
    $byType = $Findings | Group-Object Type
    $typeRows = @($byType | ForEach-Object {
            $worst = ($_.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
            [PSCustomObject]@{ Type = $_.Name; Worst = $worst; Items = $_.Group; Rank = $script:SeverityRank[$worst] }
        } | Sort-Object @{ Expression = 'Rank'; Descending = $true }, @{ Expression = { $_.Items.Count }; Descending = $true }, @{ Expression = { Get-CheckPosition $_.Type } })
    foreach ($t in $typeRows) {
        $meta = $script:EntraCheckCatalog[$t.Type]; $n = @($t.Items).Count
        & $w "<details class=`"check`" id=`"chk-$($t.Type)`"><summary>$(Get-SevPill $t.Worst)<span class=`"check-title`">$(& $H $meta.Title)</span><span class=`"check-id`">$($t.Type) &middot; $(& $H $meta.Category)</span><span class=`"count`">$n</span></summary><div class=`"body`">"
        & $w "<div class=`"kv`"><b>Why it matters.</b> $(& $H $meta.Description)</div>"
        & $w "<div class=`"kv`"><b>Remediation.</b> $(& $H $meta.Remediation)</div>"
        $attack = Format-CheckAttackHtml $t.Type $meta; if ($attack) { & $w $attack }
        if (Get-Command Format-CheckControls -ErrorAction SilentlyContinue) { & $w "<div class=`"kv`"><b>Regulatory controls.</b> $(& $H (Format-CheckControls $t.Type))</div>" }
        & $w '<div class="table-wrap"><table><tr><th>Severity</th><th>Object</th><th>Detail</th></tr>'
        foreach ($f in ($t.Items | Sort-Object { - $script:SeverityRank[$_.Severity] }, Object)) {
            & $w "<tr class=`"data-row`"><td>$(Get-SevPill $f.Severity)</td><td><b>$(& $H $f.Object)</b></td><td>$(& $H $f.Detail)</td></tr>"
        }
        & $w '</table></div></div></details>'
    }
    & $w '</details></section>'
    & $w '<p class="meta" style="margin-top:32px">Generated by IDWolf from a read-only Entra ID snapshot. Handle as confidential.</p></body></html>'
    return $sb.ToString()
}

# --------------------------------------------------------------------------
# AI helpers: tokenize UPNs, display names, IDs and the tenant.
# --------------------------------------------------------------------------
function New-EntraPseudonymizer {
    param($Snapshot)
    $pz = [PSCustomObject]@{
        Forward = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
        Reverse = @{}; Counters = @{}; Ordered = $null; DomainSuffixes = @()
    }
    $add = {
        param([string]$Value, [string]$Prefix)
        if (-not $Value -or $Value.Length -lt 3) { return }
        if ($pz.Forward.ContainsKey($Value)) { return }
        if (-not $pz.Counters.ContainsKey($Prefix)) { $pz.Counters[$Prefix] = 0 }
        $pz.Counters[$Prefix]++
        $pz.Forward[$Value] = "$Prefix-$($pz.Counters[$Prefix])"; $pz.Reverse["$Prefix-$($pz.Counters[$Prefix])"] = $Value
    }
    if ($Snapshot.org) { & $add $Snapshot.org.displayName 'TENANT' }
    & $add $Snapshot.meta.tenantId 'TENANTID'
    $suffixes = New-Object System.Collections.Generic.List[string]
    foreach ($u in @($Snapshot.users | Where-Object { $_ })) {
        & $add $u.upn 'UPN'; & $add $u.displayName 'USER'
        if ($u.upn -match '@(.+)$') { if (-not $suffixes.Contains($Matches[1])) { $suffixes.Add($Matches[1]) } }
    }
    foreach ($a in @($Snapshot.applications | Where-Object { $_ })) { & $add $a.displayName 'APP'; & $add $a.appId 'APPID' }
    foreach ($sp in @($Snapshot.servicePrincipals | Where-Object { $_ })) { & $add $sp.displayName 'SP'; & $add $sp.appId 'APPID'; & $add $sp.id 'SPID' }
    foreach ($p in @($Snapshot.conditionalAccess | Where-Object { $_ })) { & $add $p.displayName 'CAPOLICY' }
    foreach ($g in @($Snapshot.groups | Where-Object { $_ })) { & $add $g.displayName 'GROUP'; & $add $g.id 'GROUPID' }
    # Verified domains can differ from the UPN suffixes (and show up in findings).
    foreach ($d in @($Snapshot.domains | Where-Object { $_ })) { & $add "$($d.id)" 'DOMAIN'; if ($d.id -and -not $suffixes.Contains("$($d.id)")) { $suffixes.Add("$($d.id)") } }
    foreach ($l in @($Snapshot.namedLocations | Where-Object { $_ })) { & $add $l.displayName 'LOCATION' }
    foreach ($r in @($Snapshot.accessReviews | Where-Object { $_ })) { & $add $r.displayName 'REVIEW' }
    foreach ($p in @($Snapshot.accessPackages | Where-Object { $_ })) { & $add $p.accessPackage 'PACKAGE'; & $add $p.displayName 'PACKAGEPOLICY' }
    foreach ($c in @($Snapshot.entitlementCatalogs | Where-Object { $_ })) { & $add $c.displayName 'CATALOG' }
    # Intune assignment names and custom role names are chosen by the tenant; built-in role names stay.
    foreach ($ia in @($Snapshot.intuneRoles | Where-Object { $_ })) { & $add $ia.displayName 'INTUNEASSIGNMENT'; if (-not $ia.isBuiltIn) { & $add $ia.roleName 'INTUNEROLE' } }
    # Hosts in app redirect URIs end up in findings too.
    foreach ($a in @($Snapshot.applications | Where-Object { $_ })) {
        foreach ($u in @($a.redirectUris | Where-Object { $_ })) { if ("$u" -match '^[a-z][a-z0-9+.\-]*://([^/:?#]+)') { if ($Matches[1] -notmatch '^(localhost|127\.0\.0\.1)$') { & $add $Matches[1] 'HOST' } } }
    }
    $pz.DomainSuffixes = @($suffixes | Sort-Object { $_.Length } -Descending)
    $pz.Ordered = @($pz.Forward.Keys | Sort-Object { $_.Length } -Descending)
    return $pz
}

function Protect-EntraText {
    param($Pz, [string]$Text)
    if (-not $Text) { return $Text }
    $out = $Text
    $out = [regex]::Replace($out, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', { param($m) if ($Pz.Forward.ContainsKey($m.Value)) { $Pz.Forward[$m.Value] } else { Get-AiToken $Pz $m.Value 'GUID' } })
    # Longest names first, so a full UPN goes before its domain suffix.
    foreach ($k in $Pz.Ordered) {
        $out = [regex]::Replace($out, '(?<![\w.\-@])' + [regex]::Escape($k) + '(?![\w\-])', $Pz.Forward[$k], 'IgnoreCase')
    }
    foreach ($suffix in $Pz.DomainSuffixes) {
        $fq = '(?i)(?<![\w.\-])(?:[a-z0-9\-_]+\.)*' + [regex]::Escape($suffix)
        $out = [regex]::Replace($out, $fq, { param($m) if ($Pz.Forward.ContainsKey($m.Value)) { $Pz.Forward[$m.Value] } else { Get-AiToken $Pz $m.Value 'DOMAINFQDN' } })
    }
    return $out
}
function Test-EntraLeak {
    param($Pz, [string]$Text)
    $leaks = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Pz.Ordered) { if ($k.Length -lt 4) { continue }; if ($Text.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $leaks.Add($k); if ($leaks.Count -ge 10) { break } } }
    foreach ($s in $Pz.DomainSuffixes) { if ($Text.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $leaks.Add($s) } }
    return $leaks
}

function New-EntraAiPrompt {
    param($Findings, $Pz, $Snapshot, $Score)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Microsoft Entra ID tenant hygiene. Tenant: $(Protect-EntraText $Pz $(if ($Snapshot.org) { $Snapshot.org.displayName } else { 'tenant' })). Hygiene score: $(if ($Score.Reliable -eq $false) { "not reliable, only $($Score.Coverage)% of the checks were evaluated" } else { "$($Score.Score)/100" }).")
    $lines.Add("Users: $(@($Snapshot.users).Count). Service principals: $(@($Snapshot.servicePrincipals).Count). Security defaults: $($Snapshot.securityDefaults).")
    $lines.Add('')
    $lines.Add('Findings grouped by check:')
    $groups = $Findings | Group-Object Type | Sort-Object { - ($_.Group | ForEach-Object { $script:SeverityRank[$_.Severity] } | Measure-Object -Maximum).Maximum }, Count, { Get-CheckPosition $_.Name }
    foreach ($g in $groups) {
        $meta = $script:EntraCheckCatalog[$g.Name]
        $worst = ($g.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
        $lines.Add("## [$worst] $($g.Name): $($meta.Title) ($($g.Count))")
        foreach ($f in ($g.Group | Select-Object -First 12)) { $lines.Add("- [$($f.Severity)] $(Protect-EntraText $Pz $f.Object): $(Protect-EntraText $Pz $f.Detail)") }
    }
    if (Get-Command Get-AiRecentVectorLines -ErrorAction SilentlyContinue) { foreach ($vl in (Get-AiRecentVectorLines -Findings $Findings)) { $lines.Add($vl) } }
    return ($lines -join "`n")
}

# CSS for the Entra report.
function Get-IDWolfReportCss {
    # Same theme and scripts as the AD report (Reporting.ps1), then the end of <head>.
    return (Get-IDWolfThemeCss) + "`n" + (Get-IDWolfReportScript) + "</head><body>`n"
}
