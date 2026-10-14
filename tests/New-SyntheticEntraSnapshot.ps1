<#
.SYNOPSIS
    Builds a synthetic IDWolf Entra snapshot (fictional tenant
    moosebank.onmicrosoft.com) with known issues, for the demo and the
    regression suite. It tests the analysis, not the Graph collector.
#>
[CmdletBinding()]
Param([string]$OutFile = '')
$ErrorActionPreference = 'Stop'
$ref = [datetime]::new(2026, 9, 30, 8, 0, 0, [DateTimeKind]::Utc)
function Iso { param($d) if ($null -eq $d) { return $null } return $ref.AddDays(-$d).ToString('o') }
function Guid5 { param($n) "{0:d8}-0000-0000-0000-000000000000" -f $n }

$GA = '62e90394-69f5-4237-9190-012177145e10'
$SEC = '194ae4cb-b126-40b2-bd5b-6091b380977d'
$APP = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'

$users = @(
    [ordered]@{ id = (Guid5 1); upn = 'alice.ceo@moosebank.onmicrosoft.com'; displayName = 'Alice CEO'; enabled = $true; userType = 'Member'; onPremSync = $false; createdDateTime = (Iso 900); lastSignIn = (Iso 1); mfaRegistered = $true; mfaCapable = $true; licenses = @('sku-e5'); lastPasswordChange = (Iso 500); mfaMethods = @('microsoftAuthenticatorPush', 'fido2') }
    [ordered]@{ id = (Guid5 2); upn = 'bob.admin@moosebank.onmicrosoft.com'; displayName = 'Bob Admin'; enabled = $true; userType = 'Member'; onPremSync = $false; createdDateTime = (Iso 800); lastSignIn = (Iso 2); mfaRegistered = $false; mfaCapable = $false; licenses = @('sku-p2'); lastPasswordChange = (Iso 30); mfaMethods = @('sms') }
    [ordered]@{ id = (Guid5 3); upn = 'carol.sec@moosebank.onmicrosoft.com'; displayName = 'Carol Sec'; enabled = $true; userType = 'Member'; onPremSync = $false; createdDateTime = (Iso 700); lastSignIn = (Iso 3); mfaRegistered = $false; mfaCapable = $false; licenses = @(); lastPasswordChange = (Iso 60); mfaMethods = @() }
    [ordered]@{ id = (Guid5 4); upn = 'ext.partner_gmail.com#EXT#@moosebank.onmicrosoft.com'; displayName = 'External Partner'; enabled = $true; userType = 'Guest'; onPremSync = $false; createdDateTime = (Iso 500); lastSignIn = (Iso 400); mfaRegistered = $true; mfaCapable = $true; licenses = @() }
    # Synced from on-premises and holding an admin role.
    [ordered]@{ id = (Guid5 5); upn = 'dave.appadmin@moosebank.onmicrosoft.com'; displayName = 'Dave AppAdmin'; enabled = $true; userType = 'Member'; onPremSync = $true; createdDateTime = (Iso 600); lastSignIn = (Iso 5); mfaRegistered = $true; mfaCapable = $true; licenses = @(); lastPasswordChange = (Iso 90); mfaMethods = @('microsoftAuthenticatorPush') }
)
for ($i = 6; $i -le 25; $i++) { $users += [ordered]@{ id = (Guid5 $i); upn = "user$i@moosebank.onmicrosoft.com"; displayName = "User $i"; enabled = $true; userType = 'Member'; onPremSync = $true; createdDateTime = (Iso 500); lastSignIn = (Iso ($i)); mfaRegistered = $true; mfaCapable = ($i -notin 7, 8); licenses = @() } }   # user7, user8 can't do MFA
$users += [ordered]@{ id = (Guid5 30); upn = 'old.guest_outlook.com#EXT#@moosebank.onmicrosoft.com'; displayName = 'Old Guest'; enabled = $true; userType = 'Guest'; onPremSync = $false; createdDateTime = (Iso 500); lastSignIn = (Iso 300); mfaRegistered = $false; mfaCapable = $false; licenses = @() }

$roles = @(
    [ordered]@{ id = (Guid5 100); displayName = 'Global Administrator'; roleTemplateId = $GA; members = @((Guid5 1), (Guid5 2), (Guid5 4)); memberTypes = [ordered]@{ (Guid5 1) = 'user'; (Guid5 2) = 'user'; (Guid5 4) = 'user' } }  # bob has no MFA, 4 is a guest
    [ordered]@{ id = (Guid5 101); displayName = 'Security Administrator'; roleTemplateId = $SEC; members = @((Guid5 3), (Guid5 400), (Guid5 702)); memberTypes = [ordered]@{ (Guid5 3) = 'user'; (Guid5 400) = 'servicePrincipal'; (Guid5 702) = 'group' } }               # carol has no MFA
    [ordered]@{ id = (Guid5 102); displayName = 'Application Administrator'; roleTemplateId = $APP; members = @((Guid5 5)); memberTypes = [ordered]@{ (Guid5 5) = 'user' } }
)

function Ca {
    param($Id, $Name, $State, $Users = @('All'), $Roles = @(), $Grant = @(), $ClientApps = @('all'), $Transfer = '', $UserRisk = @(), $SignInRisk = @(), $Strength = '', [bool]$Freq = $false, $ExclGroups = @())
    [ordered]@{ id = (Guid5 $Id); displayName = $Name; state = $State; includeUsers = $Users; excludeUsers = @(); excludeGroups = $ExclGroups; includeGroups = @(); includeRoles = $Roles; includeApplications = @('All')
        includeUserActions = @(); includeLocations = @(); excludeLocations = @()
        clientAppTypes = $ClientApps; userRiskLevels = $UserRisk; signInRiskLevels = $SignInRisk; transferMethods = $Transfer; grantControls = $Grant; authStrengthId = $Strength
        signInFrequency = $Freq; signInFrequencyInterval = ''; persistentBrowser = ''; tokenProtection = $false; includeServicePrincipals = @() }
}
$ca = @(
    (Ca 200 'Report-only MFA test' 'enabledForReportingButNotEnforced' -Grant @('mfa'))
    # Device code is blocked: entra_device_code_flow_allowed must stay quiet.
    # Excludes a public M365 group a regular user owns (entra_ca_excluded_group_weak) and a sound emergency group.
    (Ca 201 'Block device code flow' 'enabled' -Grant @('block') -Transfer 'deviceCodeFlow' -ExclGroups @((Guid5 700), (Guid5 701)))
    # Sign-in risk covered for a pilot group, user risk not covered at all.
    (Ca 202 'Risky sign-ins need MFA (pilot)' 'enabled' -Users @((Guid5 10)) -Grant @('mfa') -SignInRisk @('high', 'medium'))
)

$apps = @(
    [ordered]@{ id = (Guid5 300); displayName = 'Legacy Sync App'; appId = (Guid5 3001); passwordCred = @($ref.AddDays(10).ToString('o')); keyCred = @(); secrets = @([ordered]@{ start = (Iso 720); end = $ref.AddDays(10).ToString('o') }); redirectUris = @('http://sync.moosebank-cloud.example/callback'); signInAudience = 'AzureADMultipleOrgs'; instanceLock = $false }
    [ordered]@{ id = (Guid5 301); displayName = 'Reporting App'; appId = (Guid5 3011); passwordCred = @($ref.AddDays(-5).ToString('o')); keyCred = @(); secrets = @([ordered]@{ start = (Iso 100); end = $ref.AddDays(-5).ToString('o') }); redirectUris = @(); signInAudience = 'AzureADMyOrg'; instanceLock = $false }
    # Entra Connect's provisioning app with a second certificate: entra_connect_app_extra_credentials.
    [ordered]@{ id = (Guid5 303); displayName = 'ConnectSyncProvisioning_SYNC01_8f3a2c'; appId = (Guid5 3061); passwordCred = @(); keyCred = @($ref.AddDays(200).ToString('o'), $ref.AddDays(700).ToString('o')); secrets = @(); redirectUris = @(); signInAudience = 'AzureADMyOrg'; instanceLock = $false }
    [ordered]@{ id = (Guid5 302); displayName = 'Healthy App'; appId = (Guid5 3021); passwordCred = @($ref.AddDays(150).ToString('o')); keyCred = @(); secrets = @([ordered]@{ start = (Iso 20); end = $ref.AddDays(150).ToString('o') }); redirectUris = @('https://app.moosebank-cloud.example/signin', 'http://localhost:8080'); signInAudience = 'AzureADMyOrg'; instanceLock = $false }
)
$servicePrincipals = @(
    [ordered]@{ id = (Guid5 400); displayName = 'Backup Automation'; appId = (Guid5 3001); appOwnerTenant = ''; appRoleIds = @('9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'); passwordCred = @(); keyCred = @(); owners = @((Guid5 12), (Guid5 405)); ownerTypes = [ordered]@{ (Guid5 12) = 'user'; (Guid5 405) = 'servicePrincipal' } }  # RoleManagement.ReadWrite.Directory
    [ordered]@{ id = (Guid5 401); displayName = 'Monitoring SP'; appId = (Guid5 3011); appOwnerTenant = ''; appRoleIds = @('b0afded3-3588-46d8-8b3d-9842eff778da'); passwordCred = @(); keyCred = @() }  # AuditLog.Read.All
    [ordered]@{ id = (Guid5 403); displayName = 'Office 365 Exchange Online'; appId = (Guid5 3031); appOwnerTenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; appRoleIds = @(); passwordCred = @($ref.AddDays(300).ToString('o')); keyCred = @() }  # credential added to a Microsoft app
    [ordered]@{ id = (Guid5 404); displayName = 'Mail Helper Pro'; appId = (Guid5 3041); appOwnerTenant = '99999999-9999-9999-9999-999999999999'; appRoleIds = @(); passwordCred = @(); keyCred = @() }  # third-party app
    # Managed identity with a tenant-wide permission: workload CA can't cover it.
    [ordered]@{ id = (Guid5 405); displayName = 'func-payroll-mi'; appId = (Guid5 3051); type = 'ManagedIdentity'; appOwnerTenant = ''; appRoleIds = @('9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'); passwordCred = @(); keyCred = @() }
    # "Microsoft" spelled with a Cyrillic o: entra_sp_lookalike_name.
    [ordered]@{ id = (Guid5 406); displayName = ('Micr' + [char]0x043E + 'soft Teams Connector'); appId = (Guid5 3071); appOwnerTenant = '88888888-8888-8888-8888-888888888888'; appRoleIds = @(); passwordCred = @(); keyCred = @() }
    [ordered]@{ id = (Guid5 402); displayName = 'Benign SP'; appId = (Guid5 3021); appOwnerTenant = ''; appRoleIds = @('df021288-bdef-4463-88db-98f22de89214'); passwordCred = @(); keyCred = @() }  # User.Read.All
)

# Four principals with permanent admin roles, one eligible assignment.
function Assign { param($P, $R, $T = 'Assigned') [ordered]@{ principalId = (Guid5 $P); roleDefinitionId = $R; assignmentType = $T; endDateTime = $null } }
$pim = [ordered]@{
    active   = @((Assign 1 $GA), (Assign 2 $GA), (Assign 4 $GA), (Assign 3 $SEC))
    eligible = @((Assign 5 $APP 'Eligible'), (Assign 703 $GA 'Eligible'))
}
# Groups behind CA exclusions and admin roles: 700 and 702 are findings, 701 and 703 are sound.
function Grp { param($Id, $Name, $Vis = 'Private', [bool]$Unified = $false, [bool]$Dyn = $false, $Rule = '', [bool]$Assignable = $false, $Owners = @{})
    $ot = [ordered]@{}; foreach ($k in $Owners.Keys) { $ot[(Guid5 $k)] = $Owners[$k] }
    [ordered]@{ id = (Guid5 $Id); displayName = $Name; visibility = $Vis; unified = $Unified; dynamic = $Dyn; membershipRule = $Rule; isAssignableToRole = $Assignable; onPremSync = $false; ownerTypes = $ot } }
$groups = @(
    (Grp 700 'Project Elk team' -Vis 'Public' -Unified $true -Owners @{ 12 = 'user' })
    (Grp 701 'CA exclusion - emergency access' -Assignable $true -Owners @{ 1 = 'user' })
    (Grp 702 'Tier 2 security operators' -Assignable $true -Owners @{ 13 = 'user'; 1 = 'user' })
    (Grp 703 'PIM - Global Admins' -Assignable $true -Owners @{ 1 = 'user' })
    # Intune admin groups: 704 is a plain security group, 705 is role-assignable.
    (Grp 704 'Endpoint team' -Owners @{ 12 = 'user' })
    (Grp 705 'Intune role admins' -Assignable $true -Owners @{ 1 = 'user' })
)
$groups[3]['pimEligible'] = @([ordered]@{ principalId = (Guid5 14); accessId = 'owner' }, [ordered]@{ principalId = (Guid5 1); accessId = 'member' })
$groups[2]['pimEligible'] = @()
# PIM rules: Global Admin allows permanent assignments, Privileged Role Admin activates without MFA for 10 hours.
$pimRules = [ordered]@{
    $GA = [ordered]@{ approval = $true; mfa = $true; justification = $true; authContext = $false; maxActivation = 'PT8H'; eligibleExpiryRequired = $false; activeExpiryRequired = $false }
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = [ordered]@{ approval = $false; mfa = $false; justification = $true; authContext = $false; maxActivation = 'PT10H'; eligibleExpiryRequired = $true; activeExpiryRequired = $true }
    $SEC = [ordered]@{ approval = $false; mfa = $true; justification = $true; authContext = $false; maxActivation = 'PT4H'; eligibleExpiryRequired = $true; activeExpiryRequired = $true }
}
# Dave's Application Administrator role is also assigned scoped to an administrative unit.
$roleAssignments = @(
    [ordered]@{ principalId = (Guid5 1); roleDefinitionId = $GA; directoryScopeId = '/' }
    [ordered]@{ principalId = (Guid5 5); roleDefinitionId = $APP; directoryScopeId = '/administrativeUnits/00000800-0000-0000-0000-000000000000' }
    # Cloud Application Administrator scoped to the Legacy Sync App registration, whose service
    # principal (Backup Automation) is privileged: entra_app_scoped_admin_privileged.
    [ordered]@{ principalId = (Guid5 13); roleDefinitionId = '158c047a-c907-4556-b7ef-446551a6b5f7'; directoryScopeId = "/$(Guid5 300)" }
    # Scoped to a harmless app: no finding.
    [ordered]@{ principalId = (Guid5 15); roleDefinitionId = '158c047a-c907-4556-b7ef-446551a6b5f7'; directoryScopeId = "/$(Guid5 402)" }
)
# Backup Automation last signed in 400 days ago; the managed identity is in use.
$spSignIns = [ordered]@{ (Guid5 3001) = (Iso 400); (Guid5 3051) = (Iso 1) }
# The IT on-call package (self-request, no approval) hands out the Security Administrator group.
$accessPackageGrants = [ordered]@{
    (Guid5 650) = @([ordered]@{ originSystem = 'AadGroup'; roleOriginId = "Member_$(Guid5 702)"; scopeOriginId = (Guid5 702); roleName = 'Member' })
    (Guid5 651) = @([ordered]@{ originSystem = 'SharePointOnline'; roleOriginId = '4'; scopeOriginId = 'https://moosebank.sharepoint.example/sites/finance'; roleName = 'Members' })
}


# Intune roles: a built-in and a custom role that can push code, both given to the plain
# Endpoint team group (two findings); Intune Role Administrator on a role-assignable group and
# Read Only Operator on the plain group are fine.
function IRole { param($Id, $Assign, $Role, [bool]$BuiltIn, $Actions, $Members)
    [ordered]@{ id = (Guid5 $Id); displayName = $Assign; roleId = (Guid5 ($Id + 50)); roleName = $Role; isBuiltIn = $BuiltIn; actions = $Actions; members = @($Members | ForEach-Object { Guid5 $_ }); resourceScopes = @() } }
$intuneRoles = @(
    (IRole 900 'Endpoint team - profiles' 'Policy and Profile Manager' $true @('Microsoft.Intune_DeviceConfigurations_Assign', 'Microsoft.Intune_DeviceConfigurations_Read') @(704))
    (IRole 901 'Endpoint team - scripts' 'Workstation scripts' $false @('Microsoft.Intune_DeviceManagementScripts_Assign', 'Microsoft.Intune_DeviceManagementScripts_Read') @(704))
    (IRole 902 'Intune RBAC owners' 'Intune Role Administrator' $true @('Microsoft.Intune_Roles_Assign') @(705))
    (IRole 903 'Endpoint team - read' 'Read Only Operator' $true @('Microsoft.Intune_DeviceConfigurations_Read') @(704))
)
# Multi Admin Approval only for apps: wipes, scripts and roles need no second admin (one finding).
$intuneApprovalPolicies = @([ordered]@{ id = (Guid5 950); policyType = 'app'; policyPlatform = 'notApplicable'; approverGroupCount = 1 })
$snapshot = [ordered]@{
    meta = [ordered]@{
        tool = 'IDWolf'; kind = 'entra'; schemaVersion = 9; collectorVersion = 'synthetic'
        collectedAtUtc = $ref.ToString('o'); tenantId = '11111111-2222-3333-4444-555555555555'; account = 'auditor@moosebank.onmicrosoft.com'
        collectionErrors = @(); synthetic = $true
    }
    org = [ordered]@{ tenantId = '11111111-2222-3333-4444-555555555555'; displayName = 'MooseBank Cloud'; onPremisesSyncEnabled = $true; lastSyncUtc = (Iso 3) }
    securityDefaults = $false
    authorizationPolicy = [ordered]@{ allowedToCreateApps = $true; allowedToCreateSecurityGroups = $true; allowedToReadOtherUsers = $true; allowedToCreateTenants = $true
        permissionGrantPolicies = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy'); allowInvitesFrom = 'everyone'; guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
        allowedToReadBitlockerKeys = $true }
    consentPolicy = [ordered]@{ adminConsentRequestEnabled = $false }
    authenticationMethods = @([ordered]@{ id = 'Sms'; state = 'enabled' }, [ordered]@{ id = 'Voice'; state = 'disabled' }, [ordered]@{ id = 'Email'; state = 'enabled' }, [ordered]@{ id = 'Fido2'; state = 'enabled' })
    passwordSettings = [ordered]@{ configured = $true; enableBannedPasswordCheck = $false; bannedPasswordCount = 0; lockoutThreshold = 20; lockoutDurationInSeconds = 30 }
    pim = $pim
    # Global Admin activation needs approval, Privileged Role Admin doesn't.
    pimPolicies = [ordered]@{ $GA = $true; 'e8611ab8-c189-46e8-94e1-60213ab1f814' = $false }
    # Authenticator on, app name shown but not location; system-preferred off; Authenticator Lite left at default.
    authenticatorSettings = [ordered]@{ systemPreferred = 'disabled'; authenticatorState = 'enabled'; showAppName = 'enabled'; showLocation = 'default'; companionApp = 'default' }
    groupCreation = [ordered]@{ m365GroupCreationAllowed = $true }
    deviceRegistration = [ordered]@{ userDeviceQuota = 50; joinAllowedFor = 'all'; globalAdminsAreLocalAdmins = $true; registeringUsersLocalAdmin = 'all'; lapsEnabled = $false }
    appManagementPolicy = [ordered]@{ isEnabled = $false; passwordRestrictions = @(); keyRestrictions = @() }
    # The onmicrosoft domain never expires passwords; the custom domain still does.
    domains = @([ordered]@{ id = 'moosebank.onmicrosoft.com'; isVerified = $true; authenticationType = 'Managed'; passwordValidityDays = 2147483647 }
        [ordered]@{ id = 'moosebank-cloud.example'; isVerified = $true; authenticationType = 'Managed'; passwordValidityDays = 90 }
        [ordered]@{ id = 'moosebank.example'; isVerified = $true; authenticationType = 'Federated'; passwordValidityDays = $null; federatedIdpMfaBehavior = 'acceptIfMfaDoneByFederatedIdp' })
    idleTimeout = [ordered]@{ policyCount = 0 }
    branding = [ordered]@{ configured = $false; hideKeepMeSignedIn = $false }
    onPremSync = [ordered]@{ syncEnabled = $true; passwordHashSync = $false }
    # Guests are reviewed, admin roles aren't.
    accessReviews = @([ordered]@{ displayName = 'Quarterly guest review'; status = 'InProgress'; scope = '{"query":"/users?$filter=(userType eq ''Guest'')"}' })
    # An office range is trusted; a country list exists but no policy blocks with it.
    namedLocations = @([ordered]@{ id = (Guid5 500); displayName = 'MooseBank HQ egress'; type = 'ip'; isTrusted = $true }
        [ordered]@{ id = (Guid5 501); displayName = 'Countries we never sign in from'; type = 'country'; isTrusted = $false })
    licenses = @([ordered]@{ skuId = 'sku-e5'; name = 'SPE_E5'; plans = @('EXCHANGE_S_ENTERPRISE', 'TEAMS1', 'AAD_PREMIUM_P2') }
        [ordered]@{ skuId = 'sku-p2'; name = 'AAD_PREMIUM_P2'; plans = @('AAD_PREMIUM_P2') })
    # Bob still has the old per-user MFA enforced.
    # Two users consented a third-party app to read their mail; an admin consented a harmless one.
    oauthGrants = @([ordered]@{ clientId = (Guid5 404); consentType = 'Principal'; principalId = (Guid5 9); scope = 'Mail.Read offline_access' }
        [ordered]@{ clientId = (Guid5 404); consentType = 'Principal'; principalId = (Guid5 11); scope = 'Mail.Read offline_access' }
        [ordered]@{ clientId = (Guid5 401); consentType = 'AllPrincipals'; principalId = ''; scope = 'User.Read openid' })
    # Direct connect opened inbound only.
    crossTenant = [ordered]@{ mfaAccepted = $true; compliantDeviceAccepted = $false; hybridJoinAccepted = $false; directConnectInbound = 'allowed'; directConnectOutbound = 'blocked' }
    # One package open to any external user without approval, one internal that
    # never expires, one done right (approval, expiry): two findings.
    accessPackages = @([ordered]@{ id = (Guid5 600); displayName = 'Partner self-service'; accessPackage = 'Project Elk partners'; allowedTargetScope = 'allExternalUsers'; selfAddEnabled = $true; approvalRequired = $false; expirationType = 'afterDuration'; reviewEnabled = $false }
        [ordered]@{ id = (Guid5 603); displayName = 'IT on-call self-service'; accessPackage = 'IT on-call'; accessPackageId = (Guid5 650); allowedTargetScope = 'allMemberUsers'; selfAddEnabled = $true; approvalRequired = $false; expirationType = 'afterDuration'; reviewEnabled = $true }
        [ordered]@{ id = (Guid5 601); displayName = 'Finance staff'; accessPackage = 'Finance share'; accessPackageId = (Guid5 651); allowedTargetScope = 'allMemberUsers'; selfAddEnabled = $true; approvalRequired = $true; expirationType = 'noExpiration'; reviewEnabled = $false }
        [ordered]@{ id = (Guid5 602); displayName = 'Vetted vendors'; accessPackage = 'Vendor portal'; allowedTargetScope = 'specificConnectedOrganizationUsers'; selfAddEnabled = $true; approvalRequired = $true; expirationType = 'afterDuration'; reviewEnabled = $true })
    perUserMfa = [ordered]@{ (Guid5 1) = 'disabled'; (Guid5 2) = 'enforced' }
    conditionalAccess = $ca
    groups = $groups
    pimRules = $pimRules
    roleAssignments = $roleAssignments
    spSignIns = $spSignIns
    accessPackageGrants = $accessPackageGrants
    intuneRoles = $intuneRoles
    intuneApprovalPolicies = $intuneApprovalPolicies
    directoryRoles = $roles
    users = $users
    applications = $apps
    servicePrincipals = $servicePrincipals
}

if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot '..\examples\synthetic_entra.json' }
$json = $snapshot | ConvertTo-Json -Depth 8
$full = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path (Get-Location).Path $OutFile }
[System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Synthetic Entra snapshot: $full  users=$($users.Count) roles=$($roles.Count) SPs=$($servicePrincipals.Count)"
