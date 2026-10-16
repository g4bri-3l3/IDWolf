<#
.SYNOPSIS
    IDWolf Entra ID collector: a read-only tenant snapshot through Microsoft Graph.

.DESCRIPTION
    The cloud counterpart of Collect-ADSnapshot.ps1. Only GET requests with
    read scopes:
      Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory,
      Application.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All,
      Policy.Read.DeviceConfiguration, AccessReview.Read.All,
      OnPremDirectorySynchronization.Read.All, RoleManagementPolicy.Read.Directory,
      EntitlementManagement.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup,
      DeviceManagementRBAC.Read.All
    Global Reader is enough. PIM data needs Entra ID P2; sign-in activity
    needs P1; Intune roles need an Intune licence.

    Not yet run against a real tenant: check the output the first time.
    Sections that fail are recorded and their checks show as "not evaluated".

.PARAMETER OutFile
    Snapshot path. Default: output\entrasnapshot_<tenant>_<timestamp>.json
.PARAMETER TenantId
    Optional tenant id to connect to.
.PARAMETER MaxUsers
    Cap on users pulled (default 0 = all). Useful for a quick first run.
.PARAMETER UseDeviceCode
    Sign in with a code on another device (servers without a browser).
.PARAMETER InstallModules
    Install Microsoft.Graph.Authentication for the current user if missing.
.PARAMETER ClientId
    Unattended runs: app registration id. Needs -TenantId and
    -CertificateThumbprint. Give the app the same permissions as application
    permissions (read-only), with admin consent.
.PARAMETER CertificateThumbprint
    Certificate of that app, in the CurrentUser or LocalMachine store of the
    account that runs the collector. No client secrets: they end up in scripts.

.EXAMPLE
    .\Collect-EntraSnapshot.ps1                       # opens the Microsoft sign-in page
.EXAMPLE
    .\Collect-EntraSnapshot.ps1 -TenantId contoso.onmicrosoft.com -UseDeviceCode
.EXAMPLE
    .\Collect-EntraSnapshot.ps1 -TenantId <tenant> -ClientId <app id> -CertificateThumbprint <thumbprint>   # unattended
#>

[CmdletBinding()]
Param(
    [string]$OutFile = "",
    [string]$TenantId = "",
    [int]$MaxUsers = 0,
    [switch]$UseDeviceCode,
    [switch]$InstallModules,
    [string]$ClientId = "",
    [string]$CertificateThumbprint = ""
)

$ErrorActionPreference = 'Stop'
$script:CollectorVersion = "1.4"
$script:Errors = New-Object System.Collections.Generic.List[object]
function Add-CollectionError {
    param([string]$Section, [string]$Message)
    $script:Errors.Add([PSCustomObject]@{ section = $Section; message = $Message })
    Write-Warning "[$Section] $Message"
}
function IsoUtc { param($v) if ($null -eq $v -or "$v" -eq '') { return $null }; try { return ([datetime]$v).ToUniversalTime().ToString('o') } catch { return "$v" } }

# Only the authentication module is needed (the rest is plain REST). Offer it if missing.
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    $want = [bool]$InstallModules
    if (-not $want) {
        $interactive = $false; try { $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected } catch { }
        if ($interactive) { $want = ((Read-Host "Microsoft.Graph.Authentication not found. Install it now (current user, no admin needed)? (y/N)") -match '^[YySs]') }
    }
    if ($want) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
        }
        catch { Write-Host "Install failed: $("$($_.Exception.Message)".Trim())" -ForegroundColor Red }
    }
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "Microsoft.Graph.Authentication not available. Install-Module Microsoft.Graph.Authentication -Scope CurrentUser (or re-run with -InstallModules)." -ForegroundColor Red
        exit 1
    }
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$scopes = 'Directory.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All',
    'Policy.Read.DeviceConfiguration', 'AccessReview.Read.All', 'OnPremDirectorySynchronization.Read.All', 'RoleManagementPolicy.Read.Directory',
    'EntitlementManagement.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'DeviceManagementRBAC.Read.All'
$ctx = $null
try { $ctx = Get-MgContext } catch { }
if ($ClientId) {
    if (-not $TenantId -or -not $CertificateThumbprint) { Write-Host "-ClientId needs -TenantId and -CertificateThumbprint." -ForegroundColor Red; exit 1 }
    # App-only: the permissions are the ones granted to the app, not scopes.
    Write-Host "Signing in to Microsoft Graph as app $ClientId (certificate)..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    $ctx = Get-MgContext
}
elseif (-not $ctx) {
    # Interactive sign-in with read-only scopes. The first time in a tenant an
    # admin has to consent to these for "Microsoft Graph Command Line Tools".
    Write-Host "Signing in to Microsoft Graph (read-only scopes)..." -ForegroundColor Cyan
    $cp = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId) { $cp['TenantId'] = $TenantId }
    if ($UseDeviceCode) { $cp['UseDeviceCode'] = $true }
    Connect-MgGraph @cp
    $ctx = Get-MgContext
}
if (-not $ctx) { Write-Host "Not connected to Microsoft Graph." -ForegroundColor Red; exit 1 }
# A delegated session started elsewhere may lack some scopes: say which, up front.
if ("$($ctx.AuthType)" -ne 'AppOnly') {
    $missing = @($scopes | Where-Object { @($ctx.Scopes) -notcontains $_ })
    if ($missing.Count) { Write-Host "This session lacks: $($missing -join ', '). The sections that need them will be 'not evaluated'. Disconnect-MgGraph and re-run to sign in with all scopes." -ForegroundColor Yellow }
}
Write-Host "IDWolf Entra collector v$script:CollectorVersion (read-only). Tenant: $($ctx.TenantId)  Account: $($ctx.Account)" -ForegroundColor Yellow

# Plain REST calls, so only Microsoft.Graph.Authentication is needed.
function Get-Graph {
    param([string]$Uri, [switch]$All)
    $base = "https://graph.microsoft.com/v1.0"
    if ($Uri -match '^https?://') { $full = $Uri } else { $full = "$base/$($Uri.TrimStart('/'))" }
    $items = New-Object System.Collections.Generic.List[object]
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $full -OutputType PSObject
        # A collection always has 'value', even when it's empty: an empty list
        # must come back empty, not as the response envelope (that once made
        # "no idle timeout policy" count as one).
        if ($null -eq $resp.PSObject.Properties['value']) { return $resp }
        foreach ($v in @($resp.value)) { $items.Add($v) }
        $full = $resp.'@odata.nextLink'
    } while ($All -and $full)
    return $items
}
# Azure AD Graph, the API Microsoft retired in favour of Microsoft Graph.
$script:AadGraphAppId = '00000002-0000-0000-c000-000000000000'

# --------------------------------------------------------------------------
$org = $null
try {
    $o = Get-Graph 'organization'
    $o = @($o)[0]
    $org = [ordered]@{ tenantId = $o.id; displayName = $o.displayName; onPremisesSyncEnabled = [bool]$o.onPremisesSyncEnabled; lastSyncUtc = IsoUtc $o.onPremisesLastSyncDateTime }
}
catch { Add-CollectionError 'organization' $_.Exception.Message }

# No tenant means no directory to audit: nearly every section would fail and the snapshot would be empty.
# A personal Microsoft account (outlook.com, hotmail.com) is the usual cause: it has no Entra directory.
$consumerTenant = '9188040d-6c67-4c5b-b112-36a304b66dad'
if (-not $org -and (-not $ctx.TenantId -or "$($ctx.TenantId)" -eq $consumerTenant)) {
    Write-Host "Could not read the tenant: the session isn't tied to an Entra ID directory (tenant '$($ctx.TenantId)', account '$($ctx.Account)')." -ForegroundColor Red
    Write-Host "A personal Microsoft account (outlook.com, hotmail.com...) has no directory to audit. Sign in with an account that belongs to an Entra tenant" -ForegroundColor Yellow
    Write-Host "(user@yourtenant.onmicrosoft.com or a work/school account), or pass -TenantId <tenant id or domain>. Run Disconnect-MgGraph first if a session is already open." -ForegroundColor Yellow
    Write-Host "No snapshot written." -ForegroundColor Red
    exit 1
}

# Security defaults
$securityDefaults = $null
try { $sd = Get-Graph 'policies/identitySecurityDefaultsEnforcementPolicy'; $securityDefaults = [bool]$sd.isEnabled }
catch { Add-CollectionError 'securityDefaults' $_.Exception.Message }

# Authorization policy (self-service app registration, user consent, guest role)
$authPolicy = $null
try {
    $ap = Get-Graph 'policies/authorizationPolicy'
    $ap = @($ap)[0]
    $authPolicy = [ordered]@{
        allowedToCreateApps           = [bool]$ap.defaultUserRolePermissions.allowedToCreateApps
        allowedToCreateSecurityGroups = [bool]$ap.defaultUserRolePermissions.allowedToCreateSecurityGroups
        allowedToReadOtherUsers       = [bool]$ap.defaultUserRolePermissions.allowedToReadOtherUsers
        allowedToCreateTenants        = $ap.defaultUserRolePermissions.allowedToCreateTenants
        allowedToReadBitlockerKeys    = $ap.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice
        permissionGrantPolicies       = @($ap.defaultUserRolePermissions.permissionGrantPoliciesAssigned | ForEach-Object { "$_" })
        allowInvitesFrom              = "$($ap.allowInvitesFrom)"
        guestUserRoleId               = "$($ap.guestUserRoleId)"
    }
}
catch { Add-CollectionError 'authorizationPolicy' $_.Exception.Message }

# Consent policy (can users consent to apps?)
$consentPolicy = $null
try {
    $cp = Get-Graph 'policies/adminConsentRequestPolicy'
    $consentPolicy = [ordered]@{ adminConsentRequestEnabled = [bool]$cp.isEnabled }
}
catch { Add-CollectionError 'consentPolicy' $_.Exception.Message }

# Conditional Access policies
$caPolicies = @()
try {
    $caPolicies = @(Get-Graph 'identity/conditionalAccess/policies' -All | ForEach-Object {
            [ordered]@{
                id                  = $_.id
                displayName         = $_.displayName
                state               = "$($_.state)"
                includeUsers        = @($_.conditions.users.includeUsers)
                excludeUsers        = @($_.conditions.users.excludeUsers)
                excludeGroups       = @($_.conditions.users.excludeGroups)
                includeGroups       = @($_.conditions.users.includeGroups)
                includeRoles        = @($_.conditions.users.includeRoles)
                includeApplications = @($_.conditions.applications.includeApplications)
                includeUserActions  = @($_.conditions.applications.includeUserActions)
                includeLocations    = @($_.conditions.locations.includeLocations)
                excludeLocations    = @($_.conditions.locations.excludeLocations)
                clientAppTypes      = @($_.conditions.clientAppTypes)
                includeServicePrincipals = @($_.conditions.clientApplications.includeServicePrincipals)
                userRiskLevels      = @($_.conditions.userRiskLevels)
                signInRiskLevels    = @($_.conditions.signInRiskLevels)
                transferMethods     = "$($_.conditions.authenticationFlows.transferMethods)"
                grantControls       = @($_.grantControls.builtInControls)
                authStrengthId      = "$($_.grantControls.authenticationStrength.id)"
                signInFrequency     = [bool]$_.sessionControls.signInFrequency.isEnabled
                signInFrequencyInterval = "$($_.sessionControls.signInFrequency.frequencyInterval)"
                persistentBrowser   = if ($_.sessionControls.persistentBrowser.isEnabled) { "$($_.sessionControls.persistentBrowser.mode)" } else { '' }
                tokenProtection     = $null
            }
        })
}
catch { Add-CollectionError 'conditionalAccess' $_.Exception.Message }

# Token protection is only exposed on the beta endpoint.
try {
    $tp = @{}
    foreach ($p in @(Get-Graph 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -All)) { $tp["$($p.id)"] = [bool]$p.sessionControls.secureSignInSession.isEnabled }
    foreach ($c in $caPolicies) { if ($tp.ContainsKey("$($c.id)")) { $c.tokenProtection = $tp["$($c.id)"] } }
}
catch { Add-CollectionError 'caTokenProtection' $_.Exception.Message }

# Named locations: trusted IP ranges and country lists.
$namedLocations = $null
try {
    $namedLocations = @(Get-Graph 'identity/conditionalAccess/namedLocations' -All | ForEach-Object {
            [ordered]@{ id = "$($_.id)"; displayName = $_.displayName; type = if ("$($_.'@odata.type')" -match 'country') { 'country' } else { 'ip' }; isTrusted = [bool]$_.isTrusted }
        })
}
catch { Add-CollectionError 'namedLocations' $_.Exception.Message }

# Authentication methods policy: which methods are switched on (SMS, voice,
# email OTP are the weak ones).
$authMethods = $null
try {
    $am = Get-Graph 'policies/authenticationMethodsPolicy'
    $authMethods = @($am.authenticationMethodConfigurations | ForEach-Object { [ordered]@{ id = "$($_.id)"; state = "$($_.state)" } })
}
catch { Add-CollectionError 'authenticationMethods' $_.Exception.Message }

# Authenticator details (number matching context, Authenticator Lite) and system-preferred MFA.
$authenticatorSettings = $null
try {
    $amp = Get-Graph 'policies/authenticationMethodsPolicy'
    $ma = Get-Graph 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator'
    $authenticatorSettings = [ordered]@{
        systemPreferred   = "$($amp.systemCredentialPreferences.state)"
        authenticatorState = "$($ma.state)"
        showAppName       = "$($ma.featureSettings.displayAppInformationRequiredState.state)"
        showLocation      = "$($ma.featureSettings.displayLocationInformationRequiredState.state)"
        companionApp      = "$($ma.featureSettings.companionAppAllowedState.state)"
    }
}
catch { Add-CollectionError 'authenticatorSettings' $_.Exception.Message }

# Banned passwords and smart lockout. No settings object means Microsoft's
# defaults. We keep how many words are banned, not which.
$passwordSettings = $null
$groupCreation = $null
try {
    $allSettings = @(Get-Graph 'groupSettings' -All)
    $gu = $allSettings | Where-Object { $_.displayName -eq 'Group.Unified' } | Select-Object -First 1
    $guVals = @{}; foreach ($v in @($gu.values)) { $guVals["$($v.name)"] = "$($v.value)" }
    # No Group.Unified object means the default: everyone can create Microsoft 365 groups.
    $groupCreation = [ordered]@{ m365GroupCreationAllowed = ("$($guVals['EnableGroupCreation'])" -ne 'false') }
    $pr = $allSettings | Where-Object { $_.displayName -eq 'Password Rule Settings' } | Select-Object -First 1
    $vals = @{}; foreach ($v in @($pr.values)) { $vals["$($v.name)"] = "$($v.value)" }
    $passwordSettings = [ordered]@{
        configured                = [bool]$pr
        enableBannedPasswordCheck = if ($vals.ContainsKey('EnableBannedPasswordCheck')) { $vals['EnableBannedPasswordCheck'] -eq 'True' } else { $null }
        bannedPasswordCount       = @("$($vals['BannedPasswordList'])" -split "`t" | Where-Object { $_ }).Count
        lockoutThreshold          = if ($vals['LockoutThreshold']) { [int]$vals['LockoutThreshold'] } else { $null }
        lockoutDurationInSeconds  = if ($vals['LockoutDurationInSeconds']) { [int]$vals['LockoutDurationInSeconds'] } else { $null }
    }
}
catch { Add-CollectionError 'passwordSettings' $_.Exception.Message; Add-CollectionError 'groupCreation' $_.Exception.Message }

# Device join and local admin settings (beta only).
$deviceRegistration = $null
try {
    $dr = Get-Graph 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
    $kind = { param($o) $t = "$($o.'@odata.type')"; if ($t -match 'allDevice') { 'all' } elseif ($t -match 'enumerated') { 'selected' } elseif ($t -match 'noDevice') { 'none' } else { '' } }
    $deviceRegistration = [ordered]@{
        userDeviceQuota            = $dr.userDeviceQuota
        joinAllowedFor             = & $kind $dr.azureADJoin.allowedToJoin
        globalAdminsAreLocalAdmins = $dr.azureADJoin.localAdmins.enableGlobalAdmins
        registeringUsersLocalAdmin = & $kind $dr.azureADJoin.localAdmins.registeringUsers
        lapsEnabled                = $dr.localAdminPassword.isEnabled
    }
}
catch { Add-CollectionError 'deviceRegistration' $_.Exception.Message }

# Tenant-wide rules for app credentials.
$appManagementPolicy = $null
try {
    $am2 = Get-Graph 'policies/defaultAppManagementPolicy'
    $rest = { param($list) @($list | ForEach-Object { [ordered]@{ type = "$($_.restrictionType)"; state = "$($_.state)"; maxLifetime = "$($_.maxLifetime)" } }) }
    $appManagementPolicy = [ordered]@{
        isEnabled = [bool]$am2.isEnabled
        passwordRestrictions = & $rest $am2.applicationRestrictions.passwordCredentials
        keyRestrictions      = & $rest $am2.applicationRestrictions.keyCredentials
    }
}
catch { Add-CollectionError 'appManagementPolicy' $_.Exception.Message }

# Domains: password expiry is set per domain.
$domains = $null
try {
    $domains = @(Get-Graph 'domains' -All | ForEach-Object {
            $mfaBehavior = $null
            if ("$($_.authenticationType)" -eq 'Federated') { try { $mfaBehavior = "$(@(Get-Graph "domains/$($_.id)/federationConfiguration")[0].federatedIdpMfaBehavior)" } catch { } }
            [ordered]@{ id = "$($_.id)"; isVerified = [bool]$_.isVerified; authenticationType = "$($_.authenticationType)"; passwordValidityDays = $_.passwordValidityPeriodInDays; federatedIdpMfaBehavior = $mfaBehavior }
        })
}
catch { Add-CollectionError 'domains' $_.Exception.Message }

# Idle session timeout for Microsoft 365 web apps.
$idleTimeout = $null
try { $idleTimeout = [ordered]@{ policyCount = @(Get-Graph 'policies/activityBasedTimeoutPolicies' -All | Where-Object { $_ }).Count } }
catch { Add-CollectionError 'idleTimeout' $_.Exception.Message }

# "Stay signed in?" prompt, from company branding. No branding means the default: shown.
$branding = $null
try {
    $b = Get-Graph "organization/$($org.tenantId)/branding"
    $branding = [ordered]@{ configured = $true; hideKeepMeSignedIn = [bool]$b.loginPageTextVisibilitySettings.hideKeepMeSignedIn }
}
catch {
    if ("$($_.Exception.Message)" -match '(?i)404|NotFound|does not exist') { $branding = [ordered]@{ configured = $false; hideKeepMeSignedIn = $false } }
    else { Add-CollectionError 'branding' $_.Exception.Message }
}

# Password hash sync, for tenants synced from on-premises.
$onPremSync = $null
try {
    if ($org -and $org.onPremisesSyncEnabled) {
        $s = @(Get-Graph 'directory/onPremisesSynchronization')[0]
        $onPremSync = [ordered]@{ syncEnabled = $true; passwordHashSync = [bool]$s.features.passwordSyncEnabled }
    }
    else { $onPremSync = [ordered]@{ syncEnabled = $false; passwordHashSync = $null } }
}
catch { Add-CollectionError 'onPremSync' $_.Exception.Message }

# Access reviews (Entra ID Governance / P2). Only names and scopes.
$accessReviews = $null
try {
    $accessReviews = @(Get-Graph 'identityGovernance/accessReviews/definitions' -All | ForEach-Object {
            [ordered]@{ displayName = $_.displayName; status = "$($_.status)"; scope = (@($_.scope, $_.instanceEnumerationScope) | ConvertTo-Json -Depth 6 -Compress) }
        })
}
catch { Add-CollectionError 'accessReviews' $_.Exception.Message }

# PIM role settings of the privileged roles: approval (pimPolicies, Global Admin and Privileged
# Role Admin, kept for older analyzers) and the full activation / assignment rules (pimRules).
$privRoleIds = '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '194ae4cb-b126-40b2-bd5b-6091b380977d', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
    '158c047a-c907-4556-b7ef-446551a6b5f7', '966707d0-3269-4727-9be2-8c3a10f19b9d', 'fe930be7-5e62-47db-91af-98c3a49a38b1', '29232cdf-9323-42fd-ade2-1d097af3e4de',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'b0f54661-2d74-4c50-afa3-1ec803f12efe',
    '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'e3973bdf-4987-49ae-837a-ba8e231c7286'
$pimPolicies = $null; $pimRules = $null
try {
    $pimPolicies = [ordered]@{}; $pimRules = [ordered]@{}
    foreach ($rid in $privRoleIds) {
        $f = [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$rid'")
        $a = @(Get-Graph "policies/roleManagementPolicyAssignments?`$filter=$f&`$expand=policy(`$expand=rules)" -All)[0]
        if (-not $a) { continue }
        $rules = @($a.policy.rules)
        $byId = { param($id) @($rules | Where-Object { "$($_.id)" -eq $id })[0] }
        $appr = & $byId 'Approval_EndUser_Assignment'
        $enab = & $byId 'Enablement_EndUser_Assignment'
        $actx = & $byId 'AuthenticationContext_EndUser_Assignment'
        $actExp = & $byId 'Expiration_EndUser_Assignment'
        $eligExp = & $byId 'Expiration_Admin_Eligibility'
        $assExp = & $byId 'Expiration_Admin_Assignment'
        if ($rid -in '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814') { $pimPolicies[$rid] = [bool]$appr.setting.isApprovalRequired }
        $pimRules[$rid] = [ordered]@{
            approval              = [bool]$appr.setting.isApprovalRequired
            mfa                   = (@($enab.enabledRules) -contains 'MultiFactorAuthentication')
            justification         = (@($enab.enabledRules) -contains 'Justification')
            authContext           = [bool]$actx.isEnabled
            maxActivation         = "$($actExp.maximumDuration)"
            eligibleExpiryRequired = [bool]$eligExp.isExpirationRequired
            activeExpiryRequired  = [bool]$assExp.isExpirationRequired
        }
    }
}
catch { Add-CollectionError 'pimPolicies' $_.Exception.Message; $pimPolicies = $null; $pimRules = $null }

# Licence plans, to tell an admin account with mailbox and Teams from an identity-only one.
$skus = $null
try {
    $skus = @(Get-Graph 'subscribedSkus' -All | ForEach-Object { [ordered]@{ skuId = "$($_.skuId)"; name = "$($_.skuPartNumber)"; plans = @($_.servicePlans | ForEach-Object { "$($_.servicePlanName)" }) } })
}
catch { Add-CollectionError 'licenses' $_.Exception.Message }

# PIM assignments. Without Entra ID P2 this fails and the PIM check is "not evaluated".
$pim = $null
try {
    $toRec = { [ordered]@{ principalId = "$($_.principalId)"; roleDefinitionId = "$($_.roleDefinitionId)"; assignmentType = "$($_.assignmentType)"; endDateTime = IsoUtc $_.endDateTime } }
    $pim = [ordered]@{
        active   = @(Get-Graph 'roleManagement/directory/roleAssignmentScheduleInstances' -All | ForEach-Object $toRec)
        eligible = @(Get-Graph 'roleManagement/directory/roleEligibilityScheduleInstances' -All | ForEach-Object $toRec)
    }
}
catch { Add-CollectionError 'pim' $_.Exception.Message }

# Directory roles and their members (privileged roles)
$roles = @()
try {
    $roles = @(Get-Graph 'directoryRoles' -All | ForEach-Object {
            $rid = $_.id; $members = @()
            $memberTypes = [ordered]@{}
            try { $members = @(Get-Graph "directoryRoles/$rid/members" -All | ForEach-Object { $memberTypes["$($_.id)"] = ("$($_.'@odata.type')" -replace '^#microsoft\.graph\.', ''); $_.id }) } catch { }
            [ordered]@{ id = $rid; displayName = $_.displayName; roleTemplateId = $_.roleTemplateId; members = $members; memberTypes = $memberTypes }
        })
}
catch { Add-CollectionError 'directoryRoles' $_.Exception.Message }

# Role assignments with their scope: "/" is tenant-wide, anything else an administrative unit
# or a single object. Conditional Access policies that target roles skip scoped assignments.
$roleAssignments = $null
try {
    $roleAssignments = @(Get-Graph 'roleManagement/directory/roleAssignments?$select=principalId,roleDefinitionId,directoryScopeId' -All | ForEach-Object {
            [ordered]@{ principalId = "$($_.principalId)"; roleDefinitionId = "$($_.roleDefinitionId)"; directoryScopeId = "$($_.directoryScopeId)" } })
}
catch { Add-CollectionError 'roleAssignments' $_.Exception.Message }

# Users, with MFA registration state from the reports endpoint
$mfaByUser = @{}; $mfaCapable = @{}; $mfaMethods = @{}
try {
    foreach ($r in @(Get-Graph 'reports/authenticationMethods/userRegistrationDetails' -All)) {
        $mfaByUser[$r.id] = [bool]$r.isMfaRegistered
        $mfaCapable[$r.id] = [bool]$r.isMfaCapable
        $mfaMethods[$r.id] = @($r.methodsRegistered | ForEach-Object { "$_" })
    }
}
catch { Add-CollectionError 'mfaRegistration' $_.Exception.Message }

$users = @()
try {
    $sel = 'id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,signInActivity,onPremisesSyncEnabled,assignedLicenses,lastPasswordChangeDateTime'
    $top = if ($MaxUsers -gt 0) { "&`$top=$([Math]::Min(999,$MaxUsers))" } else { '' }
    # signInActivity needs Entra ID P1; without it the whole request fails, so retry without it.
    try { $raw = Get-Graph "users?`$select=$sel$top" -All }
    catch {
        Add-CollectionError 'signInActivity' "Last sign-in not available (needs Entra ID P1 and AuditLog.Read.All): $($_.Exception.Message)"
        $raw = Get-Graph "users?`$select=$($sel -replace ',signInActivity', '')$top" -All
    }
    if ($MaxUsers -gt 0) { $raw = @($raw | Select-Object -First $MaxUsers) }
    $users = @($raw | ForEach-Object {
            [ordered]@{
                id             = $_.id
                upn            = $_.userPrincipalName
                displayName    = $_.displayName
                enabled        = [bool]$_.accountEnabled
                userType       = "$($_.userType)"
                onPremSync     = [bool]$_.onPremisesSyncEnabled
                createdDateTime = IsoUtc $_.createdDateTime
                lastSignIn     = IsoUtc $_.signInActivity.lastSignInDateTime
                mfaRegistered  = if ($mfaByUser.ContainsKey($_.id)) { $mfaByUser[$_.id] } else { $null }
                mfaCapable     = if ($mfaCapable.ContainsKey($_.id)) { $mfaCapable[$_.id] } else { $null }
                licenses       = @($_.assignedLicenses | ForEach-Object { "$($_.skuId)" })
                lastPasswordChange = IsoUtc $_.lastPasswordChangeDateTime
                mfaMethods     = if ($mfaMethods.ContainsKey($_.id)) { $mfaMethods[$_.id] } else { $null }
            }
        })
    Write-Host "  $($users.Count) users"
}
catch { Add-CollectionError 'users' $_.Exception.Message }

# Legacy per-user MFA, for role members only (one call per user, beta endpoint).
$perUserMfa = $null
try {
    $perUserMfa = [ordered]@{}
    foreach ($mid in @($roles | ForEach-Object { $_.members } | Select-Object -Unique)) {
        try { $perUserMfa[$mid] = "$((Get-Graph "https://graph.microsoft.com/beta/users/$mid/authentication/requirements").perUserMfaState)" } catch { }
    }
}
catch { Add-CollectionError 'perUserMfa' $_.Exception.Message; $perUserMfa = $null }

# Intune RBAC: each role assignment with its role (built-in flag, allowed actions) and the
# admin groups it is given to. Needs an Intune licence and DeviceManagementRBAC.Read.All;
# without them the section fails. Not yet checked against a real tenant.
$intuneRoles = $null
try {
    $intuneRoles = @(foreach ($d in @(Get-Graph 'deviceManagement/roleDefinitions' -All)) {
            $acts = @(foreach ($rp in @($d.rolePermissions)) { foreach ($ra in @($rp.resourceActions)) { @($ra.allowedResourceActions) } }) | Where-Object { $_ } | ForEach-Object { "$_" } | Sort-Object -Unique
            foreach ($a in @(Get-Graph "deviceManagement/roleDefinitions/$($d.id)/roleAssignments" -All)) {
                # The base roleAssignment type has no members: read the Intune assignment itself then.
                if ($null -eq $a.PSObject.Properties['members']) { $a = Get-Graph "deviceManagement/roleAssignments/$($a.id)" }
                [ordered]@{
                    id = "$($a.id)"; displayName = "$($a.displayName)"
                    roleId = "$($d.id)"; roleName = "$($d.displayName)"; isBuiltIn = [bool]$d.isBuiltIn; actions = @($acts)
                    members = @(@($a.members) | Where-Object { $_ } | ForEach-Object { "$_" }); resourceScopes = @(@($a.resourceScopes) | Where-Object { $_ } | ForEach-Object { "$_" })
                }
            }
        })
}
catch { Add-CollectionError 'intuneRoles' $_.Exception.Message; $intuneRoles = $null }

# Intune Multi Admin Approval: which operation types need a second admin (device wipe,
# scripts, apps, roles). Beta only; same licence and scope as the Intune roles. Policy names
# are not kept, only their type, platform and number of approver groups.
$intuneApprovalPolicies = $null
try {
    $intuneApprovalPolicies = @(Get-Graph 'https://graph.microsoft.com/beta/deviceManagement/operationApprovalPolicies' -All | Where-Object { $_ } | ForEach-Object {
            [ordered]@{ id = "$($_.id)"; policyType = "$($_.policyType)"; policyPlatform = "$($_.policyPlatform)"; approverGroupCount = @(@($_.approverGroupIds) | Where-Object { $_ }).Count }
        })
}
catch { Add-CollectionError 'intuneApprovalPolicies' $_.Exception.Message; $intuneApprovalPolicies = $null }

# Applications and service principals: credential expiry and high-privilege grants
# Groups that gate access: excluded from or targeted by Conditional Access, or holding an
# admin role (directly or through PIM). Visibility, dynamic rule and owners only; members
# are not read. A PIM principal that is not a group answers 404 and is skipped.
$groups = $null
try {
    $gids = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($caPolicies | Where-Object { $_ })) { foreach ($g in @($p.excludeGroups) + @($p.includeGroups)) { if ($g -and -not $gids.Contains("$g")) { $gids.Add("$g") } } }
    foreach ($r in @($roles | Where-Object { $_ })) { foreach ($k in @($r.memberTypes.Keys)) { if ("$($r.memberTypes[$k])" -eq 'group' -and -not $gids.Contains("$k")) { $gids.Add("$k") } } }
    foreach ($ia in @($intuneRoles | Where-Object { $_ })) { foreach ($g in @($ia.members)) { if ($g -and -not $gids.Contains("$g")) { $gids.Add("$g") } } }
    $userIds = @{}; foreach ($u in @($users | Where-Object { $_ })) { $userIds["$($u.id)"] = $true }
    if ($pim) { foreach ($a in @($pim.active) + @($pim.eligible)) { if ($a -and $a.principalId -and -not $userIds.ContainsKey("$($a.principalId)") -and -not $gids.Contains("$($a.principalId)")) { $gids.Add("$($a.principalId)") } } }
    # Groups that hold a role: role members of type group, plus PIM principals that turn out to be groups.
    $roleGroupIds = @{}
    foreach ($r in @($roles | Where-Object { $_ })) { foreach ($k in @($r.memberTypes.Keys)) { if ("$($r.memberTypes[$k])" -eq 'group') { $roleGroupIds["$k"] = $true } } }
    if ($pim) { foreach ($a in @($pim.active) + @($pim.eligible)) { if ($a -and $a.principalId -and -not $userIds.ContainsKey("$($a.principalId)")) { $roleGroupIds["$($a.principalId)"] = $true } } }
    $gErr = 0; $pimGroupErr = ''
    $groups = @(foreach ($gid in $gids) {
            $g = $null
            try { $g = Get-Graph "groups/$gid`?`$select=id,displayName,visibility,groupTypes,membershipRule,isAssignableToRole,securityEnabled,onPremisesSyncEnabled" }
            catch { if ("$($_.Exception.Message)" -notmatch '404|NotFound|ResourceNotFound') { $gErr++ }; continue }
            $ownerTypes = [ordered]@{}
            try { foreach ($o in @(Get-Graph "groups/$gid/owners?`$select=id" -All)) { $ownerTypes["$($o.id)"] = ("$($o.'@odata.type')" -replace '^#microsoft\.graph\.', '') } }
            catch { $gErr++ }
            # PIM for Groups: who is eligible to become member or owner (only groups holding a role).
            $pimElig = $null
            if ($roleGroupIds.ContainsKey("$gid")) {
                try {
                    $pf = [uri]::EscapeDataString("groupId eq '$gid'")
                    $pimElig = @(Get-Graph "identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=$pf" -All | ForEach-Object { [ordered]@{ principalId = "$($_.principalId)"; accessId = "$($_.accessId)" } })
                }
                catch { $pimGroupErr = "$($_.Exception.Message)" }
            }
            [ordered]@{
                id                 = "$($g.id)"
                displayName        = "$($g.displayName)"
                pimEligible        = $pimElig
                visibility         = "$($g.visibility)"
                unified            = (@($g.groupTypes) -contains 'Unified')
                dynamic            = (@($g.groupTypes) -contains 'DynamicMembership')
                membershipRule     = "$($g.membershipRule)"
                isAssignableToRole = [bool]$g.isAssignableToRole
                onPremSync         = [bool]$g.onPremisesSyncEnabled
                ownerTypes         = $ownerTypes
            }
        })
    if ($gErr) { Add-CollectionError 'groups' "$gErr group or owner read(s) failed: those groups may be missing" }
    if ($pimGroupErr) { Add-CollectionError 'pimForGroups' "PIM for Groups eligibility not readable: $pimGroupErr" }
}
catch { Add-CollectionError 'groups' $_.Exception.Message }

$apps = @()
try {
    $apps = @(Get-Graph 'applications?$select=id,displayName,appId,passwordCredentials,keyCredentials,web,spa,publicClient,signInAudience,servicePrincipalLockConfiguration,requiredResourceAccess' -All | ForEach-Object {
            # Permissions requested on the retired Azure AD Graph: counts only.
            $aadg = @(@($_.requiredResourceAccess) | Where-Object { "$($_.resourceAppId)" -eq $script:AadGraphAppId } | ForEach-Object { @($_.resourceAccess) })
            [ordered]@{
                id           = $_.id
                displayName  = $_.displayName
                appId        = $_.appId
                passwordCred = @($_.passwordCredentials | ForEach-Object { IsoUtc $_.endDateTime })
                keyCred      = @($_.keyCredentials | ForEach-Object { IsoUtc $_.endDateTime })
                secrets      = @($_.passwordCredentials | ForEach-Object { [ordered]@{ start = IsoUtc $_.startDateTime; end = IsoUtc $_.endDateTime } })
                redirectUris = @(@($_.web.redirectUris) + @($_.spa.redirectUris) + @($_.publicClient.redirectUris) | Where-Object { $_ } | ForEach-Object { "$_" })
                signInAudience = "$($_.signInAudience)"
                instanceLock = [bool]($_.servicePrincipalLockConfiguration.isEnabled -and $_.servicePrincipalLockConfiguration.allProperties)
                aadGraphScopes = @($aadg | Where-Object { "$($_.type)" -eq 'Scope' }).Count
                aadGraphRoles  = @($aadg | Where-Object { "$($_.type)" -eq 'Role' }).Count
            }
        })
}
catch { Add-CollectionError 'applications' $_.Exception.Message }

# Service principals and the application permissions granted to them.
$servicePrincipals = @()
$grantErrors = 0
# The Azure AD Graph service principal of this tenant: grants on it are counted per app.
$aadGraphSpId = ''
try { $aadGraphSpId = "$(@(Get-Graph "servicePrincipals?`$filter=appId eq '$script:AadGraphAppId'&`$select=id")[0].id)" } catch { }
try {
    $servicePrincipals = @(Get-Graph 'servicePrincipals' -All | ForEach-Object {
            $spId = $_.id; $grants = @(); $aadGraphGrants = 0
            try {
                $assigned = @(Get-Graph "servicePrincipals/$spId/appRoleAssignments" -All)
                $grants = @($assigned | ForEach-Object { $_.appRoleId })
                if ($aadGraphSpId) { $aadGraphGrants = @($assigned | Where-Object { "$($_.resourceId)" -eq $aadGraphSpId }).Count }
            }
            catch { $grantErrors++ }
            [ordered]@{
                id             = $spId
                displayName    = $_.displayName
                appId          = $_.appId
                # Application, ManagedIdentity, Legacy...: workload CA only covers Application.
                type           = "$($_.servicePrincipalType)"
                appOwnerTenant = "$($_.appOwnerOrganizationId)"
                appRoleIds     = $grants
                aadGraphRoles  = $aadGraphGrants
                passwordCred   = @($_.passwordCredentials | ForEach-Object { IsoUtc $_.endDateTime })
                keyCred        = @($_.keyCredentials | ForEach-Object { IsoUtc $_.endDateTime })
            }
        })
}
catch { Add-CollectionError 'servicePrincipals' $_.Exception.Message }
# An app whose permissions couldn't be read would otherwise look harmless.
if ($grantErrors) { Add-CollectionError 'servicePrincipals.appRoleAssignments' "application permissions unreadable for $grantErrors service principal(s)" }

# Owners of apps that hold tenant-takeover permissions: an owner can add a
# credential and act as the app. Only those apps, to keep the call count low.
$riskyRoles = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8', '19dbc75e-c2e2-444c-a770-ec69d8559fc7', '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9', '06b708a9-e830-4db3-a914-8e69da51d44f',
    '62a82d76-70ea-41e2-9197-370581804d09', '741f803b-c850-494e-b5df-cde7c675a1ca', '50483e42-d915-4231-9639-7fdb7fd190e5'
$spInRole = @{}; foreach ($r in @($roles | Where-Object { $_ })) { foreach ($k in @($r.memberTypes.Keys)) { if ("$($r.memberTypes[$k])" -eq 'servicePrincipal') { $spInRole["$k"] = $true } } }
try {
    foreach ($sp in @($servicePrincipals | Where-Object { $spInRole.ContainsKey("$($_.id)") -or @($_.appRoleIds | Where-Object { $riskyRoles -contains "$_" }).Count })) {
        $owners = @(); $ownerTypes = [ordered]@{}
        try { foreach ($o in @(Get-Graph "servicePrincipals/$($sp.id)/owners" -All)) { $owners += "$($o.id)"; $ownerTypes["$($o.id)"] = ("$($o.'@odata.type')" -replace '^#microsoft\.graph\.', '') } } catch { }
        $app = @($apps | Where-Object { $_.appId -eq $sp.appId })[0]
        if ($app) { try { foreach ($o in @(Get-Graph "applications/$($app.id)/owners" -All)) { $owners += "$($o.id)"; $ownerTypes["$($o.id)"] = ("$($o.'@odata.type')" -replace '^#microsoft\.graph\.', '') } } catch { } }
        $sp['owners'] = @($owners | Select-Object -Unique)
        $sp['ownerTypes'] = $ownerTypes
    }
}
catch { Add-CollectionError 'appOwners' $_.Exception.Message }

# Last sign-in of each service principal (beta report, needs Entra ID P1): used only for the
# privileged ones. appId -> last sign-in in any flow.
$spSignIns = $null
try {
    $spSignIns = [ordered]@{}
    foreach ($a in @(Get-Graph 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' -All)) {
        if ($a.appId) { $spSignIns["$($a.appId)"] = IsoUtc $a.lastSignInActivity.lastSignInDateTime }
    }
}
catch { Add-CollectionError 'spSignIns' $_.Exception.Message; $spSignIns = $null }

# Delegated permissions granted to apps (by an admin for everyone, or by users).
$oauthGrants = $null
try {
    $oauthGrants = @(Get-Graph 'oauth2PermissionGrants' -All | ForEach-Object {
            [ordered]@{ clientId = "$($_.clientId)"; consentType = "$($_.consentType)"; principalId = "$($_.principalId)"; scope = "$($_.scope)".Trim(); resourceId = "$($_.resourceId)" }
        })
}
catch { Add-CollectionError 'oauthGrants' $_.Exception.Message }

# Default cross-tenant settings: do we trust MFA and device claims from any other tenant?
$crossTenant = $null
try {
    $ct = Get-Graph 'policies/crossTenantAccessPolicy/default'
    $crossTenant = [ordered]@{
        mfaAccepted = [bool]$ct.inboundTrust.isMfaAccepted; compliantDeviceAccepted = [bool]$ct.inboundTrust.isCompliantDeviceAccepted; hybridJoinAccepted = [bool]$ct.inboundTrust.isHybridAzureADJoinedDeviceAccepted
        # B2B direct connect (Teams shared channels): 'allowed' or 'blocked'.
        directConnectInbound = "$($ct.b2bDirectConnectInbound.usersAndGroups.accessType)"
        directConnectOutbound = "$($ct.b2bDirectConnectOutbound.usersAndGroups.accessType)"
    }
}
catch { Add-CollectionError 'crossTenant' $_.Exception.Message }

# Entitlement management: who can request each access package, with what approval
# and for how long. Needs Entra ID Governance or P2; without it the section fails.
$accessPackages = $null
try {
    $accessPackages = @(Get-Graph 'identityGovernance/entitlementManagement/assignmentPolicies?$expand=accessPackage' -All | ForEach-Object {
            [ordered]@{
                id = $_.id; displayName = $_.displayName; accessPackage = "$($_.accessPackage.displayName)"; accessPackageId = "$($_.accessPackage.id)"
                allowedTargetScope = "$($_.allowedTargetScope)"
                selfAddEnabled = [bool]$_.requestorSettings.enableTargetsToSelfAddAccess
                approvalRequired = [bool]$_.requestApprovalSettings.isApprovalRequiredForAdd
                expirationType = "$($_.expiration.type)"
                reviewEnabled = [bool]$_.reviewSettings.isEnabled
            }
        })
}
catch { Add-CollectionError 'accessPackages' $_.Exception.Message }
# What each package grants (group memberships, Entra roles, app roles): origin system and ids.
$accessPackageGrants = $null
if ($accessPackages) {
    try {
        $accessPackageGrants = [ordered]@{}
        foreach ($apid in @($accessPackages | ForEach-Object { $_.accessPackageId } | Where-Object { $_ } | Select-Object -Unique)) {
            $pkg = Get-Graph "identityGovernance/entitlementManagement/accessPackages/$apid`?`$expand=resourceRoleScopes(`$expand=role,scope)"
            $accessPackageGrants[$apid] = @(@($pkg.resourceRoleScopes) | ForEach-Object {
                    [ordered]@{ originSystem = "$($_.role.originSystem)"; roleOriginId = "$($_.role.originId)"; scopeOriginId = "$($_.scope.originId)"; roleName = "$($_.role.displayName)" } })
        }
    }
    catch { Add-CollectionError 'accessPackageGrants' $_.Exception.Message; $accessPackageGrants = $null }
}
# Catalogs: the groups (and other resources) each one holds and its access packages. A catalog
# owner or access package manager can put any of those resources in a package; an assignment
# manager can hand out the existing packages, to themselves too.
$entitlementCatalogs = $null
try {
    $entitlementCatalogs = @(Get-Graph 'identityGovernance/entitlementManagement/catalogs?$select=id,displayName' -All | ForEach-Object {
            $cid = "$($_.id)"
            [ordered]@{
                id = $cid; displayName = "$($_.displayName)"
                resources = @(Get-Graph "identityGovernance/entitlementManagement/catalogs/$cid/resources?`$select=originId,originSystem" -All | ForEach-Object { [ordered]@{ originSystem = "$($_.originSystem)"; originId = "$($_.originId)" } })
                accessPackageIds = @(Get-Graph "identityGovernance/entitlementManagement/catalogs/$cid/accessPackages?`$select=id" -All | ForEach-Object { "$($_.id)" })
            }
        })
}
catch { Add-CollectionError 'entitlementCatalogs' $_.Exception.Message; $entitlementCatalogs = $null }
# Who holds a role on a catalog: owner, access package manager, assignment manager (readers
# can't change anything). The API wants one filter per role definition.
$catalogRoles = $null
if ($null -ne $entitlementCatalogs) {
    try {
        $catalogRoles = @(foreach ($rd in 'ae79f266-94d4-4dab-b730-feca7e132178', '7f480852-ebdc-47d4-87de-0d8498384a83', 'e2182095-804a-4656-ae11-64734e9b7ae5') {
                Get-Graph "roleManagement/entitlementManagement/roleAssignments?`$filter=roleDefinitionId eq '$rd'&`$expand=principal" -All | ForEach-Object {
                    [ordered]@{ roleDefinitionId = $rd; principalId = "$($_.principalId)"; principalType = ("$($_.principal.'@odata.type')" -replace '^#microsoft\.graph\.', ''); appScopeId = "$($_.appScopeId)" }
                }
            })
    }
    catch { Add-CollectionError 'catalogRoles' $_.Exception.Message; $catalogRoles = $null }
}

# --------------------------------------------------------------------------
$snapshot = [ordered]@{
    meta = [ordered]@{
        tool = 'IDWolf'; kind = 'entra'; schemaVersion = 10; collectorVersion = $script:CollectorVersion
        collectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        tenantId = $ctx.TenantId; account = $ctx.Account
        collectionErrors = $script:Errors.ToArray(); synthetic = $false
    }
    org               = $org
    securityDefaults  = $securityDefaults
    authorizationPolicy = $authPolicy
    consentPolicy     = $consentPolicy
    authenticationMethods = $authMethods
    passwordSettings  = $passwordSettings
    pim               = $pim
    pimPolicies       = $pimPolicies
    authenticatorSettings = $authenticatorSettings
    groupCreation     = $groupCreation
    deviceRegistration = $deviceRegistration
    appManagementPolicy = $appManagementPolicy
    domains           = $domains
    idleTimeout       = $idleTimeout
    branding          = $branding
    onPremSync        = $onPremSync
    accessReviews     = $accessReviews
    namedLocations    = $namedLocations
    licenses          = $skus
    perUserMfa        = $perUserMfa
    oauthGrants       = $oauthGrants
    crossTenant       = $crossTenant
    accessPackages    = $accessPackages
    conditionalAccess = $caPolicies
    groups            = $groups
    pimRules          = $pimRules
    roleAssignments   = $roleAssignments
    spSignIns         = $spSignIns
    accessPackageGrants = $accessPackageGrants
    entitlementCatalogs = $entitlementCatalogs
    catalogRoles      = $catalogRoles
    aadGraphSpId      = $aadGraphSpId
    intuneRoles       = $intuneRoles
    intuneApprovalPolicies = $intuneApprovalPolicies
    directoryRoles    = $roles
    users             = $users
    applications      = $apps
    servicePrincipals = $servicePrincipals
}

if (-not $OutFile) {
    $tn = if ($org -and $org.displayName) { ($org.displayName -replace '[^\w\-]', '_') } elseif ($ctx.TenantId) { "$($ctx.TenantId)" } else { 'tenant' }
    # Unnamed outputs go to .\output, not next to everything else.
    $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }
    $OutFile = Join-Path $od ("entrasnapshot_{0}_{1}.json" -f $tn, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$json = $snapshot | ConvertTo-Json -Depth 8
# PS 5.1 writes an empty function result as {}: make it null.
$json = [regex]::Replace($json, '(?<=[^\\]"):\s*\{\s*\}', ': null')
if ([System.IO.Path]::IsPathRooted($OutFile)) { $full = $OutFile } else { $full = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutFile)) }
[System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Entra snapshot written to $full" -ForegroundColor Green
if ($script:Errors.Count -gt 0) { Write-Host "$($script:Errors.Count) section(s) could not be collected; affected checks will be marked not evaluated." -ForegroundColor Yellow }
Write-Host "The snapshot contains tenant directory data. Handle it as confidential." -ForegroundColor Yellow
