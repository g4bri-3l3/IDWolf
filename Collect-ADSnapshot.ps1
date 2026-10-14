<#
.SYNOPSIS
    IDWolf collector: read-only Active Directory snapshot using only the
    native ActiveDirectory PowerShell module (RSAT).

.DESCRIPTION
    Writes one JSON snapshot that IDWolf.ps1 analyzes later, anywhere, with
    no further access to the domain.

    Only Get-* cmdlets and a read of SYSVOL: nothing is written to AD and no
    third-party binaries are involved. A standard domain user is enough for
    most of it. Whatever can't be read is recorded, and the checks that
    depended on it show up as "not evaluated" instead of looking clean.
    Passwords found in descriptions are masked here, and SYSVOL hits are kept
    by path only, so no secret ends up in the file.

.PARAMETER Server
    DC or domain to query. Default: whatever the AD module picks.
.PARAMETER OutFile
    Snapshot path. Default: output\adsnapshot_<domain>_<timestamp>.json
.PARAMETER Deep
    Also read the ACL of every user, computer, group and OU. Slow; needs broad read rights.
.PARAMETER Credential
    Account for the AD queries and SYSVOL (for example a delegated auditor).
.PARAMETER SkipSysvol
    Skip the SYSVOL scan for GPP passwords and scripts.
.PARAMETER SkipAcl
    Skip security descriptors (Tier 0 and -Deep).
.PARAMETER SkipAdcs
    Skip AD Certificate Services.
.PARAMETER SkipGpo
    Skip the GPO security settings.
.PARAMETER SkipDns
    Skip DNS zones.
.PARAMETER SkipHealth
    Skip replication, DHCP and backup status.
.PARAMETER InstallModules
    Install RSAT (AD, DNS) if missing, without asking. Needs admin.

.EXAMPLE
    .\Collect-ADSnapshot.ps1
.EXAMPLE
    .\Collect-ADSnapshot.ps1 -Server dc01.corp.local -OutFile .\snap.json
#>

[CmdletBinding()]
Param(
    [string]$Server = "",
    [string]$OutFile = "",
    [switch]$SkipSysvol,
    [switch]$SkipAcl,
    [switch]$SkipAdcs,
    [switch]$SkipGpo,
    [switch]$SkipDns,
    [switch]$SkipHealth,
    [switch]$Deep,
    [switch]$InstallModules,
    [System.Management.Automation.PSCredential]$Credential
)

# -Deep adds the slow part: the ACL of every user, computer, group and OU
# (dangerous ACEs anywhere, LAPS readers). Still read-only, but it wants an
# account with broad read rights. Without it those checks show up as
# "not evaluated".
$ErrorActionPreference = 'Stop'
$script:CollectorVersion = "1.2"
$script:Errors = New-Object System.Collections.Generic.List[object]

function Add-CollectionError {
    param([string]$Section, [string]$Message)
    $script:Errors.Add([PSCustomObject]@{ section = $Section; message = $Message })
    Write-Warning "[$Section] $Message"
}

# FILETIME (int64) -> ISO 8601 UTC string, or $null for "never" / unset.
function ConvertFrom-FileTimeSafe {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { $v = [int64]$Value } catch { return $null }
    if ($v -le 0 -or $v -eq [int64]::MaxValue) { return $null }
    try { return [DateTime]::FromFileTimeUtc($v).ToString('o') } catch { return $null }
}

function ConvertTo-IsoUtc {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('o') } catch { return $null }
}

# Spinner for slow calls, like the Gemini one. The call runs in its own
# runspace so the cursor keeps turning. Redirected output (tests, logs) just
# runs inline; IDWOLF_SPINNER=1 forces the runspace anyway.
function Invoke-WithSpinner {
    param([string]$Message, [scriptblock]$ScriptBlock, [object[]]$ArgumentList = @(), [string[]]$Modules = @())
    $redirected = $true; try { $redirected = [Console]::IsOutputRedirected } catch { }
    if ($redirected -and $env:IDWOLF_SPINNER -ne '1') { return & $ScriptBlock @ArgumentList }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($m in $Modules) { $iss.ImportPSModule($m) }
    $rs = [runspacefactory]::CreateRunspace($iss); $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript('$ErrorActionPreference = "Stop"').AddStatement().AddScript($ScriptBlock.ToString())
    foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
    try {
        $handle = $ps.BeginInvoke()
        $spin = '|', '/', '-', '\'; $i = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $handle.IsCompleted) {
            Write-Host -NoNewline ("`r  {0} {1}  ({2:N0}s)  " -f $Message, $spin[$i++ % 4], $sw.Elapsed.TotalSeconds)
            Start-Sleep -Milliseconds 120
        }
        Write-Host -NoNewline ("`r" + (' ' * ($Message.Length + 24)) + "`r")
        try { return $ps.EndInvoke($handle) }
        catch {
            # Hand back the original error, not the runspace wrapper around it.
            $e = $_.Exception
            while ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
            throw $e
        }
    }
    finally { $ps.Dispose(); $rs.Dispose() }
}

# The leading comma keeps the array whole. Unrolled, an empty result lands in
# [ordered]@{} as AutomationNull, which PS 5.1 serializes as {} and the
# analyzer used to read as a value (empty SPN / RBCD on every account).
function ConvertTo-StringArray {
    param($Value)
    if ($null -eq $Value) { return , [string[]]@() }
    return , [string[]]@($Value | ForEach-Object { if ($null -ne $_) { "$_" } })
}

# Password-in-description check runs here, so a matching description never
# reaches the snapshot. Whole words only: "passaggio" or "Ufficio Crediti"
# must not match.
$script:PasswordHintRegex = '(?i)\b(password|passwd|pass|pwd|pw|psw|kennwort|mdp|mot de passe|contrasena|senha|parola chiave)\b'
function Protect-Description {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @{ text = $Text; suspicious = $false } }
    if ($Text -match $script:PasswordHintRegex) {
        # Keep nothing of it: even a prefix can hold part of the secret ("pw: X...").
        return @{ text = "[masked by collector: $($Text.Length) chars]"; suspicious = $true }
    }
    return @{ text = $Text; suspicious = $false }
}

# False only when Windows says the machine is in a workgroup. If the check
# itself fails, assume joined and let the AD calls report the real problem.
function Test-DomainJoined {
    try { return [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { return $true }
}
$script:WorkgroupNote = "This computer is not joined to a domain. Pass the domain controller (-Server dc01.corp.local) and a domain account (-Credential (Get-Credential CORP\auditor)). The machine also needs DNS that resolves the domain, and TCP 9389 (ADWS), 445 (SYSVOL) and LDAP/RPC to the DC."

# Guided setup when started with no parameters (double-click). -Credential
# alone, as passed by Start-IDWolf.ps1, still gets it.
if (@($PSBoundParameters.Keys | Where-Object { $_ -ne 'Credential' }).Count -eq 0 -and [Environment]::UserInteractive) {
    Write-Host '######################################################################' -ForegroundColor DarkYellow
    Write-Host '#  IDWolf collector (read-only)     interactive setup                #' -ForegroundColor DarkYellow
    Write-Host '######################################################################' -ForegroundColor DarkYellow
    function Read-Default { param([string]$P, [string]$D = "") $s = if ($D) { " [$D]" } else { "" }; $v = Read-Host "$P$s"; if ([string]::IsNullOrWhiteSpace($v)) { $D } else { $v.Trim() } }
    function Read-YesNo { param([string]$P, [bool]$D = $false) $d = if ($D) { 'Y/n' } else { 'y/N' }; $v = Read-Host "$P ($d)"; if ([string]::IsNullOrWhiteSpace($v)) { $D } else { $v -match '^[YySs]' } }
    function Read-Path { param([string]$P, [string]$D = "")
        $label = "$P" + $(if ($D) { " [$D]" } else { "" })
        $rd = $true; try { $rd = [Console]::IsInputRedirected } catch { }
        if ($rd) { $v = Read-Host $label; if ([string]::IsNullOrWhiteSpace($v)) { return $D } return $v.Trim() }
        Write-Host -NoNewline "${label}: "; $buf = ''; $tm = @(); $ti = 0
        while ($true) { $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter') { Write-Host ''; if ([string]::IsNullOrWhiteSpace($buf)) { return $D } return $buf.Trim() }
            elseif ($key.Key -eq 'Backspace') { if ($buf.Length) { $buf = $buf.Substring(0, $buf.Length - 1); Write-Host -NoNewline "`b `b" }; $tm = @() }
            elseif ($key.Key -eq 'Tab') { if ($tm.Count -eq 0) { $hd = $buf -match '[\\/]'; $dir = if ($hd) { Split-Path $buf -Parent } else { '.' }; $leaf = if ($buf) { Split-Path $buf -Leaf } else { '' }; try { $tm = @(Get-ChildItem -LiteralPath $dir -Filter ($leaf + '*') -ErrorAction SilentlyContinue | ForEach-Object { $n = if ($_.PSIsContainer) { $_.Name + [IO.Path]::DirectorySeparatorChar } else { $_.Name }; if ($hd) { Join-Path $dir $n } else { $n } }) } catch { $tm = @() }; $ti = 0 }
                if ($tm.Count) { $c = $tm[$ti % $tm.Count]; $ti++; if ($buf.Length) { Write-Host -NoNewline (("`b" * $buf.Length) + (" " * $buf.Length) + ("`b" * $buf.Length)) }; $buf = $c; Write-Host -NoNewline $buf } }
            elseif ($key.KeyChar -and -not [char]::IsControl($key.KeyChar)) { $buf += $key.KeyChar; Write-Host -NoNewline $key.KeyChar; $tm = @() } }
    }
    Write-Host "Read-only collection. Press Enter to accept the [default]. Tab completes paths." -ForegroundColor Cyan
    if (Test-DomainJoined) { $Server = Read-Default "Domain controller or domain to query (blank = auto)" "" }
    else {
        Write-Host $script:WorkgroupNote -ForegroundColor Yellow
        while (-not $Server) { $Server = Read-Default "Domain controller or domain to query (required on a workgroup PC)" ""; if (-not $Server) { Write-Host "  A name is needed: there is no domain to find automatically." -ForegroundColor Yellow } }
    }
    $OutFile = Read-Path "Output snapshot path (blank = auto timestamped name)" ""
    $Deep = Read-YesNo "Deep collection? (ACL of every user/computer/group/OU, LAPS readers; slow on large domains, needs broad read rights)" $false
    $SkipAdcs = -not (Read-YesNo "Collect AD CS (certificate templates / CAs)?" $true)
    $SkipGpo = -not (Read-YesNo "Collect GPO security settings from SYSVOL?" $true)
    $SkipSysvol = -not (Read-YesNo "Scan SYSVOL for GPP cpassword?" $true)
    $SkipDns = -not (Read-YesNo "Collect DNS zone configuration? (DNS RPC if allowed, otherwise AD-integrated zones over LDAP)" $true)
    if ($Credential) { Write-Host "Using the supplied credentials ($($Credential.UserName)) for the AD queries." -ForegroundColor Cyan }
    elseif (Read-YesNo "Use different credentials for the AD queries? (delegated auditor / admin, lets a standard session read FGPP and run a deep sweep)" (-not (Test-DomainJoined))) {
        try { $Credential = Get-Credential -Message "Credentials for IDWolf read-only collection" } catch { }
    }
    Write-Host ""
}

# Installs RSAT on demand: Add-WindowsCapability on clients, Install-WindowsFeature
# on servers. Needs admin and a couple of GB free on the system drive.
$script:RsatMinFreeGB = 2
function Install-RsatFeature {
    param([string]$Capability, [string]$Feature)
    $pt = 1; try { $pt = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType } catch { }
    $name = if ($pt -eq 1) { $Capability } else { $Feature }

    $isAdmin = $false
    try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
    if (-not $isAdmin) {
        Write-Warning "Cannot install $name : this PowerShell is not elevated. Re-run it as administrator, or have IT install RSAT."
        return $false
    }
    $sysDrive = ($env:SystemDrive -replace ':$', '')
    $freeGB = $null
    try { $freeGB = [math]::Round((Get-PSDrive -Name $sysDrive -ErrorAction Stop).Free / 1GB, 1) } catch { }
    if ($null -ne $freeGB -and $freeGB -lt $script:RsatMinFreeGB) {
        Write-Warning "Cannot install $name : only $freeGB GB free on $($env:SystemDrive) (at least $script:RsatMinFreeGB GB recommended)."
        Write-Host "  Free space first (Disk Cleanup, or 'Dism /Online /Cleanup-Image /StartComponentCleanup' as admin), or run the collector on another domain-joined machine that already has RSAT (admin server, jump host). Only the snapshot JSON needs to come back here." -ForegroundColor Yellow
        return $false
    }
    try {
        if ($pt -eq 1) {
            Write-Host "Installing $Capability (Add-WindowsCapability, may take several minutes)..." -ForegroundColor Cyan
            Add-WindowsCapability -Online -Name $Capability -ErrorAction Stop | Out-Null
        }
        else {
            Write-Host "Installing $Feature (Install-WindowsFeature)..." -ForegroundColor Cyan
            Import-Module ServerManager -ErrorAction SilentlyContinue
            Install-WindowsFeature $Feature -ErrorAction Stop | Out-Null
        }
        return $true
    }
    catch {
        $msg = "$($_.Exception.Message)".Trim()
        Write-Warning "Install of $name failed: $msg"
        # 0x80070070 is ERROR_DISK_FULL; the text match covers localized messages.
        if ($msg -match '0x80070070|not enough space|spazio su disco|espace disque') {
            Write-Host "  The system drive ran out of space during the install. Free at least $script:RsatMinFreeGB GB on $($env:SystemDrive), or run the collector on another domain-joined machine that already has RSAT." -ForegroundColor Yellow
        }
        elseif ($msg -match '0x8024402[cCfF]|0x80244022|0x8024401[bB]|0x80072[eE][eE]2|0x80072[eE][fF][dD]') {
            # Windows Update / WSUS not reachable (0x8024402c and friends).
            Write-Host "  Windows Update / WSUS could not be reached (network, proxy or WSUS). Check 'netsh winhttp show proxy' (import the browser proxy with 'netsh winhttp import proxy source=ie'), ask IT to allow Features on Demand from Windows Update, or install from the FoD ISO with -Source." -ForegroundColor Yellow
            Write-Host "  Simplest alternative: run the collector on a domain-joined machine that already has RSAT; the analyzer does not need it." -ForegroundColor Yellow
        }
        elseif ($msg -match '0x800f0954|0x800f0950|WSUS|source') {
            Write-Host "  Windows could not download the Feature on Demand (often WSUS-managed clients). Ask IT to allow FoD from Windows Update, or install from the FoD ISO with -Source." -ForegroundColor Yellow
        }
        return $false
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Warning "ActiveDirectory module not available (RSAT not installed)."
    $wantInstall = [bool]$InstallModules
    if (-not $wantInstall) {
        $interactive = $false; try { $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected } catch { }
        if ($interactive) { $wantInstall = ((Read-Host "Install the RSAT ActiveDirectory module now? (needs local admin) (y/N)") -match '^[YySs]') }
    }
    $ok = $false
    if ($wantInstall -and (Install-RsatFeature -Capability 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -Feature 'RSAT-AD-PowerShell')) {
        try { Import-Module ActiveDirectory -ErrorAction Stop; $ok = $true } catch { }
    }
    if (-not $ok) {
        # Write-Host on purpose: under Stop, Write-Error would throw a stack trace at the launcher.
        Write-Host "ActiveDirectory module not available. Collection stopped." -ForegroundColor Red
        Write-Host "  Install RSAT (Windows client: 'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'; server: 'Install-WindowsFeature RSAT-AD-PowerShell'), or re-run with -InstallModules as administrator." -ForegroundColor Yellow
        Write-Host "  The analyzer (IDWolf.ps1) does not need RSAT: only the collection must run where the module is available." -ForegroundColor Yellow
        exit 1
    }
}

# A workgroup PC has no domain to find and no domain identity: say so now,
# instead of failing later with a generic "no default server" error.
if (-not (Test-DomainJoined)) {
    if (-not $Server) {
        Write-Host "Collection stopped. $script:WorkgroupNote" -ForegroundColor Red
        exit 1
    }
    if (-not $Credential) {
        Write-Warning "This computer is not in a domain and no -Credential was given: the session has no domain identity, so the queries will probably be denied."
    }
}

$common = @{}
if ($Server) { $common['Server'] = $Server }
# -Credential goes to every Get-AD* call, so you can stay logged on as
# yourself and still read FGPP or run -Deep as a delegated auditor. SYSVOL gets
# a mapped drive with the same account further down.
if ($Credential) { $common['Credential'] = $Credential }

$startedAt = Get-Date
Write-Host "IDWolf collector v$script:CollectorVersion (read-only)" -ForegroundColor Yellow

# --------------------------------------------------------------------------
# Domain and forest. If this fails there is nothing to collect, so let it throw.
# --------------------------------------------------------------------------
try { $domain = Get-ADDomain @common }
catch {
    Write-Host "Could not reach the domain$(if ($Server) { " via $Server" }): $("$($_.Exception.Message)".Trim())" -ForegroundColor Red
    Write-Host "  Check the DC name, DNS resolution of the domain, TCP 9389 (ADWS) to the DC, and the account ($(if ($Credential) { $Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME" }))." -ForegroundColor Yellow
    exit 1
}
$forest = Get-ADForest @common
$rootDse = Get-ADRootDSE @common
$domainDN = $domain.DistinguishedName
$domainSid = $domain.DomainSID.Value
$configNC = $rootDse.configurationNamingContext
$schemaNC = $rootDse.schemaNamingContext

$forestRootSid = $domainSid
if ($forest.RootDomain -ne $domain.DNSRoot) {
    try { $forestRootSid = (Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain).DomainSID.Value }
    catch { Add-CollectionError 'forest' "Could not read forest root domain SID ($($forest.RootDomain)): $($_.Exception.Message). Enterprise/Schema Admins will be matched by name only." ; $forestRootSid = $null }
}

Write-Host "Domain: $($domain.DNSRoot)  Forest: $($forest.Name)"

# --------------------------------------------------------------------------
# Schema probes: asking Get-ADUser for an attribute the schema lacks fails the
# whole query, so optional attributes are checked first.
# --------------------------------------------------------------------------
function Test-SchemaAttribute {
    param([string]$LdapName)
    try {
        return [bool](Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$LdapName)" @common)
    }
    catch {
        Add-CollectionError 'domain.lapsSchema' "Schema probe for $LdapName failed: $($_.Exception.Message)"
        return $false
    }
}
$hasLapsLegacy = Test-SchemaAttribute 'ms-Mcs-AdmPwdExpirationTime'
$hasLapsV2 = Test-SchemaAttribute 'msLAPS-PasswordExpirationTime'
# msDS-KeyCredentialLink needs a 2016+ schema.
$hasKeyCred = Test-SchemaAttribute 'msDS-KeyCredentialLink'
# unixUserPassword comes with the NIS/IDMU schema extension. Only presence is recorded.
$hasUnixPwdAttr = Test-SchemaAttribute 'unixUserPassword'
# RFC 2713 Java object classes (javaSerializedObject and friends) let LDAP clients store serialized
# objects: leftover from old extensions, a deserialization risk. Only class presence is recorded.
$javaSchemaClasses = @()
try {
    foreach ($jc in 'javaContainer', 'javaObject', 'javaSerializedObject', 'javaMarshalledObject', 'javaNamingReference') {
        if (Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(objectClass=classSchema)(lDAPDisplayName=$jc))" @common) { $javaSchemaClasses += $jc }
    }
}
catch { Add-CollectionError 'domain.javaSchema' $_.Exception.Message; $javaSchemaClasses = $null }
# Classes that a user or computer may create under itself (possSuperiors) and that inherit from
# container: any account can then add one and create objects inside it (CVE-2021-34470 with
# msExchStorageGroup). Only the class names and the inheritance chain are recorded.
$possSuperiorClasses = @()
try {
    $psHits = @(Get-ADObject -SearchBase $schemaNC -LDAPFilter '(&(objectClass=classSchema)(|(possSuperiors=computer)(possSuperiors=user)))' -Properties lDAPDisplayName, possSuperiors, subClassOf @common | Where-Object { $_ })
    foreach ($cls in $psHits) {
        $chain = @()
        $parent = "$($cls.subClassOf)"
        while ($parent -and $parent -ne 'top' -and $chain -notcontains $parent -and $chain.Count -lt 20) {
            $chain += $parent
            if ($parent -eq 'container') { break }
            $p = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(objectClass=classSchema)(lDAPDisplayName=$parent))" -Properties subClassOf @common | Select-Object -First 1
            $parent = if ($p) { "$($p.subClassOf)" } else { '' }
        }
        $possSuperiorClasses += [ordered]@{
            name              = "$($cls.lDAPDisplayName)"
            possSuperiors     = @(@($cls.possSuperiors) | Where-Object { @('computer', 'user') -contains "$_" } | ForEach-Object { "$_" })
            subClassChain     = $chain
            inheritsContainer = ($chain -contains 'container')
        }
    }
}
catch { Add-CollectionError 'domain.possSuperiors' $_.Exception.Message; $possSuperiorClasses = $null }

# LAPS attribute GUIDs differ per forest, so look them up for the LAPS-readers check.
function Get-SchemaAttrGuid {
    param([string]$LdapName)
    try {
        $o = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$LdapName)" -Properties schemaIDGUID @common | Select-Object -First 1
        if ($o -and $o.schemaIDGUID) { return ([guid]([byte[]]$o.schemaIDGUID)).ToString().ToLower() }
    }
    catch { }
    return $null
}
$lapsAttrGuids = @()
foreach ($a in 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword') { $g = Get-SchemaAttrGuid $a; if ($g) { $lapsAttrGuids += $g } }

# --------------------------------------------------------------------------
# Domain configuration
# --------------------------------------------------------------------------
$domainInfo = [ordered]@{
    dnsRoot                 = $domain.DNSRoot
    netbios                 = $domain.NetBIOSName
    distinguishedName       = $domainDN
    sid                     = $domainSid
    domainMode              = "$($domain.DomainMode)"
    forestName              = $forest.Name
    forestRootDomain        = $forest.RootDomain
    forestRootSid           = $forestRootSid
    forestMode              = "$($forest.ForestMode)"
    machineAccountQuota     = $null
    dsHeuristics            = $null
    smartcardPwdRotation    = $null
    recycleBinEnabled       = $null
    lapsLegacySchema        = $hasLapsLegacy
    lapsV2Schema            = $hasLapsV2
    javaSchemaClasses       = $javaSchemaClasses
    possSuperiorClasses     = $possSuperiorClasses
    passwordPolicy          = $null
    fineGrainedPolicies     = $null
    authPolicySiloCount     = $null
    subnetCount             = $null
    sysvolReplication       = $null
    lapsAttrGuids           = $lapsAttrGuids
}

try {
    # Authentication policy silos: only counted, to spot "never adopted".
    $silos = @(Get-ADObject -LDAPFilter '(objectClass=msDS-AuthNPolicySilo)' -SearchBase "CN=AuthN Policy Configuration,CN=Services,$configNC" @common)
    $domainInfo.authPolicySiloCount = $silos.Count
}
catch { Add-CollectionError 'domain.authPolicySilos' $_.Exception.Message }

try {
    # Subnets in Sites and Services.
    $subnets = @(Get-ADObject -LDAPFilter '(objectClass=subnet)' -SearchBase "CN=Subnets,CN=Sites,$configNC" @common)
    $domainInfo.subnetCount = $subnets.Count
}
catch { Add-CollectionError 'sites' $_.Exception.Message }

try {
    # No DFSR content set for SYSVOL means it still replicates with FRS.
    $dfsr = $null
    try { $dfsr = Get-ADObject -Identity "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$domainDN" @common -ErrorAction Stop } catch { }
    $domainInfo.sysvolReplication = if ($dfsr) { 'DFSR' } else { 'FRS' }
}
catch { Add-CollectionError 'sysvolReplication' $_.Exception.Message }

try {
    $maq = Get-ADObject -Identity $domainDN -Properties 'ms-DS-MachineAccountQuota' @common
    $domainInfo.machineAccountQuota = $maq.'ms-DS-MachineAccountQuota'
}
catch { Add-CollectionError 'domain.machineAccountQuota' $_.Exception.Message }

# 2016+ domains can roll the hidden password of smart-card-only accounts
# (msDS-ExpirePasswordsOnSmartCardOnlyAccounts); older schemas have no such attribute.
try {
    $scAttr = 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'
    if (Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$scAttr)" @common) {
        $domainInfo.smartcardPwdRotation = [bool](Get-ADObject -Identity $domainDN -Properties $scAttr @common).$scAttr
    }
    else { $domainInfo.smartcardPwdRotation = $false }
}
catch { Add-CollectionError 'domain.smartcardPwdRotation' $_.Exception.Message }

try {
    $ds = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties dSHeuristics @common
    $domainInfo.dsHeuristics = $ds.dSHeuristics
}
catch { Add-CollectionError 'domain.dsHeuristics' $_.Exception.Message }

try {
    $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" @common
    $domainInfo.recycleBinEnabled = [bool]($rb -and @($rb.EnabledScopes).Count -gt 0)
}
catch { Add-CollectionError 'domain.recycleBin' $_.Exception.Message }

try {
    $pp = Get-ADDefaultDomainPasswordPolicy @common
    $domainInfo.passwordPolicy = [ordered]@{
        minPasswordLength           = $pp.MinPasswordLength
        complexityEnabled           = [bool]$pp.ComplexityEnabled
        reversibleEncryptionEnabled = [bool]$pp.ReversibleEncryptionEnabled
        lockoutThreshold            = $pp.LockoutThreshold
        lockoutDurationMinutes      = [int]$pp.LockoutDuration.TotalMinutes
        maxPasswordAgeDays          = [int]$pp.MaxPasswordAge.TotalDays
        minPasswordAgeDays          = [int]$pp.MinPasswordAge.TotalDays
        passwordHistoryCount        = $pp.PasswordHistoryCount
    }
}
catch { Add-CollectionError 'domain.passwordPolicy' $_.Exception.Message }

try {
    # Standard users usually can't read the PSO container, so "none found" is
    # not "none exist". The error recorded here tells the analyzer which.
    $fg = @(Get-ADFineGrainedPasswordPolicy -Filter * @common)
    $domainInfo.fineGrainedPolicies = @($fg | ForEach-Object {
            [ordered]@{
                name                        = $_.Name
                precedence                  = $_.Precedence
                minPasswordLength           = $_.MinPasswordLength
                complexityEnabled           = [bool]$_.ComplexityEnabled
                reversibleEncryptionEnabled = [bool]$_.ReversibleEncryptionEnabled
                lockoutThreshold            = $_.LockoutThreshold
                maxPasswordAgeDays          = [int]$_.MaxPasswordAge.TotalDays
                appliesTo                   = ConvertTo-StringArray $_.AppliesTo
            }
        })
}
catch { Add-CollectionError 'domain.fineGrainedPolicies' $_.Exception.Message }

# --------------------------------------------------------------------------
# Domain controllers and trusts
# --------------------------------------------------------------------------
$dcs = @()
try {
    $dcs = @(Get-ADDomainController -Filter * @common | ForEach-Object {
            [ordered]@{
                name            = $_.Name
                hostName        = $_.HostName
                operatingSystem = $_.OperatingSystem
                osVersion       = $_.OperatingSystemVersion
                isGlobalCatalog = [bool]$_.IsGlobalCatalog
                isReadOnly      = [bool]$_.IsReadOnly
                site            = $_.Site
                fsmoRoles       = ConvertTo-StringArray $_.OperationMasterRoles
                computerDN      = $_.ComputerObjectDN
            }
        })
}
catch { Add-CollectionError 'domainControllers' $_.Exception.Message }

# RODC password replication policy: allowed / denied lists, the accounts whose
# password is already cached (msDS-RevealedList) and who administers the RODC.
# msDS-RevealedList is DN-String syntax: "S:<length>:<string>:<DN>".
function ConvertFrom-DnString {
    param([string]$Value)
    if ($Value -match '^S:(\d+):') {
        $len = [int]$Matches[1]; $start = $Matches[0].Length + $len + 1
        if ($Value.Length -gt $start) { return $Value.Substring($start) }
        return $null
    }
    return $Value
}
foreach ($dc in @($dcs | Where-Object { $_.isReadOnly -and $_.computerDN })) {
    $dc['rodcPolicy'] = $null
    try {
        $o = Get-ADObject -Identity $dc.computerDN -Properties 'msDS-RevealOnDemandGroup', 'msDS-NeverRevealGroup', 'msDS-RevealedList', managedBy @common -ErrorAction Stop
        # ConvertTo-StringArray hands back one array object: a foreach statement walks it, a pipe would not.
        $revealed = @()
        foreach ($v in (ConvertTo-StringArray $o.'msDS-RevealedList')) { $d = ConvertFrom-DnString $v; if ($d -and $revealed -notcontains $d) { $revealed += $d } }
        $dc['rodcPolicy'] = [ordered]@{
            allowed   = ConvertTo-StringArray $o.'msDS-RevealOnDemandGroup'
            denied    = ConvertTo-StringArray $o.'msDS-NeverRevealGroup'
            revealed  = $revealed
            managedBy = "$($o.managedBy)"
        }
    }
    catch { Add-CollectionError 'rodcPolicy' "$($dc.name): $($_.Exception.Message)" }
}

$trusts = @()
try {
    $trusts = @(Get-ADTrust -Filter * @common | ForEach-Object {
            [ordered]@{
                name                    = $_.Name
                target                  = $_.Target
                direction               = "$($_.Direction)"
                trustType               = "$($_.TrustType)"
                trustAttributes         = [int]$_.TrustAttributes
                forestTransitive        = [bool]$_.ForestTransitive
                intraForest             = [bool]$_.IntraForest
                sidFilteringQuarantined = [bool]$_.SIDFilteringQuarantined
                sidFilteringForestAware = [bool]$_.SIDFilteringForestAware
                selectiveAuthentication = [bool]$_.SelectiveAuthentication
                tgtDelegation           = [bool]$_.TGTDelegation
                usesRC4Encryption       = [bool]$_.UsesRC4Encryption
                usesAESKeys             = [bool]$_.UsesAESKeys
                whenChanged             = ConvertTo-IsoUtc $_.whenChanged
            }
        })
}
catch { Add-CollectionError 'trusts' $_.Exception.Message }

# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
$principalProps = @(
    'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated',
    'servicePrincipalName', 'adminCount', 'primaryGroupID', 'description',
    'sIDHistory', 'msDS-SupportedEncryptionTypes', 'msDS-AllowedToDelegateTo',
    'PrincipalsAllowedToDelegateToAccount', 'altSecurityIdentities'
)
if ($hasKeyCred) { $principalProps += 'msDS-KeyCredentialLink' }
$principalProps += 'userPassword'
if ($hasUnixPwdAttr) { $principalProps += 'unixUserPassword' }

# Older AD modules or schemas reject some of these properties and fail the
# whole query. If that happens, retry without them and note the gap.
$script:OptionalExtProps = @('PrincipalsAllowedToDelegateToAccount', 'PrincipalsAllowedToRetrieveManagedPassword', 'msDS-KeyCredentialLink', 'userPassword', 'unixUserPassword')
function Get-WithPropertyFallback {
    param([scriptblock]$Query, [string[]]$Props, [string]$Section)
    $label = 'Reading ' + ($Section -creplace '([A-Z])', ' $1').ToLower()
    try { return @(Invoke-WithSpinner -Message $label -ScriptBlock $Query -ArgumentList $Props, $common -Modules ActiveDirectory) }
    catch {
        $reduced = @($Props | Where-Object { $script:OptionalExtProps -notcontains $_ })
        if ($reduced.Count -eq $Props.Count) { throw }
        Add-CollectionError "rbcd.$Section" "Retrying without optional properties (RBCD / gMSA read principals / key credentials may be incomplete): $($_.Exception.Message)"
        return @(Invoke-WithSpinner -Message $label -ScriptBlock $Query -ArgumentList $reduced, $common -Modules ActiveDirectory)
    }
}

# Explicit certificate mappings (altSecurityIdentities), by type only (KB5014754): the issuer,
# subject, serial or e-mail in the mapping are not kept. Kerberos:principal mappings are skipped.
function ConvertTo-AltSecIdTypes {
    param($Value)
    $out = @()
    foreach ($m in @($Value | Where-Object { $_ })) {
        $s = "$m"
        if ($s -notmatch '^(?i)X509:') { continue }
        $tags = @([regex]::Matches($s, '<([A-Za-z0-9\-]+)>') | ForEach-Object { $_.Groups[1].Value.ToUpper() })
        $out += if ($tags -contains 'SHA1-PUKEY') { 'SHA1PublicKey' } elseif ($tags -contains 'SKI') { 'SKI' } elseif ($tags -contains 'I' -and $tags -contains 'SR') { 'IssuerSerial' } `
            elseif ($tags -contains 'RFC822') { 'RFC822' } elseif ($tags -contains 'I' -and $tags -contains 'S') { 'IssuerSubject' } elseif ($tags -contains 'S') { 'SubjectOnly' } else { 'Other' }
    }
    return , [string[]]@($out)
}

function ConvertTo-PrincipalRecord {
    param($Obj, [string]$Kind)
    $desc = Protect-Description ([string]$Obj.description)
    $rec = [ordered]@{
        kind                  = $Kind
        samAccountName        = $Obj.SamAccountName
        distinguishedName     = $Obj.DistinguishedName
        sid                   = $Obj.SID.Value
        enabled               = [bool]$Obj.Enabled
        userAccountControl    = [int64]$Obj.userAccountControl
        pwdLastSet            = ConvertFrom-FileTimeSafe $Obj.pwdLastSet
        lastLogonTimestamp    = ConvertFrom-FileTimeSafe $Obj.lastLogonTimestamp
        whenCreated           = ConvertTo-IsoUtc $Obj.whenCreated
        servicePrincipalNames = ConvertTo-StringArray $Obj.servicePrincipalName
        adminCount            = $Obj.adminCount
        primaryGroupId        = $Obj.primaryGroupID
        description           = $desc.text
        descriptionSuspicious = $desc.suspicious
        sidHistory            = @($Obj.sIDHistory | ForEach-Object { if ($_ -is [System.Security.Principal.SecurityIdentifier]) { $_.Value } else { "$_" } })
        supportedEncryptionTypes = $Obj.'msDS-SupportedEncryptionTypes'
        allowedToDelegateTo   = ConvertTo-StringArray $Obj.'msDS-AllowedToDelegateTo'
        rbcdPrincipals        = ConvertTo-StringArray $Obj.PrincipalsAllowedToDelegateToAccount
        keyCredentialCount    = @($Obj.'msDS-KeyCredentialLink' | Where-Object { $_ }).Count
        altSecIdTypes         = ConvertTo-AltSecIdTypes $Obj.altSecurityIdentities
        hasUnixPassword       = ((@($Obj.'userPassword' | Where-Object { $_ }).Count -gt 0) -or (@($Obj.'unixUserPassword' | Where-Object { $_ }).Count -gt 0))
    }
    return $rec
}

$users = @()
try {
    Write-Host "Reading users..."
    $raw = Get-WithPropertyFallback -Section 'users' -Props $principalProps -Query { param($p, $c) Get-ADUser -Filter * -Properties $p @c }
    $users = @($raw | ForEach-Object { ConvertTo-PrincipalRecord $_ 'user' })
    Write-Host "  $($users.Count) users"
}
catch { Add-CollectionError 'users' $_.Exception.Message }

# Get-ADUser skips managed service accounts. For gMSAs, also keep who can read the password.
$serviceAccountProps = $principalProps + @('PrincipalsAllowedToRetrieveManagedPassword')
$serviceAccounts = @()
try {
    $raw = Get-WithPropertyFallback -Section 'serviceAccounts' -Props $serviceAccountProps -Query { param($p, $c) Get-ADServiceAccount -Filter * -Properties $p @c }
    $serviceAccounts = @($raw | ForEach-Object {
            $r = ConvertTo-PrincipalRecord $_ 'msa'
            $r['isGroupManaged'] = ($_.ObjectClass -eq 'msDS-GroupManagedServiceAccount')
            $r['gmsaReadPrincipals'] = @($_.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object {
                    if ($null -eq $_) { return }
                    elseif ($_ -is [string]) { $_ }
                    elseif ($_.DistinguishedName) { $_.DistinguishedName }
                    else { "$_" }
                } | Where-Object { $_ })
            $r
        })
}
catch { Add-CollectionError 'serviceAccounts' $_.Exception.Message }

# --------------------------------------------------------------------------
# Computers
# --------------------------------------------------------------------------
$computerProps = $principalProps + @('OperatingSystem', 'OperatingSystemVersion', 'dNSHostName')
if ($hasLapsLegacy) { $computerProps += 'ms-Mcs-AdmPwdExpirationTime' }
if ($hasLapsV2) { $computerProps += 'msLAPS-PasswordExpirationTime' }

$computers = @()
try {
    Write-Host "Reading computers..."
    $raw = Get-WithPropertyFallback -Section 'computers' -Props $computerProps -Query { param($p, $c) Get-ADComputer -Filter * -Properties $p @c }
    $computers = @($raw | ForEach-Object {
            $r = ConvertTo-PrincipalRecord $_ 'computer'
            $r['operatingSystem'] = $_.OperatingSystem
            $r['osVersion'] = $_.OperatingSystemVersion
            $r['dnsHostName'] = $_.dNSHostName
            $r['lapsLegacyExpiry'] = if ($hasLapsLegacy) { ConvertFrom-FileTimeSafe $_.'ms-Mcs-AdmPwdExpirationTime' } else { $null }
            $r['lapsV2Expiry'] = if ($hasLapsV2) { ConvertFrom-FileTimeSafe $_.'msLAPS-PasswordExpirationTime' } else { $null }
            $r
        })
    Write-Host "  $($computers.Count) computers"
}
catch { Add-CollectionError 'computers' $_.Exception.Message }

# --------------------------------------------------------------------------
# Groups, direct members only. The analyzer resolves nesting by DN, which also
# copes with foreign principals that Get-ADGroupMember -Recursive chokes on.
# --------------------------------------------------------------------------
$groups = @()
try {
    Write-Host "Reading groups..."
    $rawGroups = Invoke-WithSpinner -Message 'Reading groups' -ScriptBlock { param($c) Get-ADGroup -Filter * -Properties member, adminCount, description @c } -ArgumentList @(, $common) -Modules ActiveDirectory
    $groups = @($rawGroups | ForEach-Object {
            [ordered]@{
                name              = $_.Name
                samAccountName    = $_.SamAccountName
                distinguishedName = $_.DistinguishedName
                sid               = $_.SID.Value
                groupScope        = "$($_.GroupScope)"
                groupCategory     = "$($_.GroupCategory)"
                adminCount        = $_.adminCount
                members           = ConvertTo-StringArray $_.member
            }
        })
    Write-Host "  $($groups.Count) groups"
}
catch { Add-CollectionError 'groups' $_.Exception.Message }

# Foreign security principals: map CN=<SID> DNs to a readable name.
$fsps = @()
try {
    $fsps = @(Get-ADObject -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -SearchBase "CN=ForeignSecurityPrincipals,$domainDN" @common | ForEach-Object {
            $name = $_.Name
            try { $name = ([System.Security.Principal.SecurityIdentifier]$_.Name).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            [ordered]@{ distinguishedName = $_.DistinguishedName; sid = $_.Name; name = $name }
        })
}
catch { Add-CollectionError 'foreignSecurityPrincipals' $_.Exception.Message }

# --------------------------------------------------------------------------
# Security descriptors of Tier 0 control points
# --------------------------------------------------------------------------
$acls = @()
$sidNames = @{}
function Resolve-SidName {
    param([string]$Sid)
    if ($sidNames.ContainsKey($Sid)) { return $sidNames[$Sid] }
    $n = $Sid
    try { $n = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { }
    $sidNames[$Sid] = $n
    return $n
}

# One object's security descriptor as a plain record; $null (error recorded) if unreadable.
function Read-ObjectSecurity {
    param([string]$Dn, [string]$Target, [string]$ObjectClass = '', [string]$ErrorSection = '')
    try {
        $sd = (Get-ADObject -Identity $Dn -Properties nTSecurityDescriptor @common).nTSecurityDescriptor
        $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $aces = @($sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                $sid = $_.IdentityReference.Value
                [ordered]@{
                    sid                 = $sid
                    name                = Resolve-SidName $sid
                    rights              = "$($_.ActiveDirectoryRights)"
                    accessType          = "$($_.AccessControlType)"
                    objectType          = "$($_.ObjectType)"
                    inheritedObjectType = "$($_.InheritedObjectType)"
                    inheritanceType     = "$($_.InheritanceType)"
                    isInherited         = [bool]$_.IsInherited
                }
            })
        return [ordered]@{ target = $Target; distinguishedName = $Dn; objectClass = $ObjectClass; ownerSid = $owner; ownerName = Resolve-SidName $owner; aces = $aces }
    }
    catch {
        if ($ErrorSection) { Add-CollectionError $ErrorSection "${Target}: $($_.Exception.Message)" } else { Add-CollectionError "acl.$Target" $_.Exception.Message }
        return $null
    }
}

if (-not $SkipAcl) {
    $aclTargets = [ordered]@{
        'DomainRoot'         = $domainDN
        'AdminSDHolder'      = "CN=AdminSDHolder,CN=System,$domainDN"
        'DomainControllersOU' = "OU=Domain Controllers,$domainDN"
    }
    foreach ($rid in @(512, 518, 519, 520, 526, 527)) {
        $g = $groups | Where-Object { $_.sid -eq "$domainSid-$rid" } | Select-Object -First 1
        if ($g) { $aclTargets["Group:$($g.name)"] = $g.distinguishedName }
    }
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-551')) {
        $g = $groups | Where-Object { $_.sid -eq $sid } | Select-Object -First 1
        if ($g) { $aclTargets["Group:$($g.name)"] = $g.distinguishedName }
    }
    # DC computer objects are Tier 0 too: a wrong owner or ACE there is game over.
    foreach ($dc in $dcs) { if ($dc.computerDN) { $aclTargets["DC:$($dc.name)"] = $dc.computerDN } }

    foreach ($key in $aclTargets.Keys) {
        $rec = Read-ObjectSecurity -Dn $aclTargets[$key] -Target $key
        if ($rec) { $acls += $rec }
    }
}

# OUs and top-level containers (not -Deep): who can create objects in them. A non-Tier 0
# principal that can create a dMSA can take over any account through it (BadSuccessor).
# Only explicit Allow ACEs that grant create or control rights are kept: inherited ones
# come from a parent that is read too (the domain head is in the Tier 0 set above).
$ouAcls = @()
if (-not $SkipAcl) {
    try {
        $ouObjs = @(Get-ADObject -LDAPFilter '(objectClass=organizationalUnit)' @common | Where-Object { $_ })
        $ouObjs += @(Get-ADObject -SearchBase $domainDN -SearchScope OneLevel -LDAPFilter '(objectClass=container)' @common | Where-Object { $_ })
        foreach ($o in $ouObjs) {
            $rec = Read-ObjectSecurity -Dn $o.DistinguishedName -Target "ou:$($o.DistinguishedName)" -ObjectClass "$($o.ObjectClass)" -ErrorSection 'ouAcls'
            if (-not $rec) { continue }
            $rec.aces = @($rec.aces | Where-Object { -not $_.isInherited -and $_.accessType -eq 'Allow' -and $_.rights -match 'CreateChild|GenericAll|WriteDacl|WriteOwner' })
            $ouAcls += $rec
        }
        Write-Host "  $($ouAcls.Count) OU and container security descriptors read"
    }
    catch { Add-CollectionError 'ouAcls' $_.Exception.Message }
}

# --------------------------------------------------------------------------
# Deep ACL sweep (-Deep): every user, computer, group and OU. Slow and needs
# broad read rights, so it's opt-in.
# --------------------------------------------------------------------------
$deepAcls = @()
if ($Deep -and -not $SkipAcl) {
    Write-Host "Deep ACL sweep (this can take a while on a large domain)..."
    try {
        $sweep = @(Invoke-WithSpinner -Message 'Reading security descriptors' -Modules ActiveDirectory -ArgumentList @(, $common) -ScriptBlock {
                param($c) Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))' -Properties nTSecurityDescriptor, objectClass @c })
        $done = 0
        foreach ($o in $sweep) {
            $rec = Read-ObjectSecurity -Dn $o.DistinguishedName -Target "obj:$($o.DistinguishedName)" -ObjectClass "$($o.ObjectClass)"
            if ($rec) { $deepAcls += $rec }
            $done++
            if ($done % 500 -eq 0) { Write-Progress -Activity 'Deep ACL sweep' -Status "$done of $($sweep.Count)" -PercentComplete ([int](($done / [Math]::Max(1, $sweep.Count)) * 100)) }
        }
        Write-Progress -Activity 'Deep ACL sweep' -Completed
        Write-Host "  $($deepAcls.Count) object security descriptors read"
    }
    catch { Add-CollectionError 'deepAcls' $_.Exception.Message }
}

# KDS root keys (-Deep): whoever reads one can compute every gMSA password of the forest
# (Golden gMSA). Only the security descriptors are read, never the key data.
$kdsRootKeyAcls = @()
if ($Deep -and -not $SkipAcl) {
    try {
        $kdsBase = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configNC"
        foreach ($k in @(Get-ADObject -SearchBase $kdsBase -SearchScope OneLevel -LDAPFilter '(objectClass=msKds-ProvRootKey)' @common | Where-Object { $_ })) {
            $rec = Read-ObjectSecurity -Dn $k.DistinguishedName -Target "kds:$($k.Name)" -ObjectClass 'msKds-ProvRootKey' -ErrorSection 'kdsRootKeys'
            if ($rec) { $kdsRootKeyAcls += $rec }
        }
    }
    catch { Add-CollectionError 'kdsRootKeys' $_.Exception.Message }
}

# Pre-Windows 2000 Compatible Access (by SID): bad news if Anonymous or Everyone is in it.
$preWin2000 = $null
try {
    $g = Get-ADGroup -Identity 'S-1-5-32-554' -Properties member @common -ErrorAction Stop
    $preWin2000 = [ordered]@{ name = $g.Name; distinguishedName = $g.DistinguishedName; members = ConvertTo-StringArray $g.member }
}
catch { Add-CollectionError 'preWin2000Group' $_.Exception.Message }

# With -Credential, mapping SYSVOL once authenticates the later UNC reads too.
$sysvolDrive = $null
if ($Credential) {
    try { $sysvolDrive = New-PSDrive -Name IDWolfSysvol -PSProvider FileSystem -Root "\\$($domain.DNSRoot)\SYSVOL" -Credential $Credential -Scope Script -ErrorAction Stop }
    catch { Add-CollectionError 'sysvol.credential' "Could not map SYSVOL with supplied credentials: $($_.Exception.Message). Using the current context for SYSVOL/GPO." }
}

# --------------------------------------------------------------------------
# SYSVOL: Group Policy Preferences cpassword (MS14-025). Path only.
# --------------------------------------------------------------------------
$sysvol = [ordered]@{ scanned = $false; cpasswordFiles = @(); scriptSecretFiles = @(); autologonFiles = @(); folderAcls = @() }
if (-not $SkipSysvol) {
    $policiesPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
    $sysvolRoot = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)"
    try {
        if (Test-Path -LiteralPath $policiesPath) {
            Write-Host "Scanning SYSVOL for GPP cpassword..."
            $hits = @(Get-ChildItem -LiteralPath $policiesPath -Recurse -Include *.xml -File -ErrorAction SilentlyContinue |
                    Select-String -Pattern 'cpassword="[^"]+"' -List -ErrorAction SilentlyContinue)
            $sysvol.cpasswordFiles = @($hits | ForEach-Object { $_.Path })
            # GPP registry item writing Winlogon DefaultPassword in clear text: path only.
            $alHits = @(Get-ChildItem -LiteralPath $policiesPath -Recurse -Filter 'Registry.xml' -File -ErrorAction SilentlyContinue |
                    Select-String -Pattern 'name="DefaultPassword"' -List -ErrorAction SilentlyContinue)
            $sysvol.autologonFiles = @($alHits | ForEach-Object { $_.Path })
            # Scripts that mention a password: path only, never the value.
            try {
                $scriptHits = @(Get-ChildItem -LiteralPath $sysvolRoot -Recurse -Include *.bat, *.cmd, *.ps1, *.vbs, *.kix -File -ErrorAction SilentlyContinue |
                        Select-String -Pattern $script:PasswordHintRegex -List -ErrorAction SilentlyContinue)
                $sysvol.scriptSecretFiles = @($scriptHits | ForEach-Object { $_.Path })
            }
            catch { }
            # NTFS permissions of the two folders every computer runs code from (logon scripts, GPO files).
            foreach ($fd in @(@('NETLOGON (scripts)', (Join-Path $sysvolRoot 'scripts')), @('Policies', $policiesPath))) {
                try {
                    $fAcl = Get-Acl -LiteralPath $fd[1] -ErrorAction Stop
                    $sysvol.folderAcls += [ordered]@{
                        folder = $fd[0]; path = $fd[1]
                        aces   = @($fAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                                [ordered]@{ sid = "$($_.IdentityReference.Value)"; name = Resolve-SidName "$($_.IdentityReference.Value)"; rights = "$($_.FileSystemRights)"; accessType = "$($_.AccessControlType)"; isInherited = [bool]$_.IsInherited } })
                    }
                }
                catch { Add-CollectionError 'sysvol.acl' "$($fd[1]): $($_.Exception.Message)" }
            }
            $sysvol.scanned = $true
        }
        else { Add-CollectionError 'sysvol' "Path not reachable: $policiesPath" }
    }
    catch { Add-CollectionError 'sysvol' $_.Exception.Message }
}

# --------------------------------------------------------------------------
# AD CS, from the Configuration partition: CAs, templates (flags, EKUs, ACLs),
# the NTAuth store and the ACLs of the PKI objects, enough for the ESC checks.
# ESC6/7/8/11/16 live on the CA itself, not in LDAP, so they are only flagged
# for manual review.
# --------------------------------------------------------------------------
# RPC filters (netsh rpc filter) are persistent WFP filters kept by BFE in the registry. Look
# for the coercion interface UUIDs inside them: the names of the interfaces some filter
# mentions, or $null when the filter store can't be read. Heuristic: a filter that names
# an interface is taken as covering it; its action and conditions are not decoded.
$script:CoercionUuids = [ordered]@{
    'MS-EFSR' = @('c681d488-d850-11d0-8c52-00c04fd90f7e', 'df1941c5-fe89-4e79-bf10-463657acf44d')
    'MS-DFSNM' = @('4fc742e0-4a10-11cf-8273-00aa004ae673')
    'MS-EVEN' = @('82273fdc-e32a-18c3-3f78-827929dc23ea')
}
function Get-RpcFilterInterfaces {
    param($CimSession)
    $hklm = [uint32]2147483650
    $key = 'SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter'
    try {
        $list = Invoke-CimMethod -CimSession $CimSession -Namespace 'root/default' -ClassName StdRegProv -MethodName EnumValues -Arguments @{ hDefKey = $hklm; sSubKeyName = $key } -OperationTimeoutSec 20 -ErrorAction Stop
        if (-not $list -or $list.ReturnValue -ne 0) { return $null }
        $patterns = @{}
        foreach ($i in $script:CoercionUuids.Keys) { $patterns[$i] = @($script:CoercionUuids[$i] | ForEach-Object { [BitConverter]::ToString(([guid]$_).ToByteArray()) }) }
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($vn in @($list.sNames | Select-Object -First 2000)) {
            $v = Invoke-CimMethod -CimSession $CimSession -Namespace 'root/default' -ClassName StdRegProv -MethodName GetBinaryValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $key; sValueName = "$vn" } -OperationTimeoutSec 20 -ErrorAction Stop
            if (-not $v -or $v.ReturnValue -ne 0 -or -not $v.uValue) { continue }
            $hex = [BitConverter]::ToString([byte[]]$v.uValue)
            foreach ($i in $patterns.Keys) { if (-not $found.Contains($i) -and @($patterns[$i] | Where-Object { $hex.Contains($_) }).Count) { $found.Add($i) } }
        }
        return , @($found | Sort-Object)
    }
    catch { return $null }
}

# On-CA registry settings of one CA. error is set (and the rest left $null) when the CA host
# can't be read; webEnrollment is $null when the installed roles can't be told apart.
function Read-CaRegistry {
    param([string]$HostName, [string]$CaName)
    $r = [ordered]@{ editFlags = $null; interfaceFlags = $null; disableExtensionList = @(); securityAces = @(); webEnrollment = $null; enrollmentWebService = $null; error = '' }
    if (-not $HostName) { $r.error = 'no DNS host name on the enrollment service'; return $r }
    $hklm = [uint32]2147483650
    $cs = $null
    try {
        $cp = @{ ComputerName = $HostName; OperationTimeoutSec = 20; ErrorAction = 'Stop' }
        if ($Credential) { $cp['Credential'] = $Credential }
        $cs = New-CimSession @cp
        $cfg = 'SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
        # The configuration key is named after the active CA (sanitized name), so ask for it.
        $act = Invoke-CimMethod -CimSession $cs -Namespace 'root/default' -ClassName StdRegProv -MethodName GetStringValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $cfg; sValueName = 'Active' } -OperationTimeoutSec 20 -ErrorAction Stop
        $caKey = if ($act -and $act.ReturnValue -eq 0 -and $act.sValue) { "$cfg\$($act.sValue)" } else { "$cfg\$CaName" }
        $pol = Invoke-CimMethod -CimSession $cs -Namespace 'root/default' -ClassName StdRegProv -MethodName GetStringValue -Arguments @{ hDefKey = $hklm; sSubKeyName = "$caKey\PolicyModules"; sValueName = 'Active' } -OperationTimeoutSec 20 -ErrorAction Stop
        $polKey = "$caKey\PolicyModules\$(if ($pol -and $pol.ReturnValue -eq 0 -and $pol.sValue) { $pol.sValue } else { 'CertificateAuthority_MicrosoftDefault.Policy' })"
        $v = Invoke-CimMethod -CimSession $cs -Namespace 'root/default' -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $polKey; sValueName = 'EditFlags' } -OperationTimeoutSec 20 -ErrorAction Stop
        if ($v.ReturnValue -ne 0) { throw "CA configuration not found under HKLM\$caKey (is $HostName the CA host?)" }
        $r.editFlags = [int64]$v.uValue
        $v = Invoke-CimMethod -CimSession $cs -Namespace 'root/default' -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $caKey; sValueName = 'InterfaceFlags' } -OperationTimeoutSec 20 -ErrorAction Stop
        if ($v.ReturnValue -eq 0) { $r.interfaceFlags = [int64]$v.uValue }
        $v = Invoke-CimMethod -CimSession $cs -Namespace 'root/default' -ClassName StdRegProv -MethodName GetMultiStringValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $polKey; sValueName = 'DisableExtensionList' } -OperationTimeoutSec 20 -ErrorAction Stop
        if ($v.ReturnValue -eq 0) { $r.disableExtensionList = @($v.sValue | Where-Object { $_ } | ForEach-Object { "$_" }) }
        # CA permissions (Manage CA = 1, Issue and Manage Certificates = 2, Read = 0x100, Enroll = 0x200).
        $v = Invoke-CimMethod -CimSession $cs -Namespace 'root/default' -ClassName StdRegProv -MethodName GetBinaryValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $caKey; sValueName = 'Security' } -OperationTimeoutSec 20 -ErrorAction Stop
        if ($v.ReturnValue -eq 0 -and $v.uValue) {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ([byte[]]$v.uValue), 0
            $r.securityAces = @($sd.DiscretionaryAcl | Where-Object { $_.AceQualifier -eq 'AccessAllowed' -and $_.SecurityIdentifier } | ForEach-Object {
                    [ordered]@{ sid = "$($_.SecurityIdentifier.Value)"; name = Resolve-SidName "$($_.SecurityIdentifier.Value)"; mask = [int64]$_.AccessMask } })
        }
        else { $r.securityAces = $null }
        # Web enrollment (ESC8). Role names are only trusted in English: on a localized OS the
        # answer stays unknown rather than "not installed".
        $feat = @(Get-CimInstance -CimSession $cs -ClassName Win32_ServerFeature -OperationTimeoutSec 20 -ErrorAction Stop | ForEach-Object { "$($_.Name)" })
        if (@($feat | Where-Object { $_ -match '^Certification Authority$|Active Directory Certificate Services' }).Count) {
            $r.webEnrollment = [bool]@($feat | Where-Object { $_ -match 'Certification Authority Web Enrollment' }).Count
            $r.enrollmentWebService = [bool]@($feat | Where-Object { $_ -match 'Certificate Enrollment Web Service' }).Count
        }
    }
    catch { $r.error = "$($_.Exception.Message)".Trim() }
    finally { if ($cs) { Remove-CimSession $cs -ErrorAction SilentlyContinue } }
    return $r
}

$adcs = [ordered]@{ collected = $false; enrollmentServices = @(); templates = @(); ntAuthCertCount = $null; oidGroupLinks = @(); pkiAcls = @() }
if (-not $SkipAdcs) {
    $pkiBase = "CN=Public Key Services,CN=Services,$configNC"
    try {
        if (Get-ADObject -Identity $pkiBase @common -ErrorAction Stop) {
            Write-Host "Reading AD CS (certificate templates and CAs)..."
            # Enrollment services are the CAs and the templates they publish.
            $enrollBase = "CN=Enrollment Services,$pkiBase"
            $enroll = @()
            try {
                $enroll = @(Get-ADObject -SearchBase $enrollBase -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates, cACertificate, flags, name @common | ForEach-Object {
                        $caCertExpiry = $null; $caKeySize = $null; $caSigAlg = $null
                        try {
                            $bytes = @($_.cACertificate)[-1]
                            if ($bytes) {
                                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([byte[]]$bytes)
                                $caCertExpiry = $cert.NotAfter.ToUniversalTime().ToString('o')
                                try { $caKeySize = $cert.PublicKey.Key.KeySize } catch { try { $caKeySize = $cert.GetRSAPublicKey().KeySize } catch { } }
                                $caSigAlg = $cert.SignatureAlgorithm.FriendlyName
                            }
                        }
                        catch { }
                        [ordered]@{
                            name              = $_.name
                            distinguishedName = $_.DistinguishedName
                            dnsHostName       = $_.dNSHostName
                            flags             = [int]$_.flags
                            publishedTemplates = ConvertTo-StringArray $_.certificateTemplates
                            caCertExpiry      = $caCertExpiry
                            caKeySize         = $caKeySize
                            caSigAlg          = $caSigAlg
                        }
                    })
            }
            catch { Add-CollectionError 'adcs.enrollmentServices' $_.Exception.Message }

            $publishedSet = @{}
            foreach ($e in $enroll) { foreach ($t in $e.publishedTemplates) { $publishedSet[$t] = $true } }

            $tmplBase = "CN=Certificate Templates,$pkiBase"
            $templates = @()
            try {
                $templates = @(Get-ADObject -SearchBase $tmplBase -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties displayName, name, nTSecurityDescriptor, 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'msPKI-Certificate-Application-Policy', pKIExtendedKeyUsage, 'msPKI-Template-Schema-Version', 'msPKI-Certificate-Policy' @common | ForEach-Object {
                        $sd = $_.nTSecurityDescriptor
                        $enrollAces = @()
                        $owner = $null
                        if ($sd) {
                            try { $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }
                            $enrollAces = @($sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                                    [ordered]@{
                                        sid         = $_.IdentityReference.Value
                                        name        = Resolve-SidName $_.IdentityReference.Value
                                        rights      = "$($_.ActiveDirectoryRights)"
                                        accessType  = "$($_.AccessControlType)"
                                        objectType  = "$($_.ObjectType)"
                                        isInherited = [bool]$_.IsInherited
                                    }
                                })
                        }
                        [ordered]@{
                            name              = $_.name
                            displayName       = $_.displayName
                            schemaVersion     = [int]$_.'msPKI-Template-Schema-Version'
                            nameFlag          = [int64]$_.'msPKI-Certificate-Name-Flag'
                            enrollmentFlag    = [int64]$_.'msPKI-Enrollment-Flag'
                            raSignature       = [int]$_.'msPKI-RA-Signature'
                            ekus              = @((ConvertTo-StringArray $_.pKIExtendedKeyUsage) + (ConvertTo-StringArray $_.'msPKI-Certificate-Application-Policy') | Select-Object -Unique)
                            issuancePolicies  = ConvertTo-StringArray $_.'msPKI-Certificate-Policy'
                            published         = [bool]$publishedSet[$_.name]
                            ownerSid          = $owner
                            ownerName         = if ($owner) { Resolve-SidName $owner } else { $null }
                            aces              = $enrollAces
                        }
                    })
            }
            catch { Add-CollectionError 'adcs.templates' $_.Exception.Message }

            try {
                $ntauth = Get-ADObject -Identity "CN=NTAuthCertificates,$pkiBase" -Properties cACertificate @common
                $adcs.ntAuthCertCount = @($ntauth.cACertificate).Count
            }
            catch { $adcs.ntAuthCertCount = $null }   # optional, not used by any check; do not flag a gap

            # Issuance policies linked to a group (msDS-OIDToGroupLink), for ESC13.
            try {
                $oidBase = "CN=OID,$pkiBase"
                $adcs.oidGroupLinks = @(Get-ADObject -SearchBase $oidBase -LDAPFilter '(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))' -Properties 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink', displayName @common | ForEach-Object {
                        [ordered]@{ oid = "$($_.'msPKI-Cert-Template-OID')"; groupDn = "$($_.'msDS-OIDToGroupLink')"; name = $_.displayName }
                    })
            }
            catch { Add-CollectionError 'adcs.oidGroupLinks' $_.Exception.Message }

            # ESC5: who controls the PKI containers, the NTAuth store, each CA object and each CA server.
            $pkiTargets = [ordered]@{
                'Public Key Services'       = $pkiBase
                'Certificate Templates'     = $tmplBase
                'Enrollment Services'       = $enrollBase
                'Certification Authorities' = "CN=Certification Authorities,$pkiBase"
                'AIA'                       = "CN=AIA,$pkiBase"
                'CDP'                       = "CN=CDP,$pkiBase"
                'OID'                       = "CN=OID,$pkiBase"
                'NTAuthCertificates'        = "CN=NTAuthCertificates,$pkiBase"
            }
            foreach ($e in $enroll) {
                if ($e.distinguishedName) { $pkiTargets["CA:$($e.name)"] = $e.distinguishedName }
                $caComputer = @($computers | Where-Object { $_.dnsHostName -and $e.dnsHostName -and "$($_.dnsHostName)" -ieq "$($e.dnsHostName)" }) | Select-Object -First 1
                if ($caComputer) { $pkiTargets["CA host:$($caComputer.samAccountName)"] = $caComputer.distinguishedName }
            }
            $pkiAcls = @()
            foreach ($k in $pkiTargets.Keys) {
                $rec = Read-ObjectSecurity -Dn $pkiTargets[$k] -Target $k -ErrorSection 'adcs.pkiAcls'
                if ($rec) { $pkiAcls += $rec }
            }
            $adcs.pkiAcls = $pkiAcls

            # On-CA settings (ESC6/7/8/11/16) live in the CA's registry, not in LDAP. Read them over
            # CIM on the CA host, read-only (StdRegProv Get* methods). Needs admin rights on the CA.
            foreach ($e in $enroll) {
                $e['caRegistry'] = Read-CaRegistry -HostName "$($e.dnsHostName)" -CaName "$($e.name)"
                if ($e['caRegistry'].error) { Add-CollectionError 'adcs.caRegistry' "$($e.name) on $($e.dnsHostName): $($e['caRegistry'].error)" }
            }

            $adcs.enrollmentServices = $enroll
            $adcs.templates = $templates
            $adcs.collected = $true
        }
    }
    catch {
        # No Public Key Services container: AD CS isn't deployed.
        $adcs.collected = $false
        $adcs.notDeployed = $true
    }
}

# --------------------------------------------------------------------------
# GPO security settings, read from SYSVOL. The host hardening that matters
# (SMB/LDAP signing, NTLM, user rights, audit) lives in each GPO's GptTmpl.inf,
# registry.pol and audit.csv, not in LDAP. Link order on the domain root and the
# DC OU is kept too, so the analyzer can work out the effective DC setting.
# --------------------------------------------------------------------------
# registry.pol (PReg) into "MACHINE\<key>\<value>" => "<type>,<data>", the same
# shape as GptTmpl.inf registry values. Best effort: a parse error returns what
# was read so far.
function ConvertFrom-RegistryPol {
    param([string]$Path, [string]$Hive = 'MACHINE')
    $out = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $out }
    try { $b = [System.IO.File]::ReadAllBytes($Path) } catch { return $out }
    if ($b.Length -lt 8 -or $b[0] -ne 0x50 -or $b[1] -ne 0x52 -or $b[2] -ne 0x65 -or $b[3] -ne 0x67) { return $out }
    $enc = [System.Text.Encoding]::Unicode
    $readStr = {
        param([int]$start)
        $j = $start
        while ($j + 1 -lt $b.Length -and -not ($b[$j] -eq 0 -and $b[$j + 1] -eq 0)) { $j += 2 }
        return , @(($enc.GetString($b, $start, $j - $start)), ($j + 2))
    }
    $pos = 8
    try {
        while ($pos + 2 -le $b.Length) {
            if (-not ($b[$pos] -eq 0x5B -and $b[$pos + 1] -eq 0)) { break }   # '['
            $pos += 2
            $r = & $readStr $pos; $key = $r[0]; $pos = $r[1]
            $pos += 2                                                          # ';'
            $r = & $readStr $pos; $val = $r[0]; $pos = $r[1]
            $pos += 2                                                          # ';'
            if ($pos + 4 -gt $b.Length) { break }
            $type = [System.BitConverter]::ToInt32($b, $pos); $pos += 4
            $pos += 2                                                          # ';'
            if ($pos + 4 -gt $b.Length) { break }
            $size = [System.BitConverter]::ToInt32($b, $pos); $pos += 4
            $pos += 2                                                          # ';'
            if ($size -lt 0 -or $pos + $size -gt $b.Length) { break }
            $data = $null
            if ($type -eq 4 -and $size -ge 4) { $data = [System.BitConverter]::ToInt32($b, $pos) }
            elseif (($type -eq 1 -or $type -eq 2) -and $size -ge 2) { $data = ($enc.GetString($b, $pos, $size)).TrimEnd([char]0) }
            $pos += $size
            $pos += 2                                                          # ']'
            if ($key -and $val) {
                $full = "$Hive\$key\$val"
                if ($type -eq 4) { $out[$full] = "4,$data" } else { $out[$full] = "1,$data" }
            }
        }
    }
    catch { }
    return $out
}

function ConvertFrom-IniText {
    param([string[]]$Lines)
    $result = [ordered]@{}
    $section = ''
    foreach ($raw in $Lines) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[(.+)\]$') { $section = $Matches[1]; if (-not $result.Contains($section)) { $result[$section] = New-Object System.Collections.Generic.List[string] }; continue }
        if ($section) { $result[$section].Add($line) }
    }
    return $result
}

# gPLink into ordered {guid, enforced, enabled}. Option bits: 1 disabled, 2 enforced.
function Parse-GpLink {
    param([string]$Value)
    $out = @()
    if (-not $Value) { return $out }
    foreach ($m in [regex]::Matches($Value, '\[LDAP://(?<dn>[^;]+);(?<opt>\d+)\]')) {
        $dn = $m.Groups['dn'].Value
        $guid = if ($dn -match '\{[0-9A-Fa-f\-]{36}\}') { $Matches[0].ToUpper() } else { $dn }
        $opt = [int]$m.Groups['opt'].Value
        $out += [ordered]@{ guid = $guid; enabled = (($opt -band 1) -eq 0); enforced = (($opt -band 2) -ne 0) }
    }
    return $out
}

# One GPO folder: what it runs (scripts.ini / psscripts.ini, GPP scheduled
# tasks) and which local groups it fills (GPP Groups.xml, Restricted Groups in
# GptTmpl.inf). Adds to the two lists passed in.
function Read-GpoExtras {
    param([string]$Dir, [string]$Guid, [string]$Name, $Exec, $Groups)
    foreach ($scope in 'Machine', 'User') {
        foreach ($iniName in 'scripts.ini', 'psscripts.ini') {
            $p = Join-Path $Dir "$scope\Scripts\$iniName"
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $ini = ConvertFrom-IniText -Lines (Get-Content -LiteralPath $p -ErrorAction Stop)
            foreach ($sec in $ini.Keys) {
                foreach ($l in $ini[$sec]) {
                    if ($l -match '^\d+CmdLine=(.+)$') { $Exec.Add([ordered]@{ guid = $Guid; gpo = $Name; scope = $scope; kind = "$sec script"; command = $Matches[1].Trim() }) }
                }
            }
        }
        $st = Join-Path $Dir "$scope\Preferences\ScheduledTasks\ScheduledTasks.xml"
        if (Test-Path -LiteralPath $st) {
            $x = New-Object System.Xml.XmlDocument
            $x.LoadXml((Get-Content -LiteralPath $st -Raw -ErrorAction Stop))
            # Old task format: appName; Task(V2) format: Exec/Command.
            foreach ($n in @($x.SelectNodes('//Properties[@appName]'))) {
                $Exec.Add([ordered]@{ guid = $Guid; gpo = $Name; scope = $scope; kind = "scheduled task '$($n.ParentNode.GetAttribute('name'))'"; command = $n.GetAttribute('appName') })
            }
            foreach ($n in @($x.SelectNodes('//Exec/Command'))) {
                $owner = $n.SelectSingleNode('ancestor::*[@name][1]')
                $Exec.Add([ordered]@{ guid = $Guid; gpo = $Name; scope = $scope; kind = "scheduled task '$(if ($owner) { $owner.GetAttribute('name') })'"; command = $n.InnerText.Trim() })
            }
        }
        $gx = Join-Path $Dir "$scope\Preferences\Groups\Groups.xml"
        if (Test-Path -LiteralPath $gx) {
            $x = New-Object System.Xml.XmlDocument
            $x.LoadXml((Get-Content -LiteralPath $gx -Raw -ErrorAction Stop))
            foreach ($pn in @($x.SelectNodes('//Group/Properties'))) {
                $grp = if ($pn.GetAttribute('groupSid')) { $pn.GetAttribute('groupSid') } else { $pn.GetAttribute('groupName') }
                foreach ($m in @($pn.SelectNodes('Members/Member[@action="ADD"]'))) {
                    $Groups.Add([ordered]@{ guid = $Guid; gpo = $Name; source = 'Preferences'; group = $grp; member = $(if ($m.GetAttribute('sid')) { $m.GetAttribute('sid') } else { $m.GetAttribute('name') }); memberName = $m.GetAttribute('name') })
                }
            }
        }
    }
    # Restricted Groups: "*S-1-5-32-544__Members = *S-1-5-11" or "*X__Memberof = *S-1-5-32-544".
    $inf = Join-Path $Dir 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (Test-Path -LiteralPath $inf) {
        $ini = ConvertFrom-IniText -Lines (Get-Content -LiteralPath $inf -ErrorAction Stop)
        foreach ($l in @($ini['Group Membership'] | Where-Object { $_ })) {
            if ($l -notmatch '^\*?(?<left>.+?)__(?<rel>Members|Memberof)\s*=\s*(?<right>.*)$') { continue }
            $left = $Matches['left'].Trim(); $rel = $Matches['rel']
            foreach ($r in @($Matches['right'].Split(',') | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })) {
                $pair = if ($rel -eq 'Members') { @($left, $r) } else { @($r, $left) }
                $Groups.Add([ordered]@{ guid = $Guid; gpo = $Name; source = 'Restricted Groups'; group = $pair[0]; member = $pair[1]; memberName = $pair[1] })
            }
        }
    }
}

$gpoData = [ordered]@{ collected = $false; gpos = @(); domainRootLinks = @(); dcOuLinks = @(); execution = @(); localGroups = @() }
if (-not $SkipGpo) {
    try {
        # Link order on the domain root and the DC OU, most specific last.
        try {
            $rootObj = Get-ADObject -Identity $domainDN -Properties gPLink @common
            $gpoData.domainRootLinks = @(Parse-GpLink $rootObj.gPLink)
        }
        catch { Add-CollectionError 'gpo.domainRootLink' $_.Exception.Message }
        try {
            $dcOu = Get-ADObject -Identity "OU=Domain Controllers,$domainDN" -Properties gPLink @common
            $gpoData.dcOuLinks = @(Parse-GpLink $dcOu.gPLink)
        }
        catch { Add-CollectionError 'gpo.dcOuLink' $_.Exception.Message }

        # GPO names and ACLs, to catch non-admins who can edit a GPO linked to Tier 0.
        $gpoNames = @{}
        $gpoAcls = @{}
        try {
            foreach ($g in Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase "CN=Policies,CN=System,$domainDN" -Properties displayName, nTSecurityDescriptor @common) {
                $key = $g.Name.ToUpper()
                $gpoNames[$key] = $g.displayName
                try {
                    $sd = $g.nTSecurityDescriptor
                    if ($sd) {
                        $owner = $null
                        try { $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }
                        $aces = @($sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                                $sid = $_.IdentityReference.Value
                                [ordered]@{
                                    sid         = $sid
                                    name        = Resolve-SidName $sid
                                    rights      = "$($_.ActiveDirectoryRights)"
                                    accessType  = "$($_.AccessControlType)"
                                    objectType  = "$($_.ObjectType)"
                                    isInherited = [bool]$_.IsInherited
                                }
                            })
                        $gpoAcls[$key] = [ordered]@{ ownerSid = $owner; ownerName = if ($owner) { Resolve-SidName $owner } else { $null }; aces = $aces }
                    }
                }
                catch { Add-CollectionError "gpo.acl.$($g.Name)" $_.Exception.Message }
            }
        }
        catch { Add-CollectionError 'gpo.names' $_.Exception.Message }

        $policiesPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
        if (Test-Path -LiteralPath $policiesPath) {
            Write-Host "Reading GPO security templates from SYSVOL..."
            $gpos = @()
            foreach ($dir in Get-ChildItem -LiteralPath $policiesPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' }) {
                # A GPO made only of administrative templates has registry.pol and no
                # security template: it still sets registry values (LLMNR, Point and Print...).
                $inf = Join-Path $dir.FullName 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
                $pol = Join-Path $dir.FullName 'Machine\registry.pol'
                $userPol = Join-Path $dir.FullName 'User\registry.pol'
                $hasInf = Test-Path -LiteralPath $inf
                if (-not $hasInf -and -not (Test-Path -LiteralPath $pol) -and -not (Test-Path -LiteralPath $userPol)) { continue }
                try {
                    $lines = if ($hasInf) { Get-Content -LiteralPath $inf -ErrorAction Stop } else { @() }
                    $ini = ConvertFrom-IniText -Lines $lines
                    $regValues = [ordered]@{}
                    foreach ($l in @($ini['Registry Values'] | Where-Object { $_ })) {
                        $eq = $l.IndexOf('=')
                        if ($eq -lt 0) { continue }
                        $regValues[$l.Substring(0, $eq).Trim()] = $l.Substring($eq + 1).Trim()
                    }
                    # Admin templates live in registry.pol; GptTmpl wins if both set a value.
                    if (Test-Path -LiteralPath $pol) {
                        try { $polVals = ConvertFrom-RegistryPol $pol; foreach ($pk in $polVals.Keys) { if (-not $regValues.Contains($pk)) { $regValues[$pk] = $polVals[$pk] } } }
                        catch { Add-CollectionError "gpo.pol.$($dir.Name)" $_.Exception.Message }
                    }
                    # User-side admin templates (AlwaysInstallElevated needs both sides): USER\... keys.
                    if (Test-Path -LiteralPath $userPol) {
                        try { $polVals = ConvertFrom-RegistryPol $userPol 'USER'; foreach ($pk in $polVals.Keys) { if (-not $regValues.Contains($pk)) { $regValues[$pk] = $polVals[$pk] } } }
                        catch { Add-CollectionError "gpo.pol.$($dir.Name)" $_.Exception.Message }
                    }
                    # An autologon password pushed as a registry value: keep that it is set, never the value.
                    foreach ($pk in @($regValues.Keys | Where-Object { $_ -match '\\Winlogon\\DefaultPassword$' })) {
                        $pv = "$($regValues[$pk])"
                        $regValues[$pk] = if (($pv -split ',', 2)[-1]) { '1,<masked>' } else { '1,' }
                    }
                    $userPolRead = $true
                    $privRights = [ordered]@{}
                    foreach ($l in @($ini['Privilege Rights'] | Where-Object { $_ })) {
                        $eq = $l.IndexOf('=')
                        if ($eq -lt 0) { continue }
                        $privRights[$l.Substring(0, $eq).Trim()] = @($l.Substring($eq + 1).Split(',') | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
                    }
                    # Service startup set by the GPO: "Name",<start>,"<SDDL>" (2 auto, 3 manual, 4 disabled).
                    $svcStart = [ordered]@{}
                    foreach ($l in @($ini['Service General Setting'] | Where-Object { $_ })) {
                        $sp = $l.Split(',')
                        $sn = $sp[0].Trim().Trim('"')
                        $sv = 0
                        if ($sp.Count -ge 2 -and $sn -and [int]::TryParse($sp[1].Trim().Trim('"'), [ref]$sv)) { $svcStart[$sn.ToLower()] = $sv }
                    }
                    $sysAccess = [ordered]@{}
                    foreach ($l in @($ini['System Access'] | Where-Object { $_ })) {
                        $eq = $l.IndexOf('=')
                        if ($eq -lt 0) { continue }
                        $sysAccess[$l.Substring(0, $eq).Trim()] = $l.Substring($eq + 1).Trim()
                    }
                    # audit.csv, keyed by subcategory GUID so the language doesn't
                    # matter. Values: 0 none, 1 success, 2 failure, 3 both.
                    $auditPolicy = [ordered]@{}
                    $auditCsv = Join-Path $dir.FullName 'MACHINE\Microsoft\Windows NT\Audit\audit.csv'
                    if (Test-Path -LiteralPath $auditCsv) {
                        try {
                            foreach ($row in @(Import-Csv -LiteralPath $auditCsv -ErrorAction Stop | Where-Object { $_ })) {
                                $g = "$($row.'Subcategory GUID')".Trim('{', '}', ' ').ToLower()
                                if ($g) { $auditPolicy[$g] = [int]("0$($row.'Setting Value')") }
                            }
                        }
                        catch { }
                    }
                    $guid = $dir.Name.ToUpper()
                    $acl = if ($gpoAcls.ContainsKey($guid)) { $gpoAcls[$guid] } else { $null }
                    $gpos += [ordered]@{
                        guid           = $guid
                        displayName    = if ($gpoNames.ContainsKey($guid)) { $gpoNames[$guid] } else { $dir.Name }
                        registryValues = $regValues
                        privilegeRights = $privRights
                        systemAccess   = $sysAccess
                        serviceStart   = $svcStart
                        userPolicyRead = $userPolRead
                        auditPolicy    = $auditPolicy
                        ownerSid       = if ($acl) { $acl.ownerSid } else { $null }
                        ownerName      = if ($acl) { $acl.ownerName } else { $null }
                        aces           = if ($acl) { $acl.aces } else { @() }
                    }
                }
                catch { Add-CollectionError "gpo.$($dir.Name)" $_.Exception.Message }
            }
            $gpoData.gpos = $gpos
            $gpoData.collected = $true
            Write-Host "  $($gpos.Count) GPO security template(s) read"

            # What each GPO runs (scripts, GPP scheduled tasks) and which local
            # groups it fills (Restricted Groups, GPP Groups.xml). Every GPO
            # folder, with or without a security template. Commands are kept as
            # written; the analysis only looks at where they live.
            $exec = New-Object System.Collections.Generic.List[object]
            $localGroups = New-Object System.Collections.Generic.List[object]
            foreach ($dir in Get-ChildItem -LiteralPath $policiesPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' }) {
                $guid = $dir.Name.ToUpper()
                $gname = if ($gpoNames.ContainsKey($guid)) { $gpoNames[$guid] } else { $dir.Name }
                try { Read-GpoExtras -Dir $dir.FullName -Guid $guid -Name $gname -Exec $exec -Groups $localGroups }
                catch { Add-CollectionError "gpo.execution.$($dir.Name)" $_.Exception.Message }
            }
            $gpoData.execution = $exec.ToArray()
            $gpoData.localGroups = $localGroups.ToArray()
        }
        else { Add-CollectionError 'gpo' "SYSVOL Policies path not reachable: $policiesPath" }
    }
    catch { Add-CollectionError 'gpo' $_.Exception.Message }
}

if ($sysvolDrive) { Remove-PSDrive -Name IDWolfSysvol -Force -ErrorAction SilentlyContinue }

# --------------------------------------------------------------------------
# DNS. Listing zones through the DnsServer cmdlets needs admin rights on the
# DNS server, which a standard user doesn't have. Then we read the
# AD-integrated zones over LDAP instead: that gives dynamic updates, aging and
# wildcard/WPAD/ISATAP records, but not zone transfers (those sit in the DNS
# server's registry).
# --------------------------------------------------------------------------
# dnsProperty blob (MS-DNSP 2.3.2.1): DataLength@0, NameLength@4, Flag@8,
# Version@12, Id@16, Data@20.
function Get-DnsPropertyValue {
    param($Props, [uint32]$Id)
    foreach ($p in @($Props)) {
        $b = [byte[]]$p
        if ($b.Length -lt 20 -or [BitConverter]::ToUInt32($b, 16) -ne $Id) { continue }
        $len = [BitConverter]::ToUInt32($b, 0)
        if ($len -eq 0 -or $b.Length -lt 20 + $len) { return $null }
        if ($len -ge 4) { return [BitConverter]::ToUInt32($b, 20) }
        return [uint32]$b[20]
    }
    return $null
}
# Who may create records in an AD-integrated zone (ADIDNS): Allow CreateChild (or GenericAll) for any
# child class or for dnsNode. An empty array is an answer; $null means the descriptor could not be read.
$script:DnsNodeClassGuid = 'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9'
function Get-DnsZoneCreateChildSids {
    param([string]$Dn, [string]$Zone)
    if (-not $Dn) { Add-CollectionError 'dnsZoneAcl' "${Zone}: no directory object for the zone"; return $null }
    try {
        $sd = (Get-ADObject -Identity $Dn -Properties nTSecurityDescriptor @common).nTSecurityDescriptor
        $sids = @($sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
                "$($_.AccessControlType)" -eq 'Allow' -and "$($_.ActiveDirectoryRights)" -match 'CreateChild|GenericAll' -and
                @('00000000-0000-0000-0000-000000000000', $script:DnsNodeClassGuid) -contains "$($_.ObjectType)".ToLower()
            } | ForEach-Object { "$($_.IdentityReference.Value)" } | Select-Object -Unique)
        return , $sids
    }
    catch { Add-CollectionError 'dnsZoneAcl' "${Zone}: $($_.Exception.Message)"; return $null }
}
function Get-DnsZonesFromAd {
    $data = [ordered]@{ collected = $false; source = 'ldap'; zones = @(); dangerousRecords = @() }
    $forestDN = 'DC=' + ($forest.RootDomain -replace '\.', ',DC=')
    $bases = @("DC=DomainDnsZones,$domainDN", "DC=ForestDnsZones,$forestDN", "CN=MicrosoftDNS,CN=System,$domainDN")
    $updateNames = @{ 0 = 'None'; 1 = 'NonsecureAndSecure'; 2 = 'Secure' }
    $typeNames = @{ 1 = 'A'; 5 = 'CNAME'; 12 = 'PTR'; 16 = 'TXT'; 28 = 'AAAA'; 33 = 'SRV' }
    $seen = @{}
    foreach ($base in $bases) {
        try { $zs = @(Get-ADObject -SearchBase $base -LDAPFilter '(objectClass=dnsZone)' -Properties name, dNSProperty @common -ErrorAction Stop | Where-Object { $_ }) }
        catch { continue }   # partition absent or not readable: try the next one
        $data.collected = $true
        foreach ($z in $zs) {
            $name = "$($z.Name)"
            if ($seen.ContainsKey($name) -or $name -match '^\.\.|^RootDNSServers$|\.(in-addr|ip6)\.arpa$') { continue }
            $type = Get-DnsPropertyValue $z.dNSProperty 1
            if ($null -ne $type -and $type -ne 1) { continue }   # primary zones only
            $seen[$name] = $true
            $upd = Get-DnsPropertyValue $z.dNSProperty 2
            $aging = Get-DnsPropertyValue $z.dNSProperty 0x40
            $createChild = Get-DnsZoneCreateChildSids -Dn $z.DistinguishedName -Zone $name
            $data.zones += [ordered]@{
                name              = $name
                dynamicUpdate     = if ($null -ne $upd -and $updateNames.ContainsKey([int]$upd)) { $updateNames[[int]$upd] } else { '' }
                secureSecondaries = $null
                isAdIntegrated    = $true
                agingEnabled      = if ($null -ne $aging) { [bool]$aging } else { $null }
                createChildSids   = $createChild
            }
            try {
                $nodes = @(Get-ADObject -SearchBase $z.DistinguishedName -SearchScope OneLevel `
                        -LDAPFilter '(&(objectClass=dnsNode)(|(name=\2a)(name=wpad)(name=isatap))(!(dNSTombstoned=TRUE)))' -Properties name, dnsRecord @common -ErrorAction Stop | Where-Object { $_ })
                foreach ($n in $nodes) {
                    $rt = ''
                    # Multi-valued byte[] attribute; tolerate a single unwrapped blob.
                    $rec = if (@($n.dnsRecord)[0] -is [byte]) { $n.dnsRecord } else { @($n.dnsRecord)[0] }
                    if ($rec -and ([byte[]]$rec).Length -ge 4) { $t = [int][BitConverter]::ToUInt16([byte[]]$rec, 2); $rt = if ($typeNames.ContainsKey($t)) { $typeNames[$t] } else { "type $t" } }
                    $data.dangerousRecords += [ordered]@{ zone = $name; name = "$($n.Name)"; type = $rt }
                }
            }
            catch { }
        }
    }
    return $data
}

$dnsData = [ordered]@{ collected = $false; zones = @(); dangerousRecords = @() }
if (-not $SkipDns) {
    try {
        try { Import-Module DnsServer -ErrorAction Stop }
        catch { if ($InstallModules) { [void](Install-RsatFeature -Capability 'Rsat.Dns.Tools~~~~0.0.1.0' -Feature 'RSAT-DNS-Server'); Import-Module DnsServer -ErrorAction Stop } else { throw } }
        $dnsServer = if ($Server) { $Server } else { "$($domain.PDCEmulator)" }
        Write-Host "Reading DNS zones from $dnsServer..."
        # The DnsServer cmdlets use CIM; with -Credential a CIM session carries the account.
        $dnsTarget = @{ ComputerName = $dnsServer }
        if ($Credential) { $script:DnsCim = New-CimSession -ComputerName $dnsServer -Credential $Credential -ErrorAction Stop; $dnsTarget = @{ CimSession = $script:DnsCim } }
        $zones = @(Get-DnsServerZone @dnsTarget -ErrorAction Stop | Where-Object { -not $_.IsReverseLookupZone -and "$($_.ZoneType)" -eq 'Primary' -and -not $_.IsAutoCreated })
        foreach ($z in $zones) {
            $aging = $null
            try { $aging = [bool](Get-DnsServerZoneAging -Name $z.ZoneName @dnsTarget -ErrorAction Stop).AgingEnabled } catch { }
            $createChild = if ($z.IsDsIntegrated) { Get-DnsZoneCreateChildSids -Dn "$($z.DistinguishedName)" -Zone $z.ZoneName } else { $null }
            $dnsData.zones += [ordered]@{
                name            = $z.ZoneName
                dynamicUpdate   = "$($z.DynamicUpdate)"
                secureSecondaries = "$($z.SecureSecondaries)"
                isAdIntegrated  = [bool]$z.IsDsIntegrated
                agingEnabled    = $aging
                createChildSids = $createChild
            }
            try {
                foreach ($rr in @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName @dnsTarget -ErrorAction Stop)) {
                    $n = "$($rr.HostName)".ToLower()
                    if ($n -eq '*' -or $n -eq 'wpad' -or $n -eq 'isatap') {
                        $dnsData.dangerousRecords += [ordered]@{ zone = $z.ZoneName; name = $rr.HostName; type = "$($rr.RecordType)" }
                    }
                }
            }
            catch { }
        }
        $dnsData.collected = $true
        $dnsData['source'] = 'rpc'
        Write-Host "  $($dnsData.zones.Count) forward primary zone(s)"
    }
    catch {
        $rpcError = $_.Exception.Message
        Write-Host "  DNS RPC not available ($rpcError). Reading AD-integrated zones over LDAP instead..."
        # Tell the user why. On the DC itself, a non-elevated session loses its admin groups to UAC.
        if ($rpcError -notmatch '(?i)modul' -and $dnsServer) {   # 'modul' also matches localized 'modulo' / 'Modul'
            $isAdmin = $false
            try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
            $onDnsServer = ($dnsServer -split '\.')[0] -eq $env:COMPUTERNAME
            if ($onDnsServer -and -not $isAdmin -and -not $Credential) {
                Write-Host "  Hint: running on the DNS server without elevation. Start PowerShell 'as administrator' to read the full DNS configuration (incl. zone transfer)." -ForegroundColor Yellow
            }
            elseif (-not $Credential) {
                Write-Host "  Hint: listing DNS zones needs DnsAdmins / Domain Admins on $dnsServer. Re-run with -Credential (Get-Credential DOMAIN\user) to read the full DNS configuration (incl. zone transfer)." -ForegroundColor Yellow
            }
        }
        try { $ldapDns = Get-DnsZonesFromAd } catch { $ldapDns = $null }
        if ($ldapDns -and $ldapDns.collected) {
            $dnsData = $ldapDns
            Write-Host "  $($dnsData.zones.Count) AD-integrated zone(s) via LDAP (zone transfer setting not readable this way)"
        }
        else { Add-CollectionError 'dns' "DNS collection skipped: RPC failed ($rpcError) and the DNS application partitions could not be read over LDAP." }
    }
    finally { if ($script:DnsCim) { Remove-CimSession $script:DnsCim -ErrorAction SilentlyContinue; $script:DnsCim = $null } }
}

# --------------------------------------------------------------------------
# Operational health: replication, authorized DHCP, last backup. Each part can fail on its own.
# --------------------------------------------------------------------------
$healthData = [ordered]@{ collected = $false; replication = @(); dhcpServers = @(); lastBackupUtc = $null }
if (-not $SkipHealth) {
    try {
        $meta = @(Get-ADReplicationPartnerMetadata -Target $domain.DNSRoot -Scope Domain @common -ErrorAction Stop)
        foreach ($m in $meta) {
            $healthData.replication += [ordered]@{
                server              = "$($m.Server)"
                partner             = "$($m.Partner)"
                lastSuccessUtc      = (ConvertTo-IsoUtc $m.LastReplicationSuccess)
                consecutiveFailures = [int]$m.ConsecutiveReplicationFailures
            }
        }
        $healthData.collected = $true
    }
    catch { Add-CollectionError 'health.replication' $_.Exception.Message }

    try {
        Import-Module DhcpServer -ErrorAction Stop
        $healthData.dhcpServers = @(Get-DhcpServerInDC -ErrorAction Stop | ForEach-Object { [ordered]@{ name = "$($_.DnsName)"; ip = "$($_.IPAddress)" } })
        $healthData.collected = $true
    }
    catch { }

    try {
        $rb = & repadmin /showbackup 2>$null
        if ($rb) {
            $rxDate = '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
            foreach ($line in $rb) {
                if ($line -match ('^\s*' + [regex]::Escape($domainDN) + '\s+' + $rxDate)) {
                    try { $healthData.lastBackupUtc = ([datetime]$Matches[1]).ToUniversalTime().ToString('o') } catch { }
                    break
                }
            }
            $healthData.collected = $true
        }
    }
    catch { Add-CollectionError 'health.backup' $_.Exception.Message }

    # FSMO role holders as AD records them. Forest roles live in the forest root domain.
    $healthData['fsmo'] = [ordered]@{
        PDCEmulator = "$($domain.PDCEmulator)"; RIDMaster = "$($domain.RIDMaster)"; InfrastructureMaster = "$($domain.InfrastructureMaster)"
        SchemaMaster = "$($forest.SchemaMaster)"; DomainNamingMaster = "$($forest.DomainNamingMaster)"
    }
    $healthData['forestRoot'] = ("$($forest.RootDomain)" -eq "$($domain.DNSRoot)")

    # Does each DC answer LDAP (through ADWS) from here? Same account, no -Server override.
    $c2 = @{}; foreach ($k in $common.Keys) { if ($k -ne 'Server') { $c2[$k] = $common[$k] } }
    $healthData['dcReachability'] = @(foreach ($dc in $dcs) {
            $ok = $false; $ms = $null; $err = ''
            try { $ms = [int](Measure-Command { Get-ADRootDSE -Server $dc.hostName @c2 -ErrorAction Stop | Out-Null }).TotalMilliseconds; $ok = $true }
            catch { $err = "$($_.Exception.Message)".Trim() }
            [ordered]@{ dc = "$($dc.hostName)"; reachable = $ok; latencyMs = $ms; error = $err }
        })

    # Clock offset of each DC from this machine (NTP query, no rights needed). Only the
    # spread between DCs is used, so this machine's own clock doesn't matter.
    $times = @(foreach ($dc in $dcs) {
            $off = $null
            try {
                $out = & w32tm /stripchart "/computer:$($dc.hostName)" /samples:1 /dataonly 2>$null
                foreach ($l in @($out)) { if ("$l" -match ',\s*([+-]?\d+[.,]\d+)s') { $off = [double]::Parse($Matches[1].Replace(',', '.'), [Globalization.CultureInfo]::InvariantCulture) } }
            }
            catch { }
            [ordered]@{ dc = "$($dc.hostName)"; offsetSeconds = $off }
        })
    $healthData['dcTime'] = $times
    if (-not @($times | Where-Object { $null -ne $_.offsetSeconds }).Count) { Add-CollectionError 'health.time' 'No DC answered the w32tm time query (UDP 123 blocked?).' }

    # Disk space and core services on each DC, over CIM. Needs admin rights on the DC
    # (or remote WMI rights); without them this part is "not evaluated".
    $svcNames = 'NTDS', 'ADWS', 'Kdc', 'Netlogon', 'W32Time', 'DFSR', 'IsmServ', 'LanmanServer', 'LanmanWorkstation', 'SamSs', 'RpcSs', 'EventSystem', 'DNS', 'Dnscache'
    $state = @(foreach ($dc in $dcs) {
            $rec = [ordered]@{ dc = "$($dc.hostName)"; systemDrive = $null; freeGB = $null; sizeGB = $null; stoppedServices = @(); spoolerStartMode = $null; spoolerState = $null; webClientStartMode = $null; webClientState = $null; netbiosAdapters = $null; osBuild = $null; osUbr = $null; coercionServices = $null; rpcFilterInterfaces = $null; error = '' }
            $reach = @($healthData.dcReachability | Where-Object { $_.dc -eq "$($dc.hostName)" })[0]
            if ($reach -and -not $reach.reachable) { $rec.error = 'not reachable'; $rec; continue }
            $cs = $null
            try {
                $cp = @{ ComputerName = $dc.hostName; OperationTimeoutSec = 20; ErrorAction = 'Stop' }
                if ($Credential) { $cp['Credential'] = $Credential }
                $cs = New-CimSession @cp
                $os = Get-CimInstance -CimSession $cs -ClassName Win32_OperatingSystem -OperationTimeoutSec 20 -ErrorAction Stop
                $disk = Get-CimInstance -CimSession $cs -ClassName Win32_LogicalDisk -Filter "DeviceID='$($os.SystemDrive)'" -OperationTimeoutSec 20 -ErrorAction Stop
                $rec.systemDrive = "$($os.SystemDrive)"
                # Patch level = build + update revision (UBR, Windows Server 2016 and later). The UBR is
                # only in the registry: read it through StdRegProv GetDWORDValue (read-only).
                $rec.osBuild = "$($os.BuildNumber)"
                try {
                    $ubr = Invoke-CimMethod -CimSession $cs -Namespace 'root/default' -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{ hDefKey = [uint32]2147483650; sSubKeyName = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'; sValueName = 'UBR' } -OperationTimeoutSec 20 -ErrorAction Stop
                    if ($ubr -and $ubr.ReturnValue -eq 0) { $rec.osUbr = [int]$ubr.uValue }
                }
                catch { }
                $rec.freeGB = [Math]::Round($disk.FreeSpace / 1GB, 1); $rec.sizeGB = [Math]::Round($disk.Size / 1GB, 1)
                $flt = ($svcNames | ForEach-Object { "Name='$_'" }) -join ' OR '
                $rec.stoppedServices = @(Get-CimInstance -CimSession $cs -ClassName Win32_Service -Filter $flt -OperationTimeoutSec 20 -ErrorAction Stop |
                        Where-Object { "$($_.StartMode)" -ne 'Disabled' -and "$($_.State)" -ne 'Running' } | ForEach-Object { "$($_.Name)" })
                # Print Spooler and WebClient (WebDAV) are wanted OFF on a DC (coercion), so they're
                # recorded apart from the "stopped" list. 'absent' = service not installed.
                $off = @(Get-CimInstance -CimSession $cs -ClassName Win32_Service -Filter "Name='Spooler' OR Name='WebClient' OR Name='EFS' OR Name='Dfs' OR Name='EventLog'" -OperationTimeoutSec 20 -ErrorAction Stop)
                # Services behind the coercion interfaces (MS-EFSR, MS-DFSNM, MS-EVEN): state only.
                $rec.coercionServices = [ordered]@{}
                foreach ($cn in 'EFS', 'Dfs', 'EventLog') {
                    $cv = @($off | Where-Object { "$($_.Name)" -eq $cn })[0]
                    $rec.coercionServices[$cn] = if ($cv) { "$($cv.StartMode)/$($cv.State)" } else { 'absent' }
                }
                $rec.rpcFilterInterfaces = Get-RpcFilterInterfaces -CimSession $cs
                $sp = @($off | Where-Object { "$($_.Name)" -eq 'Spooler' })[0]
                if ($sp) { $rec.spoolerStartMode = "$($sp.StartMode)"; $rec.spoolerState = "$($sp.State)" }
                else { $rec.spoolerStartMode = 'absent'; $rec.spoolerState = 'absent' }
                $wcs = @($off | Where-Object { "$($_.Name)" -eq 'WebClient' })[0]
                if ($wcs) { $rec.webClientStartMode = "$($wcs.StartMode)"; $rec.webClientState = "$($wcs.State)" }
                else { $rec.webClientStartMode = 'absent'; $rec.webClientState = 'absent' }
                # NetBIOS over TCP/IP per IP-enabled adapter: 0 = from DHCP (on with a static IP), 1 = on, 2 = off.
                $rec.netbiosAdapters = @(Get-CimInstance -CimSession $cs -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -OperationTimeoutSec 20 -ErrorAction Stop |
                        ForEach-Object { [ordered]@{ adapter = "$($_.Description)"; netbiosOption = $(if ($null -ne $_.TcpipNetbiosOptions) { [int]$_.TcpipNetbiosOptions } else { $null }) } })
            }
            catch { $rec.error = "$($_.Exception.Message)".Trim() }
            finally { if ($cs) { Remove-CimSession $cs -ErrorAction SilentlyContinue } }
            $rec
        })
    $healthData['dcState'] = $state
    # Some DCs read, others refused: say which, since the live checks only cover the ones read.
    $deniedDcs = @($state | Where-Object { $_.error -and $_.error -ne 'not reachable' })
    if ($deniedDcs.Count -and @($state | Where-Object { -not $_.error }).Count) {
        Write-Host "  Warning: services and network settings could not be read on $(@($deniedDcs | ForEach-Object { $_.dc }) -join ', ') (needs admin rights on each DC). Checks that read them live cover only the other DCs and are listed as not fully evaluated." -ForegroundColor Yellow
    }
    if ($dcs.Count -and -not @($state | Where-Object { -not $_.error }).Count) {
        Add-CollectionError 'health.dcState' "Could not read disk space and services on any DC (needs admin rights on the DCs): $(@($state)[0].error)"
        $isAdminHs = $false
        try { $isAdminHs = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
        if (-not $isAdminHs -and -not $Credential) {
            Write-Host "  Hint: this session is not elevated. Start PowerShell 'as administrator' (or pass -Credential) to read disk space and services on the DCs." -ForegroundColor Yellow
        }
    }
}

# --------------------------------------------------------------------------
# Write snapshot
# --------------------------------------------------------------------------
$snapshot = [ordered]@{
    meta              = [ordered]@{
        tool             = 'IDWolf'
        schemaVersion    = 2
        collectorVersion = $script:CollectorVersion
        collectedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
        collectedBy      = "$env:USERDOMAIN\$env:USERNAME"
        collectedFrom    = $env:COMPUTERNAME
        server           = if ($Server) { $Server } else { "$($domain.PDCEmulator)" }
        options          = [ordered]@{ skipSysvol = [bool]$SkipSysvol; skipAcl = [bool]$SkipAcl; skipAdcs = [bool]$SkipAdcs; skipGpo = [bool]$SkipGpo; skipDns = [bool]$SkipDns; skipHealth = [bool]$SkipHealth; deep = [bool]$Deep }
        collectionErrors = $script:Errors.ToArray()
        synthetic        = $false
    }
    domain            = $domainInfo
    domainControllers = $dcs
    trusts            = $trusts
    users             = $users
    serviceAccounts   = $serviceAccounts
    computers         = $computers
    groups            = $groups
    foreignPrincipals = $fsps
    acls              = $acls
    ouAcls            = $ouAcls
    deepAcls          = $deepAcls
    kdsRootKeyAcls    = $kdsRootKeyAcls
    preWin2000        = $preWin2000
    adcs              = $adcs
    gpo               = $gpoData
    sysvol            = $sysvol
    dns               = $dnsData
    health            = $healthData
}

if (-not $OutFile) {
    # Unnamed outputs go to .\output, not next to everything else.
    $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }
    $OutFile = Join-Path $od ("adsnapshot_{0}_{1}.json" -f $domain.DNSRoot, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$json = $snapshot | ConvertTo-Json -Depth 10
# Belt and braces for the PS 5.1 {} issue (see ConvertTo-StringArray).
$json = [regex]::Replace($json, '(?<=[^\\]"):\s*\{\s*\}', ': null')
if ([System.IO.Path]::IsPathRooted($OutFile)) { $fullOut = $OutFile }
else { $fullOut = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutFile)) }
[System.IO.File]::WriteAllText($fullOut, $json, (New-Object System.Text.UTF8Encoding($false)))

$elapsed = (Get-Date) - $startedAt
Write-Host ("Snapshot written to {0} ({1:N1}s)" -f $fullOut, $elapsed.TotalSeconds) -ForegroundColor Green
if ($script:Errors.Count -gt 0) {
    Write-Host "$($script:Errors.Count) section(s) could not be collected; see meta.collectionErrors. Affected checks will be marked as not evaluated." -ForegroundColor Yellow
}
Write-Host "The snapshot contains directory data (names, group membership, ACLs). Handle it as confidential." -ForegroundColor Yellow
# w32tm against an unreachable DC leaves a non-zero exit code behind; the collection itself worked.
exit 0
