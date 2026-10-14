# Just enough of the ActiveDirectory module to run Collect-ADSnapshot.ps1
# without a domain (Test-CollectorMock.ps1).

$script:Dom = 'S-1-5-21-4444444444-5555555555-6666666666'
$script:DN = 'DC=mock,DC=local'
# SecurityIdentifier cannot be constructed off Windows: mock its Value.
function Sid { param($s) [PSCustomObject]@{ Value = "$s" } }
function Get-FileTimeAgo { param([int]$DaysAgo) if ($DaysAgo -lt 0) { return 0 } return [DateTime]::UtcNow.AddDays(-$DaysAgo).ToFileTimeUtc() }

function Get-ADDomain { param($Identity, $Server)
    [PSCustomObject]@{ DNSRoot = 'mock.local'; NetBIOSName = 'MOCK'; DistinguishedName = $script:DN; DomainSID = (Sid $script:Dom)
        DomainMode = 'Windows2016Domain'; PDCEmulator = 'dc1.mock.local' } }
function Get-ADForest { param($Server) [PSCustomObject]@{ Name = 'mock.local'; RootDomain = 'mock.local'; ForestMode = 'Windows2016Forest' } }
function Get-ADRootDSE { param($Server) [PSCustomObject]@{ configurationNamingContext = "CN=Configuration,$script:DN"; schemaNamingContext = "CN=Schema,CN=Configuration,$script:DN" } }

# dnsProperty blob (MS-DNSP 2.3.2.1): DataLength, NameLength, Flag, Version, Id, Data, Name.
function DnsProp { param([uint32]$Id, [byte[]]$Data)
    [byte[]](@([BitConverter]::GetBytes([uint32]$Data.Length)) + [BitConverter]::GetBytes([uint32]1) + [BitConverter]::GetBytes([uint32]0) +
        [BitConverter]::GetBytes([uint32]1) + [BitConverter]::GetBytes($Id) + $Data + [byte]0) }
function Get-ADObject {
    param($Identity, $Properties, $LDAPFilter, $SearchBase, $SearchScope, $Server)
    # One AD-integrated zone: non-secure updates, aging off, a WPAD record.
    if ($LDAPFilter -eq '(objectClass=dnsZone)') {
        if ($SearchBase -notlike 'DC=DomainDnsZones*') { return }
        return [PSCustomObject]@{ Name = 'mock.local'; DistinguishedName = "DC=mock.local,CN=MicrosoftDNS,$SearchBase"
            dNSProperty = @((DnsProp 1 ([BitConverter]::GetBytes([uint32]1))), (DnsProp 2 ([byte[]]@(1))), (DnsProp 0x40 ([BitConverter]::GetBytes([uint32]0)))) }
    }
    if ($LDAPFilter -like '*objectClass=dnsNode*') {
        return [PSCustomObject]@{ Name = 'wpad'; dnsRecord = @(, [byte[]](@(4, 0, 1, 0) + (@(0) * 20))) }
    }
    # Schema: msExchStorageGroup left behind by Exchange (CVE-2021-34470).
    if ($LDAPFilter -like '*possSuperiors=computer*') { return [PSCustomObject]@{ lDAPDisplayName = 'msExchStorageGroup'; possSuperiors = @('computer', 'msExchInformationStore'); subClassOf = 'container' } }
    if ($LDAPFilter -like '*msLAPS-PasswordExpirationTime*') { return [PSCustomObject]@{ Name = 'ms-LAPS-PasswordExpirationTime' } }
    if ($LDAPFilter -like '*ms-Mcs-AdmPwdExpirationTime*') { return $null }
    if ($LDAPFilter -like '*foreignSecurityPrincipal*') { return @() }
    # One OU and one top-level container for the OU ACL read (BadSuccessor).
    if ($LDAPFilter -eq '(objectClass=organizationalUnit)') { return [PSCustomObject]@{ DistinguishedName = "OU=Staff,$script:DN"; ObjectClass = 'organizationalUnit' } }
    if ($LDAPFilter -eq '(objectClass=container)' -and $SearchScope -eq 'OneLevel') { return [PSCustomObject]@{ DistinguishedName = "CN=Users,$script:DN"; ObjectClass = 'container' } }
    if ($Identity -eq $script:DN -and $Properties -contains 'ms-DS-MachineAccountQuota') { return [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 10 } }
    if ($Identity -like 'CN=Directory Service*') { return [PSCustomObject]@{ dSHeuristics = $null } }
    # RODC password replication policy; msDS-RevealedList in its DN-String form.
    if ($Properties -contains 'msDS-RevealedList') {
        return [PSCustomObject]@{
            'msDS-RevealOnDemandGroup' = @("CN=Allowed RODC Password Replication Group,CN=Users,$script:DN", "CN=Domain Users,CN=Users,$script:DN")
            'msDS-NeverRevealGroup'    = @("CN=Denied RODC Password Replication Group,CN=Users,$script:DN")
            'msDS-RevealedList'        = @("S:4:0a1b:CN=Administrator,CN=Users,$script:DN", "S:4:0c2d:CN=mario,CN=Users,$script:DN", "CN=RODC1,OU=Domain Controllers,$script:DN")
            managedBy                  = "CN=mario,CN=Users,$script:DN"
        }
    }
    # AD CS: one CA on PC1, no templates.
    if ($Identity -like 'CN=Public Key Services*' -and -not $Properties) { return [PSCustomObject]@{ Name = 'Public Key Services' } }
    if ($LDAPFilter -eq '(objectClass=pKIEnrollmentService)') {
        return [PSCustomObject]@{ name = 'MOCK-CA'; DistinguishedName = "CN=MOCK-CA,$SearchBase"; dNSHostName = 'pc1.mock.local'; certificateTemplates = @(); cACertificate = $null; flags = 0 }
    }
    if ($LDAPFilter -like '*pKICertificateTemplate*' -or $LDAPFilter -like '*msPKI-Enterprise-Oid*') { return @() }
    if ($Properties -contains 'nTSecurityDescriptor') {
        if ($Identity -like 'OU=Domain Controllers*') { throw 'Access is denied (mock)' }
        $sd = [PSCustomObject]@{ Owner = "$script:Dom-512"; Pki = ("$Identity" -like '*Public Key Services*'); Dns = ("$Identity" -like '*CN=MicrosoftDNS*'); Ou = ("$Identity" -like 'OU=Staff,*') }
        $sd | Add-Member -MemberType ScriptMethod -Name GetOwner -Value { param($t) Sid $this.Owner }
        $sd | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value {
            param($a, $b, $t)
            @(
                [PSCustomObject]@{ IdentityReference = (Sid "$script:Dom-512"); ActiveDirectoryRights = 'GenericAll'; AccessControlType = 'Allow'; ObjectType = [guid]::Empty; InheritedObjectType = [guid]::Empty; InheritanceType = 'All'; IsInherited = $false }
                [PSCustomObject]@{ IdentityReference = (Sid "$script:Dom-1300"); ActiveDirectoryRights = 'ExtendedRight'; AccessControlType = 'Allow'; ObjectType = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; InheritedObjectType = [guid]::Empty; InheritanceType = 'None'; IsInherited = $false }
                # mario can rewrite every PKI object: ESC5.
                # Default ADIDNS ACL: Authenticated Users may create records in the zone.
                if ($this.Dns) { [PSCustomObject]@{ IdentityReference = (Sid 'S-1-5-11'); ActiveDirectoryRights = 'CreateChild'; AccessControlType = 'Allow'; ObjectType = [guid]::Empty; InheritedObjectType = [guid]::Empty; InheritanceType = 'None'; IsInherited = $false } }
                # mario may create dMSAs in OU=Staff; the collector must drop the inherited ACE.
                if ($this.Ou) { [PSCustomObject]@{ IdentityReference = (Sid "$script:Dom-1301"); ActiveDirectoryRights = 'CreateChild'; AccessControlType = 'Allow'; ObjectType = [guid]'0feb936f-47b3-49f2-9386-1dedc2c23765'; InheritedObjectType = [guid]::Empty; InheritanceType = 'None'; IsInherited = $false } }
                if ($this.Ou) { [PSCustomObject]@{ IdentityReference = (Sid "$script:Dom-1300"); ActiveDirectoryRights = 'GenericAll'; AccessControlType = 'Allow'; ObjectType = [guid]::Empty; InheritedObjectType = [guid]::Empty; InheritanceType = 'All'; IsInherited = $true } }
                if ($this.Pki) { [PSCustomObject]@{ IdentityReference = (Sid "$script:Dom-1301"); ActiveDirectoryRights = 'GenericWrite'; AccessControlType = 'Allow'; ObjectType = [guid]::Empty; InheritedObjectType = [guid]::Empty; InheritanceType = 'None'; IsInherited = $false } }
            )
        }
        return [PSCustomObject]@{ nTSecurityDescriptor = $sd }
    }
    return $null
}
function Get-ADOptionalFeature { param($Filter, $Server) [PSCustomObject]@{ EnabledScopes = @() } }
function Get-ADDefaultDomainPasswordPolicy { param($Server)
    [PSCustomObject]@{ MinPasswordLength = 7; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false; LockoutThreshold = 0
        LockoutDuration = [timespan]::FromMinutes(30); MaxPasswordAge = [timespan]::FromDays(42); MinPasswordAge = [timespan]::FromDays(1); PasswordHistoryCount = 24 } }
function Get-ADFineGrainedPasswordPolicy { param($Filter, $Server) throw 'Insufficient access rights (mock)' }
function Get-ADDomainController { param($Filter, $Server)
    [PSCustomObject]@{ Name = 'DC1'; HostName = 'dc1.mock.local'; OperatingSystem = 'Windows Server 2012 R2 Standard'; OperatingSystemVersion = '6.3 (9600)'
        IsGlobalCatalog = $true; IsReadOnly = $false; Site = 'HQ'; OperationMasterRoles = @('PDCEmulator'); ComputerObjectDN = "CN=DC1,OU=Domain Controllers,$script:DN" }
    [PSCustomObject]@{ Name = 'RODC1'; HostName = 'rodc1.mock.local'; OperatingSystem = 'Windows Server 2022 Standard'; OperatingSystemVersion = '10.0 (20348)'
        IsGlobalCatalog = $true; IsReadOnly = $true; Site = 'Branch'; OperationMasterRoles = @(); ComputerObjectDN = "CN=RODC1,OU=Domain Controllers,$script:DN" } }
function Get-ADTrust { param($Filter, $Server) @() }

function New-MockPrincipal {
    param($Sam, $Rid, $Uac = 0x200, $PwdAge = 30, $Logon = 1, $Spn = @(), $Pg = 513, $Desc = $null, $Ou = "CN=Users,$script:DN", $AdminCount = $null)
    [PSCustomObject]@{
        SamAccountName = $Sam; DistinguishedName = "CN=$Sam,$Ou"; SID = (Sid "$script:Dom-$Rid"); Enabled = (($Uac -band 2) -eq 0)
        userAccountControl = $Uac; pwdLastSet = (Get-FileTimeAgo $PwdAge); lastLogonTimestamp = (Get-FileTimeAgo $Logon); whenCreated = [DateTime]::UtcNow.AddDays(-800)
        servicePrincipalName = $Spn; adminCount = $AdminCount; primaryGroupID = $Pg; description = $Desc; sIDHistory = @()
        'msDS-SupportedEncryptionTypes' = $null; 'msDS-AllowedToDelegateTo' = $null; PrincipalsAllowedToDelegateToAccount = @()
    }
}
function Get-ADUser { param($Filter, $Properties, $Server)
    if ($Properties -contains 'PrincipalsAllowedToDelegateToAccount') { throw 'One or more properties are invalid (mock, exercises fallback)' }
    @(
        (New-MockPrincipal 'Administrator' 500 -PwdAge 600 -AdminCount 1)
        (New-MockPrincipal 'krbtgt' 502 -Uac 0x202 -PwdAge 2000 -Logon -1 -AdminCount 1)
        (New-MockPrincipal 'svc_sql' 1300 -Spn @('MSSQLSvc/sql.mock.local') -PwdAge 900 -Desc 'SQL service pwd Summer2020')
        (New-MockPrincipal 'mario' 1301 -Desc 'Ufficio Crediti')
    ) }
function Get-ADServiceAccount { param($Filter, $Properties, $Server) @() }
function Get-ADComputer { param($Filter, $Properties, $Server)
    $dc = New-MockPrincipal 'DC1$' 1000 -Uac 0x82000 -Pg 516 -Ou "OU=Domain Controllers,$script:DN"
    $dc | Add-Member OperatingSystem 'Windows Server 2012 R2 Standard'; $dc | Add-Member OperatingSystemVersion '6.3'; $dc | Add-Member dNSHostName 'dc1.mock.local'
    $dc | Add-Member 'msLAPS-PasswordExpirationTime' $null
    $pc = New-MockPrincipal 'PC1$' 1100 -Uac 0x1000 -Pg 515 -Ou "CN=Computers,$script:DN"
    $pc | Add-Member OperatingSystem 'Windows 10 Enterprise'; $pc | Add-Member OperatingSystemVersion '10.0'; $pc | Add-Member dNSHostName 'pc1.mock.local'
    $pc | Add-Member 'msLAPS-PasswordExpirationTime' $null
    @($dc, $pc) }
function Get-ADGroup { param($Filter, $Properties, $Server)
    @(
        [PSCustomObject]@{ Name = 'Domain Admins'; SamAccountName = 'Domain Admins'; DistinguishedName = "CN=Domain Admins,CN=Users,$script:DN"; SID = (Sid "$script:Dom-512"); GroupScope = 'Global'; GroupCategory = 'Security'; adminCount = 1; member = @("CN=Administrator,CN=Users,$script:DN", "CN=svc_sql,CN=Users,$script:DN") }
        [PSCustomObject]@{ Name = 'Domain Users'; SamAccountName = 'Domain Users'; DistinguishedName = "CN=Domain Users,CN=Users,$script:DN"; SID = (Sid "$script:Dom-513"); GroupScope = 'Global'; GroupCategory = 'Security'; adminCount = $null; member = @() }
        [PSCustomObject]@{ Name = 'Protected Users'; SamAccountName = 'Protected Users'; DistinguishedName = "CN=Protected Users,CN=Users,$script:DN"; SID = (Sid "$script:Dom-525"); GroupScope = 'Global'; GroupCategory = 'Security'; adminCount = $null; member = @() }
        [PSCustomObject]@{ Name = 'Administrators'; SamAccountName = 'Administrators'; DistinguishedName = "CN=Administrators,CN=Builtin,$script:DN"; SID = (Sid 'S-1-5-32-544'); GroupScope = 'DomainLocal'; GroupCategory = 'Security'; adminCount = 1; member = @("CN=Domain Admins,CN=Users,$script:DN") }
    ) }

Export-ModuleMember -Function *
