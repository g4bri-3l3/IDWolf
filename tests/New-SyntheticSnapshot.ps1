<#
.SYNOPSIS
    Generates a synthetic IDWolf snapshot (fictional domain moosebank.local)
    with known, deliberately planted issues. Used for demos and regression.

.PARAMETER Scenario
    demo     curated domain that triggers every check at least once
    partial  same as demo, but with collection errors (FGPP, ACLs) and
             SYSVOL skipped, to exercise the "not evaluated" logic
    large    demo plus -ExtraUsers / -ExtraComputers random clean-ish
             objects, for performance testing
.PARAMETER OutFile
    Output path.
#>
[CmdletBinding()]
Param(
    [ValidateSet('demo', 'partial', 'large')][string]$Scenario = 'demo',
    [string]$OutFile = '',
    [switch]$Deep,
    [int]$ExtraUsers = 20000,
    [int]$ExtraComputers = 5000
)

$ErrorActionPreference = 'Stop'
$ref = [datetime]::new(2026, 9, 28, 8, 0, 0, [DateTimeKind]::Utc)
$dom = 'S-1-5-21-1111111111-2222222222-3333333333'
$dn = 'DC=moosebank,DC=local'
$usersOu = "OU=Users,OU=MooseBank,$dn"
$adminsOu = "OU=Admins,OU=Tier0,$dn"
$svcOu = "OU=ServiceAccounts,OU=MooseBank,$dn"
$srvOu = "OU=Servers,OU=MooseBank,$dn"
$wksOu = "OU=Workstations,OU=MooseBank,$dn"
$dcOu = "OU=Domain Controllers,$dn"
$script:nextRid = 1200

function Iso { param($Days) if ($null -eq $Days) { return $null } return $ref.AddDays(-$Days).ToString('o') }
function Next-Sid { $script:nextRid++; return "$dom-$($script:nextRid)" }

function New-U {
    param([string]$Sam, [string]$Ou = $usersOu, [string]$Sid = '', [int64]$Uac = 0x200, $PwdAge = 60, $Logon = 2, $Created = 700,
        [string[]]$Spn = @(), $AdminCount = $null, [int]$Pg = 513, [string]$Desc = '', [bool]$DescSusp = $false,
        [string[]]$SidHistory = @(), $Enc = $null, [string[]]$Deleg = @(), [string[]]$Rbcd = @(), [string]$Kind = 'user', [int]$KeyCred = 0, [bool]$UnixPwd = $false, [string[]]$AltSec = @())
    if (-not $Sid) { $Sid = Next-Sid }
    [ordered]@{
        kind = $Kind; samAccountName = $Sam; distinguishedName = "CN=$Sam,$Ou"; sid = $Sid
        enabled = (($Uac -band 2) -eq 0); userAccountControl = $Uac
        pwdLastSet = (Iso $PwdAge); lastLogonTimestamp = (Iso $Logon); whenCreated = (Iso $Created)
        servicePrincipalNames = @($Spn); adminCount = $AdminCount; primaryGroupId = $Pg
        description = $Desc; descriptionSuspicious = $DescSusp; sidHistory = @($SidHistory)
        supportedEncryptionTypes = $Enc; allowedToDelegateTo = @($Deleg); rbcdPrincipals = @($Rbcd)
        keyCredentialCount = $KeyCred; hasUnixPassword = $UnixPwd; altSecIdTypes = @($AltSec)
    }
}

function New-C {
    param([string]$Name, [string]$Ou = $wksOu, [string]$Os = 'Windows 11 Enterprise', [string]$OsVer = '10.0 (22631)',
        [int64]$Uac = 0x1000, $Logon = 3, $PwdAge = 10, $Created = 500, [int]$Pg = 515, $LapsV2 = -20, $LapsLegacy = $null,
        [string[]]$Deleg = @(), [string[]]$Rbcd = @(), [string]$Desc = '', [bool]$DescSusp = $false, $Enc = 28)
    $sam = "$Name`$"
    [ordered]@{
        kind = 'computer'; samAccountName = $sam; distinguishedName = "CN=$Name,$Ou"; sid = (Next-Sid)
        enabled = (($Uac -band 2) -eq 0); userAccountControl = $Uac
        pwdLastSet = (Iso $PwdAge); lastLogonTimestamp = (Iso $Logon); whenCreated = (Iso $Created)
        servicePrincipalNames = @("HOST/$Name", "HOST/$($Name.ToLower()).moosebank.local"); adminCount = $null; primaryGroupId = $Pg
        description = $Desc; descriptionSuspicious = $DescSusp; sidHistory = @()
        supportedEncryptionTypes = $Enc; allowedToDelegateTo = @($Deleg); rbcdPrincipals = @($Rbcd)
        operatingSystem = $Os; osVersion = $OsVer; dnsHostName = "$($Name.ToLower()).moosebank.local"
        lapsLegacyExpiry = (Iso $LapsLegacy); lapsV2Expiry = (Iso $LapsV2)
    }
}

function New-G {
    param([string]$Name, [string]$Sid, [string[]]$Members = @(), [string]$Ou = "CN=Users,$dn", $AdminCount = $null, [string]$Scope = 'Global')
    [ordered]@{ name = $Name; samAccountName = $Name; distinguishedName = "CN=$Name,$Ou"; sid = $Sid
        groupScope = $Scope; groupCategory = 'Security'; adminCount = $AdminCount; members = @($Members) }
}

function Ace {
    param([string]$Sid, [string]$Name, [string]$Rights, [string]$ObjectType = '00000000-0000-0000-0000-000000000000',
        [string]$InhObj = '00000000-0000-0000-0000-000000000000', [string]$Inh = 'All', [string]$Type = 'Allow')
    [ordered]@{ sid = $Sid; name = $Name; rights = $Rights; accessType = $Type; objectType = $ObjectType
        inheritedObjectType = $InhObj; inheritanceType = $Inh; isInherited = $false }
}

# ------------------------------------------------------------------ users
$UAC_DIS = 0x2; $PNR = 0x20; $REV = 0x80; $DEXP = 0x10000; $TFD = 0x80000; $ND = 0x100000; $DES = 0x200000; $NOPRE = 0x400000; $T2A = 0x1000000

$u = [ordered]@{}
$u.Administrator   = New-U 'Administrator' -Ou "CN=Users,$dn" -Sid "$dom-500" -Uac (0x200 -bor $DEXP) -PwdAge 800 -Logon 5 -Created 3000 -AdminCount 1
$u.Guest           = New-U 'Guest' -Ou "CN=Users,$dn" -Sid "$dom-501" -Uac (0x200 -bor $UAC_DIS -bor $PNR) -PwdAge $null -Logon $null -Created 3000 -Pg 514
$u.krbtgt          = New-U 'krbtgt' -Ou "CN=Users,$dn" -Sid "$dom-502" -Uac (0x200 -bor $UAC_DIS) -PwdAge 1500 -Logon $null -Created 3000 -Spn @('kadmin/changepw') -AdminCount 1
$u.krbtgtRodc      = New-U 'krbtgt_12345' -Ou "CN=Users,$dn" -Uac (0x200 -bor $UAC_DIS) -PwdAge 400 -Logon $null -Created 900
$u.rossi           = New-U 'adm.rossi' -Ou $adminsOu -Uac (0x200 -bor $ND) -PwdAge 60 -Logon 1 -AdminCount 1
$u.bianchi         = New-U 'adm.bianchi' -Ou $adminsOu -PwdAge 400 -Logon 2 -AdminCount 1
$u.verdi           = New-U 'adm.verdi' -Ou $adminsOu -PwdAge 30 -Logon 1 -AdminCount 1
$u.old             = New-U 'adm.old' -Ou $adminsOu -Uac (0x200 -bor $DEXP) -PwdAge 900 -Logon 200 -Created 2000 -AdminCount 1
$u.sqladm          = New-U 'svc_sql_admin' -Ou $svcOu -Uac (0x200 -bor $DEXP) -PwdAge 1200 -Logon 1 -Spn @('MSSQLSvc/sql01.moosebank.local:1433') -AdminCount 1 -KeyCred 1
$u.neri            = New-U 'adm.neri' -Ou $adminsOu -PwdAge 20 -Logon 1 -AdminCount 1
$u.gialli          = New-U 'adm.gialli' -Ou $adminsOu -Uac (0x200 -bor $NOPRE) -PwdAge 100 -Logon 3 -AdminCount 1
$u.ferrari         = New-U 'adm.ferrari' -Ou $adminsOu -Uac (0x200 -bor $PNR) -PwdAge 50 -Logon 1 -AdminCount 1
$u.exdip           = New-U 'adm.exdipendente' -Ou $adminsOu -Uac (0x200 -bor $UAC_DIS) -PwdAge 500 -Logon 300 -AdminCount 1
$u.loop            = New-U 'loop.user' -Ou $adminsOu -PwdAge 40 -Logon 1 -AdminCount 1
$u.hidden          = New-U 'hidden.admin' -Ou $usersOu -PwdAge 40 -Logon 4 -Pg 512
$u.hdlead          = New-U 'helpdesk.lead' -Ou $usersOu -PwdAge 80 -Logon 1 -AdminCount 1
$u.backup          = New-U 'svc_backup' -Ou $svcOu -Uac (0x200 -bor $DEXP) -PwdAge 700 -Logon 1 -Spn @('backup/bkp01.moosebank.local') -Enc 4 -AdminCount 1
$u.dns             = New-U 'dns.admin' -Ou $usersOu -PwdAge 90 -Logon 5
$u.web             = New-U 'svc_web' -Ou $svcOu -Uac (0x200 -bor $DEXP) -PwdAge 500 -Logon 1 -Spn @('HTTP/web01.moosebank.local') -Enc 24
$u.app             = New-U 'svc_app' -Ou $svcOu -PwdAge 100 -Logon 1 -Spn @('HTTP/app01.moosebank.local', 'HTTP/app01') -UnixPwd $true
$u.iis             = New-U 'svc_iis_deleg' -Ou $svcOu -Uac (0x200 -bor $T2A) -PwdAge 50 -Logon 1 -Spn @('HTTP/iis01.moosebank.local') -Enc 24 -Deleg @('cifs/dc01.moosebank.local', 'cifs/DC01')
$u.legacy          = New-U 'svc_legacy' -Ou $svcOu -Uac (0x200 -bor $NOPRE -bor $DES) -PwdAge 1000 -Logon 10
$u.orphan          = New-U 'old.admin.2019' -Ou $usersOu -PwdAge 200 -Logon 30 -AdminCount 1
$u.inactive        = New-U 'mario.rossi.old' -PwdAge 500 -Logon 400 -Created 2500
$u.temp            = New-U 'temp.user' -PwdAge 200 -Logon $null -Created 200
$u.newhire         = New-U 'new.hire' -PwdAge 10 -Logon $null -Created 10
$u.revers          = New-U 'revers.user' -Uac (0x200 -bor $REV) -PwdAge 30 -Logon 3
$u.printer         = New-U 'printer.svc' -Ou $svcOu -Uac (0x200 -bor $PNR) -PwdAge 300 -Logon 1 -Desc '[masked by collector: 31 chars]' -DescSusp $true
$u.creditiDesc     = New-U 'laura.conti' -Desc 'Ufficio Crediti - passaggio consegne' -PwdAge 40 -Logon 1
$u.migrated        = New-U 'migrated.user' -PwdAge 60 -Logon 2 -SidHistory @('S-1-5-21-777777777-888888888-999999999-1234')
$u.evil            = New-U 'evil.user' -PwdAge 60 -Logon 2 -SidHistory @("$dom-512")
$u.unconstr        = New-U 'unconstrained.user' -Uac (0x200 -bor $TFD) -PwdAge 60 -Logon 2
$u.msol            = New-U 'MSOL_a1b2c3d4e5f6' -Ou "CN=Users,$dn" -Uac (0x200 -bor $DEXP) -PwdAge 30 -Logon 1
$u.backdoor        = New-U 'backdoor.user' -PwdAge 20 -Logon 1
# Get-Changes + Get-Changes-In-Filtered-Set on the domain head, no Get-Changes-All: DirSync of LAPS (sync_laps_rights).
$u.dirsync         = New-U 'svc.dirsync' -Ou $svcOu -PwdAge 30 -Logon 1
$u.gmsa            = New-U 'gmsa_sql$' -Ou "CN=Managed Service Accounts,$dn" -Uac 0x1000 -PwdAge 5 -Logon 1 -Spn @('MSSQLSvc/sql02.moosebank.local:1433') -Pg 515 -Kind 'msa' -Enc 24
$u.smsa            = New-U 'svc_smsa$' -Ou "CN=Managed Service Accounts,$dn" -Uac 0x1000 -PwdAge 400 -Logon 1 -Spn @('MSSQLSvc/legacy.moosebank.local:1433') -Pg 515 -Kind 'msa' -Enc 4
# gMSA whose managed password can be read by a non-Tier 0 group (Helpdesk).
$u.gmsa['gmsaReadPrincipals'] = @("CN=Helpdesk,CN=Users,$dn")
foreach ($i in 1..30) { $u["std$i"] = New-U ("user{0:D3}" -f $i) -PwdAge (($i * 7) % 90 + 5) -Logon (($i * 3) % 20 + 1) }
$u.hd1 = New-U 'hd.operator1' -PwdAge 30 -Logon 1
$u.hd2 = New-U 'hd.operator2' -PwdAge 30 -Logon 1
# Smart card required (0x40000), hash never rolled: smartcard_password_not_rotated.
# Also a subject-only certificate mapping next to a strong one: altsecid_weak_mapping.
$u.scard = New-U 'sc.bianchi' -Uac (0x200 -bor 0x40000) -PwdAge 900 -Logon 1 -AltSec @('IssuerSerial', 'SubjectOnly')
# Entra Kerberos server object (cloud Kerberos trust), key not rotated: cloud_kerberos_trust_key_old.
$u.krbAad = New-U 'krbtgt_AzureAD' -Ou "CN=Users,$dn" -Uac (0x200 -bor $UAC_DIS) -PwdAge 250 -Logon $null -Created 900

# -------------------------------------------------------------- computers
$c = [ordered]@{}
$DC_UAC = 0x2000 -bor $TFD
$c.dc01   = New-C 'DC01' -Ou $dcOu -Os 'Windows Server 2022 Datacenter' -OsVer '10.0 (20348)' -Uac $DC_UAC -Pg 516 -LapsV2 $null -Rbcd @("CN=EVILPC,CN=Computers,$dn")
$c.dc02   = New-C 'DC02' -Ou $dcOu -Os 'Windows Server 2016 Standard' -OsVer '10.0 (14393)' -Uac $DC_UAC -Pg 516 -LapsV2 $null -PwdAge 200
$c.rodc   = New-C 'RODC01' -Ou $dcOu -Os 'Windows Server 2019 Standard' -OsVer '10.0 (17763)' -Uac (0x1000 -bor 0x4000000) -Pg 521 -LapsV2 $null
$c.bkp    = New-C 'SRV-BACKUP01' -Ou $srvOu -Os 'Windows Server 2019 Standard' -OsVer '10.0 (17763)'
$c.print  = New-C 'SRV-PRINT01' -Ou $srvOu -Os 'Windows Server 2019 Standard' -OsVer '10.0 (17763)' -Uac (0x1000 -bor $TFD)
$c.old08  = New-C 'SRV-OLD2008' -Ou $srvOu -Os 'Windows Server 2008 R2 Standard' -OsVer '6.1 (7601)' -LapsV2 $null
$c.win7   = New-C 'WKS-W7-01' -Os 'Windows 7 Professional' -OsVer '6.1 (7601)' -Logon 300 -LapsV2 $null
$c.app    = New-C 'SRV-APP01' -Ou $srvOu -Os 'Windows Server 2022 Standard' -OsVer '10.0 (20348)' -Rbcd @("CN=SRV-WEB01,$srvOu")
$c.web    = New-C 'SRV-WEB01' -Ou $srvOu -Os 'Windows Server 2022 Standard' -OsVer '10.0 (20348)'
$c.evil   = New-C 'EVILPC' -Ou "CN=Computers,$dn" -Os 'Windows 10 Pro' -OsVer '10.0 (19045)' -Created 20 -LapsV2 $null
# The second target was a file server long gone: no account holds it (delegation_orphan_spn).
$c.sql    = New-C 'SRV-SQL01' -Ou $srvOu -Os 'Windows Server 2022 Standard' -OsVer '10.0 (20348)' -Deleg @('MSSQLSvc/sql02.moosebank.local:1433', 'cifs/srv-files-old.moosebank.local')
$c.linux  = New-C 'LINUX01' -Ou $srvOu -Os 'Ubuntu 24.04' -OsVer '' -LapsV2 $null
# Pre-staged computer left with PASSWD_NOTREQD (predictable default password).
$c.prestaged = New-C 'PRESTAGE01' -Ou $srvOu -Os 'Windows Server 2022 Standard' -OsVer '10.0 (20348)' -Uac (0x1000 -bor $PNR)
# Seamless SSO account: never logs on (not stale), key rolled over 400 days ago: azuread_sso_key_old.
$c.sso = New-C 'AZUREADSSOACC' -Ou "CN=Computers,$dn" -Os '' -OsVer '' -Logon $null -PwdAge 400 -Created 1500 -LapsV2 $null -Enc 24
foreach ($i in 1..20) {
    $name = "WKS-{0:D3}" -f $i
    $laps = -20; $logon = ($i % 10) + 1; $desc = ''; $susp = $false
    if ($i -eq 15) { $laps = 100 }
    if ($i -eq 16) { $laps = $null }
    if ($i -eq 17) { $logon = 120 }
    if ($i -eq 18) { $desc = '[masked by collector: 28 chars]'; $susp = $true }
    $c["wks$i"] = New-C $name -Logon $logon -LapsV2 $laps -Desc $desc -DescSusp $susp
}

# ----------------------------------------------------------------- groups
$fspDn = "CN=S-1-5-21-999999999-999999999-999999999-1105,CN=ForeignSecurityPrincipals,$dn"
$g = [ordered]@{}
$g.loopA   = New-G 'G-Loop-A' "$dom-1104" @("CN=G-Loop-B,CN=Users,$dn")
$g.loopB   = New-G 'G-Loop-B' "$dom-1105" @("CN=G-Loop-A,CN=Users,$dn", $u.loop.distinguishedName)
$g.tier0   = New-G 'IT-Tier0-Admins' "$dom-1102" @($u.neri.distinguishedName, $u.gialli.distinguishedName, $g.loopA.distinguishedName)
$g.da      = New-G 'Domain Admins' "$dom-512" @($u.Administrator.distinguishedName, $u.rossi.distinguishedName, $u.bianchi.distinguishedName, $u.verdi.distinguishedName,
    $u.old.distinguishedName, $u.sqladm.distinguishedName, $u.ferrari.distinguishedName, $u.exdip.distinguishedName, $g.tier0.distinguishedName) -AdminCount 1
$g.ea      = New-G 'Enterprise Admins' "$dom-519" @($u.Administrator.distinguishedName, $u.rossi.distinguishedName) -AdminCount 1 -Scope 'Universal'
$g.sa      = New-G 'Schema Admins' "$dom-518" @() -AdminCount 1 -Scope 'Universal'
$g.admins  = New-G 'Administrators' 'S-1-5-32-544' @($u.Administrator.distinguishedName, $g.da.distinguishedName, $g.ea.distinguishedName, $c.bkp.distinguishedName, $fspDn) -Ou "CN=Builtin,$dn" -AdminCount 1 -Scope 'DomainLocal'
$g.accop   = New-G 'Account Operators' 'S-1-5-32-548' @($u.hdlead.distinguishedName) -Ou "CN=Builtin,$dn" -AdminCount 1 -Scope 'DomainLocal'
$g.srvop   = New-G 'Server Operators' 'S-1-5-32-549' @() -Ou "CN=Builtin,$dn" -AdminCount 1 -Scope 'DomainLocal'
$g.prnop   = New-G 'Print Operators' 'S-1-5-32-550' @() -Ou "CN=Builtin,$dn" -AdminCount 1 -Scope 'DomainLocal'
$g.bkpop   = New-G 'Backup Operators' 'S-1-5-32-551' @($u.backup.distinguishedName) -Ou "CN=Builtin,$dn" -AdminCount 1 -Scope 'DomainLocal'
$g.dnsadm  = New-G 'DnsAdmins' "$dom-1101" @($u.dns.distinguishedName) -Scope 'DomainLocal'
$g.gpco    = New-G 'Group Policy Creator Owners' "$dom-520" @($u.Administrator.distinguishedName)
$g.ka      = New-G 'Key Admins' "$dom-526" @()
$g.eka     = New-G 'Enterprise Key Admins' "$dom-527" @() -Scope 'Universal'
$g.pu      = New-G 'Protected Users' "$dom-525" @()
$g.du      = New-G 'Domain Users' "$dom-513" @()
$g.dg      = New-G 'Domain Guests' "$dom-514" @()
$g.dcomp   = New-G 'Domain Computers' "$dom-515" @()
$g.dcs     = New-G 'Domain Controllers' "$dom-516" @()
$g.rodcs   = New-G 'Read-only Domain Controllers' "$dom-521" @()
$g.erodcs  = New-G 'Enterprise Read-only Domain Controllers' "$dom-498" @() -Scope 'Universal'
$g.deniedRodc = New-G 'Denied RODC Password Replication Group' "$dom-572" @()   # empty: Tier 0 not protected
$g.allowedRodc = New-G 'Allowed RODC Password Replication Group' "$dom-571" @() -Scope 'DomainLocal'
$g.hd      = New-G 'Helpdesk' "$dom-1103" @($u.hd1.distinguishedName, $u.hd2.distinguishedName, $u.hdlead.distinguishedName)
$g.itops   = New-G 'IT-Ops' "$dom-1106" @($u.verdi.distinguishedName)
$g.svcgrp  = New-G 'ServiceAccounts-PSO' "$dom-1107" @($u.web.distinguishedName, $u.app.distinguishedName)
$g.exwp    = New-G 'Exchange Windows Permissions' "$dom-1108" @() -Ou "OU=Microsoft Exchange Security Groups,$dn" -Scope 'Universal'

# ------------------------------------------------------------------- ACLs
$GC = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; $GCA = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$FCP = '00299570-246d-11d0-a768-00aa006e0529'; $KCL = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
$USER = 'bf967aba-0de6-11d0-a285-00aa003049e2'; $GPLINK = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
function Default-Aces {
    @(
        (Ace "$dom-512" 'MOOSEBANK\Domain Admins' 'CreateChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, WriteOwner')
        (Ace "$dom-519" 'MOOSEBANK\Enterprise Admins' 'GenericAll')
        (Ace 'S-1-5-32-544' 'BUILTIN\Administrators' 'CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner')
        (Ace 'S-1-5-18' 'NT AUTHORITY\SYSTEM' 'GenericAll')
        (Ace 'S-1-5-11' 'NT AUTHORITY\Authenticated Users' 'GenericRead')
        (Ace 'S-1-5-10' 'NT AUTHORITY\SELF' 'WriteProperty' -ObjectType $KCL)
        (Ace 'S-1-1-0' 'Everyone' 'ExtendedRight' -ObjectType 'ab721a53-1e2f-11d0-9819-00aa0040529b')
    )
}
$rootAces = @(Default-Aces) + @(
    (Ace 'S-1-5-9' 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS' 'ExtendedRight' -ObjectType $GCA -Inh 'None')
    (Ace "$dom-516" 'MOOSEBANK\Domain Controllers' 'ExtendedRight' -ObjectType $GCA -Inh 'None')
    (Ace "$dom-498" 'MOOSEBANK\Enterprise Read-only Domain Controllers' 'ExtendedRight' -ObjectType $GC -Inh 'None')
    (Ace "$dom-526" 'MOOSEBANK\Key Admins' 'ReadProperty, WriteProperty' -ObjectType $KCL -Inh 'All')
    (Ace $u.msol.sid "MOOSEBANK\$($u.msol.samAccountName)" 'ExtendedRight' -ObjectType $GC -Inh 'None')
    (Ace $u.msol.sid "MOOSEBANK\$($u.msol.samAccountName)" 'ExtendedRight' -ObjectType $GCA -Inh 'None')
    (Ace $u.backdoor.sid 'MOOSEBANK\backdoor.user' 'ExtendedRight' -ObjectType $GC -Inh 'None')
    (Ace $u.backdoor.sid 'MOOSEBANK\backdoor.user' 'ExtendedRight' -ObjectType $GCA -Inh 'None')
    (Ace $u.dirsync.sid 'MOOSEBANK\svc.dirsync' 'ExtendedRight' -ObjectType $GC -Inh 'None')
    (Ace $u.dirsync.sid 'MOOSEBANK\svc.dirsync' 'ExtendedRight' -ObjectType '89e95b76-444d-4c62-991a-0facbeda640c' -Inh 'None')
    (Ace "$dom-1103" 'MOOSEBANK\Helpdesk' 'ExtendedRight' -ObjectType $FCP -InhObj $USER -Inh 'Descendents')
    # Exchange left without split permissions: WriteDacl on the domain head (PrivExchange).
    (Ace "$dom-1108" 'MOOSEBANK\Exchange Windows Permissions' 'WriteDacl' -Inh 'None')
    (Ace 'S-1-5-11' 'NT AUTHORITY\Authenticated Users' 'WriteProperty' -ObjectType $GPLINK -Inh 'None' -Type 'Deny')
)
$acls = @(
    [ordered]@{ target = 'DomainRoot'; distinguishedName = $dn; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'; aces = $rootAces }
    [ordered]@{ target = 'AdminSDHolder'; distinguishedName = "CN=AdminSDHolder,CN=System,$dn"; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
        aces = @(Default-Aces) + @((Ace $u.backdoor.sid 'MOOSEBANK\backdoor.user' 'GenericAll' -Inh 'None')) }
    [ordered]@{ target = 'DomainControllersOU'; distinguishedName = $dcOu; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
        aces = @(Default-Aces) + @((Ace "$dom-1106" 'MOOSEBANK\IT-Ops' 'ReadProperty, WriteProperty' -ObjectType $GPLINK -Inh 'None')) }
    [ordered]@{ target = 'Group:Domain Admins'; distinguishedName = $g.da.distinguishedName; ownerSid = $u.old.sid; ownerName = 'MOOSEBANK\adm.old'; aces = @(Default-Aces) }
    [ordered]@{ target = 'Group:Schema Admins'; distinguishedName = $g.sa.distinguishedName; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'; aces = @(Default-Aces) }
    [ordered]@{ target = 'Group:Enterprise Admins'; distinguishedName = $g.ea.distinguishedName; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'; aces = @(Default-Aces) }
    [ordered]@{ target = 'Group:Administrators'; distinguishedName = $g.admins.distinguishedName; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'; aces = @(Default-Aces) }
    # Default ACL of a non-protected group: Account Operators has GenericAll. Must not be flagged.
    [ordered]@{ target = 'Group:Group Policy Creator Owners'; distinguishedName = $g.gpco.distinguishedName; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
        aces = @(Default-Aces) + @((Ace 'S-1-5-32-548' 'BUILTIN\Account Operators' 'GenericAll' -Inh 'None')) }
)

# ----------------------------------------------------------- extra (large)
if ($Scenario -eq 'large') {
    $rnd = New-Object System.Random 42
    $members = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -le $ExtraUsers; $i++) {
        $logon = $rnd.Next(1, 400); $uac = 0x200
        if ($rnd.Next(0, 20) -eq 0) { $uac = $uac -bor $DEXP }
        if ($rnd.Next(0, 50) -eq 0) { $uac = $uac -bor 0x2 }
        $x = New-U ("bulk{0:D6}" -f $i) -Uac $uac -PwdAge ($rnd.Next(1, 500)) -Logon $logon -Created ($rnd.Next(100, 3000))
        $u["bulk$i"] = $x
        if ($i % 10 -eq 0) { $members.Add($x.distinguishedName) }
    }
    $g.bulk = New-G 'All-Staff' "$dom-1199" @($members)
    for ($i = 1; $i -le $ExtraComputers; $i++) {
        $c["bulkc$i"] = New-C ("PC{0:D5}" -f $i) -Logon ($rnd.Next(1, 200)) -LapsV2 ($rnd.Next(-30, 60))
    }
}

# ------------------------------------------------------------------- AD CS
$ENROLL_GUID = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$EKU_CLIENT = '1.3.6.1.5.5.7.3.2'; $EKU_ANY = '2.5.29.37.0'; $EKU_AGENT = '1.3.6.1.4.1.311.20.2.1'; $EKU_EMAIL = '1.3.6.1.5.5.7.3.4'; $EKU_SERVER = '1.3.6.1.5.5.7.3.1'
$CT_NAME_SUPPLY = 0x1; $CT_PEND = 0x2; $CT_NO_SEC_EXT = 0x80000   # ENROLLEE_SUPPLIES_SUBJECT ; PEND_ALL_REQUESTS ; NO_SECURITY_EXTENSION (ESC9)
function CertTemplate {
    param([string]$Name, [string]$Display, [int64]$NameFlag = 0, [int64]$EnrollFlag = 0, [int]$RaSig = 0, [string[]]$Ekus = @(), [bool]$Published = $true, [array]$Aces, [string]$OwnerSid = "$dom-512", [string]$OwnerName = 'MOOSEBANK\Domain Admins', [int]$Schema = 2, [string[]]$Policies = @())
    if (-not $Aces) { $Aces = @() }
    [ordered]@{ name = $Name; displayName = $Display; schemaVersion = $Schema; nameFlag = $NameFlag; enrollmentFlag = $EnrollFlag; raSignature = $RaSig
        ekus = $Ekus; issuancePolicies = @($Policies); published = $Published; ownerSid = $OwnerSid; ownerName = $OwnerName; aces = $Aces }
}
$duEnroll = @((Ace "$dom-513" 'MOOSEBANK\Domain Users' 'ExtendedRight' -ObjectType $ENROLL_GUID -Inh 'None'))
$authEnroll = @((Ace 'S-1-5-11' 'NT AUTHORITY\Authenticated Users' 'ExtendedRight' -ObjectType $ENROLL_GUID -Inh 'None'))
$pkiBase = "CN=Public Key Services,CN=Services,CN=Configuration,$dn"
function PkiAcl { param([string]$Target, [string]$Dn, [array]$Extra = @())
    [ordered]@{ target = $Target; distinguishedName = $Dn; objectClass = ''; ownerSid = "$dom-519"; ownerName = 'MOOSEBANK\Enterprise Admins'; aces = @(Default-Aces) + $Extra } }
$certPub = (Ace "$dom-517" 'MOOSEBANK\Cert Publishers' 'ReadProperty, WriteProperty' -Inh 'None')
$pkiAcls = @(
    (PkiAcl 'Public Key Services' $pkiBase)
    (PkiAcl 'Certificate Templates' "CN=Certificate Templates,$pkiBase")
    # Cert Publishers write to the AIA and NTAuth objects by default: no finding.
    (PkiAcl 'AIA' "CN=AIA,$pkiBase" @($certPub))
    (PkiAcl 'NTAuthCertificates' "CN=NTAuthCertificates,$pkiBase" @($certPub))
    # IT-Ops (not Tier 0) can rewrite the CA object's ACL: ESC5.
    (PkiAcl 'CA:MOOSEBANK-CA' "CN=MOOSEBANK-CA,CN=Enrollment Services,$pkiBase" @((Ace "$dom-1106" 'MOOSEBANK\IT-Ops' 'WriteDacl' -Inh 'None')))
)
$adcs = [ordered]@{
    collected = $true
    enrollmentServices = @(
        [ordered]@{ name = 'MOOSEBANK-CA'; distinguishedName = "CN=MOOSEBANK-CA,CN=Enrollment Services,$pkiBase"; dnsHostName = 'ca01.moosebank.local'; flags = 0; publishedTemplates = @('MooseUser', 'MooseESC1', 'MooseESC2', 'MooseESC3', 'MooseWeb', 'MooseESC4', 'MooseESC9', 'MooseESC15', 'MooseESC13'); caCertExpiry = $ref.AddDays(120).ToString('o'); caKeySize = 1024; caSigAlg = 'sha256RSA'
            # Read on the CA host: EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6), Helpdesk is a CA officer (ESC7),
            # web enrollment installed (ESC8), InterfaceFlags without 0x200 (ESC11). SID extension kept (no ESC16).
            caRegistry = [ordered]@{ editFlags = 0x15014E; interfaceFlags = 0x41; disableExtensionList = @(); webEnrollment = $true; enrollmentWebService = $false; error = ''
                securityAces = @(
                    [ordered]@{ sid = "$dom-512"; name = 'MOOSEBANK\Domain Admins'; mask = 3 }
                    [ordered]@{ sid = 'S-1-5-32-544'; name = 'BUILTIN\Administrators'; mask = 3 }
                    [ordered]@{ sid = 'S-1-5-11'; name = 'NT AUTHORITY\Authenticated Users'; mask = 0x200 }
                    [ordered]@{ sid = "$dom-1103"; name = 'MOOSEBANK\Helpdesk'; mask = 2 }) } }
    )
    templates = @(
        # ESC1: enrollee supplies subject + client auth + no approval + no RA sig, Domain Users can enroll
        (CertTemplate -Name 'MooseESC1' -Display 'Moose ESC1 Vulnerable' -NameFlag $CT_NAME_SUPPLY -EnrollFlag 0 -RaSig 0 -Ekus @($EKU_CLIENT) -Aces $duEnroll)
        # ESC2: Any Purpose, Authenticated Users, no approval
        (CertTemplate -Name 'MooseESC2' -Display 'Moose ESC2 AnyPurpose' -Ekus @($EKU_ANY) -Aces $authEnroll)
        # ESC3: enrollment agent EKU, Domain Users, no approval
        (CertTemplate -Name 'MooseESC3' -Display 'Moose ESC3 EnrollAgent' -Ekus @($EKU_AGENT) -Aces $duEnroll)
        # ESC4: benign purpose but low-priv principal can WriteDacl the template
        (CertTemplate -Name 'MooseESC4' -Display 'Moose ESC4 WeakACL' -Ekus @($EKU_EMAIL) -Aces (@((Ace "$dom-513" 'MOOSEBANK\Domain Users' 'WriteDacl' -Inh 'None')) + $duEnroll))
        # Client auth open to Domain Users, but with manager approval: no ESC1, still adcs_low_priv_enroll.
        (CertTemplate -Name 'MooseWeb' -Display 'Moose Web Server' -EnrollFlag $CT_PEND -Ekus @($EKU_CLIENT) -Aces $duEnroll)
        # ESC9: no security extension + client auth + no approval, Domain Users enroll
        (CertTemplate -Name 'MooseESC9' -Display 'Moose ESC9 NoSecExt' -EnrollFlag $CT_NO_SEC_EXT -Ekus @($EKU_CLIENT) -Aces $duEnroll)
        # ESC15 (EKUwu): schema v1 + enrollee supplies subject, non-client-auth EKU, Domain Users enroll
        (CertTemplate -Name 'MooseESC15' -Display 'Moose ESC15 SchemaV1' -Schema 1 -NameFlag $CT_NAME_SUPPLY -Ekus @($EKU_SERVER) -Aces $duEnroll)
        # ESC13: benign EKU but the issuance policy OID is linked to a privileged group
        (CertTemplate -Name 'MooseESC13' -Display 'Moose ESC13 PolicyLink' -Ekus @($EKU_EMAIL) -Policies @('1.3.6.1.4.1.311.21.8.1.1') -Aces $duEnroll)
        # Benign: restricted to Domain Admins only, no low-priv enroll
        (CertTemplate -Name 'MooseUser' -Display 'Moose User' -Ekus @($EKU_CLIENT) -Aces @((Ace "$dom-512" 'MOOSEBANK\Domain Admins' 'ExtendedRight' -ObjectType $ENROLL_GUID -Inh 'None')))
    )
    ntAuthCertCount = 1
    oidGroupLinks = @(
        [ordered]@{ oid = '1.3.6.1.4.1.311.21.8.1.1'; groupDn = "CN=Domain Admins,CN=Users,$dn"; name = 'High Assurance Policy' }
    )
    pkiAcls = $pkiAcls
}

# ------------------------------------------------------- pre-Win2000 group
$anonDn = "CN=S-1-5-7,CN=ForeignSecurityPrincipals,$dn"
$preWin2000 = [ordered]@{ name = 'Pre-Windows 2000 Compatible Access'; distinguishedName = "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$dn"; members = @($anonDn, "CN=Domain Users,CN=Users,$dn") }

# LAPS attribute GUID: the real collector looks it up, here it's fixed.
$lapsGuid = 'ea2b1b3a-0000-4b1a-9c0d-000000000001'
# ------------------------------------------------------- deep ACL sweep (-Deep)
$deepAcls = @()
$kdsRootKeyAcls = @()
if ($Deep) {
    # Helpdesk can read the forest KDS root key: Golden gMSA. Domain Admins on it is the default.
    $kdsRootKeyAcls = @(
        [ordered]@{ target = 'kds:3f1c8e2a-5d4b-4c1e-9a7f-2b6d0e8c4a11'; distinguishedName = "CN=3f1c8e2a-5d4b-4c1e-9a7f-2b6d0e8c4a11,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,$dn"
            objectClass = 'msKds-ProvRootKey'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
            aces = @((Ace "$dom-512" 'MOOSEBANK\Domain Admins' 'GenericAll' -Inh 'None'), (Ace "$dom-1103" 'MOOSEBANK\Helpdesk' 'GenericRead' -Inh 'None')) }
    )
    $deepAcls = @(
        # Helpdesk (non-privileged) has GenericAll over a Domain Admin: a real escalation path a deep sweep finds.
        [ordered]@{ target = "obj:$($u.bianchi.distinguishedName)"; distinguishedName = $u.bianchi.distinguishedName; objectClass = 'user'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
            aces = @(Default-Aces) + @((Ace "$dom-1103" 'MOOSEBANK\Helpdesk' 'GenericAll' -Inh 'None')) }
        # Authenticated Users can WriteDacl an OU: broad, Critical.
        [ordered]@{ target = "obj:$srvOu"; distinguishedName = $srvOu; objectClass = 'organizationalUnit'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
            aces = @(Default-Aces) + @((Ace 'S-1-5-11' 'NT AUTHORITY\Authenticated Users' 'WriteDacl' -Inh 'None')) }
        # A normal user object with only default ACEs: must NOT produce a finding.
        [ordered]@{ target = "obj:$($u.std1.distinguishedName)"; distinguishedName = $u.std1.distinguishedName; objectClass = 'user'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'; aces = @(Default-Aces) }
        # Helpdesk can read a workstation's LAPS password -> laps_readers.
        [ordered]@{ target = "obj:$($c.web.distinguishedName)"; distinguishedName = $c.web.distinguishedName; objectClass = 'computer'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
            aces = @(Default-Aces) + @((Ace "$dom-1103" 'MOOSEBANK\Helpdesk' 'ReadProperty' -ObjectType $lapsGuid -Inh 'None')) }
        # Only Domain Admins read this one's LAPS password: no finding.
        [ordered]@{ target = "obj:$($c.app.distinguishedName)"; distinguishedName = $c.app.distinguishedName; objectClass = 'computer'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
            aces = @(Default-Aces) + @((Ace "$dom-512" 'MOOSEBANK\Domain Admins' 'ReadProperty' -ObjectType $lapsGuid -Inh 'None')) }
        # IT-Ops can write the account-restrictions property set of a server: it can set RBCD on it.
        [ordered]@{ target = "obj:$($c.sql.distinguishedName)"; distinguishedName = $c.sql.distinguishedName; objectClass = 'computer'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
            aces = @(Default-Aces) + @((Ace "$dom-1106" 'MOOSEBANK\IT-Ops' 'WriteProperty' -ObjectType '4c164200-20c0-11d0-a768-00aa003049e2' -Inh 'None')) }
    )
}

# ------------------------------------------------ OU and container ACLs (BadSuccessor)
# As the collector keeps them: explicit Allow ACEs with create or control rights only.
# No Windows Server 2025 DC in the demo, so none of this is reported; the regression adds one.
$dmsaGuid = '0feb936f-47b3-49f2-9386-1dedc2c23765'
$ouAcls = @(
    # Helpdesk may create dMSAs in the workstations OU: the BadSuccessor delegation.
    # Account Operators (Tier 0) and a user-only CreateChild for IT-Ops are fine.
    [ordered]@{ target = "ou:$wksOu"; distinguishedName = $wksOu; objectClass = 'organizationalUnit'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
        aces = @((Ace "$dom-1103" 'MOOSEBANK\Helpdesk' 'CreateChild' -ObjectType $dmsaGuid -Inh 'None'),
            (Ace 'S-1-5-32-548' 'BUILTIN\Account Operators' 'CreateChild, DeleteChild' -ObjectType 'bf967aba-0de6-11d0-a285-00aa003049e2' -Inh 'None'),
            (Ace "$dom-1106" 'MOOSEBANK\IT-Ops' 'CreateChild, DeleteChild' -ObjectType 'bf967aba-0de6-11d0-a285-00aa003049e2' -Inh 'None')) }
    # GenericAll that only reaches user objects below the OU: not a container right.
    [ordered]@{ target = "ou:$srvOu"; distinguishedName = $srvOu; objectClass = 'organizationalUnit'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
        aces = @((Ace "$dom-1106" 'MOOSEBANK\IT-Ops' 'GenericAll' -InhObj 'bf967aba-0de6-11d0-a285-00aa003049e2' -Inh 'Descendents')) }
    # IT-Ops owns the service accounts OU: as owner it can grant itself CreateChild.
    [ordered]@{ target = "ou:$svcOu"; distinguishedName = $svcOu; objectClass = 'organizationalUnit'; ownerSid = "$dom-1106"; ownerName = 'MOOSEBANK\IT-Ops'; aces = @() }
    [ordered]@{ target = "ou:CN=Users,$dn"; distinguishedName = "CN=Users,$dn"; objectClass = 'container'; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'; aces = @() }
)

# ------------------------------------------------------ SCCM System Management
# SRV-APP01 is the site server (Full Control, expected); Helpdesk can create objects there:
# sccm_system_management_writable.
$sccm = [ordered]@{ present = $true
    acl = [ordered]@{ target = 'SystemManagement'; distinguishedName = "CN=System Management,CN=System,$dn"; objectClass = ''; ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
        aces = @((Ace $c.app.sid 'MOOSEBANK\SRV-APP01$' 'GenericAll'), (Ace "$dom-1103" 'MOOSEBANK\Helpdesk' 'CreateChild, DeleteChild'), (Ace 'S-1-5-11' 'NT AUTHORITY\Authenticated Users' 'ReadProperty, ListChildren')) }
    managementPoints = @([ordered]@{ host = 'srv-app01.moosebank.local'; siteCode = 'MB1' }) }

# ------------------------------------------------------------------- GPO
# DC policy at Microsoft defaults (SMB signing on, LDAP signing and channel
# binding off) plus a sloppy GPO handing SeDebugPrivilege to a non-Tier 0 group.
$gpoDefaultDc = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
$gpoBad = '{11111111-1111-1111-1111-111111111111}'
$gpo = [ordered]@{
    collected = $true
    domainRootLinks = @([ordered]@{ guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'; enabled = $true; enforced = $false })
    dcOuLinks = @(
        [ordered]@{ guid = $gpoDefaultDc; enabled = $true; enforced = $false }
        [ordered]@{ guid = $gpoBad; enabled = $true; enforced = $false }
    )
    gpos = @(
        [ordered]@{ guid = $gpoDefaultDc; displayName = 'Default Domain Controllers Policy'
            registryValues = [ordered]@{
                'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature' = '4,1'
                'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' = '4,3'
                'MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential' = '4,1'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes' = '4,7'
                'MACHINE\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement' = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1' = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey' = '4,0'
                # Null sessions opened: anonymous_sam_enum lists them (the default pipes are not reported).
                'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous' = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares' = '7,COMCFG,DFS$'
                'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes' = '7,netlogon,samr,lsarpc,BROWSER'
            }
            privilegeRights = [ordered]@{ 'SeBackupPrivilege' = @('S-1-5-32-544', 'S-1-5-32-551') }
            systemAccess = [ordered]@{}; kerberosPolicy = [ordered]@{}; serviceStart = [ordered]@{}; userPolicyRead = $true
            # Partial audit policy: audit_policy_insufficient, not audit_advanced_policy_missing.
            auditPolicy = [ordered]@{
                '0cce923f-69ae-11d9-bed3-505054503030' = 3   # Credential Validation OK
                '0cce9215-69ae-11d9-bed3-505054503030' = 3   # Logon OK
                '0cce9235-69ae-11d9-bed3-505054503030' = 1   # User Account Mgmt: only Success (need both -> gap)
            } }
        [ordered]@{ guid = $gpoBad; displayName = 'MooseBank DC Extra'
            # RDP without NLA and with Restricted Admin: rdp_nla_disabled, rdp_restricted_admin.
            registryValues = [ordered]@{ 'MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication' = '4,0'
                'MACHINE\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin' = '4,0'
                # The DCs take updates over HTTPS; MooseESC15 issues server certificates for any name: adcs_esc17.
                'MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\WUServer' = '1,https://wsus02.moosebank.local:8531' }
            privilegeRights = [ordered]@{ 'SeDebugPrivilege' = @("$dom-1103") }  # Helpdesk (non Tier 0) can debug on DCs
            systemAccess = [ordered]@{}; kerberosPolicy = [ordered]@{}; serviceStart = [ordered]@{}; userPolicyRead = $true
            # Non-Tier 0 principal (Helpdesk) can edit this DC-OU-linked GPO.
            ownerSid = "$dom-512"; ownerName = 'MOOSEBANK\Domain Admins'
            aces = @((Ace "$dom-1103" 'MOOSEBANK\Helpdesk' 'GenericWrite' -Inh 'None')) }
        [ordered]@{ guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'; displayName = 'Default Domain Policy'
            # Point and Print opened to non-admins, silently (point_and_print_unsafe, Critical).
            registryValues = [ordered]@{ 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash' = '4,1'
                'MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators' = '4,0'
                'MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall' = '4,1'
                # Both sides of AlwaysInstallElevated (Critical), WSUS over HTTP, an autologon password (masked by the collector).
                'MACHINE\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' = '4,1'
                'USER\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' = '4,1'
                'MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\WUServer' = '1,http://wsus01.moosebank.local:8530'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon' = '1,1'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword' = '1,<masked>' }
            privilegeRights = [ordered]@{}; systemAccess = [ordered]@{}
            # Ticket renewal stretched to 30 days: kerberos_ticket_lifetime_long.
            kerberosPolicy = [ordered]@{ MaxTicketAge = '10'; MaxRenewAge = '30'; MaxServiceAge = '600'; MaxClockSkew = '5' }; userPolicyRead = $true
            # WebClient left on Manual: webclient_not_disabled.
            serviceStart = [ordered]@{ 'webclient' = 3 } }
    )
    # What the GPOs run and which local groups they fill.
    execution = @(
        # DC GPO runs a script from a file server: Critical.
        [ordered]@{ guid = $gpoBad; gpo = 'MooseBank DC Extra'; scope = 'Machine'; kind = 'Startup script'; command = '\\fs01.moosebank.local\it$\dc-tools.cmd' }
        # From NETLOGON and a local path: fine.
        [ordered]@{ guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'; gpo = 'Default Domain Policy'; scope = 'User'; kind = 'Logon script'; command = '\\moosebank.local\NETLOGON\map-drives.bat' }
        [ordered]@{ guid = '{22222222-2222-2222-2222-222222222222}'; gpo = 'Workstation Baseline'; scope = 'Machine'; kind = "scheduled task 'Cleanup'"; command = 'C:\Windows\System32\cleanmgr.exe' }
        # Workstation GPO (not linked to root or DCs) runs an agent from a share: Medium.
        [ordered]@{ guid = '{22222222-2222-2222-2222-222222222222}'; gpo = 'Workstation Baseline'; scope = 'Machine'; kind = "scheduled task 'Inventory'"; command = '"\\fs01\inventory\agent.exe"' }
    )
    localGroups = @(
        [ordered]@{ guid = '{22222222-2222-2222-2222-222222222222}'; gpo = 'Workstation Baseline'; source = 'Preferences'; group = 'S-1-5-32-544'; member = "$dom-513"; memberName = 'MOOSEBANK\Domain Users' }
        [ordered]@{ guid = '{22222222-2222-2222-2222-222222222222}'; gpo = 'Workstation Baseline'; source = 'Restricted Groups'; group = 'Remote Desktop Users'; member = 'S-1-5-11'; memberName = 'S-1-5-11' }
        # A named admin group in local Administrators is what you want: no finding.
        [ordered]@{ guid = $gpoBad; gpo = 'MooseBank DC Extra'; source = 'Preferences'; group = 'S-1-5-32-544'; member = "$dom-1106"; memberName = 'MOOSEBANK\IT-Ops' }
    )
}

# --------------------------------------------------------------- snapshot
$errors = @()
if ($Scenario -eq 'partial') {
    $errors = @(
        [ordered]@{ section = 'domain.fineGrainedPolicies'; message = 'Insufficient access rights to perform the operation (synthetic).' }
        [ordered]@{ section = 'acl.DomainRoot'; message = 'Access is denied (synthetic).' }
    )
    $acls = @($acls | Where-Object { $_.target -ne 'DomainRoot' })
}

$users = @($u.Values | Where-Object { $_.kind -eq 'user' })
$msas = @($u.Values | Where-Object { $_.kind -eq 'msa' } | ForEach-Object { $_['isGroupManaged'] = ($_.samAccountName -like 'gmsa*'); $_ })

$snapshot = [ordered]@{
    meta = [ordered]@{
        tool = 'IDWolf'; schemaVersion = 2; collectorVersion = 'synthetic'
        collectedAtUtc = $ref.ToString('o'); collectedBy = 'MOOSEBANK\auditor'; collectedFrom = 'PAW-01'; server = 'dc01.moosebank.local'
        # The partial scenario stands for an older collector: no connection record.
        connection = if ($Scenario -eq 'partial') { $null } else { [ordered]@{
                requestedServer = 'dc01.moosebank.local'; servedBy = 'dc01.moosebank.local'; protocol = 'ADWS'; port = 9389; firstAnswerMs = 412
                diagnostics = [ordered]@{
                    requestedServer = 'dc01.moosebank.local'; domain = 'moosebank.local'; localDnsServers = @('10.10.0.10', '10.10.0.11')
                    domainDns = [ordered]@{ name = 'moosebank.local'; addresses = @('10.10.0.10', '10.10.0.11'); ms = 4; error = '' }
                    dcLocator = [ordered]@{ record = '_ldap._tcp.dc._msdcs.moosebank.local'; targets = @('dc01.moosebank.local', 'dc02.moosebank.local'); ms = 6; error = '' }
                    dc = 'dc01.moosebank.local'; dcSelectedBy = 'chosen (-Server)'
                    dcDns = [ordered]@{ name = 'dc01.moosebank.local'; addresses = @('10.10.0.10'); ms = 2; error = '' }
                    ldap = [ordered]@{ target = 'dc01.moosebank.local'; protocol = 'LDAP'; port = 389; ms = 23; answeredBy = 'dc01.moosebank.local'; site = 'Milano-HQ'; error = '' }
                    ports = @(
                        [ordered]@{ host = '10.10.0.10'; port = 9389; service = 'ADWS'; usedFor = 'every Get-AD* read (the collection)'; used = $true; open = $true; ms = 3; error = '' }
                        [ordered]@{ host = '10.10.0.10'; port = 445; service = 'SMB'; usedFor = 'SYSVOL (GPP passwords, GPO settings, scripts)'; used = $true; open = $true; ms = 2; error = '' }
                        [ordered]@{ host = '10.10.0.10'; port = 5985; service = 'WinRM'; usedFor = 'CIM: DC health, DNS server, CA settings'; used = $true; open = $false; ms = $null; error = 'no answer in 2000 ms (filtered?)' }
                        [ordered]@{ host = '10.10.0.10'; port = 636; service = 'LDAPS'; usedFor = 'LDAP over TLS, when 389 does not answer'; used = $false; open = $false; ms = $null; error = 'connection refused' }
                    )
                }
            } }
        options = [ordered]@{ skipSysvol = ($Scenario -eq 'partial'); skipAcl = $false; skipAdcs = $false; skipGpo = $false; skipDns = $false; skipHealth = $false; deep = [bool]$Deep }
        collectionErrors = $errors; synthetic = $true
    }
    domain = [ordered]@{
        dnsRoot = 'moosebank.local'; netbios = 'MOOSEBANK'; distinguishedName = $dn; sid = $dom
        domainMode = 'Windows2012R2Domain'; forestName = 'moosebank.local'; forestRootDomain = 'moosebank.local'; forestRootSid = $dom; forestMode = 'Windows2012R2Forest'
        machineAccountQuota = 10; dsHeuristics = '0000002'; smartcardPwdRotation = $false; recycleBinEnabled = $false; tombstoneLifetime = 90; lapsLegacySchema = $false; lapsV2Schema = $true; javaSchemaClasses = @('javaSerializedObject', 'javaContainer'); possSuperiorClasses = @([ordered]@{ name = 'msExchStorageGroup'; possSuperiors = @('computer'); subClassChain = @('container'); inheritsContainer = $true }, [ordered]@{ name = 'mooseDevice'; possSuperiors = @('user'); subClassChain = @('device'); inheritsContainer = $false }); lapsAttrGuids = @($lapsGuid); authPolicySiloCount = 0; subnetCount = 0; sysvolReplication = 'FRS'
        passwordPolicy = [ordered]@{ minPasswordLength = 8; complexityEnabled = $true; reversibleEncryptionEnabled = $false; lockoutThreshold = 0
            lockoutDurationMinutes = 30; maxPasswordAgeDays = 90; minPasswordAgeDays = 1; passwordHistoryCount = 24 }
        fineGrainedPolicies = if ($Scenario -eq 'partial') { $null } else { @(
                [ordered]@{ name = 'PSO-ServiceAccounts'; precedence = 20; minPasswordLength = 6; complexityEnabled = $false; reversibleEncryptionEnabled = $false; lockoutThreshold = 0; maxPasswordAgeDays = 0; appliesTo = @($g.svcgrp.distinguishedName) }
                [ordered]@{ name = 'PSO-Admins'; precedence = 10; minPasswordLength = 10; complexityEnabled = $true; reversibleEncryptionEnabled = $false; lockoutThreshold = 5; maxPasswordAgeDays = 180; appliesTo = @($g.da.distinguishedName) }
            ) }
    }
    domainControllers = @(
        [ordered]@{ name = 'DC01'; hostName = 'dc01.moosebank.local'; operatingSystem = 'Windows Server 2022 Datacenter'; osVersion = '10.0 (20348)'; isGlobalCatalog = $true; isReadOnly = $false; site = 'Milano'; fsmoRoles = @('PDCEmulator', 'RIDMaster', 'InfrastructureMaster'); computerDN = $c.dc01.distinguishedName }
        [ordered]@{ name = 'DC02'; hostName = 'dc02.moosebank.local'; operatingSystem = 'Windows Server 2016 Standard'; osVersion = '10.0 (14393)'; isGlobalCatalog = $true; isReadOnly = $false; site = 'Roma'; fsmoRoles = @('SchemaMaster', 'DomainNamingMaster'); computerDN = $c.dc02.distinguishedName }
        [ordered]@{ name = 'RODC01'; hostName = 'rodc01.moosebank.local'; operatingSystem = 'Windows Server 2019 Standard'; osVersion = '10.0 (17763)'; isGlobalCatalog = $true; isReadOnly = $true; site = 'Filiale-Torino'; fsmoRoles = @(); computerDN = $c.rodc.distinguishedName
            # Domain Users allowed, a Tier 0 admin's password already cached, administered by Helpdesk.
            rodcPolicy = [ordered]@{
                allowed = @($g.allowedRodc.distinguishedName, $g.du.distinguishedName)
                denied = @($g.deniedRodc.distinguishedName)
                revealed = @($u.neri.distinguishedName, $u.std5.distinguishedName, $c.rodc.distinguishedName)
                managedBy = $g.hd.distinguishedName } }
    )
    trusts = @(
        [ordered]@{ name = 'partner.example'; target = 'partner.example'; direction = 'Inbound'; trustType = 'Uplevel'; trustAttributes = 0x80; forestTransitive = $false; intraForest = $false
            sidFilteringQuarantined = $false; sidFilteringForestAware = $false; selectiveAuthentication = $false; tgtDelegation = $false; usesRC4Encryption = $true; usesAESKeys = $false; whenChanged = (Iso 400) }
        [ordered]@{ name = 'legacy-forest.local'; target = 'legacy-forest.local'; direction = 'BiDirectional'; trustType = 'Uplevel'; trustAttributes = (0x8 -bor 0x40 -bor 0x800); forestTransitive = $true; intraForest = $false
            sidFilteringQuarantined = $false; sidFilteringForestAware = $false; selectiveAuthentication = $false; tgtDelegation = $true; usesRC4Encryption = $false; usesAESKeys = $true; whenChanged = (Iso 12) }
        [ordered]@{ name = 'child.moosebank.local'; target = 'child.moosebank.local'; direction = 'BiDirectional'; trustType = 'Uplevel'; trustAttributes = 0x20; forestTransitive = $false; intraForest = $true
            sidFilteringQuarantined = $false; sidFilteringForestAware = $false; selectiveAuthentication = $false; tgtDelegation = $false; usesRC4Encryption = $false; usesAESKeys = $true; whenChanged = (Iso 12) }
    )
    users = $users
    serviceAccounts = $msas
    computers = @($c.Values)
    groups = @($g.Values)
    foreignPrincipals = @([ordered]@{ distinguishedName = $fspDn; sid = 'S-1-5-21-999999999-999999999-999999999-1105'; name = 'PARTNER\ext.admin' })
    acls = $acls
    ouAcls = $ouAcls
    sccm = $sccm
    deepAcls = $deepAcls
    kdsRootKeyAcls = $kdsRootKeyAcls
    preWin2000 = $preWin2000
    adcs = $adcs
    gpo = $gpo
    sysvol = if ($Scenario -eq 'partial') { [ordered]@{ scanned = $false; cpasswordFiles = @(); scriptSecretFiles = @(); autologonFiles = @(); folderAcls = @() } } else {
        [ordered]@{ scanned = $true; cpasswordFiles = @('\\moosebank.local\SYSVOL\moosebank.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml')
            scriptSecretFiles = @('\\moosebank.local\SYSVOL\moosebank.local\scripts\mapdrives.bat')
            # GPP registry item with the kiosk autologon password: gpo_autologon_password.
            # NETLOGON modifiable by Domain Users (sysvol_writable); Policies at the defaults.
            folderAcls = @(
                [ordered]@{ folder = 'NETLOGON (scripts)'; path = '\\moosebank.local\SYSVOL\moosebank.local\scripts'; aces = @(
                        [ordered]@{ sid = 'S-1-5-32-544'; name = 'BUILTIN\Administrators'; rights = 'FullControl'; accessType = 'Allow'; isInherited = $true }
                        [ordered]@{ sid = 'S-1-5-18'; name = 'NT AUTHORITY\SYSTEM'; rights = 'FullControl'; accessType = 'Allow'; isInherited = $true }
                        [ordered]@{ sid = 'S-1-5-32-549'; name = 'BUILTIN\Server Operators'; rights = 'Modify, Synchronize'; accessType = 'Allow'; isInherited = $true }
                        [ordered]@{ sid = 'S-1-5-11'; name = 'NT AUTHORITY\Authenticated Users'; rights = 'ReadAndExecute, Synchronize'; accessType = 'Allow'; isInherited = $true }
                        [ordered]@{ sid = "$dom-513"; name = 'MOOSEBANK\Domain Users'; rights = 'Modify, Synchronize'; accessType = 'Allow'; isInherited = $false }) }
                [ordered]@{ folder = 'Policies'; path = '\\moosebank.local\SYSVOL\moosebank.local\Policies'; aces = @(
                        [ordered]@{ sid = 'S-1-5-32-544'; name = 'BUILTIN\Administrators'; rights = 'FullControl'; accessType = 'Allow'; isInherited = $true }
                        [ordered]@{ sid = 'S-1-3-0'; name = 'CREATOR OWNER'; rights = 'FullControl'; accessType = 'Allow'; isInherited = $true }
                        [ordered]@{ sid = "$dom-520"; name = 'MOOSEBANK\Group Policy Creator Owners'; rights = 'Modify, Synchronize'; accessType = 'Allow'; isInherited = $false }
                        [ordered]@{ sid = 'S-1-5-11'; name = 'NT AUTHORITY\Authenticated Users'; rights = 'ReadAndExecute, Synchronize'; accessType = 'Allow'; isInherited = $true }) })
            autologonFiles = @('\\moosebank.local\SYSVOL\moosebank.local\Policies\{22222222-2222-2222-2222-222222222222}\Machine\Preferences\Registry\Registry.xml') } }
    dns = [ordered]@{
        collected = $true
        zones = @([ordered]@{ name = 'moosebank.local'; dynamicUpdate = 'NonsecureAndSecure'; secureSecondaries = 'TransferToAnyServer'; isAdIntegrated = $true; agingEnabled = $false; createChildSids = @('S-1-5-11', "$dom-512") })
        dangerousRecords = @([ordered]@{ zone = 'moosebank.local'; name = 'wpad'; type = 'A' })
    }
    health = [ordered]@{
        collected = $true
        replication = @(
            # DC02 -> DC01: failing (consecutive failures) -> replication_failures.
            [ordered]@{ server = 'dc02.moosebank.local'; partner = 'dc01.moosebank.local'; lastSuccessUtc = (Iso 4); consecutiveFailures = 6 }
            # RODC01 -> DC01: no outright failure but last success is stale -> replication_stale.
            [ordered]@{ server = 'rodc01.moosebank.local'; partner = 'dc01.moosebank.local'; lastSuccessUtc = (Iso 3); consecutiveFailures = 0 }
            # DC01 -> DC02: healthy and recent -> no finding.
            [ordered]@{ server = 'dc01.moosebank.local'; partner = 'dc02.moosebank.local'; lastSuccessUtc = (Iso 0); consecutiveFailures = 0 }
        )
        # DHCP authorized on a domain controller (DC02) -> dhcp_on_dc.
        dhcpServers = @([ordered]@{ name = 'dc02.moosebank.local'; ip = '10.0.0.12' })
        # Last AD backup of the naming context well over the 7-day threshold -> ad_backup_overdue.
        lastBackupUtc = (Iso 45)
        # Infrastructure master still points at a DC that was removed -> fsmo_holder_invalid.
        fsmo = [ordered]@{ PDCEmulator = 'dc01.moosebank.local'; RIDMaster = 'dc01.moosebank.local'; InfrastructureMaster = 'dc-old.moosebank.local'
            SchemaMaster = 'dc02.moosebank.local'; DomainNamingMaster = 'dc02.moosebank.local' }
        forestRoot = $true
        # The RODC doesn't answer from the collecting machine -> dc_unreachable.
        dcReachability = @(
            [ordered]@{ dc = 'dc01.moosebank.local'; reachable = $true; latencyMs = 12; error = '' }
            [ordered]@{ dc = 'dc02.moosebank.local'; reachable = $true; latencyMs = 25; error = '' }
            [ordered]@{ dc = 'rodc01.moosebank.local'; reachable = $false; latencyMs = $null; error = 'Unable to contact the server.' })
        # DC02 runs 95 s ahead of DC01 -> dc_time_skew.
        dcTime = @([ordered]@{ dc = 'dc01.moosebank.local'; offsetSeconds = 0.012 }, [ordered]@{ dc = 'dc02.moosebank.local'; offsetSeconds = 95.4 }, [ordered]@{ dc = 'rodc01.moosebank.local'; offsetSeconds = $null })
        # DC02: 3.5 GB free and DFSR stopped -> dc_low_disk, dc_service_stopped. DC01 healthy.
        dcState = @(
            [ordered]@{ dc = 'dc01.moosebank.local'; systemDrive = 'C:'; freeGB = 41.2; sizeGB = 99.4; stoppedServices = @(); webClientStartMode = 'absent'; webClientState = 'absent'
                netbiosAdapters = @([ordered]@{ adapter = 'vmxnet3 Ethernet Adapter'; netbiosOption = 2 }); osBuild = '20348'; osUbr = 2849
                # RPC filters deployed for every coercion interface: no coercion finding on DC01.
                coercionServices = [ordered]@{ EFS = 'Manual/Stopped'; Dfs = 'Auto/Running'; EventLog = 'Auto/Running' }; rpcFilterInterfaces = @('MS-DFSNM', 'MS-EFSR', 'MS-EVEN'); dsrmAdminLogonBehavior = 0; error = '' }
            # DC02 also runs WebClient (Desktop Experience installed) -> webclient_on_dc.
            [ordered]@{ dc = 'dc02.moosebank.local'; systemDrive = 'C:'; freeGB = 3.5; sizeGB = 59.4; stoppedServices = @('DFSR'); webClientStartMode = 'Manual'; webClientState = 'Running'
                # NetBIOS left at the default on a static address -> nbtns_enabled_dc.
                netbiosAdapters = @([ordered]@{ adapter = 'vmxnet3 Ethernet Adapter'; netbiosOption = 0 }, [ordered]@{ adapter = 'Backup NIC'; netbiosOption = 2 })
                # Server 2019 still on an October 2021 build -> nopac_unpatched_dc (Critical: MAQ = 10).
                osBuild = '17763'; osUbr = 2237
                # No RPC filter: coercion_unfiltered_dc, High (LDAP signing not required, ESC8 on the CA).
                # DsrmAdminLogonBehavior = 2 -> dsrm_logon_behavior (Tier 0 persistence).
                coercionServices = [ordered]@{ EFS = 'Manual/Stopped'; Dfs = 'Auto/Running'; EventLog = 'Auto/Running' }; rpcFilterInterfaces = @(); dsrmAdminLogonBehavior = 2; error = '' }
            [ordered]@{ dc = 'rodc01.moosebank.local'; systemDrive = $null; freeGB = $null; sizeGB = $null; stoppedServices = @(); error = 'not reachable' })
    }
}

if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot "..\examples\synthetic_$Scenario.json" }
$json = $snapshot | ConvertTo-Json -Depth 10
$full = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path (Get-Location).Path $OutFile }
[System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Synthetic snapshot ($Scenario): $full  users=$($users.Count) computers=$($c.Count) groups=$($g.Count)"
