<#
.SYNOPSIS
    TEST LAB ONLY. Plants a multi-hop escalation chain (and a few delegation findings) in a lab
    domain, so the attack-path map has something to draw.

.DESCRIPTION
    THIS SCRIPT WRITES TO ACTIVE DIRECTORY. IDWolf itself never does: this lives under tests\lab and
    is not part of the tool. Run it only in a throw-away lab domain, as a Domain Admin, in an
    elevated PowerShell on a DC (or a machine with RSAT).

    It creates, inside one OU (default IDWolfLab):

      Chain, four steps long:
        lab.entry  (member of)  LabHelpdesk
        LabHelpdesk      --GenericWrite-->  LabOps
        LabOps           --WriteDacl------>  LabAdminsShadow
        LabAdminsShadow  --GenericAll----->  lab.svcsync
        lab.svcsync      has DCSync rights on the domain head (Replicating Directory Changes (All))

      Extra escalation findings:
        lab.delegsvc   constrained delegation with protocol transition to ldap/<this DC>
        lab-unconstr   computer with unconstrained delegation
        lab-rbcdtarget computer that lets lab.rbcdsrc act on its behalf (RBCD)
        lab.asrep      pre-authentication disabled

    Users get random passwords that are never shown or saved.

    After it: collect with -Deep (the chain is made of ACLs the deep sweep reads) and run
    Test-LabAttackMap.ps1, or just run IDWolf and look at the attack-path map.

    -Remove deletes the OU with everything in it and removes the DCSync ACEs it added to the domain head.

.EXAMPLE
    .\New-LabAttackPaths.ps1
    .\New-LabAttackPaths.ps1 -Remove
#>
[CmdletBinding()]
Param(
    [switch]$Remove,
    [string]$OuName = 'IDWolfLab',
    [string]$ConfirmDomain = ''
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain = Get-ADDomain
$dn = $domain.DistinguishedName
$dns = $domain.DNSRoot
$ouDn = "OU=$OuName,$dn"

if (-not $ConfirmDomain) { $ConfirmDomain = Read-Host "This WRITES to $dns. Type the domain name to confirm it is a lab" }
if ($ConfirmDomain -ne $dns) { throw "Not confirmed ('$ConfirmDomain' is not '$dns'). Nothing was changed." }

$guidGetChanges = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$guidGetChangesAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

function Add-LabAce {
    param([string]$TargetDn, [System.Security.Principal.SecurityIdentifier]$Sid, [System.DirectoryServices.ActiveDirectoryRights]$Rights, [guid]$ObjectType = [guid]::Empty)
    $path = "AD:\$TargetDn"
    $acl = Get-Acl -Path $path
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, [System.Security.AccessControl.AccessControlType]::Allow, $ObjectType, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    $acl.AddAccessRule($rule)
    Set-Acl -Path $path -AclObject $acl
}

function New-LabPassword {
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
    $p = -join (1..24 | ForEach-Object { $chars | Get-Random })
    return (ConvertTo-SecureString ($p + 'aB3!') -AsPlainText -Force)
}

function Get-LabUser { param([string]$Sam) Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue }
function Get-LabGroup { param([string]$Sam) Get-ADGroup -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue }

if ($Remove) {
    $svc = Get-LabUser 'lab.svcsync'
    if ($svc) {
        $acl = Get-Acl -Path "AD:\$dn"
        $acl.PurgeAccessRules($svc.SID)
        Set-Acl -Path "AD:\$dn" -AclObject $acl
        Write-Host "Removed the DCSync ACEs of lab.svcsync from the domain head."
    }
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDn'" -ErrorAction SilentlyContinue) {
        Set-ADOrganizationalUnit -Identity $ouDn -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit -Identity $ouDn -Recursive -Confirm:$false
        Write-Host "Removed $ouDn."
    }
    return
}

if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDn'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $OuName -Path $dn -ProtectedFromAccidentalDeletion $false
}

foreach ($u in 'lab.entry', 'lab.svcsync', 'lab.delegsvc', 'lab.rbcdsrc', 'lab.asrep') {
    if (-not (Get-LabUser $u)) {
        New-ADUser -Name $u -SamAccountName $u -Path $ouDn -AccountPassword (New-LabPassword) -Enabled $true -PasswordNeverExpires $true -Description 'IDWolf lab account'
    }
}
foreach ($g in 'LabHelpdesk', 'LabOps', 'LabAdminsShadow') {
    if (-not (Get-LabGroup $g)) { New-ADGroup -Name $g -SamAccountName $g -GroupScope Global -GroupCategory Security -Path $ouDn -Description 'IDWolf lab group' }
}
Add-ADGroupMember -Identity 'LabHelpdesk' -Members 'lab.entry' -ErrorAction SilentlyContinue

# The chain.
$helpdesk = Get-LabGroup 'LabHelpdesk'; $ops = Get-LabGroup 'LabOps'; $shadow = Get-LabGroup 'LabAdminsShadow'; $sync = Get-LabUser 'lab.svcsync'
Add-LabAce -TargetDn $ops.DistinguishedName -Sid $helpdesk.SID -Rights GenericWrite
Add-LabAce -TargetDn $shadow.DistinguishedName -Sid $ops.SID -Rights WriteDacl
Add-LabAce -TargetDn $sync.DistinguishedName -Sid $shadow.SID -Rights GenericAll
Add-LabAce -TargetDn $dn -Sid $sync.SID -Rights ExtendedRight -ObjectType $guidGetChanges
Add-LabAce -TargetDn $dn -Sid $sync.SID -Rights ExtendedRight -ObjectType $guidGetChangesAll

# Delegation findings.
$dc = (Get-ADDomainController -Discover).HostName | Select-Object -First 1
Set-ADUser -Identity 'lab.delegsvc' -TrustedForDelegation $false
Set-ADAccountControl -Identity 'lab.delegsvc' -TrustedToAuthForDelegation $true
Set-ADUser -Identity 'lab.delegsvc' -ServicePrincipalNames @{ Add = 'HTTP/labdeleg.' + $dns }
Set-ADUser -Identity 'lab.delegsvc' -Add @{ 'msDS-AllowedToDelegateTo' = @("ldap/$dc") }
Set-ADAccountControl -Identity 'lab.asrep' -DoesNotRequirePreAuth $true

if (-not (Get-ADComputer -Filter "Name -eq 'lab-unconstr'" -ErrorAction SilentlyContinue)) { New-ADComputer -Name 'lab-unconstr' -Path $ouDn -Enabled $true -TrustedForDelegation $true }
if (-not (Get-ADComputer -Filter "Name -eq 'lab-rbcdtarget'" -ErrorAction SilentlyContinue)) { New-ADComputer -Name 'lab-rbcdtarget' -Path $ouDn -Enabled $true }
Set-ADComputer -Identity 'lab-rbcdtarget' -PrincipalsAllowedToDelegateToAccount (Get-LabUser 'lab.rbcdsrc')

Write-Host ""
Write-Host "Lab chain planted in ${ouDn}:" -ForegroundColor Green
Write-Host "  lab.entry > LabHelpdesk -GenericWrite-> LabOps -WriteDacl-> LabAdminsShadow -GenericAll-> lab.svcsync -DCSync-> Tier 0"
Write-Host "Next: .\Collect-ADSnapshot.ps1 -Deep -OutFile lab.json   then   .\tests\lab\Test-LabAttackMap.ps1 -Snapshot lab.json"
Write-Host "Undo with: .\tests\lab\New-LabAttackPaths.ps1 -Remove" -ForegroundColor Yellow
