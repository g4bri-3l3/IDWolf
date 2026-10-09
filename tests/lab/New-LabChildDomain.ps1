<#
.SYNOPSIS
    TEST LAB ONLY. Builds a child domain (child.<parent>) with a few users and admins, to see how
    IDWolf behaves on a forest with more than one domain.

.DESCRIPTION
    THIS SCRIPT WRITES TO ACTIVE DIRECTORY AND PROMOTES A SERVER. IDWolf itself never does either:
    this is under tests\lab and is not part of the tool. Not tested here (no domain available):
    try it on a throw-away VM and snapshot the VMs first. Undoing it means reverting the VM snapshots;
    demoting a child domain by hand is not something to script blindly.

    Two phases.

    -Phase Install   (on a NEW Windows Server VM, elevated PowerShell)
        Before: static IP, DNS pointing at the parent domain's DC, the parent resolves
        (nslookup <parent>), clocks in sync, a local Administrator password set.
        Needs -ParentCredential: an Enterprise Admin of the parent (PARENT\Administrator).
        Installs AD DS and promotes the server as the first DC of the child domain. It restarts.

    -Phase Populate  (on the new child DC, after the restart, as the child's Administrator)
        Creates OU IDWolfLabChild with: child.alice, child.bob, child.carol (plain users),
        child.admin (child Domain Admins), child.svc (service account with an SPN, so Kerberoastable),
        and a two-step ACL chain inside the child:
            ChildHelpdesk --GenericWrite--> ChildOps --WriteDacl--> the child's Domain Admins group
        With -ParentUser (a user of the parent, e.g. lab.entry from New-LabAttackPaths.ps1) it also
        adds that parent user to the child's Domain Admins: a cross-domain member of a Tier 0 group.

    What to look at afterwards (collect against each domain: -Server <a DC of that domain>):
      - the child snapshot: forest root SID resolved (Enterprise / Schema Admins live in the parent),
        child.admin and the cross-domain member among the Tier 0 principals, the ChildOps chain in the map;
      - the parent snapshot: child Domain Admins are not parent Tier 0, but the parent's Administrators
        and Enterprise Admins are.

.PARAMETER Phase
    Install or Populate.

.EXAMPLE
    .\New-LabChildDomain.ps1 -Phase Install -ParentDomain test.com -ChildName child -ParentCredential (Get-Credential TEST\Administrator)
    .\New-LabChildDomain.ps1 -Phase Populate -ParentUser lab.entry
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][ValidateSet('Install', 'Populate')][string]$Phase,
    [string]$ParentDomain = 'test.com',
    [string]$ChildName = 'child',
    [System.Management.Automation.PSCredential]$ParentCredential,
    [securestring]$SafeModePassword,
    [string]$ParentUser = '',
    [string]$OuName = 'IDWolfLabChild'
)

$ErrorActionPreference = 'Stop'

function New-LabPassword {
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
    $p = -join (1..24 | ForEach-Object { $chars | Get-Random })
    return (ConvertTo-SecureString ($p + 'aB3!') -AsPlainText -Force)
}

if ($Phase -eq 'Install') {
    if (-not $ParentCredential) { $ParentCredential = Get-Credential -Message "Enterprise Admin of $ParentDomain" }
    if (-not $SafeModePassword) { $SafeModePassword = Read-Host "Directory Services Restore Mode password for the new DC" -AsSecureString }
    $answer = Read-Host "This promotes THIS server as the first DC of $ChildName.$ParentDomain and restarts it. Type the child name ($ChildName) to confirm"
    if ($answer -ne $ChildName) { throw "Not confirmed. Nothing was changed." }
    if (-not (Resolve-DnsName $ParentDomain -ErrorAction SilentlyContinue)) { throw "$ParentDomain doesn't resolve: point this server's DNS at the parent DC first." }

    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
    Import-Module ADDSDeployment
    Install-ADDSDomain -NewDomainName $ChildName -ParentDomainName $ParentDomain -DomainType ChildDomain `
        -Credential $ParentCredential -SafeModeAdministratorPassword $SafeModePassword `
        -InstallDns:$true -CreateDnsDelegation:$true -DnsDelegationCredential $ParentCredential `
        -NewDomainNetbiosName $ChildName.ToUpper() -Force:$true
    return   # the server restarts on its own
}

# ---- Populate ----
Import-Module ActiveDirectory
$domain = Get-ADDomain
$dn = $domain.DistinguishedName
if ($domain.ParentDomain -ne $ParentDomain) { throw "This is $($domain.DNSRoot) (parent: '$($domain.ParentDomain)'), not a child of $ParentDomain. Run this on the child DC." }
$ouDn = "OU=$OuName,$dn"

function Add-LabAce {
    param([string]$TargetDn, [System.Security.Principal.SecurityIdentifier]$Sid, [System.DirectoryServices.ActiveDirectoryRights]$Rights)
    $path = "AD:\$TargetDn"
    $acl = Get-Acl -Path $path
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, [System.Security.AccessControl.AccessControlType]::Allow, [guid]::Empty, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)))
    Set-Acl -Path $path -AclObject $acl
}

if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDn'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $OuName -Path $dn -ProtectedFromAccidentalDeletion $false
}
foreach ($u in 'child.alice', 'child.bob', 'child.carol', 'child.admin', 'child.svc') {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$u'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $u -SamAccountName $u -Path $ouDn -AccountPassword (New-LabPassword) -Enabled $true -Description 'IDWolf lab account'
    }
}
Add-ADGroupMember -Identity 'Domain Admins' -Members 'child.admin' -ErrorAction SilentlyContinue
Set-ADUser -Identity 'child.svc' -ServicePrincipalNames @{ Add = "HTTP/childapp.$($domain.DNSRoot)" } -PasswordNeverExpires $true

foreach ($g in 'ChildHelpdesk', 'ChildOps') {
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$g'" -ErrorAction SilentlyContinue)) { New-ADGroup -Name $g -SamAccountName $g -GroupScope Global -GroupCategory Security -Path $ouDn }
}
Add-ADGroupMember -Identity 'ChildHelpdesk' -Members 'child.alice' -ErrorAction SilentlyContinue
$helpdesk = Get-ADGroup 'ChildHelpdesk'; $ops = Get-ADGroup 'ChildOps'; $da = Get-ADGroup -Identity "$($domain.DomainSID.Value)-512"
Add-LabAce -TargetDn $ops.DistinguishedName -Sid $helpdesk.SID -Rights GenericWrite
Add-LabAce -TargetDn $da.DistinguishedName -Sid $ops.SID -Rights WriteDacl

if ($ParentUser) {
    $pu = Get-ADUser -Identity $ParentUser -Server $ParentDomain
    Add-ADGroupMember -Identity $da -Members $pu
    Write-Host "Added $ParentDomain\$ParentUser to $($domain.NetBIOSName)\Domain Admins (cross-domain Tier 0 member)."
}

Write-Host ""
Write-Host "Child domain populated: $($domain.DNSRoot)" -ForegroundColor Green
Write-Host "Collect each domain on its own, from a machine that can reach both:"
Write-Host "  .\Collect-ADSnapshot.ps1 -Server <DC of $($domain.DNSRoot)> -Deep -OutFile child.json"
Write-Host "  .\Collect-ADSnapshot.ps1 -Server <DC of $ParentDomain> -Deep -OutFile parent.json"
