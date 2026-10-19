# Connection diagnostics and domain controller selection, shared by Start-IDWolf.ps1 and
# Collect-ADSnapshot.ps1 (the collector dot-sources it when it is there, and works without it).
#
# Everything here only looks: DNS lookups, a TCP connect that is closed straight away (no byte
# is sent), an LDAP read of RootDSE and of the Sites container. No RSAT is needed (.NET
# System.DirectoryServices), and nothing throws: what can't be read comes back with the reason.

# The ports a collection uses, and what for. Used = $true for the ones IDWolf itself talks to;
# the others are tested because a broken domain usually shows up there first.
$script:IDWolfDcPorts = @(
    [ordered]@{ port = 9389; service = 'ADWS'; usedFor = 'every Get-AD* read (the collection)'; used = $true }
    [ordered]@{ port = 389; service = 'LDAP'; usedFor = 'DC list and rights check (launcher), DC locator'; used = $true }
    [ordered]@{ port = 445; service = 'SMB'; usedFor = 'SYSVOL (GPP passwords, GPO settings, scripts)'; used = $true }
    [ordered]@{ port = 5985; service = 'WinRM'; usedFor = 'CIM: DC health, DNS server, CA settings'; used = $true }
    [ordered]@{ port = 135; service = 'RPC'; usedFor = 'repadmin, password-quality replication'; used = $true }
    [ordered]@{ port = 88; service = 'Kerberos'; usedFor = 'sign-in to the DC'; used = $false }
    [ordered]@{ port = 53; service = 'DNS'; usedFor = 'name resolution, if the DC is a DNS server'; used = $false }
    [ordered]@{ port = 636; service = 'LDAPS'; usedFor = 'LDAP over TLS, when 389 does not answer'; used = $false }
    [ordered]@{ port = 3268; service = 'GC'; usedFor = 'not used by IDWolf (informational)'; used = $false }
)

function Get-ElapsedMs { param($Stopwatch) return [int][Math]::Round($Stopwatch.Elapsed.TotalMilliseconds) }

# The innermost exception message, trimmed: .NET wraps the useful one.
function Get-InnerMessage {
    param($Exception)
    $e = $Exception
    while ($e.InnerException) { $e = $e.InnerException }
    return "$($e.Message)".Trim()
}

# A/AAAA lookup through the system resolver. IPv4 first.
function Resolve-HostTimed {
    param([string]$Name)
    $r = [ordered]@{ name = $Name; addresses = @(); ms = $null; error = '' }
    if (-not $Name) { $r.error = 'no name'; return $r }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $ips = @([System.Net.Dns]::GetHostAddresses($Name))
        $r.addresses = @(@($ips | Where-Object { "$($_.AddressFamily)" -eq 'InterNetwork' }) + @($ips | Where-Object { "$($_.AddressFamily)" -ne 'InterNetwork' }) | ForEach-Object { "$_" })
    }
    catch { $r.error = Get-InnerMessage $_.Exception }
    $r.ms = Get-ElapsedMs $sw
    return $r
}

# TCP connects to several (host, port) pairs at once, each closed as soon as it opens. Returns
# one record per pair: open $true / $false (refused or timed out), ms to connect.
function Test-TcpPorts {
    param([object[]]$Targets, [int]$TimeoutMs = 2000)
    $jobs = @(foreach ($t in $Targets) {
            $c = New-Object System.Net.Sockets.TcpClient
            $task = $null; $err = ''
            try { $task = $c.ConnectAsync("$($t.host)", [int]$t.port) } catch { $err = Get-InnerMessage $_.Exception }
            [PSCustomObject]@{ Target = $t; Client = $c; Task = $task; Ms = $null; Done = ($null -eq $task); Error = $err }
        })
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (@($jobs | Where-Object { -not $_.Done }).Count -and $sw.Elapsed.TotalMilliseconds -lt $TimeoutMs) {
        foreach ($j in $jobs) { if (-not $j.Done -and $j.Task.IsCompleted) { $j.Done = $true; $j.Ms = Get-ElapsedMs $sw } }
        Start-Sleep -Milliseconds 5
    }
    foreach ($j in $jobs) {
        $open = $false
        if ($j.Task) {
            if (-not $j.Task.IsCompleted) { $j.Error = "no answer in $TimeoutMs ms (filtered?)" }
            elseif ($j.Task.IsFaulted) { $j.Error = Get-InnerMessage $j.Task.Exception }
            else { $open = $true }
        }
        try { $j.Client.Close() } catch { }
        $rec = [ordered]@{}
        foreach ($k in $j.Target.Keys) { $rec[$k] = $j.Target[$k] }
        $rec['open'] = $open; $rec['ms'] = if ($open) { $j.Ms } else { $null }; $rec['error'] = $j.Error
        $rec
    }
}

# The domain to diagnose when none is given: the user's, then the computer's.
function Get-DefaultDomainName {
    if ($env:USERDNSDOMAIN) { return "$env:USERDNSDOMAIN".ToLower() }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) { return "$($cs.Domain)".ToLower() }
    }
    catch { }
    return ''
}

# DNS servers this machine asks, from the network adapters that are up.
function Get-LocalDnsServers {
    try {
        return @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
                Where-Object { "$($_.OperationalStatus)" -eq 'Up' -and "$($_.NetworkInterfaceType)" -ne 'Loopback' } |
                ForEach-Object { @($_.GetIPProperties().DnsAddresses) } | Where-Object { $_ } |
                ForEach-Object { "$_" } | Where-Object { $_ -notmatch '^fec0:' } | Select-Object -Unique)
    }
    catch { return @() }
}

function New-LdapEntry {
    param([string]$Path, [System.Management.Automation.PSCredential]$Credential = $null, [switch]$Ssl)
    if ($Ssl) {
        # LDAPS: TLS on 636 under the Negotiate bind. The DC's certificate is checked by Windows
        # (trusted chain, matching name); a bad one fails the bind, it is never ignored.
        $auth = [System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
        if ($Credential) { return (New-Object System.DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password, $auth)) }
        return (New-Object System.DirectoryServices.DirectoryEntry($Path, $null, $null, $auth))
    }
    if ($Credential) { return (New-Object System.DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)) }
    return (New-Object System.DirectoryServices.DirectoryEntry($Path))
}

# The LDAP error of a failed LDAPS bind, with the usual cause: Windows only says "The server is
# not operational" when it refuses the DC's certificate.
function Get-LdapsHint {
    param([string]$Message)
    return "$Message (LDAPS on 636: the DC's certificate must be trusted by this machine and carry the name used)"
}

# How the launcher reaches a DC over LDAP: plain LDAP on 389 (a Negotiate bind, signed), or
# LDAPS on 636 when 389 does not answer and 636 does (a firewall that lets only LDAPS through).
# Server may carry its own port (dc01:636 forces LDAPS). Without Server the bind is serverless;
# if that fails, the first DC of the locator's SRV record is tested the same way. Binds RootDSE
# with Properties and returns Root, Prefix (for the other entries), Ssl, Protocol and Error.
function Open-LdapRootDse {
    param([string]$Server = '', [System.Management.Automation.PSCredential]$Credential = $null, [string[]]$Properties = @('defaultNamingContext'), [int]$TimeoutMs = 2000)
    $r = [ordered]@{ Root = $null; Prefix = ''; Ssl = $false; Protocol = 'LDAP'; Error = '' }
    $bind = {
        param([string]$Target, [bool]$Ssl)
        $r.Prefix = if ($Target) { "LDAP://$Target/" } else { 'LDAP://' }
        $r.Ssl = $Ssl; $r.Protocol = if ($Ssl) { 'LDAPS' } else { 'LDAP' }
        try {
            $root = New-LdapEntry ($r.Prefix + 'RootDSE') $Credential -Ssl:$Ssl
            $root.RefreshCache($Properties)
            $r.Root = $root; $r.Error = ''
        }
        catch {
            $m = Get-InnerMessage $_.Exception
            $r.Root = $null; $r.Error = if ($Ssl) { Get-LdapsHint $m } else { $m }
        }
    }
    # Which port answers on a DC: 'ldap' (389 open: the caller binds), 'ldaps' (only 636: bound
    # here over LDAPS), 'none'.
    $viaLdaps = {
        param([string]$TargetHost)
        $p = @(Test-TcpPorts -TimeoutMs $TimeoutMs -Targets @([ordered]@{ host = $TargetHost; port = 389 }, [ordered]@{ host = $TargetHost; port = 636 }))
        if (@($p | Where-Object { $_.port -eq 389 -and $_.open }).Count) { return 'ldap' }
        if (-not @($p | Where-Object { $_.port -eq 636 -and $_.open }).Count) { return 'none' }
        & $bind "$($TargetHost):636" $true
        return 'ldaps'
    }

    if ($Server -match ':(\d+)$') { & $bind $Server ($Matches[1] -eq '636' -or $Matches[1] -eq '3269') }
    elseif ($Server) {
        $how = & $viaLdaps $Server
        if ($how -eq 'ldap') { & $bind $Server $false }
        elseif ($how -eq 'none') { $r.Prefix = "LDAP://$Server/"; $r.Error = "TCP 389 (LDAP) and 636 (LDAPS) of $Server do not answer" }
    }
    else {
        & $bind '' $false
        if ($r.Error) {
            # Serverless bind refused: the locator's first DC, over LDAPS if only 636 answers there.
            $dom = Get-DefaultDomainName
            $first = ''
            if ($dom -and (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
                try { $first = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$dom" -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { "$($_.Type)" -eq 'SRV' } | ForEach-Object { "$($_.NameTarget)".ToLower() } | Sort-Object -Unique)[0] } catch { }
            }
            if ($first) {
                $plainError = $r.Error
                if ((& $viaLdaps $first) -ne 'ldaps') { $r.Prefix = 'LDAP://'; $r.Ssl = $false; $r.Protocol = 'LDAP'; $r.Error = $plainError }
                elseif ($r.Error) { $r.Error = "$plainError; over LDAPS to $first`: $($r.Error)" }
            }
        }
    }
    return [PSCustomObject]$r
}

# Everything that has to work before a collection can, measured: DNS of the domain, the DC
# locator SRV record, the DC the collection will use (Server, or the one the locator picks),
# an LDAP bind, and a TCP connect to each port in $script:IDWolfDcPorts. Server may be a DC or
# a domain name; Domain defaults to the machine's.
function Get-ConnectionDiagnostics {
    param([string]$Server = '', [string]$Domain = '', [System.Management.Automation.PSCredential]$Credential = $null, [int]$TimeoutMs = 2000)
    $d = [ordered]@{
        requestedServer = $Server; domain = ''; localDnsServers = @(Get-LocalDnsServers)
        domainDns = $null; dcLocator = $null; dc = ''; dcSelectedBy = ''; dcDns = $null; ldap = $null; ports = @()
    }
    if (-not $Domain) { $Domain = Get-DefaultDomainName }
    $testDc = {
        param([string]$Name, [string]$Why)
        $d.dc = $Name.ToLower(); $d.dcSelectedBy = $Why; $d.ports = @()
        $d.dcDns = Resolve-HostTimed $d.dc
        if (@($d.dcDns.addresses).Count) {
            $ip = @($d.dcDns.addresses)[0]
            $d.ports = @(Test-TcpPorts -TimeoutMs $TimeoutMs -Targets @($script:IDWolfDcPorts | ForEach-Object { $p = [ordered]@{ host = $ip }; foreach ($k in $_.Keys) { $p[$k] = $_[$k] }; $p }))
        }
    }

    # A server given: its DNS and ports first, so a filtered LDAP port is known before the bind
    # (which would otherwise hang for ~20 s).
    if ($Server) { & $testDc $Server 'chosen (-Server)' }

    # LDAP RootDSE: proves the bind works, and names the DC that answered (the locator's pick
    # when no server is given) and its domain (all a workgroup PC has to go on).
    # Plain LDAP on 389; LDAPS on 636 when only that port answers (protocol / port say which).
    $ldap = [ordered]@{ target = $(if ($Server) { $Server } else { $Domain }); protocol = 'LDAP'; port = 389; ms = $null; answeredBy = ''; site = ''; error = '' }
    $bindLdap = {
        param([string]$Target, [bool]$Ssl)
        $ldap.protocol = if ($Ssl) { 'LDAPS' } else { 'LDAP' }; $ldap.port = if ($Ssl) { 636 } else { 389 }
        $ldap.error = ''; $ldap.answeredBy = ''; $ldap.site = ''
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $prefix = if (-not $Target) { 'LDAP://' } elseif ($Ssl) { "LDAP://$($Target):636/" } else { "LDAP://$Target/" }
            $root = New-LdapEntry ($prefix + 'RootDSE') $Credential -Ssl:$Ssl
            $root.RefreshCache(@('dnsHostName', 'serverName', 'defaultNamingContext'))
            $ldap.answeredBy = "$($root.Properties['dnsHostName'].Value)".ToLower()
            # serverName = CN=DC01,CN=Servers,CN=<site>,CN=Sites,...
            if ("$($root.Properties['serverName'].Value)" -match ',CN=Servers,CN=([^,]+),CN=Sites,') { $ldap.site = $Matches[1] }
            $nc = "$($root.Properties['defaultNamingContext'].Value)"
            if ($nc) { $bound.Domain = ((($nc -split ',') | ForEach-Object { $_ -replace '^DC=', '' }) -join '.').ToLower() }
        }
        catch { $m = Get-InnerMessage $_.Exception; $ldap.error = if ($Ssl) { Get-LdapsHint $m } else { $m } }
        $ldap.ms = Get-ElapsedMs $sw
    }
    $bound = @{ Domain = '' }
    $portOpen = { param([int]$Port) [bool]@($d.ports | Where-Object { $_.port -eq $Port -and $_.open }).Count }
    if (-not $Server) { & $bindLdap '' $false }
    elseif (& $portOpen 389) { & $bindLdap $Server $false }
    elseif (& $portOpen 636) { & $bindLdap $Server $true }
    else { $ldap.error = 'not tried: TCP 389 (LDAP) and 636 (LDAPS) do not answer' }
    if (-not $Domain -and $bound.Domain) { $Domain = $bound.Domain }
    $d.ldap = $ldap
    # Still nothing (workgroup PC, LDAP refused): a dotted -Server may be the domain itself.
    if (-not $Domain -and $Server -match '\.') { $Domain = $Server.ToLower() }
    $d.domain = $Domain

    if ($Domain) {
        $d.domainDns = Resolve-HostTimed $Domain
        $srv = "_ldap._tcp.dc._msdcs.$Domain"
        $loc = [ordered]@{ record = $srv; targets = @(); ms = $null; error = '' }
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try { $loc.targets = @(Resolve-DnsName -Name $srv -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { "$($_.Type)" -eq 'SRV' } | ForEach-Object { "$($_.NameTarget)".ToLower() } | Sort-Object -Unique) }
            catch { $loc.error = Get-InnerMessage $_.Exception }
            $loc.ms = Get-ElapsedMs $sw
            if (-not $loc.error -and -not @($loc.targets).Count) { $loc.error = "no SRV record ($srv)" }
        }
        else { $loc.error = 'not tested (Resolve-DnsName not available here)' }
        $d.dcLocator = $loc
    }

    # The DC to test when none was named: the one that answered LDAP, else the first SRV target.
    # A domain name given as -Server is replaced by the DC that answered for it.
    if ($Server -and $ldap.answeredBy -and $Server.ToLower() -eq "$Domain".ToLower()) { & $testDc $ldap.answeredBy 'DC locator, for the domain given as -Server' }
    elseif (-not $Server) {
        if ($ldap.answeredBy) { & $testDc $ldap.answeredBy 'DC locator (automatic)' }
        elseif ($d.dcLocator -and @($d.dcLocator.targets).Count) { & $testDc @($d.dcLocator.targets)[0] 'first DNS SRV record' }
        # The serverless bind failed and that DC answers only on 636: LDAPS to it.
        if ($ldap.error -and $d.dc -and -not (& $portOpen 389) -and (& $portOpen 636)) {
            $plainError = $ldap.error
            & $bindLdap $d.dc $true
            $ldap.target = $d.dc
            if ($ldap.error) { $ldap.error = "$plainError; over LDAPS: $($ldap.error)" }
        }
    }
    return $d
}

# The diagnostics on the console. Compact: one line when every port IDWolf uses is open, the
# full table otherwise.
function Show-ConnectionDiagnostics {
    param($Diag, [switch]$Compact)
    if (-not $Diag) { return }
    $ms = { param($v) if ($null -eq $v) { '' } else { "$v ms" } }
    $usedPorts = @($Diag.ports | Where-Object { $_.used })
    $closed = @($usedPorts | Where-Object { -not $_.open })
    $dnsOk = $Diag.domainDns -and -not $Diag.domainDns.error
    if ($Compact -and $dnsOk -and $Diag.dc -and $usedPorts.Count -and -not $closed.Count -and -not $Diag.ldap.error) {
        $adws = @($usedPorts | Where-Object { $_.port -eq 9389 })[0]
        Write-Host ("Connection: {0} -> {1} ({2}), DC {3} ({4}, {5}), ADWS 9389 open ({6}), LDAP bind {7}" -f $Diag.domain, (@($Diag.domainDns.addresses) -join ', '), (& $ms $Diag.domainDns.ms), $Diag.dc, (@($Diag.dcDns.addresses)[0]), $Diag.dcSelectedBy, (& $ms $adws.ms), (& $ms $Diag.ldap.ms)) -ForegroundColor DarkGray
        return
    }
    Write-Host "`nConnection diagnostics:" -ForegroundColor Cyan
    if (@($Diag.localDnsServers).Count) { Write-Host ("  DNS servers of this machine  {0}" -f (@($Diag.localDnsServers) -join ', ')) }
    if (-not $Diag.domain) { Write-Host '  Domain                       unknown (not domain-joined and no -Server given)' -ForegroundColor Yellow }
    else {
        $dd = $Diag.domainDns
        if ($dd.error) { Write-Host ("  DNS {0,-25} FAILED in {1}: {2}" -f $Diag.domain, (& $ms $dd.ms), $dd.error) -ForegroundColor Yellow }
        else { Write-Host ("  DNS {0,-25} {1} ({2})" -f $Diag.domain, (@($dd.addresses) -join ', '), (& $ms $dd.ms)) }
        $lc = $Diag.dcLocator
        if ($lc.error) { Write-Host ("  DC locator (SRV)             {0}" -f $lc.error) -ForegroundColor $(if ($lc.error -like 'not tested*') { 'DarkGray' } else { 'Yellow' }) }
        else { Write-Host ("  DC locator (SRV)             {0} DC(s) in {1}" -f @($lc.targets).Count, (& $ms $lc.ms)) }
    }
    $l = $Diag.ldap
    $lbl = if ($l.protocol -eq 'LDAPS') { 'LDAPS bind (TCP 636)  ' } else { 'LDAP bind             ' }
    if ($l.error -like 'not tried*') { Write-Host ("  {0}       {1} {2}" -f $lbl, $l.target, $l.error) -ForegroundColor Yellow }
    elseif ($l.error) { Write-Host ("  {0}       {1} FAILED in {2}: {3}" -f $lbl, $(if ($l.target) { $l.target } else { '(default)' }), (& $ms $l.ms), $l.error) -ForegroundColor Yellow }
    else { Write-Host ("  {0}       {1}, answered by {2}{3}{4}" -f $lbl, (& $ms $l.ms), $l.answeredBy, $(if ($l.site) { " (site $($l.site))" }), $(if ($l.protocol -eq 'LDAPS') { ': TCP 389 does not answer, LDAP over TLS used instead' })) }
    if (-not $Diag.dc) { Write-Host '  Domain controller            none found: check the DNS servers above and the domain name' -ForegroundColor Yellow; return }
    $cd = $Diag.dcDns
    if ($cd.error) { Write-Host ("  Domain controller            {0} [{1}]: DNS FAILED ({2})" -f $Diag.dc, $Diag.dcSelectedBy, $cd.error) -ForegroundColor Yellow; return }
    Write-Host ("  Domain controller            {0} = {1} ({2}) [{3}]" -f $Diag.dc, (@($cd.addresses) -join ', '), (& $ms $cd.ms), $Diag.dcSelectedBy)
    Write-Host '  Ports on the DC:'
    foreach ($p in $Diag.ports) {
        $state = if ($p.open) { "open    $(& $ms $p.ms)" } else { 'CLOSED' }
        $col = if ($p.open) { 'Gray' } elseif ($p.used) { 'Yellow' } else { 'DarkGray' }
        Write-Host ("    TCP {0,-5} {1,-9} {2,-16} {3}" -f $p.port, $p.service, $state, $p.usedFor) -ForegroundColor $col
    }
    if (@($closed | Where-Object { $_.port -eq 9389 }).Count) { Write-Host '  ADWS (9389) is closed: the collection will fail against this DC. Pick another DC or ask for the firewall rule.' -ForegroundColor Yellow }
}

# Every DC of the domain, from the Sites container (one LDAP query, no RSAT): name, site,
# read-only, global catalog, PDC. Sorted by site, then name. Error explains an empty list.
function Get-DomainControllerList {
    param([string]$Server = '', [System.Management.Automation.PSCredential]$Credential = $null)
    $r = [ordered]@{ Domain = ''; Dcs = @(); Protocol = ''; Error = '' }
    try {
        $conn = Open-LdapRootDse -Server $Server -Credential $Credential -Properties @('defaultNamingContext', 'configurationNamingContext')
        if ($conn.Error) { throw "no domain controller answered over LDAP$(if ($Server) { " ($Server)" }): $($conn.Error)" }
        $prefix = $conn.Prefix; $ssl = $conn.Ssl; $r.Protocol = $conn.Protocol
        $root = $conn.Root
        $nc = "$($root.Properties['defaultNamingContext'].Value)"
        $config = "$($root.Properties['configurationNamingContext'].Value)"
        $r.Domain = (($nc -split ',') | ForEach-Object { $_ -replace '^DC=', '' }) -join '.'
        $head = New-LdapEntry ($prefix + $nc) $Credential -Ssl:$ssl
        $head.RefreshCache(@('fSMORoleOwner'))
        $pdcNtds = "$($head.Properties['fSMORoleOwner'].Value)".ToLower()

        # NTDS settings objects (nTDSDSA, nTDSDSARO for an RODC) of this domain's DCs. options bit 1 = GC.
        $sites = New-LdapEntry ($prefix + "CN=Sites,$config") $Credential -Ssl:$ssl
        $ds = New-Object System.DirectoryServices.DirectorySearcher($sites, '(|(objectClass=nTDSDSA)(objectClass=nTDSDSARO))', @('distinguishedName', 'objectClass', 'options', 'msDS-HasDomainNCs', 'hasMasterNCs'))
        $ds.PageSize = 500
        $ntds = @{}
        foreach ($h in $ds.FindAll()) {
            $ncs = @($h.Properties['msds-hasdomainncs']) + @($h.Properties['hasmasterncs']) | ForEach-Object { "$_".ToLower() }
            if ($ncs -notcontains $nc.ToLower()) { continue }
            $dn = "$($h.Properties['distinguishedname'][0])"
            $opt = 0; if ($h.Properties['options'].Count) { $opt = [int]$h.Properties['options'][0] }
            $ntds[($dn -replace '^CN=NTDS Settings,', '').ToLower()] = [PSCustomObject]@{ Ntds = $dn.ToLower(); Ro = (@($h.Properties['objectclass']) -contains 'nTDSDSARO'); Gc = [bool]($opt -band 1) }
        }
        $ss = New-Object System.DirectoryServices.DirectorySearcher($sites, '(objectClass=server)', @('distinguishedName', 'dNSHostName'))
        $ss.PageSize = 500
        $found = @(foreach ($h in $ss.FindAll()) {
                $dn = "$($h.Properties['distinguishedname'][0])"
                $n = $ntds[$dn.ToLower()]
                if (-not $n) { continue }
                $site = if ($dn -match ',CN=Servers,CN=([^,]+),CN=Sites,') { $Matches[1] } else { '' }
                $name = if ($h.Properties['dnshostname'].Count) { "$($h.Properties['dnshostname'][0])".ToLower() } else { ($dn -split ',')[0] -replace '^CN=', '' }
                [PSCustomObject]@{ Name = $name; Site = $site; ReadOnly = $n.Ro; GlobalCatalog = $n.Gc; Pdc = ($n.Ntds -eq $pdcNtds) }
            })
        $r.Dcs = @($found | Sort-Object Site, Name)
        if (-not $r.Dcs.Count) { $r.Error = 'no DC found in the Sites container' }
    }
    catch { $r.Error = Get-InnerMessage $_.Exception }
    return [PSCustomObject]$r
}

# Numbered list of the DCs on the console, with their ADWS latency (TCP 9389, all at once).
# Returns Get-DomainControllerList's result. The list comes from Server when it answers, else
# from the locator (Server may be the very DC one wants to move away from).
function Show-DomainControllerList {
    param([string]$Server = '', [System.Management.Automation.PSCredential]$Credential = $null, [string]$Current = '')
    Write-Host 'Reading the domain controllers...' -ForegroundColor DarkGray
    $list = Get-DomainControllerList -Server $Server -Credential $Credential
    if ($list.Error -and $Server) { $list = Get-DomainControllerList -Credential $Credential }
    if ($list.Error) { Write-Host "  DC list not available: $($list.Error)" -ForegroundColor Yellow; return $list }
    $lat = @{}
    foreach ($p in @(Test-TcpPorts -TimeoutMs 2000 -Targets @($list.Dcs | ForEach-Object { [ordered]@{ host = $_.Name; port = 9389 } }))) { $lat[$p.host] = $p }
    Write-Host "`nDomain controllers of $($list.Domain) ($(@($list.Dcs).Count)$(if ($list.Protocol -eq 'LDAPS') { ', read over LDAPS' })), ADWS (TCP 9389) from here:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $list.Dcs.Count; $i++) {
        $dc = $list.Dcs[$i]; $t = $lat[$dc.Name]
        $roles = @(); if ($dc.Pdc) { $roles += 'PDC' }; if ($dc.GlobalCatalog) { $roles += 'GC' }; if ($dc.ReadOnly) { $roles += 'RODC' }
        $roles = $roles -join ','
        $state = if ($t -and $t.open) { "$($t.ms) ms" } else { 'no answer' }
        $mark = if ($Current -and $dc.Name -eq $Current.ToLower()) { ' *' } else { '' }
        Write-Host ("  [{0,2}] {1,-40} {2,-22} {3,-12} {4}{5}" -f ($i + 1), $dc.Name, $dc.Site, $roles, $state, $mark) -ForegroundColor $(if ($t -and $t.open) { 'Gray' } else { 'DarkGray' })
    }
    if (@($list.Dcs | Where-Object { $_.ReadOnly }).Count) { Write-Host '  An RODC holds no secrets and may lack some attributes: prefer a writable DC for the collection.' -ForegroundColor DarkGray }
    return $list
}

# The list above, then a choice: a number, a name typed in, or Enter to keep the current one.
# Returns the DC name, or '' for automatic (the DC locator picks). Ask is there for the tests.
function Select-DomainController {
    param([string]$Current = '', [string]$Server = '', [System.Management.Automation.PSCredential]$Credential = $null, [scriptblock]$Ask = { param($q) Read-Host $q })
    $list = Show-DomainControllerList -Server $Server -Credential $Credential -Current $Current
    if ($list.Error) {
        $v = & $Ask "Domain controller name (Enter = $(if ($Current) { $Current } else { 'automatic' }), - = automatic)"
        if ([string]::IsNullOrWhiteSpace($v)) { return $Current }
        if ("$v".Trim() -eq '-') { return '' }
        return "$v".Trim()
    }
    while ($true) {
        $v = & $Ask "Number or name (Enter = $(if ($Current) { "keep $Current" } else { 'automatic' }), - = automatic, chosen by the DC locator)"
        if ([string]::IsNullOrWhiteSpace($v)) { return $Current }
        $v = "$v".Trim()
        if ($v -eq '-') { return '' }
        if ($v -match '^\d+$') {
            if ([int]$v -ge 1 -and [int]$v -le $list.Dcs.Count) { return $list.Dcs[[int]$v - 1].Name }
            Write-Host "  Pick 1-$($list.Dcs.Count)." -ForegroundColor Yellow; continue
        }
        return $v
    }
}
