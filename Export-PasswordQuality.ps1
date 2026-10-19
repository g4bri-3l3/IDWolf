<#
.SYNOPSIS
    Password-quality report for IDWolf, without hashes. Feed the result to
    IDWolf.ps1 -PasswordQualityFile.

.DESCRIPTION
    Spotting duplicate, weak, breached or empty passwords needs the hashes,
    and IDWolf never stores them. So this script runs DSInternals where the
    hashes are and writes out only account names grouped by problem.

    Needs DSInternals (offered if missing) and either an account with DCSync
    rights, or an offline NTDS.dit plus its SYSTEM hive. Tested on a lab
    domain; still try it on a test DC before production.

.PARAMETER WeakPasswordsFile
    Optional list of known-bad passwords, either plaintext with one password
    per line, or NTLM hashes sorted ascending, one per line (optionally
    HASH:count, as in the Have I Been Pwned NTLM files). The first non-empty
    line decides which; the file name doesn't matter.
.PARAMETER Credential
    Account with DCSync rights, if the session doesn't have them.
.PARAMETER Server
    Writable DC to replicate from (alias -DomainController). Default: the PDC.
    An RODC holds no password hashes, so it can't be used.
.PARAMETER OutFile
    Output JSON path (default passwordquality_<domain>_<ts>.json).
.PARAMETER FromDatabase
    Path to an offline NTDS.dit to read instead of live replication.
.PARAMETER BootKeyFile
    SYSTEM hive path (required with -FromDatabase).
.PARAMETER InstallModules
    Install DSInternals from the PowerShell Gallery (CurrentUser scope) if it
    is missing, without asking. Interactive runs are offered the install.

.EXAMPLE
    .\Export-PasswordQuality.ps1 -WeakPasswordsFile .\weak.txt
.EXAMPLE
    .\Export-PasswordQuality.ps1 -FromDatabase .\ntds.dit -BootKeyFile .\SYSTEM
#>

[CmdletBinding()]
Param(
    [string]$WeakPasswordsFile = "",
    [string]$OutFile = "",
    [string]$FromDatabase = "",
    [string]$BootKeyFile = "",
    [System.Management.Automation.PSCredential]$Credential,
    [Alias('DomainController')]
    [string]$Server = "",
    [switch]$InstallModules
)

$ErrorActionPreference = 'Stop'

# DSInternals on demand, for the current user only (no admin needed).
function Install-DSInternals {
    try {
        # PS 5.1 defaults to TLS 1.0/1.1, which the Gallery refuses.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }
        Write-Host "Installing DSInternals from the PowerShell Gallery (CurrentUser)..." -ForegroundColor Cyan
        Install-Module DSInternals -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        return $true
    }
    catch {
        Write-Host "Install of DSInternals failed: $("$($_.Exception.Message)".Trim())" -ForegroundColor Red
        Write-Host "  Without Internet / PSGallery access: on a connected machine run 'Save-Module DSInternals -Path <folder>', then copy the DSInternals folder to $([Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules on this machine." -ForegroundColor Yellow
        Write-Host "  If the EDR/antivirus blocked or quarantined it, ask the security team for an exception for this audit." -ForegroundColor Yellow
        return $false
    }
}

if (-not (Get-Module -ListAvailable -Name DSInternals)) {
    Write-Host "DSInternals module not found." -ForegroundColor Yellow
    $want = [bool]$InstallModules
    if (-not $want) {
        $interactive = $false; try { $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected } catch { }
        if ($interactive) {
            Write-Host "  Note: DSInternals reads password hashes locally and is often flagged by EDR/antivirus; make sure this audit is authorized." -ForegroundColor DarkGray
            $want = ((Read-Host "Install DSInternals now from the PowerShell Gallery (current user, no admin needed)? (y/N)") -match '^[YySs]')
        }
    }
    if (-not ($want -and (Install-DSInternals) -and (Get-Module -ListAvailable -Name DSInternals))) {
        Write-Host "DSInternals not available. Install it with: Install-Module DSInternals -Scope CurrentUser (or re-run with -InstallModules)." -ForegroundColor Red
        exit 1
    }
}
Import-Module DSInternals -ErrorAction Stop

# Find the domain and PDC through .NET, so no RSAT needed.
$domainDns = 'domain'; $pdc = $null
try {
    $ctx = if ($Credential) {
        # Local-account sessions have no USERDNSDOMAIN: use the computer's domain.
        $dn = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name }
        New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $dn, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else { New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain') }
    $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
    $domainDns = $dom.Name; $pdc = $dom.PdcRoleOwner.Name
}
catch {
    if (-not $FromDatabase -and $Server) { $pdc = $Server; Write-Host "Domain not located ($("$($_.Exception.Message)".Trim())); replicating from $Server as given." -ForegroundColor Yellow }
    elseif (-not $FromDatabase) {
        Write-Host "Could not locate the domain / PDC: $($_.Exception.Message)" -ForegroundColor Red
        $joined = $true; try { $joined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
        if (-not $joined) { Write-Host "  This computer is not joined to a domain, and live replication needs to find the PDC. Run it from a domain-joined machine or the DC, or use -FromDatabase with an offline NTDS.dit + SYSTEM hive." -ForegroundColor Yellow }
        exit 1
    }
}
# -Server: replicate from that DC instead of the PDC (any writable DC holds the secrets).
if ($Server) { $pdc = $Server }

# Spinner for the slow steps, like the Gemini one (see Collect-ADSnapshot.ps1).
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
            $e = $_.Exception
            while ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
            throw $e
        }
    }
    finally { $ps.Dispose(); $rs.Dispose() }
}

# DSInternals has used both singular and plural property names; try both.
# The leading comma keeps an empty list a list (PS 5.1 would write {}).
function Get-QualityList {
    param($Result, [string[]]$Names)
    foreach ($n in $Names) { if ($Result.PSObject.Properties[$n]) { return , [string[]]@($Result.$n | Where-Object { $_ } | ForEach-Object { "$_" }) } }
    return , [string[]]@()
}

Write-Host "Collecting account secrets locally for quality testing (nothing leaves this script but account names)..." -ForegroundColor Yellow
$accounts = $null
if ($FromDatabase) {
    if (-not $BootKeyFile) { Write-Host "-BootKeyFile (SYSTEM hive) is required with -FromDatabase." -ForegroundColor Red; exit 1 }
    $key = Get-BootKey -SystemHiveFilePath $BootKeyFile
    $accounts = @(Invoke-WithSpinner -Message "Reading $FromDatabase" -Modules DSInternals -ArgumentList $FromDatabase, $key -ScriptBlock { param($db, $k) Get-ADDBAccount -All -DatabasePath $db -BootKey $k })
}
else {
    # Live replication from the PDC: needs DCSync rights (or -Credential for an account that has them).
    $replParams = @{ All = $true; Server = $pdc }
    if ($Credential) { $replParams['Credential'] = $Credential }
    try { $accounts = @(Invoke-WithSpinner -Message "Replicating accounts from $pdc" -Modules DSInternals -ArgumentList @(, $replParams) -ScriptBlock { param($rp) Get-ADReplAccount @rp }) }
    catch {
        $msg = "$($_.Exception.Message)".Trim()
        Write-Host "Replication from $pdc failed: $msg" -ForegroundColor Red
        if ($msg -match '(?i)access|denied|8453|0x2105|negat') {
            $who = if ($Credential) { $Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME" }
            Write-Host "  Account used: $who. It needs 'Replicating Directory Changes' and 'Replicating Directory Changes All' on the domain root." -ForegroundColor Yellow
            Write-Host "  By default: BUILTIN\Administrators (incl. Domain Admins / Enterprise Admins), Domain Controllers, Enterprise Domain Controllers." -ForegroundColor Yellow
            if ($who -notmatch '\\|@') { Write-Host "  The user name has no domain: type it as DOMAIN\user, or a local account of the same name may be used." -ForegroundColor Yellow }
            Write-Host "  If a Domain Admin is still denied, the domain-root ACL or the Administrators membership was changed (see README, 'Who can replicate')." -ForegroundColor Yellow
            Write-Host "  Re-run with -Credential (Get-Credential DOMAIN\user), or use -FromDatabase with an offline NTDS.dit + SYSTEM hive." -ForegroundColor Yellow
        }
        exit 1
    }
}

$tpqParams = @{}
if ($WeakPasswordsFile) {
    if (-not (Test-Path -LiteralPath $WeakPasswordsFile)) { Write-Host "Weak-password list not found: $WeakPasswordsFile" -ForegroundColor Red; exit 1 }
    # The first non-empty line decides: 32 hex characters (optionally ":count", as in the Have I Been Pwned
    # NTLM files) means a sorted NTLM hash list; anything else is one plaintext password per line.
    # The file name says nothing: the HIBP hash files are .txt too.
    $firstLine = ''
    $sr = New-Object System.IO.StreamReader((Resolve-Path -LiteralPath $WeakPasswordsFile).Path)
    try { while (($l = $sr.ReadLine()) -ne $null) { if ($l.Trim()) { $firstLine = $l.Trim(); break } } }
    finally { $sr.Dispose() }
    if ($firstLine -match '^[0-9A-Fa-f]{32}(:\d+)?$') { $tpqParams['WeakPasswordHashesSortedFile'] = $WeakPasswordsFile; Write-Host "Weak-password list read as sorted NTLM hashes." }
    else { $tpqParams['WeakPasswordsFile'] = $WeakPasswordsFile; Write-Host "Weak-password list read as plaintext, one password per line." }
}
$q = @(Invoke-WithSpinner -Message "Testing password quality ($(@($accounts).Count) accounts)" -Modules DSInternals -ArgumentList @($accounts), $tpqParams -ScriptBlock { param($a, $t) $a | Test-PasswordQuality @t })[0]

# Only account names go in, grouped by problem. No hash, no password.
$report = [ordered]@{
    tool                      = 'IDWolf-PasswordQuality'
    generatedAtUtc            = (Get-Date).ToUniversalTime().ToString('o')
    domain                    = $domainDns
    source                    = if ($FromDatabase) { 'ntds.dit (offline)' } else { 'live replication' }
    weakListUsed              = [bool]$WeakPasswordsFile
    duplicatePasswordGroups   = @($q.DuplicatePasswordGroups | ForEach-Object { , @($_) })
    # [string[]] so Windows PowerShell 5.1 writes a plain JSON list, even an empty one.
    emptyPassword             = [string[]]@(Get-QualityList $q 'EmptyPassword', 'EmptyPasswords')
    defaultOrUsernamePassword = [string[]]@(@(Get-QualityList $q 'DefaultComputerPassword', 'DefaultComputerPasswords') + @(Get-QualityList $q 'SamAccountNameAsPassword') | Select-Object -Unique)
    breachedPassword          = [string[]]@(Get-QualityList $q 'WeakPassword', 'WeakPasswords')
    clearTextPassword         = [string[]]@(Get-QualityList $q 'ClearTextPassword', 'ClearTextPasswords')
    # Extra flags DSInternals reports anyway (other IDWolf checks cover them):
    lmHashPresent             = [string[]]@(Get-QualityList $q 'LMHash', 'LMHashes')
    passwordNotRequired       = [string[]]@(Get-QualityList $q 'PasswordNotRequired')
    passwordNeverExpires      = [string[]]@(Get-QualityList $q 'PasswordNeverExpires')
}
# A DSInternals version we don't recognise would give an empty, falsely clean report. Stop instead.
if (-not ($q.PSObject.Properties['WeakPassword'] -or $q.PSObject.Properties['WeakPasswords'])) {
    Write-Host "Unexpected Test-PasswordQuality result shape (DSInternals $((Get-Module DSInternals).Version)); properties: $(($q.PSObject.Properties.Name) -join ', '). Report not written." -ForegroundColor Red
    exit 1
}

if (-not $OutFile) {
    # Unnamed outputs go to .\output, not next to everything else.
    $od = Join-Path (Get-Location).Path 'output'; if (-not (Test-Path -LiteralPath $od)) { New-Item -ItemType Directory -Path $od | Out-Null }
    $OutFile = Join-Path $od ("passwordquality_{0}_{1}.json" -f $domainDns, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$json = $report | ConvertTo-Json -Depth 6
# And in case PS 5.1 still wrote a {} somewhere.
$json = [regex]::Replace($json, '(?<=[^\\]"):\s*\{\s*\}', ': null')
if ([System.IO.Path]::IsPathRooted($OutFile)) { $full = $OutFile } else { $full = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutFile)) }
[System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Password-quality report (hashless) written to $full" -ForegroundColor Green
Write-Host "Feed it to: .\\IDWolf.ps1 -Snapshot <adsnapshot.json> -PasswordQualityFile $full"
