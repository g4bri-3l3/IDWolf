<#
.SYNOPSIS
    Reads the IDWolf scripts (without running them) and shows everything they
    can do: every command they call, every place they write, every address
    they talk to. Fails if anything falls outside the expected list.

.DESCRIPTION
    Meant for whoever has to approve running IDWolf on a server or a DC. It
    uses the PowerShell parser, the same one PowerShell uses before running a
    script, so it sees every command call, not just the ones that look obvious.

    It fails (exit code 1) on:
      - any command that changes AD, Entra, DNS, DHCP or GPOs (Set-AD*, New-Mg*...);
      - any command not in the reviewed list below, so a new one can't slip in unnoticed;
      - run-time code tricks: Invoke-Expression, encoded commands, Base64
        decoding, downloads, starting processes, scheduled tasks, services,
        script blocks built from text, & or . on a command name built at run
        time or on a variable the file never sets to its own code;
      - directory writes and processes through .NET (CommitChanges, SetInfo,
        ModifyRequest, Process.Start), HTTP writes other than the Gemini POST;
      - a Graph request that isn't a GET;
      - a CIM method call other than reading the registry (StdRegProv Get*/Enum*);
      - Invoke-Item anywhere but lib\Wizard.ps1 (which only opens the .html report);
      - a web address in the code other than Microsoft Graph, Gemini, the
        GitHub tag list (the launcher's version check) and the
        MITRE links in the report.

.PARAMETER Path
    IDWolf folder. Default: the folder of this script.
.PARAMETER Quiet
    Print only the verdict.

.EXAMPLE
    .\Test-IDWolfSafety.ps1
#>
[CmdletBinding()]
Param([string]$Path = '', [switch]$Quiet)

$ErrorActionPreference = 'Stop'
# $PSScriptRoot isn't set yet in a parameter default on PS 5.1.
if (-not $Path) { $Path = Split-Path -Parent $MyInvocation.MyCommand.Path }
# PS 5.1 ignores -Include together with -LiteralPath, so filter by extension by hand.
function Get-ScriptFiles { param([string]$Dir) Get-ChildItem -LiteralPath $Dir -Recurse -File | Where-Object { @('.ps1', '.psm1', '.cmd') -contains $_.Extension.ToLower() } }

# Every external command the shipped scripts may call, and why.
$allowed = [ordered]@{
    'Read Active Directory (no write cmdlet exists in this list)' = @(
        'Get-ADComputer', 'Get-ADDefaultDomainPasswordPolicy', 'Get-ADDomain', 'Get-ADDomainController', 'Get-ADFineGrainedPasswordPolicy',
        'Get-ADForest', 'Get-ADGroup', 'Get-ADObject', 'Get-ADOptionalFeature', 'Get-ADReplicationPartnerMetadata', 'Get-ADRootDSE',
        'Get-ADServiceAccount', 'Get-ADTrust', 'Get-ADUser')
    'Read DNS / DHCP / replication / time status' = @('Get-DnsServerZone', 'Get-DnsServerZoneAging', 'Get-DnsServerResourceRecord', 'Get-DhcpServerInDC', 'repadmin', 'w32tm')
    'Read Entra ID (Microsoft Graph, GET only: checked below)' = @('Connect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest')
    'Password quality (DSInternals: reads hashes locally, writes only account names)' = @('Get-ADReplAccount', 'Get-ADDBAccount', 'Get-BootKey', 'Test-PasswordQuality')
    'Install a missing prerequisite (only after asking, or with -InstallModules)' = @('Install-Module', 'Install-PackageProvider', 'Add-WindowsCapability', 'Install-WindowsFeature')
    'Connections for the collection (SYSVOL drive, CIM session to the DNS server and the DCs)' = @('New-PSDrive', 'Remove-PSDrive', 'New-CimSession', 'Remove-CimSession', 'Get-CimInstance')
    'Read a registry value on a DC (StdRegProv, read methods only: checked below)' = @('Invoke-CimMethod')
    'Files: read inputs, write the snapshot / report' = @('Get-Acl', 'Get-Content', 'Set-Content', 'Export-Csv', 'Import-Csv', 'Get-ChildItem', 'Select-String', 'Test-Path', 'Resolve-Path', 'Join-Path', 'Split-Path', 'Get-Location', 'Set-Location', 'New-Item', 'Remove-Item', 'Get-PSDrive')
    'Connection diagnostics (DNS lookup of the domain and the DC locator record; the TCP connect test is .NET and sends nothing)' = @('Resolve-DnsName')
    'Modules and environment' = @('Import-Module', 'Get-Module', 'Get-PackageProvider', 'Get-Command', 'Add-Type', 'Get-Credential', 'Get-Date', 'Start-Sleep')
    'Console' = @('Write-Host', 'Write-Warning', 'Write-Progress', 'Read-Host', 'Out-Null')
    'Session log of an interactive run (transcript in output; hidden prompts leave nothing in it)' = @('Start-Transcript', 'Stop-Transcript')
    'Open the finished report in the default browser (wizard only, after asking; lib\Wizard.ps1 only: checked below)' = @('Invoke-Item')
    'Data handling' = @('Measure-Command', 'ConvertTo-Json', 'ConvertFrom-Json', 'Select-Object', 'Where-Object', 'ForEach-Object', 'Sort-Object', 'Group-Object', 'Measure-Object', 'New-Object', 'Add-Member')
}
$allowedSet = @{}; foreach ($k in $allowed.Keys) { foreach ($c in $allowed[$k]) { $allowedSet[$c.ToLower()] = $k } }

# Never acceptable in shipped code.
$writeVerbs = '^(Set|New|Remove|Add|Rename|Move|Enable|Disable|Clear|Grant|Revoke|Reset|Unlock|Restore|Update|Uninstall|Sync)-(AD|Mg|Dns|Dhcp|GP)'
$bannedCommands = @('Invoke-Expression', 'iex', 'Start-Process', 'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm', 'curl', 'wget',
    'Start-Job', 'Register-ScheduledTask', 'New-ScheduledTask', 'schtasks', 'New-Service', 'Set-Service', 'Set-ExecutionPolicy',
    'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'reg', 'net', 'Enter-PSSession', 'Invoke-Command', 'New-PSSession')
$bannedText = [ordered]@{
    'Base64 decoding'          = 'FromBase64String'
    'Encoded command'          = '(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}'
    'Download helper'          = '(?i)DownloadString|DownloadFile|Net\.WebClient'
    'Compiled C# at run time'  = '(?i)Add-Type\s+-TypeDefinition|Add-Type\s+-MemberDefinition'
    'Hidden window'            = '(?i)-WindowStyle\s+Hidden'
    # Code built at run time escapes the command list below.
    'Script block built from text' = '(?i)\[scriptblock\]::Create|NewScriptBlock|\$ExecutionContext\.InvokeCommand'
    'Process started from .NET'    = '(?i)Diagnostics\.Process\]::Start|ProcessStartInfo'
    # Directory writes through .NET (System.DirectoryServices and .Protocols) rather than a cmdlet.
    'Directory write through .NET' = '(?i)\.CommitChanges\(|\.SetInfo\(|\.InvokeSet\(|\.DeleteTree\(|\.Children\.(Add|Remove)\(|\b(Modify|Add|Delete|ModifyDN)Request\b|\.Invoke\(\s*[''"]Set'
    'HTTP write other than POST'   = '(?i)\.(PutAsync|PatchAsync|DeleteAsync|SendAsync)\('
}
# The only POST: the Gemini request of the optional AI step.
$postAllowedIn = @('lib/AI.ps1')
$allowedHosts = @('graph.microsoft.com', 'generativelanguage.googleapis.com', 'attack.mitre.org', 'api.github.com')

$root = (Resolve-Path -LiteralPath $Path).Path
# Relative to the IDWolf folder, either separator: a copy kept under C:\tests\ must still be read.
$files = @(Get-ScriptFiles $root | Where-Object { $_.FullName.Substring($root.Length).TrimStart('\', '/') -notmatch '^(tests|examples)[\\/]' -and $_.Name -ne 'Test-IDWolfSafety.ps1' })

$problems = New-Object System.Collections.Generic.List[string]
$used = @{}          # command -> files
$writes = New-Object System.Collections.Generic.List[string]
$urls = @{}

# Functions IDWolf defines itself are internal, not external commands.
$internal = @{}
$asts = @{}
foreach ($f in $files | Where-Object { $_.Extension -ne '.cmd' }) {
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
    if ($errs.Count) { $problems.Add("$($f.Name): does not parse ($($errs[0].Message))") }
    $asts[$f.FullName] = $ast
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $internal[$fn.Name.ToLower()] = $true }
}

foreach ($f in $files) {
    $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
    $text = [System.IO.File]::ReadAllText($f.FullName)
    foreach ($k in $bannedText.Keys) { if ($text -match $bannedText[$k]) { $problems.Add("${rel}: $k") } }
    if ($text -match '(?i)\.PostAsync\(' -and $postAllowedIn -notcontains ($rel -replace '\\', '/')) { $problems.Add("${rel}: HTTP POST outside lib\AI.ps1") }

    # Web addresses in the code (comments and help blocks are ignored).
    $codeOnly = $text
    if ($f.Extension -ne '.cmd') {
        $codeOnly = [regex]::Replace($text, '(?s)<#.*?#>', '')
        $codeOnly = [regex]::Replace($codeOnly, '(?m)^\s*#.*$', '')
    }
    foreach ($m in [regex]::Matches($codeOnly, 'https?://([A-Za-z0-9.\-]+)')) {
        $h = $m.Groups[1].Value.ToLower()
        if (-not $urls.ContainsKey($h)) { $urls[$h] = New-Object System.Collections.Generic.List[string] }
        if (-not $urls[$h].Contains($rel)) { $urls[$h].Add($rel) }
        if ($allowedHosts -notcontains $h) { $problems.Add("${rel}: unexpected web address $h") }
    }

    if ($f.Extension -eq '.cmd') {
        if ($text -notmatch '(?i)powershell\.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-IDWolf\.ps1"') { $problems.Add("${rel}: does more than start Start-IDWolf.ps1") }
        continue
    }

    $ast = $asts[$f.FullName]
    # Variables the file fills with code it wrote itself (a { } block, a table of them) or with the
    # path of one of its own .ps1 files: & $x and . $x on those run nothing new.
    $codeVars = @{}
    # foreach ($f in @('Common.ps1', ...)): a loop over literal .ps1 names only.
    $ps1Loops = @{}
    foreach ($fe in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
        $items = @($fe.Condition.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true))
        $others = @($fe.Condition.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] -or $args[0] -is [System.Management.Automation.Language.CommandAst] -or $args[0] -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))
        if ($items.Count -and $others.Count -eq 0 -and @($items | Where-Object { $_.Value -notmatch '^[\w.\-]+\.ps1$' }).Count -eq 0) { $ps1Loops[$fe.Variable.VariablePath.UserPath.ToLower()] = $true }
    }
    foreach ($a in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        $left = $a.Left
        if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
        if ($left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $rhs = $a.Right.Extent.Text.Trim()
        if ($rhs -match '^(\[ordered\]\s*)?@?\{' -or $rhs -match "^\(?Join-Path\s+\S+\s+'[^']+\.ps1'\)?$" -or
            ($rhs -match '^Join-Path\s+\$\w+\s+\$(\w+)$' -and $ps1Loops.ContainsKey($Matches[1].ToLower()))) {
            $codeVars[($left.VariablePath.UserPath -replace '^(script|local|global):', '').ToLower()] = $true
        }
    }
    # A parameter is filled by the caller, whose own call is read here too.
    foreach ($p in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $true)) { $codeVars[$p.Name.VariablePath.UserPath.ToLower()] = $true }
    foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $c.GetCommandName()
        if (-not $name) {
            # & or . on something that is not a plain command name: the reviewed list can't see what runs.
            $head = $c.CommandElements[0]
            $line = $c.Extent.StartLineNumber
            $var = $head
            while ($var -is [System.Management.Automation.Language.IndexExpressionAst]) { $var = $var.Target }
            if ($var -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $vn = ($var.VariablePath.UserPath -replace '^(script|local|global):', '').ToLower()
                if (-not $codeVars.ContainsKey($vn)) { $problems.Add("${rel}:${line}: runs `$$vn, which this file never sets to its own code") }
            }
            elseif ($head.Extent.Text -notmatch "^\(Join-Path\s+\`$\w+\s+'[^']+\.ps1'\)$") {
                $problems.Add("${rel}:${line}: command name built at run time ($($head.Extent.Text))")
            }
            continue
        }
        $lc = $name.ToLower()
        if ($internal.ContainsKey($lc)) { continue }
        if (-not $used.ContainsKey($name)) { $used[$name] = New-Object System.Collections.Generic.List[string] }
        if (-not $used[$name].Contains($rel)) { $used[$name].Add($rel) }
        $line = $c.Extent.StartLineNumber
        if ($name -match $writeVerbs) { $problems.Add("${rel}:${line}: $name changes the directory") }
        if ($bannedCommands -contains $lc) { $problems.Add("${rel}:${line}: $name is not allowed") }
        if (-not $allowedSet.ContainsKey($lc) -and $name -notmatch $writeVerbs -and $bannedCommands -notcontains $lc) { $problems.Add("${rel}:${line}: $name is not on the reviewed list") }
        # Invoke-Item opens a file with its default program: only the report opener may use it,
        # and that one opens nothing but an .html file the run has just written.
        if ($lc -eq 'invoke-item' -and ($rel -replace '\\', '/') -ne 'lib/Wizard.ps1') { $problems.Add("${rel}:${line}: Invoke-Item outside lib\Wizard.ps1") }
        if ($lc -eq 'invoke-mggraphrequest' -and $c.Extent.Text -notmatch '(?i)-Method\s+GET\b') { $problems.Add("${rel}:${line}: Graph request that is not a GET") }
        # StdRegProv also has Set*/Delete* methods: only a literal read method may be named.
        if ($lc -eq 'invoke-cimmethod' -and ($c.Extent.Text -notmatch "(?i)-ClassName\s+'?StdRegProv'?\s" -or $c.Extent.Text -notmatch "(?i)-MethodName\s+'?(GetDWORDValue|GetQWORDValue|GetStringValue|GetExpandedStringValue|GetMultiStringValue|GetBinaryValue|EnumKey|EnumValues)'?\s")) {
            $problems.Add("${rel}:${line}: CIM method call that is not a registry read (StdRegProv Get*/Enum*)")
        }
        if ($lc -in 'set-content', 'export-csv', 'new-item', 'remove-item') { $writes.Add("${rel}:${line}: $($c.Extent.Text.Split("`n")[0].Trim())") }
    }
    # .NET file writes.
    foreach ($m in [regex]::Matches($text, '\[(System\.)?IO\.File\]::(Write\w+|Delete|Move|Copy)')) {
        $ln = ($text.Substring(0, $m.Index) -split "`n").Count
        $writes.Add("${rel}:${ln}: $($m.Value)")
    }
}

if (-not $Quiet) {
    Write-Host "IDWolf safety review of $root" -ForegroundColor Cyan
    Write-Host "$($files.Count) files read, nothing executed.`n"
    Write-Host "External commands used, by purpose:" -ForegroundColor Cyan
    foreach ($k in $allowed.Keys) {
        $here = @($allowed[$k] | Where-Object { $used.ContainsKey($_) })
        if ($here.Count) { Write-Host "  $k"; foreach ($c in $here) { Write-Host ("    {0,-34} {1}" -f $c, ($used[$c] -join ', ')) -ForegroundColor DarkGray } }
    }
    Write-Host "`nWhere it writes (all local files: snapshot, report, temp folder for the BloodHound zip):" -ForegroundColor Cyan
    foreach ($w in $writes) { Write-Host "  $w" -ForegroundColor DarkGray }
    Write-Host "`nWeb addresses in the code:" -ForegroundColor Cyan
    foreach ($h in $urls.Keys | Sort-Object) { Write-Host ("  {0,-36} {1}" -f $h, ($urls[$h] -join ', ')) -ForegroundColor DarkGray }
    Write-Host "  (Graph only from Collect-EntraSnapshot.ps1; Gemini only after you agree, or with -SendToAI; GitHub only for the launcher's version check, GET, off with -NoUpdateCheck.)" -ForegroundColor DarkGray
    Write-Host ""
}

if ($problems.Count) {
    Write-Host "FAILED: $($problems.Count) problem(s)" -ForegroundColor Red
    foreach ($p in $problems) { Write-Host "  $p" -ForegroundColor Red }
    exit 1
}
Write-Host "PASSED: only read-only directory calls, GET-only Graph, read-only registry queries, no hidden code, no unexpected network or system changes." -ForegroundColor Green
exit 0
