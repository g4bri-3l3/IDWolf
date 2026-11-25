<#
.SYNOPSIS
    Stages the IDWolf module for the PowerShell Gallery, verifies it, and
    publishes it only when told to.

.DESCRIPTION
    The repository root is not publishable: output\ holds real snapshots and
    reports, threat-model\ is private review material, tests\lab\ writes to AD.
    So nothing is ever published from the root. This script copies a closed list
    of files into packaging\out\IDWolf and refuses to go on if anything else
    turns up there.

    Checks, in order:
      1. ModuleVersion in IDWolf.psd1 equals $script:IDWolfVersion in IDWolf.ps1.
      2. Every file on the list exists; the staged folder holds nothing else.
      3. No file matching the real-data patterns from .gitignore (adsnap_*,
         report_*, pwq_*, *.zip, *_ai_prompt.txt ...).
      4. Test-ModuleManifest passes on the staged manifest.
      5. The staged Test-IDWolfSafety.ps1 passes over the staged folder.
      6. In a fresh process, per shell available: the module imports, exports
         exactly the functions the manifest names, and Invoke-IDWolf analyzes
         the bundled synthetic snapshot.

    Staging and all the checks run under Windows PowerShell 5.1 as well as 7.
    -LocalTest and -Publish need PSResourceGet, which only PowerShell 7 has, so
    run those with pwsh. The package does not change for it: the smoke test
    exercises both shells either way.

    This script lives under packaging\ and is release tooling, not part of what
    users install: it is never staged, and Test-IDWolfSafety.ps1 skips
    packaging\ the way it already skips tests\ and examples\. It is the only
    place in the repository that copies files or talks to a package repository.

.PARAMETER OutDir
    Staging root. Default packaging\out. The module lands in <OutDir>\IDWolf.

.PARAMETER LocalTest
    Rehearsal: publish the staged module to a throwaway local repository,
    install it from there into a temporary folder, import it and run an
    analysis. Nothing leaves the machine. Do this before -Publish: a version
    published to the PowerShell Gallery cannot be replaced or deleted.

.PARAMETER Publish
    Publish the staged module to -Repository. Needs an API key.

.PARAMETER Repository
    Repository name for -Publish. Default PSGallery.

.PARAMETER ApiKey
    Gallery API key. Defaults to $env:PSGALLERY_API_KEY so the key need not
    appear on a command line. It is never written to the console or to a file.

.EXAMPLE
    .\packaging\Build-GalleryPackage.ps1
.EXAMPLE
    .\packaging\Build-GalleryPackage.ps1 -LocalTest
.EXAMPLE
    $env:PSGALLERY_API_KEY = '...'; .\packaging\Build-GalleryPackage.ps1 -Publish
#>
[CmdletBinding()]
Param(
    [string]$OutDir = '',
    [switch]$LocalTest,
    [switch]$Publish,
    [string]$Repository = 'PSGallery',
    [string]$ApiKey = $env:PSGALLERY_API_KEY
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot 'out' }
$stage = Join-Path $OutDir 'IDWolf'

function Write-Step { param([string]$Text) Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok { param([string]$Text) Write-Host "   ok   $Text" -ForegroundColor Green }
function Stop-Build { param([string]$Text) throw $Text }

# --- 0. prerequisites, before any work --------------------------------------
# Packing and publishing need PSResourceGet, which ships with PowerShell 7 and
# not with Windows PowerShell 5.1. Say so here rather than after staging and
# four rounds of checks. The staging and the checks themselves run anywhere.
if ($LocalTest -or $Publish) {
    if (-not (Get-Command Publish-PSResource -ErrorAction SilentlyContinue)) {
        Stop-Build @'
Publish-PSResource is missing, so there is nothing to pack with. It comes with
Microsoft.PowerShell.PSResourceGet, which PowerShell 7 has and Windows PowerShell
5.1 does not. Run this script under PowerShell 7:

    pwsh -NoProfile -File .\packaging\Build-GalleryPackage.ps1 -Publish

What gets published is the same either way: the package is plain files, and the
smoke test runs it under both 5.1 and 7 regardless of which shell builds it.
'@
    }
}

# --- 1. version -------------------------------------------------------------
Write-Step 'Version'
$verLine = Select-String -LiteralPath (Join-Path $root 'IDWolf.ps1') `
    -Pattern '^\s*\$script:IDWolfVersion\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $verLine) { Stop-Build 'IDWolf.ps1: $script:IDWolfVersion not found.' }
$toolVersion = $verLine.Matches[0].Groups[1].Value

$manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $root 'IDWolf.psd1')
$moduleVersion = [string]$manifest.ModuleVersion
if ($moduleVersion -ne $toolVersion) {
    Stop-Build "Version mismatch: IDWolf.psd1 says $moduleVersion, IDWolf.ps1 says $toolVersion. Bump both."
}
Write-Ok "IDWolf $toolVersion"

# --- 2. stage ---------------------------------------------------------------
Write-Step 'Staging'

# A closed list. Add a file here on purpose, never with a wildcard over the root.
$files = @(
    'IDWolf.psd1'
    'IDWolf.psm1'
    'IDWolf.ps1'
    'Start-IDWolf.ps1'
    'Start-IDWolf.cmd'
    'Collect-ADSnapshot.ps1'
    'Collect-EntraSnapshot.ps1'
    'Export-PasswordQuality.ps1'
    'Export-BloodHound.ps1'
    'Invoke-IDWolfScheduled.ps1'
    'Test-IDWolfSafety.ps1'
    'LICENSE'
    'README.md'
    'CHANGELOG.md'
    'COVERAGE.md'
    'SECURITY.md'
    'CONTRIBUTING.md'
    # Synthetic only: the examples a new user can run against straight away.
    'examples\exceptions.example.json'
    'examples\passwordquality.example.json'
    'examples\synthetic_demo.json'
    'examples\synthetic_entra.json'
)
# Every check file: the analyzer is useless without lib\.
$files += @(Get-ChildItem -LiteralPath (Join-Path $root 'lib') -File |
    Where-Object { $_.Extension -eq '.ps1' } | ForEach-Object { "lib\$($_.Name)" })

# tests\ is deliberately absent: tests\lab\New-Lab*.ps1 write to AD, and
# nothing that writes to a directory belongs in a package. The synthetic
# snapshots above are shipped already generated instead.

if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

foreach ($rel in $files) {
    $src = Join-Path $root $rel
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Stop-Build "Missing file: $rel" }
    $dst = Join-Path $stage $rel
    $dstDir = Split-Path -Parent $dst
    if (-not (Test-Path -LiteralPath $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
    Copy-Item -LiteralPath $src -Destination $dst -Force
}
Write-Ok "$($files.Count) files -> $stage"

# --- 3. nothing else, and nothing real --------------------------------------
Write-Step 'Contents'
$staged = @(Get-ChildItem -LiteralPath $stage -Recurse -File)
$wanted = @{}
foreach ($rel in $files) { $wanted[$rel.Replace('/', '\').ToLower()] = $true }
foreach ($f in $staged) {
    $rel = $f.FullName.Substring($stage.Length).TrimStart('\', '/').Replace('/', '\').ToLower()
    if (-not $wanted[$rel]) { Stop-Build "Unexpected file in the package: $rel" }
}
if ($staged.Count -ne $files.Count) { Stop-Build "Staged $($staged.Count) files, expected $($files.Count)." }

# Real directory data must never reach a package. Same patterns as .gitignore.
$forbidden = @('adsnapshot_*.json', 'adsnap_*.json', 'entrasnapshot_*.json', 'pwq_*.json', 'pwquality*.json',
    'report_*.html', 'report_*.csv', 'report*.jsonl', 'findings*.jsonl', 'ai_prompt*.txt',
    '*_ai_prompt.txt', '*_ai_response.json', 'lab*.json', '*.zip', 'CLAUDE.md', 'ROADMAP.md')
foreach ($f in $staged) {
    foreach ($pat in $forbidden) {
        if ($f.Name -like $pat) { Stop-Build "Looks like real or private data: $($f.Name) (matched $pat)" }
    }
}
$bytes = ($staged | Measure-Object -Property Length -Sum).Sum
Write-Ok ("nothing unexpected, {0:N1} MB" -f ($bytes / 1MB))

# --- 4. manifest ------------------------------------------------------------
Write-Step 'Manifest'
$tested = Test-ModuleManifest -Path (Join-Path $stage 'IDWolf.psd1')
Write-Ok "$($tested.Name) $($tested.Version), $(@($tested.ExportedFunctions.Keys).Count) functions"

# --- 5. safety review on the staged copy ------------------------------------
Write-Step 'Safety review of the staged copy'
& (Join-Path $stage 'Test-IDWolfSafety.ps1') -Path $stage -Quiet
if ($LASTEXITCODE -ne 0) { Stop-Build "Test-IDWolfSafety.ps1 failed on the staged package (exit $LASTEXITCODE)." }
Write-Ok 'the package calls nothing it should not'

# --- 6. import and analyze, in a fresh process, per shell -------------------
Write-Step 'Smoke test'
$expected = @($manifest.FunctionsToExport) | Sort-Object

$smokeLines = @(
    'param([string]$Stage, [string]$Expected, [string]$WorkDir)'
    '$ErrorActionPreference = ''Stop'''
    'Import-Module (Join-Path $Stage ''IDWolf.psd1'') -Force'
    '$got = (Get-Command -Module IDWolf -CommandType Function | Select-Object -ExpandProperty Name | Sort-Object) -join '','''
    'if ($got -ne $Expected) { Write-Host "EXPORTS: got [$got] expected [$Expected]"; exit 2 }'
    '$snap = Join-Path $Stage ''examples\synthetic_demo.json'''
    '$html = Join-Path $WorkDir ''smoke.html'''
    'Invoke-IDWolf -Snapshot $snap -OutHtml $html -SkipLLM | Out-Null'
    'if (-not (Test-Path -LiteralPath $html)) { Write-Host ''REPORT: not written''; exit 3 }'
    '$len = (Get-Item -LiteralPath $html).Length'
    'if ($len -lt 50000) { Write-Host "REPORT: only $len bytes"; exit 4 }'
    'Write-Host "report $len bytes"'
    'exit 0'
)
$smokeFile = Join-Path $OutDir 'smoke.ps1'
Set-Content -LiteralPath $smokeFile -Value $smokeLines -Encoding ASCII

$shells = @()
$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh) { $shells += @{ Name = 'PowerShell 7'; Exe = $pwsh.Source } }
$ps51 = Get-Command powershell.exe -ErrorAction SilentlyContinue
if ($ps51) { $shells += @{ Name = 'Windows PowerShell 5.1'; Exe = $ps51.Source } }
if (-not $shells.Count) { Stop-Build 'No shell found to smoke test with.' }

$work = Join-Path $OutDir 'smokework'
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
New-Item -ItemType Directory -Path $work -Force | Out-Null

foreach ($sh in $shells) {
    $out = & $sh.Exe -NoProfile -ExecutionPolicy Bypass -File $smokeFile $stage ($expected -join ',') $work 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($out | Out-String)
        Stop-Build "Smoke test failed under $($sh.Name) (exit $LASTEXITCODE)."
    }
    Write-Ok "$($sh.Name): imports, exports $($expected.Count) functions, $($out | Select-Object -Last 1)"
}

# --- 7. rehearsal in a local repository -------------------------------------
if ($LocalTest) {
    Write-Step 'Rehearsal in a local repository'
    $repoDir = Join-Path $OutDir 'localrepo'
    $instDir = Join-Path $OutDir 'localinstall'
    foreach ($d in @($repoDir, $instDir)) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
    $repoName = 'IDWolfLocalRehearsal'
    if (Get-PSResourceRepository -Name $repoName -ErrorAction SilentlyContinue) {
        Unregister-PSResourceRepository -Name $repoName
    }
    Register-PSResourceRepository -Name $repoName -Uri $repoDir -Trusted | Out-Null
    try {
        Publish-PSResource -Path $stage -Repository $repoName
        $nupkg = @(Get-ChildItem -LiteralPath $repoDir -Filter '*.nupkg')
        if (-not $nupkg.Count) { Stop-Build 'No .nupkg produced.' }
        Write-Ok ("packed {0} ({1:N1} MB)" -f $nupkg[0].Name, ($nupkg[0].Length / 1MB))

        Save-PSResource -Name IDWolf -Repository $repoName -Path $instDir -TrustRepository
        # Installed as IDWolf\<version>\, the way a gallery install lays it out.
        $found = @(Get-ChildItem -LiteralPath $instDir -Recurse -File |
            Where-Object { $_.Name -eq 'IDWolf.psd1' }) | Select-Object -First 1
        if (-not $found) { Stop-Build 'Install from the local repository produced no IDWolf.psd1.' }
        $installed = Split-Path -Parent $found.FullName
        Write-Ok "installed to $($installed.Substring($instDir.Length).TrimStart('\'))"
        $out = & $shells[0].Exe -NoProfile -ExecutionPolicy Bypass -File $smokeFile $installed ($expected -join ',') $work 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host ($out | Out-String)
            Stop-Build "The installed copy failed its smoke test (exit $LASTEXITCODE)."
        }
        Write-Ok "installed copy runs: $($out | Select-Object -Last 1)"
    }
    finally {
        Unregister-PSResourceRepository -Name $repoName -ErrorAction SilentlyContinue
    }
}

# --- 8. publish -------------------------------------------------------------
if ($Publish) {
    Write-Step "Publish to $Repository"
    if (-not $ApiKey) {
        Stop-Build 'No API key. Set $env:PSGALLERY_API_KEY, or pass -ApiKey. The key is never logged.'
    }
    $existing = $null
    try { $existing = Find-PSResource -Name IDWolf -Repository $Repository -ErrorAction Stop } catch { }
    if ($existing) {
        $already = @($existing | Where-Object { [string]$_.Version -eq $moduleVersion -or [string]$_.Version -eq "$moduleVersion.0" })
        if ($already.Count) {
            Stop-Build "$Repository already has IDWolf $moduleVersion. A published version cannot be replaced: bump the version."
        }
        Write-Host "   $Repository currently has IDWolf $(($existing | Select-Object -First 1).Version)." -ForegroundColor DarkGray
    }
    Publish-PSResource -Path $stage -Repository $Repository -ApiKey $ApiKey
    Write-Ok "published IDWolf $moduleVersion to $Repository"
    Write-Host '   Indexing takes a few minutes. Then: Install-PSResource -Name IDWolf' -ForegroundColor DarkGray
}

Write-Host "`nPackage ready: $stage" -ForegroundColor Yellow
if (-not $LocalTest -and -not $Publish) {
    Write-Host 'Next: -LocalTest to rehearse, then -Publish.' -ForegroundColor DarkGray
}
