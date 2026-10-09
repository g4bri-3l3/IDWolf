<#
.SYNOPSIS
    Checks that the attack-path map of a snapshot taken after New-LabAttackPaths.ps1 shows the whole
    chain, not only direct paths to Tier 0. Needs no AD module and no domain: it reads a snapshot.

.DESCRIPTION
    Expects the chain  LabHelpdesk -> LabOps -> LabAdminsShadow -> lab.svcsync -> Tier 0  (4 steps),
    so the snapshot must come from Collect-ADSnapshot.ps1 -Deep. It also writes the map section to
    an HTML file so the layout can be looked at (one column per step, arrows between the boxes).

    Hard checks (exit code 1 if they fail): the four chain nodes exist, they sit 3, 2, 1 and 0 steps
    from Tier 0, and three of the edges are hops between boxes. The delegation, RBCD and AS-REP
    objects of the lab are reported as OK / MISSING without failing the run.

.EXAMPLE
    .\Collect-ADSnapshot.ps1 -Deep -OutFile lab.json
    .\tests\lab\Test-LabAttackMap.ps1 -Snapshot lab.json
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$Snapshot,
    [string]$OutHtml = 'lab_attackmap.html'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
foreach ($f in 'Common', 'Checks', 'Reporting', 'Graph', 'AI', 'ChecksHost') { . (Join-Path $root "lib\$f.ps1") }

$config = @{ KrbtgtMaxAgeDays = 180; KrbtgtCriticalDays = 365; PrivInactiveDays = 90; InactiveDays = 180; NeverLoggedOnGraceDays = 90
    StaleComputerDays = 90; PasswordMaxAgeDays = 365; MinPasswordLength = 12; MaxDomainAdmins = 5; LapsOverdueDays = 30; BuiltinAdminRecentDays = 30; DcPasswordMaxAgeDays = 90 }

$snap = Import-ADSnapshot $Snapshot
$script:RefDate = ConvertTo-UtcDate $snap.meta.collectedAtUtc
$idx = New-SnapshotIndex -Snapshot $snap
$pm = Get-PrivilegedMap -Index $idx
$findings = @(Invoke-ADHygieneChecks -Snapshot $snap -Index $idx -PrivMap $pm -Config $config)
$graph = Get-AttackGraph -Snapshot $snap -Index $idx -PrivMap $pm -Findings $findings

$script:Fail = 0
function Check { param([bool]$Ok, [string]$Text, [switch]$Soft)
    if ($Ok) { Write-Host "  OK       $Text" -ForegroundColor Green }
    elseif ($Soft) { Write-Host "  MISSING  $Text" -ForegroundColor Yellow }
    else { Write-Host "  FAIL     $Text" -ForegroundColor Red; $script:Fail++ }
}

if (@($snap.deepAcls).Count -eq 0) { Write-Host "This snapshot has no deep ACL data: collect with -Deep, or the chain can't appear." -ForegroundColor Yellow }

Write-Host "Chain (hard checks)"
$level = @{}
foreach ($n in $graph.Nodes) { $level[(($n.Label -split '\\')[-1]).ToLower()] = $n.Level }
$expected = [ordered]@{ 'labhelpdesk' = 3; 'labops' = 2; 'labadminsshadow' = 1; 'lab.svcsync' = 0 }
foreach ($k in $expected.Keys) {
    Check ($level.ContainsKey($k) -and $level[$k] -eq $expected[$k]) "$k is $($expected[$k]) step(s) from Tier 0 (found: $(if ($level.ContainsKey($k)) { $level[$k] } else { 'not in the map' }))"
}
$hops = @($graph.Edges | Where-Object { $_.To -ge 0 })
Check ($hops.Count -ge 3) "at least 3 edges are hops between boxes (found $($hops.Count))"

Write-Host "Extra lab findings (informational)"
foreach ($pair in @(@('constrained_delegation_protocol_transition', 'lab.delegsvc'), @('unconstrained_delegation', 'lab-unconstr$'), @('rbcd_configured', 'lab-rbcdtarget$'), @('asrep_roastable', 'lab.asrep'), @('dcsync_rights', '*lab.svcsync'))) {
    $t = $pair[0]; $o = $pair[1]
    Check (@($findings | Where-Object { $_.Type -eq $t -and $_.Object -like $o }).Count -gt 0) "$t on $o" -Soft
}

$html = ConvertTo-AttackMapHtml -Snapshot $snap -Index $idx -PrivMap $pm -Findings $findings
$page = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>IDWolf lab attack map</title></head><body style='font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:20px auto'>$html</body></html>"
$htmlFull = if ([System.IO.Path]::IsPathRooted($OutHtml)) { $OutHtml } else { Join-Path (Get-Location).Path $OutHtml }
[System.IO.File]::WriteAllText($htmlFull, $page, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Map written to $OutHtml (open it: the chain should read left to right, one column per step)."

if ($script:Fail -gt 0) { Write-Host "$($script:Fail) check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host "Attack-path chain test passed." -ForegroundColor Green
