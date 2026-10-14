<#
.SYNOPSIS
    Runs Collect-ADSnapshot.ps1 against a mocked ActiveDirectory module and
    feeds the result to IDWolf.ps1. Validates the collector code path
    (property fallback, error capture, masking, JSON shape) without a domain.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "idwolf_mock_$PID"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$sep = [System.IO.Path]::PathSeparator
$env:PSModulePath = (Join-Path $PSScriptRoot 'mock') + $sep + $env:PSModulePath

$snapPath = Join-Path $tmp 'mock.json'
& (Join-Path $root 'Collect-ADSnapshot.ps1') -Server mock.local -OutFile $snapPath -WarningAction SilentlyContinue | Out-Null
$snap = Get-Content -Raw -LiteralPath $snapPath | ConvertFrom-Json

$fail = 0
function Check { param([bool]$c, [string]$m) if (-not $c) { $script:fail++; Write-Host "  FAIL: $m" -ForegroundColor Red } }
$errSections = @($snap.meta.collectionErrors | ForEach-Object { $_.section })
Check ($errSections -contains 'rbcd.users') 'RBCD property fallback recorded'
Check ($errSections -contains 'domain.fineGrainedPolicies') 'FGPP access error recorded'
Check ($errSections -contains 'acl.DomainControllersOU') 'ACL access error recorded'
Check ($errSections -contains 'adcs.caRegistry') 'unreadable CA host recorded (no CIM in the mock)'
Check (@($snap.users).Count -eq 4) 'users collected after fallback'
$svc = $snap.users | Where-Object samAccountName -eq 'svc_sql'
Check ($svc.descriptionSuspicious -and $svc.description -notmatch 'Summer2020') 'password in description masked at collection'
Check (-not ($snap.users | Where-Object samAccountName -eq 'mario').descriptionSuspicious) 'no false positive on Italian description'
Check (@(@($snap.acls | Where-Object target -eq 'DomainRoot').aces | Where-Object { $_.objectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }).Count -eq 1) 'ACE GUIDs serialized as strings'
# OU and container ACLs: only explicit create/control ACEs are kept (BadSuccessor).
$staff = @($snap.ouAcls | Where-Object { $_.distinguishedName -eq 'OU=Staff,DC=mock,DC=local' })
Check (@($snap.ouAcls).Count -eq 2 -and $staff.Count -eq 1) "OU and top-level container ACLs collected (got $(@($snap.ouAcls).Count))"
Check ((@($staff[0].aces | ForEach-Object { "$($_.sid)|$($_.rights)|$($_.objectType)" }) -join ';') -match '^S-1-5-21-[\d-]+-512\|GenericAll\|00000000-0000-0000-0000-000000000000;S-1-5-21-[\d-]+-1301\|CreateChild\|0feb936f-47b3-49f2-9386-1dedc2c23765$') "OU ACL keeps explicit create/control ACEs only (got $(@($staff[0].aces | ForEach-Object { "$($_.sid)|$($_.rights)" }) -join ';'))"
# RODC policy: DN-String values of msDS-RevealedList come out as plain DNs.
$rodcPol = @($snap.domainControllers | Where-Object { $_.isReadOnly })[0].rodcPolicy
Check ((@($rodcPol.revealed) -join '|') -eq 'CN=Administrator,CN=Users,DC=mock,DC=local|CN=mario,CN=Users,DC=mock,DC=local|CN=RODC1,OU=Domain Controllers,DC=mock,DC=local') "msDS-RevealedList parsed to DNs (got $(@($rodcPol.revealed) -join '|'))"
Check (@($rodcPol.allowed).Count -eq 2 -and $rodcPol.managedBy -match '^CN=mario') 'RODC allowed list and managedBy collected'
# AD CS: the 8 PKI containers, the CA object and the CA server's computer account.
Check ($snap.adcs.collected -and @($snap.adcs.pkiAcls).Count -eq 10 -and @($snap.adcs.pkiAcls | Where-Object { $_.target -eq 'CA host:PC1$' }).Count -eq 1) "PKI object ACLs collected (got $(@($snap.adcs.pkiAcls).Count))"

$psc = @($snap.domain.possSuperiorClasses)
Check ($psc.Count -eq 1 -and $psc[0].name -eq 'msExchStorageGroup' -and $psc[0].inheritsContainer -and (@($psc[0].possSuperiors) -join ',') -eq 'computer') "schema possSuperiors probe (got $($psc | ConvertTo-Json -Compress -Depth 3))"

# DNS: no DnsServer RPC in the mock, so the LDAP fallback must parse the zone.
Check ("$($snap.dns.source)" -eq 'ldap' -and $snap.dns.collected) 'DNS falls back to LDAP when RPC is unavailable'
$mz = @($snap.dns.zones)[0]
Check (@($snap.dns.zones).Count -eq 1 -and $mz.dynamicUpdate -eq 'NonsecureAndSecure' -and $mz.agingEnabled -eq $false) 'dnsProperty parsed (allow update, aging)'
Check (@($mz.createChildSids) -contains 'S-1-5-11') "zone CreateChild grantees read from the zone ACL (got $(@($mz.createChildSids) -join ', '))"
Check (@($snap.dns.dangerousRecords | Where-Object { $_.name -eq 'wpad' -and $_.type -eq 'A' }).Count -eq 1) 'WPAD dnsNode found over LDAP'

$csv = Join-Path $tmp 'mock.csv'
& (Join-Path $root 'IDWolf.ps1') -Snapshot $snapPath -OutHtml (Join-Path $tmp 'mock.html') -OutCsv $csv -SkipLLM | Out-Null
$types = @(Import-Csv $csv | ForEach-Object { $_.Type })
# Empty attributes must stay empty (PS 5.1 used to write {}): only svc_sql
# has an SPN and nobody has delegation.
$rows = @(Import-Csv $csv)
$spnObjs = @($rows | Where-Object { $_.Type -in 'kerberoastable_user', 'privileged_kerberoastable', 'spn_account_rc4' } | ForEach-Object { $_.Object } | Select-Object -Unique)
Check (($spnObjs -join ',') -eq 'svc_sql') "SPN findings only on svc_sql (got: $($spnObjs -join ','))"
Check (@($rows | Where-Object { $_.Type -in 'constrained_delegation', 'rbcd_configured' }).Count -eq 0) 'no phantom delegation / RBCD findings'
Check (-not ([System.IO.File]::ReadAllText($snapPath) -match '":\s*\{\s*\}')) 'snapshot JSON holds no empty-object values'
foreach ($t in 'krbtgt_password_old', 'privileged_kerberoastable', 'password_in_description', 'dcsync_rights', 'dc_obsolete_os', 'single_dc', 'password_policy_short', 'dns_insecure_updates', 'dns_dangerous_record', 'adcs_esc5', 'rodc_prp_too_broad', 'rodc_tier0_revealed') {
    Check ($types -contains $t) "mock analysis produced $t"
}

# Scheduled wrapper: two runs, the second compared with the first, one kept.
$sched = Join-Path $tmp 'sched'
$schedScript = Join-Path $root 'Invoke-IDWolfScheduled.ps1'
& $schedScript -Server mock.local -OutputDir $sched -KeepRuns 1 -WarningAction SilentlyContinue *>&1 | Out-Null
$exit1 = $LASTEXITCODE
Start-Sleep -Seconds 1   # run folders are named to the second
& $schedScript -Server mock.local -OutputDir $sched -KeepRuns 1 -WarningAction SilentlyContinue *>&1 | Out-Null
$exit2 = $LASTEXITCODE
Check ($exit1 -eq 0 -and $exit2 -eq 0) "scheduled runs exit 0 (got $exit1, $exit2)"
$runs = @(Get-ChildItem -LiteralPath $sched -Directory)
Check ($runs.Count -eq 1) "retention keeps 1 run folder (got $($runs.Count))"
$siemLines = @([System.IO.File]::ReadAllLines((Join-Path $sched 'idwolf.jsonl')) | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
$summaries = @($siemLines | Where-Object { $_.event_type -eq 'summary' })
Check ($summaries.Count -eq 2) "SIEM file holds one summary per run (got $($summaries.Count))"
Check ($summaries.Count -eq 2 -and $summaries[1].new -eq 0 -and $summaries[1].resolved -eq 0 -and $null -eq $summaries[0].new) 'second run compared with the first, first run not compared'
$second = @($siemLines | Where-Object { $_.event_type -eq 'finding' -and $_.run_id -eq $summaries[1].run_id })
Check ($second.Count -gt 0 -and @($second | Where-Object { $_.status -ne 'persisting' }).Count -eq 0) 'second-run findings marked persisting'
Check (@($siemLines | Where-Object { $_.event_type -eq 'finding' -and -not $_.finding_id }).Count -eq 0) 'every finding has a finding_id'

Remove-Item -Recurse -Force $tmp
if ($fail -gt 0) { Write-Host "$fail collector mock check(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host 'Collector mock test passed' -ForegroundColor Green
exit 0
