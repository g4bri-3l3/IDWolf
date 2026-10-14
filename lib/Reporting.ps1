# IDWolf reporting: HTML report, findings CSV, JSON Lines (SIEM) and
# comparison with a previous run.

# Regulatory controls of a check (lib\Compliance.ps1), empty when that file isn't loaded.
function Get-FindingControls {
    param([string]$Type)
    # Get-CheckControls hands back one array object: assign it, don't wrap it in @() again.
    if (Get-Command Get-CheckControls -ErrorAction SilentlyContinue) { $c = Get-CheckControls $Type; return , [string[]]$c }
    return , [string[]]@()
}

function Export-FindingsCsv {
    param($Findings, [string]$Path)
    $rows = @($Findings | Select-Object Severity, Type, Title, Category, Object, ObjectType, ObjectDn, Detail, Mitre, @{ Name = 'Controls'; Expression = { (Get-FindingControls $_.Type) -join '; ' } })
    if ($rows.Count -eq 0) {
        # Keep the header so -CompareTo works against a clean run.
        'Severity,Type,Title,Category,Object,ObjectType,ObjectDn,Detail,Mitre,Controls' | Set-Content -LiteralPath $Path -Encoding UTF8
        return
    }
    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

# One JSON object per line, flat fields, for any SIEM (Splunk _json, Sentinel,
# Elastic). Three kinds of event, told apart by event_type:
#   finding  - one per active finding; status new/persisting with -CompareTo
#   resolved - in the previous run, gone now (only with -CompareTo)
#   summary  - one per run: score, counts, checks not evaluated
# finding_id is the same for the same check on the same object in every run,
# so a SIEM can follow one issue over time. run_id groups the lines of a run.
$script:SeverityScore = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }

function Get-FindingId {
    param([string]$Type, [string]$Object)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Type|$Object".ToLower()))
        return (-join ($bytes[0..7] | ForEach-Object { $_.ToString('x2') }))
    }
    finally { $sha.Dispose() }
}

function Export-FindingsJsonl {
    param($Findings, $Snapshot, [string]$Path, [string]$ToolVersion,
        $Score = $null, $Comparison = $null, $NotEvaluated = @(), [int]$AcceptedCount = 0)
    $sb = New-Object System.Text.StringBuilder
    $collected = ConvertTo-UtcDate $Snapshot.meta.collectedAtUtc
    $isEntra = "$($Snapshot.meta.kind)" -eq 'entra'
    $source = if ($isEntra) { if ($Snapshot.org) { "$($Snapshot.org.displayName)" } else { "$($Snapshot.meta.tenantId)" } } else { "$($Snapshot.domain.dnsRoot)" }
    $runId = "{0}-{1}" -f ($source -replace '[^\w\.\-]', '_'), $collected.ToString('yyyyMMddHHmmss')
    $base = {
        param([string]$EventType)
        $o = [ordered]@{
            time         = $collected.ToString('o')
            event_type   = $EventType
            run_id       = $runId
            tool         = 'IDWolf'
            tool_version = $ToolVersion
            source_kind  = $(if ($isEntra) { 'entra' } else { 'ad' })
            domain       = $source
        }
        if ($isEntra) { $o['tenant_id'] = "$($Snapshot.meta.tenantId)" }
        $o
    }
    $newKeys = @{}
    if ($Comparison) { foreach ($n in @($Comparison.New)) { $newKeys["$($n.Type)|$($n.Object)".ToLower()] = $true } }
    foreach ($f in $Findings) {
        $o = & $base 'finding'
        $o['severity'] = $f.Severity
        $o['severity_score'] = $script:SeverityScore[$f.Severity]
        $o['check'] = $f.Type
        $o['title'] = $f.Title
        $o['category'] = $f.Category
        $o['object'] = $f.Object
        $o['object_type'] = $f.ObjectType
        $o['object_dn'] = $f.ObjectDn
        $o['detail'] = $f.Detail
        $o['mitre'] = $f.Mitre
        $o['controls'] = Get-FindingControls $f.Type
        $o['finding_id'] = Get-FindingId $f.Type $f.Object
        $o['status'] = $(if (-not $Comparison) { $null } elseif ($newKeys.ContainsKey("$($f.Type)|$($f.Object)".ToLower())) { 'new' } else { 'persisting' })
        [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
    }
    if ($Comparison) {
        foreach ($r in @($Comparison.Resolved)) {
            $o = & $base 'resolved'
            $o['severity'] = $r.Severity
            $o['severity_score'] = $script:SeverityScore["$($r.Severity)"]
            $o['check'] = $r.Type
            $o['title'] = $r.Title
            $o['object'] = $r.Object
            $o['finding_id'] = Get-FindingId $r.Type $r.Object
            $o['status'] = 'resolved'
            [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
        }
    }
    if ($Score) {
        $o = & $base 'summary'
        $o['score'] = $Score.Score
        $o['grade'] = $Score.Grade
        $o['score_reliable'] = [bool]$Score.Reliable
        $o['coverage_pct'] = $Score.Coverage
        $o['findings'] = @($Findings).Count
        foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $o[$s.ToLower()] = @($Findings | Where-Object { $_.Severity -eq $s }).Count }
        $o['accepted'] = $AcceptedCount
        $o['new'] = $(if ($Comparison) { @($Comparison.New).Count } else { $null })
        $o['resolved'] = $(if ($Comparison) { @($Comparison.Resolved).Count } else { $null })
        $o['not_evaluated'] = @($NotEvaluated).Count
        $o['not_evaluated_checks'] = [string[]]@($NotEvaluated | ForEach-Object { $_.Type })
        [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
    }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-FindingsComparison {
    param($Findings, [string]$PreviousCsv)
    $prev = @(Import-Csv -LiteralPath $PreviousCsv)
    $key = { param($f) "$($f.Type)|$($f.Object)".ToLower() }
    $prevMap = @{}; foreach ($p in $prev) { $prevMap[(& $key $p)] = $p }
    $curMap = @{}; foreach ($c in $Findings) { $curMap[(& $key $c)] = $c }
    $new = @($Findings | Where-Object { -not $prevMap.ContainsKey((& $key $_)) })
    $resolved = @($prev | Where-Object { -not $curMap.ContainsKey((& $key $_)) })
    $persisting = @($Findings | Where-Object { $prevMap.ContainsKey((& $key $_)) })
    return [PSCustomObject]@{ New = $new; Resolved = $resolved; Persisting = $persisting; PreviousPath = $PreviousCsv }
}

function Get-SevPill {
    param([string]$Severity)
    $s = $Severity.ToLower()
    return "<span class=`"sev-pill sev-pill-$s`">$Severity</span>"
}

function Get-MitreLink {
    param([string]$Id)
    if (-not $Id) { return '' }
    $path = $Id -replace '\.', '/'
    return "<a href=`"https://attack.mitre.org/techniques/$path/`" target=`"_blank`" rel=`"noopener`">$Id</a>"
}

# Wolf-fur palette, charcoal to silver. Only severity and risk keep a muted
# colour, because there it means something.
$script:WolfCategoryRamp = @('#161513', '#2B2925', '#45413A', '#5F5A51', '#78726A', '#8F887C', '#ABA497', '#C6BFB0', '#DDD6C8')
$script:WolfSeverityColors = @('#E2372A', '#EF8A6F', '#F2B632', '#B9B1A1')

# Same wolf as the console banner. Single-quoted: the art has a backtick in it.
$script:WolfAscii = @'
                     .
                    / V\
                  / `  /
                 <<   |
                 /    |
               /      |
             /        |
           /    \  \ /
          (      ) | |
  ________|   _/_  | |
<__________\______)\__)
'@
function Get-WolfLogoHtml {
    return "<pre class='wolf-logo' role='img' aria-label='IDWolf wolf'>$(ConvertTo-HtmlSafe $script:WolfAscii)</pre>"
}

# Donut chart in plain SVG: each slice is a dash on a ring.
function Get-SvgPieChart {
    param([string[]]$Labels, [int[]]$Values, [string[]]$Colors, [int]$Size = 130, [string]$CenterLabel = "")
    $total = ($Values | Measure-Object -Sum).Sum
    if ($total -le 0) { return "<p class='meta'>No data.</p>" }
    $cx = $Size / 2; $cy = $Size / 2
    $strokeWidth = [Math]::Round($Size * 0.13, 1)
    $r = ($Size / 2) - ($strokeWidth / 2) - 1
    $circ = [Math]::Round(2 * [Math]::PI * $r, 2)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $rings = "<circle cx='$cx' cy='$cy' r='$($r.ToString($inv))' fill='none' stroke='#E8E2D4' stroke-width='$($strokeWidth.ToString($inv))' />"
    $legend = ""; $cum = 0
    for ($i = 0; $i -lt $Labels.Count; $i++) {
        $v = $Values[$i]
        if ($v -le 0) { continue }
        $seg = [Math]::Round(($v / $total) * $circ, 2)
        $off = [Math]::Round(-1 * $cum, 2)
        $rings += "<circle cx='$cx' cy='$cy' r='$($r.ToString($inv))' fill='none' stroke='$($Colors[$i])' stroke-width='$($strokeWidth.ToString($inv))' stroke-dasharray='$($seg.ToString($inv)) $($circ.ToString($inv))' stroke-dashoffset='$($off.ToString($inv))'><title>$(ConvertTo-HtmlSafe $Labels[$i]): $v</title></circle>"
        $cum += $seg
        $pct = [Math]::Round(($v / $total) * 100, 1).ToString($inv)
        $legend += "<div class='pie-legend-item'><span class='pie-legend-swatch' style='background:$($Colors[$i])'></span>$(ConvertTo-HtmlSafe $Labels[$i]) ($v, $pct%)</div>"
    }
    $svg = "<svg viewBox='0 0 $Size $Size' width='$Size' height='$Size' role='img'><g transform='rotate(-90 $cx $cy)'>$rings</g><text x='$cx' y='$($cy - 2)' text-anchor='middle' font-size='20' font-weight='600' fill='#161513'>$total</text><text x='$cx' y='$($cy + 14)' text-anchor='middle' font-size='9' fill='#5F5A51'>$CenterLabel</text></svg>"
    return "<div class='pie-chart-wrap'>$svg<div class='pie-legend'>$legend</div></div>"
}

function Get-ChartsRowHtml {
    param($Findings, $Index, $PrivMap)
    $sevLabels = @('Critical', 'High', 'Medium', 'Low')
    $sevVals = @($sevLabels | ForEach-Object { $s = $_; @($Findings | Where-Object { $_.Severity -eq $s }).Count })
    $sevPie = Get-SvgPieChart -Labels $sevLabels -Values $sevVals -Colors $script:WolfSeverityColors -CenterLabel 'findings'

    $cats = @('Kerberos', 'Privileged Access', 'Account Hygiene', 'Domain Configuration', 'Permissions', 'Certificate Services', 'Host Hardening', 'Password Quality', 'Operational Health')
    $catVals = @($cats | ForEach-Object { $c = $_; @($Findings | Where-Object { $_.Category -eq $c }).Count })
    $catPie = Get-SvgPieChart -Labels $cats -Values $catVals -Colors $script:WolfCategoryRamp -CenterLabel 'findings'

    # Tier 0: people actually using it versus dormant, machine or foreign members.
    $t = @{ active = 0; dormant = 0; disabled = 0; service = 0; computer = 0; foreign = 0 }
    foreach ($rec in $PrivMap.Principals.Values) {
        $p = $rec.Principal
        if (-not $p -or $rec.Type -eq 'foreign' -or $rec.Type -eq 'unresolved') { $t.foreign++; continue }
        if ($rec.Type -eq 'computer') { $t.computer++; continue }
        if (-not $p.enabled) { $t.disabled++; continue }
        if ($p.kind -ne 'user' -or @($p.servicePrincipalNames | Where-Object { $_ }).Count -gt 0) { $t.service++; continue }
        $ll = Get-AgeDays $p.lastLogonTimestamp
        if ($null -eq $ll -or $ll -gt 90) { $t.dormant++ } else { $t.active++ }
    }
    $tierPie = Get-SvgPieChart -Labels @('Active admins', 'Dormant (90d+)', 'Service accounts', 'Disabled', 'Computers', 'Foreign / unresolved') `
        -Values @($t.active, $t.dormant, $t.service, $t.disabled, $t.computer, $t.foreign) `
        -Colors @('#2B2925', '#F2B632', '#161513', '#D3CCBD', '#A39C8F', '#E2372A') -CenterLabel 'Tier 0'

    # Enabled user accounts by activity (standard + privileged, no MSA).
    $a = @{ recent = 0; inactive = 0; never = 0 }
    foreach ($u in @($Index.Users | Where-Object { $_.enabled -and $_.kind -eq 'user' })) {
        $ll = Get-AgeDays $u.lastLogonTimestamp
        if ($null -eq $ll) { $a.never++ } elseif ($ll -gt 180) { $a.inactive++ } else { $a.recent++ }
    }
    $actPie = Get-SvgPieChart -Labels @('Logon within 180d', 'Inactive 180d+', 'Never logged on') -Values @($a.recent, $a.inactive, $a.never) `
        -Colors @('#2B2925', '#8F887C', '#D3CCBD') -CenterLabel 'enabled users'

    $h = "<div class='chart-row'>"
    $h += "<div><div class='pie-chart-title'>Findings by severity</div>$sevPie</div>"
    $h += "<div><div class='pie-chart-title'>Findings by category</div>$catPie</div>"
    $h += "<div><div class='pie-chart-title'>Tier 0 composition</div>$tierPie</div>"
    $h += "<div><div class='pie-chart-title'>Enabled users by activity</div>$actPie</div>"
    $h += "</div>"
    return $h
}

# Pies about the directory itself rather than the findings: how many accounts, of what kind,
# how old the passwords are, what the machines run. A pie with no data is left out.
function Get-AdInfoChartsRow {
    param($Snapshot, $Index)
    $pies = New-Object System.Collections.Generic.List[string]
    $add = {
        param([string]$Title, [string]$Center, [string[]]$Labels, [int[]]$Values, [string[]]$Colors)
        if (($Values | Measure-Object -Sum).Sum -gt 0) {
            $pies.Add("<div><div class='pie-chart-title'>$(ConvertTo-HtmlSafe $Title)</div>$(Get-SvgPieChart -Labels $Labels -Values $Values -Colors $Colors -CenterLabel $Center)</div>")
        }
    }
    $users = @($Index.Users)
    $isSvc = { param($u) $u.kind -ne 'user' -or @($u.servicePrincipalNames | Where-Object { $_ }).Count -gt 0 }
    $enabled = @($users | Where-Object { $_.enabled })
    $svc = @($enabled | Where-Object { & $isSvc $_ }).Count
    & $add 'All accounts' 'accounts' @('User accounts', 'Service accounts', 'Disabled users', 'Computers') `
        @(($enabled.Count - $svc), $svc, ($users.Count - $enabled.Count), @($Index.Computers).Count) @('#2B2925', '#78726A', '#D3CCBD', '#F2B632')

    $pw = @{ recent = 0; mid = 0; old = 0; never = 0 }
    foreach ($u in $enabled) {
        $a = Get-AgeDays $u.pwdLastSet
        if ($null -eq $a) { $pw.never++ } elseif ($a -le 90) { $pw.recent++ } elseif ($a -le 365) { $pw.mid++ } else { $pw.old++ }
    }
    & $add 'Password age (enabled accounts)' 'accounts' @('Changed within 90d', '91 to 365 days', 'Over 1 year', 'Never set') @($pw.recent, $pw.mid, $pw.old, $pw.never) @('#2B2925', '#8F887C', '#E2372A', '#D3CCBD')

    $notReq = @($enabled | Where-Object { Test-Uac $_ 'PASSWD_NOTREQD' }).Count
    $never = @($enabled | Where-Object { -not (Test-Uac $_ 'PASSWD_NOTREQD') -and (Test-Uac $_ 'DONT_EXPIRE_PASSWORD') }).Count
    & $add 'Password settings (enabled accounts)' 'accounts' @('Expires normally', 'Never expires', 'Password not required') @(($enabled.Count - $notReq - $never), $never, $notReq) @('#2B2925', '#F2B632', '#E2372A')

    $comps = @($Index.Computers)
    $osNames = @{}
    foreach ($c in $comps) { $n = if ($c.operatingSystem) { "$($c.operatingSystem)" -replace '(?i)^Windows\s+', '' } else { 'Unknown' }; if ($osNames.ContainsKey($n)) { $osNames[$n]++ } else { $osNames[$n] = 1 } }
    $top = @($osNames.GetEnumerator() | Sort-Object @{ Expression = { $_.Value }; Descending = $true }, Name)
    $labels = @(); $vals = @()
    foreach ($e in @($top | Select-Object -First 5)) { $labels += "$($e.Name)"; $vals += [int]$e.Value }
    $rest = ($top | Select-Object -Skip 5 | ForEach-Object { $_.Value } | Measure-Object -Sum).Sum
    if ($rest) { $labels += 'Other'; $vals += [int]$rest }
    if ($labels.Count) { & $add 'Computers by operating system' 'computers' $labels $vals @($script:WolfCategoryRamp[1], $script:WolfCategoryRamp[3], $script:WolfCategoryRamp[4], $script:WolfCategoryRamp[6], $script:WolfCategoryRamp[7], $script:WolfCategoryRamp[8]) }

    $cr = 0; $cs = 0; $cn = 0
    foreach ($c in @($comps | Where-Object { $_.enabled })) {
        $a = Get-AgeDays $c.lastLogonTimestamp
        if ($null -eq $a) { $cn++ } elseif ($a -le 90) { $cr++ } else { $cs++ }
    }
    & $add 'Enabled computers by activity' 'computers' @('Seen within 90d', 'Stale 90d+', 'Never logged on') @($cr, $cs, $cn) @('#2B2925', '#8F887C', '#D3CCBD')

    $grp = @{ Global = 0; DomainLocal = 0; Universal = 0 }
    foreach ($g in @($Index.Groups)) { $s = "$($g.groupScope)"; if ($grp.ContainsKey($s)) { $grp[$s]++ } }
    & $add 'Groups by scope' 'groups' @('Global', 'Domain local', 'Universal') @($grp.Global, $grp.DomainLocal, $grp.Universal) @('#2B2925', '#8F887C', '#D3CCBD')

    # Password quality (DSInternals), worst problem per account. Only with a report attached.
    $pq = $Snapshot.passwordQuality
    if ($pq) {
        $lists = [ordered]@{
            'Empty password'      = @(ConvertTo-PqNameList $pq.emptyPassword)
            'Cleartext stored'    = @(ConvertTo-PqNameList $pq.clearTextPassword)
            'Breached password'   = @(ConvertTo-PqNameList $pq.breachedPassword)
            'Default / username'  = @(ConvertTo-PqNameList $pq.defaultOrUsernamePassword)
            'Shared password'     = @($pq.duplicatePasswordGroups | Where-Object { $_ } | ForEach-Object { ConvertTo-PqNameList $_ })
        }
        $seen = @{}; $counts = @()
        foreach ($k in $lists.Keys) {
            $c = 0
            foreach ($name in @($lists[$k] | Where-Object { $_ })) { $key = "$name".ToLower(); if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $c++ } }
            $counts += $c
        }
        $clean = [Math]::Max(0, $enabled.Count - $seen.Count)
        $pqLabels = @('No weakness found') + @($lists.Keys)
        $pqVals = @($clean) + @($counts)
        & $add 'Password quality (enabled accounts)' 'accounts' $pqLabels $pqVals @('#2B2925', '#E2372A', '#A8261C', '#EF8A6F', '#F2B632', '#8F887C')
    }
    if (-not $pies.Count) { return '' }
    return "<div class='chart-row'>$($pies -join '')</div>"
}

# The report theme, shared by the AD and the Entra report: one <style> block, no external
# resource (system font stacks), so the HTML opens the same on an offline machine.
function Get-IDWolfThemeCss {
    return @'
<style>
  /* "Keycap" theme: paper, ink, hard shadows. Self-contained: system font stacks, no web fonts. */
  :root {
    --paper: #F3EFE6; --surface: #FFFDF8; --tint: #E8E2D4; --ink: #161513; --muted: #5F5A51;
    --red: #E2372A; --red-soft: #FBD9D2; --coral: #EF8A6F; --amber: #F2B632; --amber-soft: #FBE7B5; --green: #84CC5F;
    --line: 3px solid var(--ink);
    --shadow: 7px 7px 0 var(--ink); --shadow-sm: 4px 4px 0 var(--ink); --shadow-xs: 3px 3px 0 var(--ink);
    --display: "Bahnschrift", "Segoe UI Variable Display", "Segoe UI", system-ui, sans-serif;
    --body: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Helvetica, Arial, sans-serif;
    --mono: "Cascadia Mono", "Cascadia Code", Consolas, ui-monospace, monospace;
  }
  body {
    max-width: 1240px; margin: 0 auto; padding: 28px 24px 64px; color: var(--ink); line-height: 1.5;
    font-family: var(--body); font-size: 15px; -webkit-font-smoothing: antialiased;
    background: var(--paper) radial-gradient(circle, rgba(22, 21, 19, .10) 1.1px, transparent 1.5px) 0 0 / 18px 18px;
  }
  @media (max-width: 700px) { body { padding: 16px 16px 40px; } .wolf-logo { font-size: 7px; } }
  :focus-visible { outline: 3px solid var(--ink); outline-offset: 3px; }

  h1 {
    font-family: var(--display); font-weight: 800; letter-spacing: -0.04em; line-height: .95; font-size: clamp(2rem, 4.6vw, 3.4rem);
    border: var(--line); border-radius: 22px; background: var(--surface); box-shadow: var(--shadow); padding: 22px 26px; margin: 0 0 28px;
  }
  h1.title { display: flex; align-items: center; gap: 22px; }
  .wolf-logo {
    font-family: var(--mono); font-size: 10px; line-height: 1.05; font-weight: 700; margin: 0; flex-shrink: 0;
    color: var(--surface); background: var(--ink); border-radius: 14px; padding: 10px 12px; box-shadow: 4px 4px 0 var(--red);
  }
  h2 { margin: 0; font-family: var(--display); font-weight: 750; letter-spacing: -0.03em; font-size: clamp(1.35rem, 2.4vw, 1.9rem); color: var(--ink); }
  h3 { font-family: var(--display); letter-spacing: -0.02em; }
  .meta { font-family: var(--mono); font-size: 12px; line-height: 1.55; letter-spacing: .01em; color: var(--muted); }
  h1 + .meta { text-transform: uppercase; letter-spacing: .06em; font-size: 11.5px; }
  code { background: var(--tint); border: 1.5px solid var(--ink); border-radius: 6px; padding: 0 5px; font-family: var(--mono); font-size: 0.92em; }

  /* Score cards: keys with a hard shadow, the number is the label. */
  .cards { display: flex; flex-wrap: wrap; gap: 18px; margin: 26px 0 30px; clear: both; }
  .card {
    border: var(--line); border-radius: 18px; background: var(--surface); box-shadow: var(--shadow-sm);
    padding: 14px 20px 16px; min-width: 150px; transition: transform .12s ease, box-shadow .12s ease;
  }
  .card:hover { transform: translate(-2px, -2px); box-shadow: 6px 6px 0 var(--ink); }
  .card .num, .grade { font-family: var(--display); font-weight: 800; font-size: 2.6rem; letter-spacing: -0.04em; line-height: 1; color: var(--ink); }
  .card .lbl { font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin-top: 6px; }
  .card.critical { background: var(--red); } .card.critical .num, .card.critical .lbl { color: var(--surface); }
  .card.high { background: var(--red-soft); } .card.medium { background: var(--amber); } .card.low { background: var(--tint); }

  /* Severity pills as small keycaps. */
  .sev-pill {
    display: inline-block; white-space: nowrap; font-family: var(--mono); font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
    border: 2px solid var(--ink); border-radius: 8px; padding: 3px 9px; box-shadow: 2px 2px 0 var(--ink); color: var(--ink);
  }
  .sev-pill-critical { background: var(--red); color: var(--surface); }
  .sev-pill-high { background: var(--red-soft); }
  .sev-pill-medium { background: var(--amber); }
  .sev-pill-low { background: var(--tint); }

  /* Sections and checks: bento panels. */
  details { margin-top: 34px; }
  details > summary { cursor: pointer; list-style: none; border-bottom: var(--line); padding-bottom: 10px; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary h2 { display: inline-block; }
  details > summary::before { content: '\25b6'; display: inline-block; margin-right: 8px; font-size: 14px; color: var(--red); transition: transform .15s ease; }
  details[open] > summary::before { transform: rotate(90deg); }
  details.check {
    margin: 12px 0; border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-xs);
    transition: box-shadow .12s ease, transform .12s ease;
  }
  details.check:hover { transform: translate(-1px, -1px); box-shadow: var(--shadow-sm); }
  details.check[open] { box-shadow: var(--shadow); }
  details.check > summary { border-bottom: none; padding: 12px 16px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  details.check[open] > summary { border-bottom: var(--line); }
  details.check > summary::before { margin-right: 0; }
  details.check .body { padding: 12px 18px 16px; }
  .check-title { font-family: var(--display); font-weight: 700; font-size: 1.02rem; letter-spacing: -0.01em; }
  .check-id { font-family: var(--mono); font-size: 11px; letter-spacing: .06em; color: var(--muted); }
  .count { margin-left: auto; font-family: var(--mono); font-size: 11px; letter-spacing: .06em; background: var(--tint); border: 2px solid var(--ink); border-radius: 99px; padding: 1px 10px; }
  .kv { font-size: 13px; margin: 6px 0; }
  .kv b { font-family: var(--mono); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--ink); }

  /* Tables: ink header, mono labels, framed panel. */
  .table-wrap { border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-sm); overflow-x: auto; margin: 14px 0; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  th, td { padding: 8px 12px; text-align: left; vertical-align: top; border-top: 1.5px solid var(--tint); }
  th { background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 10.5px; font-weight: 500; letter-spacing: .1em; text-transform: uppercase; padding: 10px 12px; border-top: none; }
  /* Key / value tables (a th at the start of a data row): light row headers, not a black column. */
  tr:has(> td) > th { background: var(--tint); color: var(--ink); border-top: 1.5px solid var(--surface); }
  tr.data-row:nth-child(even) td { background: #FAF6EE; }
  tr.data-row:hover td { background: var(--amber-soft); }
  tr.filter-row td { background: var(--tint); padding: 5px 6px; }
  tr.filter-row input { width: 100%; box-sizing: border-box; font-family: var(--mono); font-size: 11px; padding: 4px 7px; border: 2px solid var(--ink); border-radius: 8px; background: var(--surface); }
  tr.filter-row input:focus { outline: 3px solid var(--red); outline-offset: 1px; }
  .filter-status { font-family: var(--mono); font-size: 11px; color: var(--muted); margin: 6px 0 0 2px; }
  .compare-new { color: var(--red); font-weight: bold; }
  .compare-resolved { color: var(--muted); font-weight: bold; }
  .yes { color: var(--red); font-weight: 600; } .no { color: var(--muted); }

  /* Callouts. */
  blockquote { background: var(--surface); border: var(--line); border-left-width: 10px; border-radius: 14px; box-shadow: var(--shadow-xs); margin: 14px 0; padding: 12px 16px; }
  .warn { background: var(--red-soft); border-left-color: var(--red); }

  /* Charts and map. */
  .chart-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 22px; margin: 18px 0; }
  .pie-chart-wrap { display: flex; align-items: center; gap: 16px; }
  .pie-chart-wrap svg { flex-shrink: 0; }
  .pie-chart-title { font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
  .pie-legend { font-size: 12px; min-width: 0; }
  .pie-legend-item { display: flex; align-items: center; gap: 6px; margin: 3px 0; }
  .pie-legend-swatch { display: inline-block; width: 10px; height: 10px; border: 1.5px solid var(--ink); border-radius: 3px; flex-shrink: 0; }
  .map-wrap { border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-sm); padding: 10px; margin: 14px 0; overflow-x: auto; }
  .attack-map .am-edge.am-hot { opacity: 1 !important; stroke-width: 2.6px; }

  /* AI section. */
  .ai-section { background: var(--surface); border: var(--line); border-radius: 18px; box-shadow: var(--shadow); padding: 6px 24px 20px; margin-top: 18px; }
  .ai-badge { display: inline-block; font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--ink); background: var(--green); border: 2px solid var(--ink); border-radius: 8px; box-shadow: 2px 2px 0 var(--ink); padding: 2px 10px; margin: 12px 0 8px; }
  .ai-section h3 { color: var(--ink); margin: 16px 0 6px; }
  .ai-section ol li { margin: 6px 0; }
  .ai-script { background: var(--ink); color: #ECE7DC; border: var(--line); border-radius: 12px; padding: 10px 12px; font-family: var(--mono); font-size: 12px; white-space: pre-wrap; overflow-x: auto; margin: 6px 0; }
  .ai-triage td { vertical-align: top; }

  @media print {
    body { background: #fff; max-width: none; }
    h1, .card, details.check, .table-wrap, .map-wrap, blockquote, .ai-section { box-shadow: none; }
    .card:hover, details.check:hover { transform: none; }
  }
</style>
'@
}

function ConvertTo-ReportHtml {
    param(
        $Snapshot, $Index, $PrivMap, $Split, $Score, $NotEvaluated, $Comparison,
        [hashtable]$Config, [string]$ToolVersion, [string]$ElapsedText,
        $AiResult = $null
    )
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $findings = @($Split.Active)
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }

    $sevOrder = @('Critical', 'High', 'Medium', 'Low')
    $counts = @{}; foreach ($s in $sevOrder) { $counts[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }
    $collected = ConvertTo-UtcDate $Snapshot.meta.collectedAtUtc

    & $w '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<title>IDWolf report - $(& $H $Snapshot.domain.dnsRoot)</title>"
    & $w (Get-IDWolfThemeCss)
    & $w @'
<script>
function filterIDWolfTable(input) {
  var table = input.closest('table');
  var filters = Array.prototype.map.call(table.querySelectorAll('tr.filter-row input'), function (i) { return i.value.toLowerCase(); });
  var rows = table.querySelectorAll('tr.data-row'); var shown = 0;
  rows.forEach(function (row) {
    var cells = row.children; var ok = true;
    for (var i = 0; i < filters.length; i++) { if (filters[i] && (!cells[i] || cells[i].textContent.toLowerCase().indexOf(filters[i]) === -1)) { ok = false; break; } }
    row.style.display = ok ? '' : 'none'; if (ok) shown++;
  });
  var status = table.parentNode.parentNode.querySelector('.filter-status');
  if (status) status.textContent = shown + ' of ' + rows.length + ' rows shown';
}
function amMap(g, on) {
  try {
    var nid = g.getAttribute('data-nid');
    var svg = g.ownerSVGElement; if (!svg) return;
    var seen = {};
    (function walk(id) {
      if (seen[id]) return; seen[id] = 1;
      var edges = svg.querySelectorAll('.am-from-' + id);
      for (var i = 0; i < edges.length; i++) {
        if (on) { edges[i].classList.add('am-hot'); } else { edges[i].classList.remove('am-hot'); }
        var to = edges[i].getAttribute('data-to'); if (to) walk(to);
      }
    })(nid);
  } catch (e) { }
}
</script>
</head><body>
'@
    & $w "<h1 class=`"title`">$(Get-WolfLogoHtml)<span>IDWolf: Active Directory Hygiene Report</span></h1>"
    & $w "<div class=`"meta`">Domain <b>$(& $H $Snapshot.domain.dnsRoot)</b> ($(& $H $Snapshot.domain.netbios)) &middot; forest $(& $H $Snapshot.domain.forestName) &middot; snapshot $(& $H $collected.ToString('yyyy-MM-dd HH:mm')) UTC by $(& $H $Snapshot.meta.collectedBy) from $(& $H $Snapshot.meta.collectedFrom) &middot; IDWolf v$ToolVersion &middot; analysis $ElapsedText</div>"
    if ($Snapshot.meta.synthetic) {
        & $w '<blockquote>Synthetic snapshot generated for testing and demonstration. No real directory data.</blockquote>'
    }

    & $w '<div class="cards">'
    if ($Score.Reliable) { & $w "<div class=`"card`"><div class=`"grade`">$($Score.Grade) &middot; $($Score.Score)/100</div><div class=`"lbl`">Hygiene score ($($Score.ChecksTriggered) checks triggered)</div></div>" }
    else { & $w "<div class=`"card`"><div class=`"grade`">n/a</div><div class=`"lbl`">Hygiene score not reliable: only $($Score.Coverage)% of the checks could be evaluated</div></div>" }
    foreach ($s in $sevOrder) { & $w "<div class=`"card $($s.ToLower())`"><div class=`"num`">$($counts[$s])</div><div class=`"lbl`">$s findings</div></div>" }
    & $w "<div class=`"card`"><div class=`"num`">$(@($Index.Users).Count)</div><div class=`"lbl`">Users / service accounts</div></div>"
    & $w "<div class=`"card`"><div class=`"num`">$(@($Index.Computers).Count)</div><div class=`"lbl`">Computers</div></div>"
    & $w "<div class=`"card`"><div class=`"num`">$($PrivMap.Principals.Count)</div><div class=`"lbl`">Tier 0 principals</div></div>"
    & $w '</div>'
    & $w '<div class="meta">Score = 100 &times; e<sup>&minus;penalty/100</sup>, where penalty sums a weight per triggered check at its worst severity (Critical 20, High 8, Medium 3, Low 1), capped by the worst severity present: any Critical check limits the score to 35 (grade E), any High to 65 (grade C). It never reaches zero, so a bad domain and a catastrophic one still rank differently. Per-object counts are shown separately so that many low-impact objects do not hide a single critical exposure.</div>'
    & $w (Get-ChartsRowHtml -Findings $findings -Index $Index -PrivMap $PrivMap)
    try { & $w (Get-AdInfoChartsRow -Snapshot $Snapshot -Index $Index) } catch { Write-Warning "Directory charts skipped: $($_.Exception.Message)" }
    if (Get-Command ConvertTo-AttackMapHtml -ErrorAction SilentlyContinue) {
        try { & $w (ConvertTo-AttackMapHtml -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap -Findings $findings) }
        catch { Write-Warning "Attack-path map skipped: $($_.Exception.Message)" }
    }
    if ($AiResult) { & $w (ConvertTo-AiSectionHtml -AiResult $AiResult) }

    $errs = @($Snapshot.meta.collectionErrors | Where-Object { $_ })
    if ($errs.Count -gt 0 -or @($NotEvaluated).Count -gt 0) {
        & $w '<blockquote class="warn"><b>Incomplete coverage.</b> Some sections could not be collected; the checks below were <b>not evaluated</b> (zero findings there does not mean compliant).<ul>'
        foreach ($n in $NotEvaluated) { & $w "<li><code>$($n.Type)</code> $(& $H $n.Title): $(& $H $n.Reason)</li>" }
        & $w '</ul></blockquote>'
    }

    # ---------------- Category summary ----------------
    & $w '<details open><summary><h2>Summary by category</h2></summary><div class="table-wrap"><table><tr><th>Category</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Checks triggered</th></tr>'
    $cats = @($script:CheckCatalog.Values | ForEach-Object { $_.Category } | Select-Object -Unique)
    foreach ($c in $cats) {
        $cf = @($findings | Where-Object { $_.Category -eq $c })
        $row = "<tr class=`"data-row`"><td>$(& $H $c)</td>"
        foreach ($s in $sevOrder) { $row += "<td>$(@($cf | Where-Object { $_.Severity -eq $s }).Count)</td>" }
        $row += "<td>$(@($cf | ForEach-Object { $_.Type } | Select-Object -Unique).Count)</td></tr>"
        & $w $row
    }
    & $w '</table></div></details>'

    if (Get-Command ConvertTo-ComplianceHtml -ErrorAction SilentlyContinue) {
        try { & $w (ConvertTo-ComplianceHtml -Catalog $script:CheckCatalog -Findings $findings -NotEvaluated $NotEvaluated) }
        catch { Write-Warning "Regulatory mapping skipped: $($_.Exception.Message)" }
    }

    # ---------------- Checks ----------------
    & $w '<details open><summary><h2>Findings by check</h2></summary>'
    if ($findings.Count -eq 0) { & $w '<p>No findings.</p>' }
    $byType = $findings | Group-Object Type
    $typeRows = @($byType | ForEach-Object {
            $worst = ($_.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
            [PSCustomObject]@{ Type = $_.Name; Worst = $worst; Items = $_.Group; Rank = $script:SeverityRank[$worst] }
        } | Sort-Object @{ Expression = 'Rank'; Descending = $true }, @{ Expression = { $_.Items.Count }; Descending = $true }, @{ Expression = { Get-CheckPosition $_.Type } })
    foreach ($t in $typeRows) {
        $meta = $script:CheckCatalog[$t.Type]
        $n = @($t.Items).Count
        & $w "<details class=`"check`"><summary>$(Get-SevPill $t.Worst)<span class=`"check-title`">$(& $H $meta.Title)</span><span class=`"check-id`">$($t.Type) &middot; $(& $H $meta.Category)</span><span class=`"count`">$n object$(if ($n -ne 1) { 's' })</span></summary><div class=`"body`">"
        & $w "<div class=`"kv`"><b>Why it matters.</b> $(& $H $meta.Description)</div>"
        & $w "<div class=`"kv`"><b>Remediation.</b> $(& $H $meta.Remediation)</div>"
        if ($meta.Mitre) { & $w "<div class=`"kv`"><b>MITRE ATT&amp;CK.</b> $(Get-MitreLink $meta.Mitre)</div>" }
        if (Get-Command Format-CheckControls -ErrorAction SilentlyContinue) { & $w "<div class=`"kv`"><b>Regulatory controls.</b> $(& $H (Format-CheckControls $t.Type))</div>" }
        & $w '<div class="table-wrap"><table><tr><th>Severity</th><th>Object</th><th>Type</th><th>Detail</th></tr>'
        foreach ($f in ($t.Items | Sort-Object { - $script:SeverityRank[$_.Severity] }, Object)) {
            & $w "<tr class=`"data-row`"><td>$(Get-SevPill $f.Severity)</td><td title=`"$(& $H $f.ObjectDn)`"><b>$(& $H $f.Object)</b></td><td>$(& $H $f.ObjectType)</td><td>$(& $H $f.Detail)</td></tr>"
        }
        & $w '</table></div></div></details>'
    }
    & $w '</details>'

    # ---------------- Tier 0 inventory ----------------
    & $w '<details><summary><h2>Tier 0 inventory</h2></summary>'
    & $w '<p class="meta">Effective members of privileged groups, resolved by SID through nested groups and primaryGroupID. PU = Protected Users, ND = "sensitive and cannot be delegated".</p>'
    & $w '<div class="table-wrap"><table><tr><th>Principal</th><th>Type</th><th>Enabled</th><th>Privileged groups</th><th>Membership path</th><th>Last logon</th><th>Password age</th><th>SPN</th><th>PU / ND</th><th>Never expires</th></tr>'
    $tierRows = @($PrivMap.Principals.Values | Sort-Object { if ($_.Principal -and $_.Principal.samAccountName) { $_.Principal.samAccountName } else { $_.Dn } })
    foreach ($r in $tierRows) {
        $p = $r.Principal
        $name = if ($p -and $p.samAccountName) { $p.samAccountName } elseif ($p -and $p.name) { $p.name } else { $r.Dn }
        $enabled = if ($p -and $null -ne $p.enabled) { if ($p.enabled) { 'yes' } else { '<span class="no">no</span>' } } else { 'n/a' }
        $ll = if ($p) { Format-Age (Get-AgeDays $p.lastLogonTimestamp) } else { '' }
        $pa = if ($p) { Format-Age (Get-AgeDays $p.pwdLastSet) } else { '' }
        $spn = if ($p -and @($p.servicePrincipalNames | Where-Object { $_ }).Count -gt 0) { '<span class="yes">yes</span>' } else { '<span class="no">no</span>' }
        $pu = if ($p -and $PrivMap.ProtectedUsersSet.ContainsKey($r.Dn.ToLower())) { 'PU' } else { '' }
        $nd = if ($p -and $p.userAccountControl -and (Test-Uac $p 'NOT_DELEGATED')) { 'ND' } else { '' }
        $pund = (@($pu, $nd) | Where-Object { $_ }) -join ' '
        if (-not $pund) { $pund = if ($r.Type -eq 'user') { '<span class="yes">none</span>' } else { '' } }
        $ne = if ($p -and $p.userAccountControl -and (Test-Uac $p 'DONT_EXPIRE_PASSWORD')) { '<span class="yes">yes</span>' } else { '<span class="no">no</span>' }
        & $w "<tr class=`"data-row`"><td title=`"$(& $H $r.Dn)`"><b>$(& $H $name)</b></td><td>$(& $H $r.Type)</td><td>$enabled</td><td>$(& $H ($r.Groups -join ', '))</td><td>$(& $H ($r.Paths -join ' | '))</td><td>$ll</td><td>$pa</td><td>$spn</td><td>$pund</td><td>$ne</td></tr>"
    }
    & $w '</table></div></details>'

    # ---------------- Domain posture ----------------
    & $w '<details><summary><h2>Domain posture</h2></summary><div class="table-wrap"><table><tr><th>Item</th><th>Value</th></tr>'
    $krb = $Index.BySid["$($Index.DomainSid)-502"]
    $pp = $Snapshot.domain.passwordPolicy
    $postureRows = [ordered]@{
        'Domain / forest functional level' = "$($Snapshot.domain.domainMode) / $($Snapshot.domain.forestMode)"
        'krbtgt password age'              = if ($krb) { Format-Age (Get-AgeDays $krb.pwdLastSet) } else { 'n/a' }
        'Domain controllers'               = (@($Snapshot.domainControllers | Where-Object { $_ } | ForEach-Object { "$($_.name) ($($_.operatingSystem)$(if ($_.isReadOnly) { ', RODC' }))" }) -join '; ')
        'Password policy'                  = if ($pp) { "min length $($pp.minPasswordLength), complexity $($pp.complexityEnabled), lockout $($pp.lockoutThreshold), max age $($pp.maxPasswordAgeDays)d, history $($pp.passwordHistoryCount)" } else { 'not collected' }
        'Fine-grained policies'            = if ($null -ne $Snapshot.domain.fineGrainedPolicies) { "$(@($Snapshot.domain.fineGrainedPolicies | Where-Object { $_ }).Count)" } else { 'not collected (requires read access to the Password Settings Container)' }
        'ms-DS-MachineAccountQuota'        = "$($Snapshot.domain.machineAccountQuota)"
        'LAPS schema (legacy / Windows)'   = "$($Snapshot.domain.lapsLegacySchema) / $($Snapshot.domain.lapsV2Schema)"
        'Recycle Bin'                      = "$($Snapshot.domain.recycleBinEnabled)"
        'dSHeuristics'                     = if ($Snapshot.domain.dsHeuristics) { "$($Snapshot.domain.dsHeuristics)" } else { '(not set)' }
        'External / forest trusts'         = "$(@($Snapshot.trusts | Where-Object { $_ -and -not $_.intraForest }).Count)"
        'SYSVOL scanned for cpassword'     = "$($Snapshot.sysvol.scanned)"
    }
    foreach ($k in $postureRows.Keys) { & $w "<tr class=`"data-row`"><td>$(& $H $k)</td><td>$(& $H $postureRows[$k])</td></tr>" }
    & $w '</table></div>'
    & $w "<p class=`"meta`">Thresholds: krbtgt $($Config.KrbtgtMaxAgeDays)/$($Config.KrbtgtCriticalDays) days, privileged inactivity $($Config.PrivInactiveDays) days, user inactivity $($Config.InactiveDays) days, stale computer $($Config.StaleComputerDays) days, password age $($Config.PasswordMaxAgeDays) days, minimum length $($Config.MinPasswordLength), max Domain Admins $($Config.MaxDomainAdmins).</p></details>"

    # ---------------- Comparison ----------------
    if ($Comparison) {
        & $w "<details open><summary><h2>Comparison with previous run</h2></summary><p class=`"meta`">Baseline: $(& $H $Comparison.PreviousPath). Matched by (check, object).</p>"
        & $w "<div class=`"cards`"><div class=`"card`"><div class=`"num compare-new`">$(@($Comparison.New).Count)</div><div class=`"lbl`">New</div></div><div class=`"card`"><div class=`"num compare-resolved`">$(@($Comparison.Resolved).Count)</div><div class=`"lbl`">Resolved</div></div><div class=`"card`"><div class=`"num`">$(@($Comparison.Persisting).Count)</div><div class=`"lbl`">Still present</div></div></div>"
        & $w '<div class="table-wrap"><table><tr><th>Status</th><th>Severity</th><th>Check</th><th>Object</th><th>Detail</th></tr>'
        foreach ($f in $Comparison.New) { & $w "<tr class=`"data-row`"><td class=`"compare-new`">NEW</td><td>$(Get-SevPill $f.Severity)</td><td>$($f.Type)</td><td>$(& $H $f.Object)</td><td>$(& $H $f.Detail)</td></tr>" }
        foreach ($f in $Comparison.Resolved) { & $w "<tr class=`"data-row`"><td class=`"compare-resolved`">RESOLVED</td><td>$(Get-SevPill $f.Severity)</td><td>$($f.Type)</td><td>$(& $H $f.Object)</td><td>$(& $H $f.Detail)</td></tr>" }
        & $w '</table></div></details>'
    }

    # ---------------- Accepted risks ----------------
    if (@($Split.Accepted).Count -gt 0 -or @($Split.Expired).Count -gt 0) {
        & $w '<details><summary><h2>Accepted risks (exceptions)</h2></summary>'
        if (@($Split.Expired).Count -gt 0) {
            & $w '<blockquote class="warn"><b>Expired exceptions ignored</b> (their findings are back in the report):<ul>'
            foreach ($e in $Split.Expired) { & $w "<li><code>$(& $H $e.type)</code> / $(& $H $e.object): expired $(& $H $e.expires). $(& $H $e.reason)</li>" }
            & $w '</ul></blockquote>'
        }
        & $w '<div class="table-wrap"><table><tr><th>Severity</th><th>Check</th><th>Object</th><th>Reason</th><th>Owner</th><th>Expires</th></tr>'
        foreach ($a in $Split.Accepted) {
            & $w "<tr class=`"data-row`"><td>$(Get-SevPill $a.Finding.Severity)</td><td>$($a.Finding.Type)</td><td>$(& $H $a.Finding.Object)</td><td>$(& $H $a.Exception.reason)</td><td>$(& $H $a.Exception.owner)</td><td>$(& $H $a.Exception.expires)</td></tr>"
        }
        & $w '</table></div></details>'
    }

    # ---------------- All findings (filterable) ----------------
    & $w '<details><summary><h2>All findings</h2></summary><div class="table-wrap"><table>'
    & $w '<tr><th>Severity</th><th>Check</th><th>Category</th><th>Object</th><th>Type</th><th>Detail</th><th>MITRE</th></tr>'
    & $w ('<tr class="filter-row">' + ((1..7 | ForEach-Object { '<td><input type="text" placeholder="filter" oninput="filterIDWolfTable(this)"></td>' }) -join '') + '</tr>')
    foreach ($f in ($findings | Sort-Object { - $script:SeverityRank[$_.Severity] }, Type, Object)) {
        & $w "<tr class=`"data-row`"><td>$(Get-SevPill $f.Severity)</td><td>$($f.Type)</td><td>$(& $H $f.Category)</td><td title=`"$(& $H $f.ObjectDn)`">$(& $H $f.Object)</td><td>$(& $H $f.ObjectType)</td><td>$(& $H $f.Detail)</td><td>$(Get-MitreLink $f.Mitre)</td></tr>"
    }
    & $w "</table></div><div class=`"filter-status`">$($findings.Count) rows</div></details>"

    & $w '<p class="meta" style="margin-top:32px">Generated by IDWolf from a read-only snapshot. The report contains directory data: handle as confidential.</p>'
    & $w '</body></html>'
    return $sb.ToString()
}
