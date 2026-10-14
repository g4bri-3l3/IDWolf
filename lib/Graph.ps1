# Attack-path and trust maps: what can reach Tier 0, and whom the domain
# trusts. Built from the findings, drawn as plain SVG so it works offline;
# the bit of script only highlights paths on hover.

# Escalation finding types -> edge label toward Tier 0. Order roughly by impact.
$script:EscalationKinds = [ordered]@{
    dcsync_rights                              = 'DCSync'
    dangerous_ace_tier0                        = 'Dangerous ACL on Tier 0'
    nonstandard_owner_tier0                    = 'Owns Tier 0 object'
    gpo_dangerous_acl                          = 'GPO control -> DCs'
    adcs_esc1                                  = 'AD CS ESC1'
    adcs_esc2                                  = 'AD CS ESC2'
    adcs_esc3                                  = 'AD CS ESC3'
    adcs_esc4                                  = 'AD CS ESC4'
    adcs_esc5                                  = 'AD CS ESC5'
    adcs_esc9                                  = 'AD CS ESC9'
    adcs_esc10                                 = 'AD CS ESC10'
    adcs_esc13                                 = 'AD CS ESC13'
    adcs_esc15                                 = 'AD CS ESC15'
    constrained_delegation_protocol_transition = 'Protocol transition'
    unconstrained_delegation                   = 'Unconstrained delegation'
    constrained_delegation                     = 'Constrained delegation'
    rbcd_configured                            = 'RBCD'
    privileged_kerberoastable                  = 'Kerberoastable Tier 0'
    privileged_foreign_member                  = 'Foreign Tier 0 member'
    privileged_computer_member                 = 'Computer in Tier 0'
    gmsa_password_readable                     = 'gMSA password read'
    shadow_credentials_present                 = 'Shadow credentials'
    dangerous_ace_anywhere                     = 'ACL path'
    dangerous_privilege_right                  = 'Sensitive right on DCs'
}

$script:GraphSevColor = @{ Critical = '#E2372A'; High = '#EF8A6F'; Medium = '#F2B632'; Low = '#B9B1A1' }

function Get-GraphSevRank { param([string]$S) if ($script:SeverityRank.ContainsKey($S)) { return $script:SeverityRank[$S] } return 0 }

# Edges toward Tier 0: one node per source, one edge per technique, worst severity kept.
function Get-AttackGraph {
    param($Snapshot, $Index, $PrivMap, $Findings)

    $nodes = [ordered]@{}   # key: object label -> node record
    $edges = New-Object System.Collections.Generic.List[object]
    $escal = @($Findings | Where-Object { $_ -and $script:EscalationKinds.Contains($_.Type) -and "$($_.Object)" })
    foreach ($f in $escal) {
        $key = "$($f.Object)"
        if (-not $nodes.Contains($key)) {
            $nodes[$key] = [PSCustomObject]@{ Id = $nodes.Count; Label = $key; Type = "$($f.ObjectType)"; Sev = $f.Severity; Techniques = New-Object System.Collections.Generic.List[string]; Level = 0 }
        }
        $n = $nodes[$key]
        if ((Get-GraphSevRank $f.Severity) -gt (Get-GraphSevRank $n.Sev)) { $n.Sev = $f.Severity }
    }
    # A node is found by the short name of its object ("TEST\sales" -> "sales").
    $nodeByName = @{}
    foreach ($n in $nodes.Values) { $nodeByName[(($n.Label -split '\\')[-1]).ToLower()] = $n }

    # DNs of everything that already is Tier 0, to tell "a right over Tier 0" from "a right over something".
    $t0Dns = @{}
    foreach ($k in $PrivMap.Principals.Keys) { $t0Dns["$k".ToLower()] = $true }
    foreach ($e in $PrivMap.Groups.Values) { if ($e.Group -and $e.Group.distinguishedName) { $t0Dns["$($e.Group.distinguishedName)".ToLower()] = $true } }

    foreach ($f in $escal) {
        $n = $nodes["$($f.Object)"]
        $kind = $script:EscalationKinds[$f.Type]
        $to = -1
        $unverified = $false
        # An ACL over an object that is itself a source is a hop, not a jump to Tier 0:
        # group A -> GenericWrite over account B -> B has DCSync.
        if ($f.Type -eq 'dangerous_ace_anywhere' -and $f.ObjectDn) {
            $victim = $Index.ByDn["$($f.ObjectDn)".ToLower()]
            if ($victim) {
                $vn = if ($victim.samAccountName) { "$($victim.samAccountName)" } else { "$($victim.name)" }
                $t = $nodeByName[$vn.ToLower()]
                if ($t -and $t.Id -ne $n.Id) {
                    $to = $t.Id
                    $kind = if ("$($f.Detail)" -match '^(.+?) over ') { "ACL path ($($Matches[1]))" } else { 'ACL path' }
                }
            }
            # No hop and the object is not Tier 0: the right is real, but nothing in the findings
            # shows that the object leads to Tier 0, so the arrow is drawn as unverified.
            if ($to -lt 0 -and -not $t0Dns.ContainsKey("$($f.ObjectDn)".ToLower())) { $unverified = $true }
        }
        if ($n.Techniques -notcontains $kind) { $n.Techniques.Add($kind) }
        $edges.Add([PSCustomObject]@{ From = $n.Id; To = $to; Kind = $kind; Sev = $f.Severity; Unverified = $unverified; EdgeKey = "$($f.Object)|$kind|$to|$unverified" })
    }
    # Dedup edges by (from, kind, to) keeping worst severity.
    $byEdge = [ordered]@{}
    foreach ($e in $edges) {
        if (-not $byEdge.Contains($e.EdgeKey) -or (Get-GraphSevRank $e.Sev) -gt (Get-GraphSevRank $byEdge[$e.EdgeKey].Sev)) { $byEdge[$e.EdgeKey] = $e }
    }
    # Hops to Tier 0: 0 when every edge goes straight there, else 1 + the longest chain behind it.
    $outTo = @{}; foreach ($e in $byEdge.Values) { if ($e.To -ge 0) { if (-not $outTo.ContainsKey($e.From)) { $outTo[$e.From] = New-Object System.Collections.Generic.List[int] }; $outTo[$e.From].Add($e.To) } }
    $memo = @{}
    $levelOf = $null
    $levelOf = { param($id, $path)
        if ($memo.ContainsKey($id)) { return $memo[$id] }
        if (-not $outTo.ContainsKey($id) -or $path -contains $id) { return 0 }
        $best = 0
        foreach ($t in $outTo[$id]) { $l = 1 + (& $levelOf $t (@($path) + $id)); if ($l -gt $best) { $best = $l } }
        $memo[$id] = $best
        return $best
    }
    foreach ($n in $nodes.Values) { $n.Level = [int](& $levelOf $n.Id @()) }
    $nodeList = @($nodes.Values | Sort-Object @{ Expression = { - (Get-GraphSevRank $_.Sev) } }, @{ Expression = 'Label' })

    # Trusts.
    $trusts = @()
    foreach ($t in @($Snapshot.trusts | Where-Object { $_ -and -not $_.intraForest })) {
        $risk = ($t.usesRC4Encryption -or -not $t.sidFilteringQuarantined -or $t.tgtDelegation)
        $trusts += [PSCustomObject]@{ Name = $t.name; Direction = "$($t.direction)"; Type = "$($t.trustType)"; Forest = [bool]$t.forestTransitive; Risk = [bool]$risk }
    }

    return [PSCustomObject]@{ Nodes = $nodeList; Edges = @($byEdge.Values); Trusts = $trusts }
}

# The real paths, tokenized, for the AI prompt, so the model describes them instead of making them up.
function Get-AttackPathLines {
    param($Findings, $Pz, [int]$Max = 30)
    $lines = New-Object System.Collections.Generic.List[string]
    $rows = @()
    foreach ($f in @($Findings | Where-Object { $_ })) {
        if (-not $script:EscalationKinds.Contains($f.Type)) { continue }
        $rows += [PSCustomObject]@{ Sev = $f.Severity; Obj = $f.Object; Kind = $script:EscalationKinds[$f.Type] }
    }
    # Worst first, otherwise input order (Sort-Object on PS 5.1 isn't stable).
    $rows = @(foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $rows | Where-Object { $_.Sev -eq $s } })
    $rows = @($rows | Select-Object -First $Max)
    foreach ($r in $rows) {
        $o = if ($Pz) { Protect-AiText $Pz $r.Obj } else { $r.Obj }
        $lines.Add("- [$($r.Sev)] $o  ->  Tier 0  via $($r.Kind)")
    }
    return $lines
}

function ConvertTo-GraphLabel { param([string]$S, [int]$Max = 28) if ($null -eq $S) { return '' }; if ($S.Length -le $Max) { return $S }; return $S.Substring(0, $Max - 1) + [char]0x2026 }

# Renders the attack-path map + trust map as one collapsible report section.
function ConvertTo-AttackMapHtml {
    param($Snapshot, $Index, $PrivMap, $Findings)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $g = Get-AttackGraph -Snapshot $Snapshot -Index $Index -PrivMap $PrivMap -Findings $Findings

    $allNodes = @($g.Nodes)
    $cap = 26
    $shown = @($allNodes | Select-Object -First $cap)
    $moreCount = $allNodes.Count - $shown.Count

    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    & $w '<details open class="map-details"><summary><h2>Attack-path map (toward Tier 0)</h2></summary>'

    if ($shown.Count -eq 0) {
        & $w '<p class="meta">No escalation path toward Tier 0 was found in this snapshot. This is a good sign, but remember that deep ACL findings need a <code>-Deep</code> collection and password-based paths need the password-quality report.</p>'
    }
    else {
        # Layout. With no chains, up to two columns of sources on the left and the Tier 0 anchor on the right.
        # With chains (A has a right over B, B reaches Tier 0), one column per hop: the longest chain starts
        # at the left, and every arrow points one or more columns to the right.
        $shownIds = @{}; foreach ($n in $shown) { $shownIds[$n.Id] = $true }
        $edgesList = @($g.Edges)
        # Keep the targets of the visible hops, or a chain would end in the air.
        do {
            $grew = $false
            foreach ($e in $edgesList) {
                if ($shownIds.ContainsKey($e.From) -and $e.To -ge 0 -and -not $shownIds.ContainsKey($e.To)) {
                    $t = $allNodes | Where-Object { $_.Id -eq $e.To } | Select-Object -First 1
                    if ($t) { $shown += $t; $shownIds[$t.Id] = $true; $grew = $true }
                }
            }
        } while ($grew)
        $moreCount = $allNodes.Count - $shown.Count
        $maxLevel = [int](($shown | ForEach-Object { $_.Level } | Measure-Object -Maximum).Maximum)
        $chain = $maxLevel -gt 0
        $boxH = 24; $rowH = 32; $top = 54; $t0w = 150; $t0h = 44
        $pos = @{}
        if ($chain) {
            $boxW = 190; $gapX = 70
            $colX = @(0..$maxLevel | ForEach-Object { 16 + $_ * ($boxW + $gapX) })
            $byCol = @{}
            foreach ($n in ($shown | Sort-Object @{ Expression = { - (Get-GraphSevRank $_.Sev) } }, Label)) {
                $c = $maxLevel - $n.Level
                if (-not $byCol.ContainsKey($c)) { $byCol[$c] = 0 }
                $pos[$n.Id] = @{ X = $colX[$c]; Y = $top + $byCol[$c] * $rowH }
                $byCol[$c]++
            }
            $rows = [int](($byCol.Values | Measure-Object -Maximum).Maximum)
            $svgH = [int]([Math]::Max($rows, 3) * $rowH + $top + 30)
            $t0x = 16 + ($maxLevel + 1) * ($boxW + $gapX); $svgW = $t0x + $t0w + 20
        }
        else {
            $boxW = 210; $colX = @(16, 250)
            $perCol = [Math]::Ceiling($shown.Count / [double]($colX.Count))
            $svgH = [int]([Math]::Max($perCol, 3) * $rowH + $top + 30)
            $svgW = 760; $t0x = 560
            for ($i = 0; $i -lt $shown.Count; $i++) {
                $col = [int]([Math]::Floor($i / $perCol))
                $pos[$shown[$i].Id] = @{ X = $colX[[Math]::Min($col, $colX.Count - 1)]; Y = $top + ($i % $perCol) * $rowH }
            }
        }
        $t0y = [int]($svgH / 2)

        $svg = New-Object System.Text.StringBuilder
        [void]$svg.AppendLine("<svg viewBox='0 0 $svgW $svgH' width='100%' preserveAspectRatio='xMinYMin meet' font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif' class='attack-map'>")
        [void]$svg.AppendLine("<defs><marker id='amArrow' markerWidth='9' markerHeight='9' refX='8' refY='3' orient='auto'><path d='M0,0 L8,3 L0,6 Z' fill='#5F5A51'/></marker></defs>")
        # Edges first (under nodes).
        $nodeById = @{}; foreach ($n in $shown) { $nodeById[$n.Id] = $n }
        foreach ($e in $edgesList) {
            if (-not $pos.ContainsKey($e.From)) { continue }
            $p = $pos[$e.From]
            $x1 = $p.X + $boxW; $y1 = $p.Y + [int]($boxH / 2)
            $toHop = ($e.To -ge 0 -and $pos.ContainsKey($e.To) -and $chain)
            if ($toHop) { $x2 = $pos[$e.To].X; $y2 = $pos[$e.To].Y + [int]($boxH / 2); $dest = & $H $nodeById[$e.To].Label }
            else { $x2 = $t0x; $y2 = $t0y; $dest = 'Tier 0' }
            $mx = [int](($x1 + $x2) / 2)
            $col = $script:GraphSevColor[$e.Sev]
            $dataTo = if ($toHop) { " data-to='$($e.To)'" } else { '' }
            $dash = if ($e.Unverified) { " stroke-dasharray='5,4'" } else { '' }
            $unv = if ($e.Unverified) { ' (unverified: the object is not known to lead to Tier 0)' } else { '' }
            [void]$svg.AppendLine("<path class='am-edge am-from-$($e.From)'$dataTo d='M$x1,$y1 C$mx,$y1 $mx,$y2 $x2,$y2' fill='none' stroke='$col' stroke-width='1.6' opacity='0.45'$dash marker-end='url(#amArrow)'><title>$(& $H $nodeById[$e.From].Label) -> $dest via $(& $H $e.Kind) [$($e.Sev)]$unv</title></path>")
        }
        # Tier 0 anchor.
        [void]$svg.AppendLine("<rect x='$t0x' y='$([int]($t0y-$t0h/2))' width='$t0w' height='$t0h' rx='8' fill='#161513' stroke='#161513' stroke-width='2'/>")
        [void]$svg.AppendLine("<text x='$([int]($t0x+$t0w/2))' y='$([int]($t0y-2))' text-anchor='middle' fill='#F3EFE6' font-size='13' font-weight='700'>Tier 0</text>")
        [void]$svg.AppendLine("<text x='$([int]($t0x+$t0w/2))' y='$([int]($t0y+13))' text-anchor='middle' fill='#B9B1A1' font-size='10'>domain compromise</text>")
        # Source nodes.
        foreach ($n in $shown) {
            $p = $pos[$n.Id]
            $col = $script:GraphSevColor[$n.Sev]
            $label = & $H (ConvertTo-GraphLabel $n.Label)
            $tech = & $H (($n.Techniques | Select-Object -First 3) -join ', ')
            [void]$svg.AppendLine("<g class='am-node' data-nid='$($n.Id)' onmouseover='amMap(this,true)' onmouseout='amMap(this,false)'>")
            [void]$svg.AppendLine("<rect x='$($p.X)' y='$($p.Y)' width='$boxW' height='$boxH' rx='5' fill='#fff' stroke='$col' stroke-width='1.6'/>")
            [void]$svg.AppendLine("<rect x='$($p.X)' y='$($p.Y)' width='4' height='$boxH' rx='2' fill='$col'/>")
            [void]$svg.AppendLine("<text x='$($p.X + 10)' y='$($p.Y + 16)' font-size='11' fill='#161513'>$label</text>")
            [void]$svg.AppendLine("<title>$(& $H $n.Label) [$($n.Type)] - $tech</title>")
            [void]$svg.AppendLine("</g>")
        }
        [void]$svg.AppendLine('</svg>')
        & $w "<div class='map-wrap'>$($svg.ToString())</div>"
        if ($moreCount -gt 0) { & $w "<p class='meta'>Showing the $cap highest-severity sources; $moreCount more escalation source(s) are in the findings tables below.</p>" }
        $dashNote = if (@($edgesList | Where-Object { $_.Unverified }).Count) { ' Dashed arrows: the right is real but the object it is held over is not known to lead to Tier 0, so the arrow to Tier 0 is an assumption; check those first.' } else { '' }
        $hopNote = $dashNote + $(if ($chain) { " Boxes joined by an arrow are hops of one chain: a principal that holds a right over the next box and so inherits what it reaches ($($maxLevel + 1) steps at most). Hover a box to light up its whole path." } else { '' })
        & $w "<p class='meta'>Each box is a principal or object that has a path to Tier 0; the arrow is the technique. Colour is the severity. Hover an arrow for the exact path.$hopNote This is derived from the deterministic findings, not a live reachability test.</p>"
    }

    # ---- Trust map ----
    & $w "<h3 style='margin-top:18px'>Trust map</h3>"
    $trusts = @($g.Trusts)
    if ($trusts.Count -eq 0) {
        & $w '<p class="meta">No external or forest trusts.</p>'
    }
    else {
        $tw = 760; $cx = 380; $cy = 150; $r = 110
        $tsvg = New-Object System.Text.StringBuilder
        [void]$tsvg.AppendLine("<svg viewBox='0 0 $tw 320' width='100%' preserveAspectRatio='xMinYMin meet' font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif'>")
        $n = $trusts.Count
        for ($i = 0; $i -lt $n; $i++) {
            $ang = (2 * [Math]::PI * $i / [Math]::Max(1, $n)) - [Math]::PI / 2
            $tx = [int]($cx + $r * [Math]::Cos($ang) * 1.6)
            $ty = [int]($cy + $r * [Math]::Sin($ang))
            $tr = $trusts[$i]
            $col = if ($tr.Risk) { '#E2372A' } else { '#8A857A' }
            $dash = if ($tr.Forest) { "stroke-dasharray='5,3'" } else { '' }
            [void]$tsvg.AppendLine("<line x1='$cx' y1='$cy' x2='$tx' y2='$ty' stroke='$col' stroke-width='1.6' opacity='0.6' $dash/>")
            $boxw = 150; $bx = [int]($tx - $boxw / 2); $by = [int]($ty - 14)
            [void]$tsvg.AppendLine("<rect x='$bx' y='$by' width='$boxw' height='28' rx='5' fill='#fff' stroke='$col' stroke-width='1.6'/>")
            [void]$tsvg.AppendLine("<text x='$tx' y='$([int]($ty+1))' text-anchor='middle' font-size='10.5' fill='#161513'>$(& $H (ConvertTo-GraphLabel $tr.Name 20))</text>")
            [void]$tsvg.AppendLine("<text x='$tx' y='$([int]($ty+13))' text-anchor='middle' font-size='9' fill='#5F5A51'>$(& $H $tr.Direction) $(if ($tr.Forest){'forest'}else{'external'})</text>")
        }
        [void]$tsvg.AppendLine("<rect x='$([int]($cx-85))' y='$([int]($cy-18))' width='170' height='36' rx='8' fill='#161513' stroke='#161513' stroke-width='2'/>")
        [void]$tsvg.AppendLine("<text x='$cx' y='$([int]($cy+5))' text-anchor='middle' fill='#F3EFE6' font-size='12' font-weight='700'>$(& $H (ConvertTo-GraphLabel $Snapshot.domain.dnsRoot 24))</text>")
        [void]$tsvg.AppendLine('</svg>')
        & $w "<div class='map-wrap'>$($tsvg.ToString())</div>"
        & $w "<p class='meta'>Red = a trust with a weak setting (RC4, no SID filtering, or TGT delegation). Dashed = forest trust. See the Domain Configuration findings for detail.</p>"
    }

    # ---- Tier 0 members ----
    # The map shows what can reach Tier 0. The accounts that already are Tier 0 (Administrator, Domain
    # Admins...) are the destination, so they are listed here instead of drawn as sources.
    $t0 = @($PrivMap.Principals.Values | Where-Object { $_ })
    if ($t0.Count -gt 0) {
        & $w "<h3 style='margin-top:18px'>Tier 0 members ($($t0.Count))</h3>"
        & $w '<p class="meta">These principals already hold Tier 0 rights, so they are the target of the paths above, not a source. Compromising any of them is domain compromise.</p>'
        & $w '<div class="table-wrap"><table><tr><th>Principal</th><th>Kind</th><th>Status</th><th>Last logon</th><th>Password age</th><th>Tier 0 through</th></tr>'
        $rows = foreach ($rec in $t0) {
            $p = $rec.Principal
            $name = if ($p) { "$($p.samAccountName)" } else { "$($rec.Dn)" }
            $kind = if ($rec.Type -eq 'foreign' -or $rec.Type -eq 'unresolved') { "$($rec.Type)" } elseif ($rec.Type -eq 'computer') { 'computer' } elseif ($p -and ($p.kind -ne 'user' -or @($p.servicePrincipalNames | Where-Object { $_ }).Count)) { 'service account' } else { 'user' }
            $status = if ($p) { if ($p.enabled) { 'enabled' } else { 'disabled' } } else { '' }
            $ll = if ($p) { Get-AgeDays $p.lastLogonTimestamp } else { $null }
            $pa = if ($p) { Get-AgeDays $p.pwdLastSet } else { $null }
            [PSCustomObject]@{ Name = $name; Kind = $kind; Status = $status; Logon = $(if ($p) { if ($null -eq $ll) { 'never' } else { "$ll d ago" } } else { '' }); Pwd = $(if ($null -ne $pa) { "$pa d" } else { '' }); Groups = ($rec.Groups -join ', ') }
        }
        foreach ($r in @($rows | Sort-Object Kind, Name)) {
            & $w "<tr class=`"data-row`"><td><b>$(& $H $r.Name)</b></td><td>$(& $H $r.Kind)</td><td>$(& $H $r.Status)</td><td>$(& $H $r.Logon)</td><td>$(& $H $r.Pwd)</td><td>$(& $H $r.Groups)</td></tr>"
        }
        & $w '</table></div>'
    }

    & $w '</details>'
    return $sb.ToString()
}
