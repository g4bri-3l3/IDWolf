# Optional Gemini step. The ground rules:
#   - findings are computed locally and the report is saved before anything is sent;
#     the model writes on top of them, it never decides what a finding is;
#   - nothing leaves without consent (a prompt, or -SendToAI);
#   - names, DNs, SIDs, domains and paths are swapped for tokens first, and the
#     map never leaves this machine;
#   - -AiDryRun writes the exact prompt to a file and sends nothing;
#   - every real send leaves the prompt and the reply next to the report
#     (<report>_ai_prompt.txt / _ai_response.json), still pseudonymized; the
#     prompt file is self-contained, to paste into another model;
#   - a safety refusal gets one retry with the defensive instructions
#     (<report>_ai_prompt_defensive.txt).

# Names that are the same everywhere: they help the model and give nothing away.
$script:AiKeepNames = @(
    'Administrator', 'Guest', 'krbtgt', 'Domain Admins', 'Enterprise Admins', 'Schema Admins',
    'Administrators', 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators',
    'Key Admins', 'Enterprise Key Admins', 'Group Policy Creator Owners', 'DnsAdmins', 'Protected Users',
    'Domain Users', 'Domain Computers', 'Domain Controllers', 'Read-only Domain Controllers',
    'Enterprise Read-only Domain Controllers', 'Cert Publishers', 'RAS and IAS Servers',
    'Allowed RODC Password Replication Group', 'Denied RODC Password Replication Group',
    'Cloneable Domain Controllers', 'Enterprise Domain Controllers', 'Default Domain Policy',
    'Default Domain Controllers Policy',
    # Builtin local groups: identical in every domain, identify nothing.
    'Users', 'Guests', 'Remote Desktop Users', 'Remote Management Users', 'IIS_IUSRS',
    'Performance Log Users', 'Performance Monitor Users', 'Distributed COM Users',
    'Event Log Readers', 'Certificate Service DCOM Access', 'Cryptographic Operators',
    'Network Configuration Operators', 'Access Control Assistance Operators',
    'Pre-Windows 2000 Compatible Access', 'Windows Authorization Access Group',
    'Terminal Server License Servers', 'Incoming Forest Trust Builders',
    'Replicator', 'Storage Replica Administrators'
)

# --------------------------------------------------------------------------
# Pseudonymizer
# --------------------------------------------------------------------------
function New-Pseudonymizer {
    param($Snapshot, $Index)
    $pz = [PSCustomObject]@{
        Forward  = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
        Reverse  = @{}
        Counters = @{}
        Ordered  = $null
    }
    $keep = @{}; foreach ($k in $script:AiKeepNames) { $keep[$k.ToLower()] = $true }

    $add = {
        param([string]$Value, [string]$Prefix)
        if (-not $Value -or $Value.Length -lt 3) { return }
        if ($keep.ContainsKey($Value.ToLower())) { return }
        if ($pz.Forward.ContainsKey($Value)) { return }
        if (-not $pz.Counters.ContainsKey($Prefix)) { $pz.Counters[$Prefix] = 0 }
        $pz.Counters[$Prefix]++
        $token = "$Prefix-$($pz.Counters[$Prefix])"
        $pz.Forward[$Value] = $token
        $pz.Reverse[$token] = $Value
    }

    # Domain-level names first so they get the lowest, most readable tokens.
    & $add $Snapshot.domain.dnsRoot 'DOMAIN'
    & $add $Snapshot.domain.netbios 'NETBIOS'
    if ($Snapshot.domain.forestName -ne $Snapshot.domain.dnsRoot) { & $add $Snapshot.domain.forestName 'FOREST' }
    foreach ($t in @($Snapshot.trusts | Where-Object { $_ })) { & $add $t.name 'TRUST' }
    foreach ($dc in @($Snapshot.domainControllers | Where-Object { $_ })) { & $add $dc.hostName 'DCHOST'; & $add $dc.name 'DC' }
    foreach ($ca in @($Snapshot.adcs.enrollmentServices | Where-Object { $_ })) { & $add $ca.name 'CA'; & $add $ca.dnsHostName 'HOSTFQDN' }
    foreach ($g in @($Snapshot.gpo.gpos | Where-Object { $_ })) { & $add $g.displayName 'GPO' }
    # GPOs with only scripts, tasks or groups have no security template, so
    # they're not in gpos: take their names from here too. Task names as well.
    foreach ($e in @(@($Snapshot.gpo.execution) + @($Snapshot.gpo.localGroups) | Where-Object { $_ })) { & $add "$($e.gpo)" 'GPO' }
    foreach ($e in @($Snapshot.gpo.execution | Where-Object { $_ })) { if ("$($e.kind)" -match "^scheduled task '(.+)'$") { & $add $Matches[1] 'TASK' } }
    foreach ($c in @($Index.Computers | Where-Object { $_._isDc })) { & $add $c.dnsHostName 'DCHOST'; & $add ($c.samAccountName.TrimEnd('$')) 'DC' }
    foreach ($u in $Index.Users) { & $add ($u.samAccountName.TrimEnd('$')) 'USER' }
    # Stored without the '$'; the pattern keeps it, so "SRV01$" becomes "HOST-1$".
    foreach ($c in @($Index.Computers | Where-Object { -not $_._isDc })) {
        & $add ($c.samAccountName.TrimEnd('$')) 'HOST'
        & $add $c.dnsHostName 'HOSTFQDN'
    }
    # Hosts named in SPNs and delegation targets, even without a computer object.
    foreach ($p in @($Index.Users) + @($Index.Computers)) {
        foreach ($spn in @($p.servicePrincipalNames) + @($p.allowedToDelegateTo)) {
            if (-not $spn) { continue }
            $hostPart = (("$spn" -split '/')[1] -split ':')[0]
            if ($hostPart -and $hostPart -notmatch '\.') { & $add $hostPart 'HOST' }
        }
    }
    foreach ($g in $Index.Groups) { & $add $g.name 'GROUP' }
    foreach ($f in @($Snapshot.domain.fineGrainedPolicies | Where-Object { $_ })) { & $add $f.name 'PSO' }
    foreach ($f in @($Snapshot.foreignPrincipals | Where-Object { $_ })) { & $add $f.name 'FOREIGN' }

    # Longest first, so "adm.rossi.old" is replaced before "adm.rossi".
    $pz.Ordered = @($pz.Forward.Keys | Sort-Object { $_.Length } -Descending)
    # Whole FQDNs go first, before the single names.
    $pz | Add-Member -NotePropertyName DomainSuffixes -NotePropertyValue @(@($Snapshot.domain.dnsRoot, $Snapshot.domain.forestName) + @($Snapshot.trusts | Where-Object { $_ } | ForEach-Object { $_.name }) | Where-Object { $_ } | Select-Object -Unique)
    return $pz
}

function Protect-AiText {
    param($Pz, [string]$Text)
    if (-not $Text) { return $Text }
    $out = $Text
    # Structural identifiers first: whatever they contain is replaced whole.
    $out = [regex]::Replace($out, '\\\\[^\s]+', { param($m) Get-AiToken $Pz $m.Value 'PATH' })
    $out = [regex]::Replace($out, '(?i)\b(?:CN|OU|DC)=[^;|\s][^;|]*?(?=(?:\.\s|;|\||\)|$))', { param($m) Get-AiToken $Pz $m.Value.TrimEnd(',', ' ', '.') 'DN' })
    $out = [regex]::Replace($out, 'S-1-5-21-\d+-\d+-\d+(?:-\d+)?', { param($m) Get-AiToken $Pz $m.Value 'SID' })
    foreach ($suffix in $Pz.DomainSuffixes) {
        $fq = '(?i)(?<![\w.\-])(?:[a-z0-9\-_]+\.)+' + [regex]::Escape($suffix) + '(?![\w\-])'
        $out = [regex]::Replace($out, $fq, { param($m) if ($Pz.Forward.ContainsKey($m.Value)) { $Pz.Forward[$m.Value] } else { Get-AiToken $Pz $m.Value 'HOSTFQDN' } })
    }
    foreach ($k in $Pz.Ordered) {
        $pattern = '(?<![\w.\-$])' + [regex]::Escape($k) + '(\$?)(?![\w\-$]|\.[\w])'
        $out = [regex]::Replace($out, $pattern, ($Pz.Forward[$k] + '$1'), 'IgnoreCase')
    }
    return $out
}

function Get-AiToken {
    param($Pz, [string]$Value, [string]$Prefix)
    if ($Pz.Forward.ContainsKey($Value)) { return $Pz.Forward[$Value] }
    if (-not $Pz.Counters.ContainsKey($Prefix)) { $Pz.Counters[$Prefix] = 0 }
    $Pz.Counters[$Prefix]++
    $token = "$Prefix-$($Pz.Counters[$Prefix])"
    $Pz.Forward[$Value] = $token
    $Pz.Reverse[$token] = $Value
    return $token
}

function Unprotect-AiText {
    param($Pz, [string]$Text)
    if (-not $Text) { return $Text }
    # Any PREFIX-n the map knows, AD or Entra (UPN-3, APP-2, CAPOLICY-1...); \b keeps HOST-12
    # whole. Anything else that looks like one (CVE-2025, a model's typo) is left alone.
    return [regex]::Replace($Text, '\b[A-Z][A-Z0-9]*-\d+\b', {
            param($m)
            if ($Pz.Reverse.ContainsKey($m.Value)) { return $Pz.Reverse[$m.Value] }
            return $m.Value
        })
}

# Last check before sending: if any real identifier survived, refuse.
function Test-AiLeak {
    param($Pz, [string]$Text)
    $leaks = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Pz.Ordered) {
        if ($k.Length -lt 4) { continue }
        if ([regex]::IsMatch($Text, '(?<![\w.\-@$])' + [regex]::Escape($k) + '\$?(?![\w\-$]|\.[\w])', 'IgnoreCase')) { $leaks.Add($k) }
        if ($leaks.Count -ge 10) { break }
    }
    if ($Text -match 'S-1-5-21-\d+-\d+-\d+') { $leaks.Add('(domain SID)') }
    foreach ($suffix in $Pz.DomainSuffixes) { if ($Text.IndexOf($suffix, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $leaks.Add($suffix) } }
    return $leaks
}

# --------------------------------------------------------------------------
# Prompt
# --------------------------------------------------------------------------
# Two variants of the same instructions. The full one has the model reason like an attacker
# (every foothold, every combination), then try to break its own chains, then plan the defence
# from what survived. If Gemini refuses it (a safety block), the defensive one is sent instead,
# once: same output, no adversary wording. The output never holds exploitation steps either way.
$script:AiMethodFull = @'
How to work (internally; output only the JSON object described below):
A. Adversary pass. Think like a skilled intruder. For each realistic
   foothold (unauthenticated on the network; any domain user or any tenant
   user; a guest; a specific account, group or application token that the
   findings name), look for the shortest and the most reliable ways to reach
   full control, combining findings across categories. Look for the
   non-obvious combinations as well as the textbook ones: a Low or Medium
   finding is often the missing link of a critical chain. Judge each finding
   by what it gives an intruder, not by its severity label.
B. Verification pass. Then try to break every chain you found. For each
   link, decide whether a finding in the input shows it ("shown") or whether
   it depends on something the input does not show ("assumed": a patch
   level, network reachability, a weak password, an account actually in
   use). A check listed under "Not evaluated" is unknown: never clean, never
   shown. Drop a chain when a link contradicts the input (a disabled account,
   a right on a different object, a setting the findings say is fine). Keep
   a chain whose only weakness is an assumed link, with lower confidence.
   Remember the strongest chains you dropped, and why.
C. Defender pass. Derive everything else (summary, triage, plan, quick
   wins, monitoring) from the chains that survived: the change that breaks
   the most surviving chains, and the most likely ones, comes first.
'@

$script:AiMethodDefensive = @'
How to work (internally; output only the JSON object described below):
A. Combination review. For each kind of starting access (none, any domain
   or tenant user, a guest, a specific account, group or application token
   that the findings name), work out which findings, taken together, would
   let that access grow into full control of the directory, including
   combinations across categories. A Low or Medium finding can complete a
   critical combination.
B. Evidence review. For each step of each combination, decide whether a
   finding in the input shows it ("shown") or whether it depends on
   something the input does not show ("assumed": a patch level, network
   reachability, a weak password, an account actually in use). A check
   listed under "Not evaluated" is unknown: never clean, never shown. Drop a
   combination when a step contradicts the input; keep one whose only
   weakness is an assumed step, with lower confidence. Remember the
   strongest combinations you dropped, and why.
C. Planning. Derive everything else (summary, triage, plan, quick wins,
   monitoring) from the combinations that remain: the change that breaks the
   most of them, and the most likely ones, comes first.
'@

$script:AiSystemPromptTemplate = @'
You are an identity security analyst working for the defenders who own
this Active Directory domain or Microsoft Entra ID tenant (the input says
which). You receive deterministic hygiene findings already computed by a
local tool from a read-only snapshot. Treat them as established facts: do
not recompute, dispute or add findings that are not in the input. When the
input lists checks as "Not evaluated", the tool could not collect their
data: treat them as unknown.

Identifiers were replaced by placeholder tokens (USER-3, HOST-7, GROUP-2,
DOMAIN-1, DN-4, SID-1, PATH-1, UPN-2, APP-1, SP-4...). Always refer to
objects by their token exactly as written; never guess the real name.
Well-known built-in names (Administrator, krbtgt, Domain Admins...) are left
as is.

{{METHOD}}
Your output is for defenders. Describe WHAT grants control and WHERE to
break it, in terms of impact and business consequence. Never write HOW to
exploit it: no commands, tool names, payloads or step-by-step attack
procedures.

Produce:
1. executive_summary: 4-6 sentences for management. Overall posture, the
   two or three exposures that matter most and why, in plain language.
2. remediation_plan: an ordered list of work packages. Group related
   checks that share an owner or a change window (for example all
   Kerberos service-account items). Order by risk reduction per unit of
   effort: what breaks the surviving chains to full control first, then
   credential exposure, then hygiene. Each item: title, the check ids it
   covers, affected object tokens (at most 8), why this position in the
   order (name the chains it breaks), effort (low | medium | high), and
   operational caveats (what can break, what to test first). Do NOT number
   the items yourself.
3. quick_wins: up to 5 changes that are low effort and low disruption.
4. monitoring: for exposures that cannot be fixed immediately, what to
   monitor meanwhile: relevant Windows Security event IDs (or, for Entra,
   the sign-in and audit log activity) and a short description of the
   detection logic for a SIEM. Only reference event IDs you are confident
   exist and apply.
5. comparison_narrative: only if a "Comparison" section is present,
   2-4 sentences on the trend (real progress vs churn). Omit otherwise.
6. attack_paths: using the "Attack surface toward Tier 0" section as the
   only source, describe up to 6 of the most important escalation paths.
   For each: a short title, the severity, an ordered list of steps naming
   the object tokens and the technique at each hop toward Tier 0, and a one
   or two sentence narrative of the business impact and where to break the
   chain. When the input has no such section, return an empty list.
7. remediation_scripts: for the check ids where a safe, standard fix can be
   expressed as PowerShell, give a snippet. Each: the check id, a short
   PowerShell block using native cmdlets (use the object tokens as
   placeholders the operator will substitute), and caveats. Only for changes
   that are routine and reversible; for anything destructive or
   environment-specific, return guidance in caveats and keep the script
   minimal or empty. Never include credential theft or offensive code.
8. triage: re-rank the fired checks by real exploitability in THIS
   environment (the surviving chains, reachability, privilege of the
   affected objects), not by static severity alone. Each: a rank (1 = fix
   first), the check ids, the key object tokens, and a one sentence
   rationale.
9. known_exploitation: which fired checks match attack vectors used in
   publicly reported attacks or published research of roughly the last
   three years. Start from the "Recent attack vectors" section of the input
   (the local tool's own list); add another fired check only if you are
   confident it belongs. Each: the check ids, the vector, what is publicly
   known (name a campaign, threat actor or CVE only when you are sure of it;
   otherwise say it is widely reported in intrusions), and why it matters
   here (which objects or conditions in the findings). Never invent
   incidents, dates or CVE numbers.
10. compromise_assessment: can the findings be chained into full
   compromise (Domain Admin or equivalent control of the domain; for an
   Entra tenant, Global Administrator or equivalent)? Unlike attack_paths,
   combine any findings (for example coercion, a relay target and a
   certificate template). Give: verdict (likely | possible | unlikely), a
   2-3 sentence summary, and up to 4 chains, most likely first. Each chain:
   - title;
   - starting_point: the access needed for THAT chain (unauthenticated on
     the network, any domain user, any tenant user, a guest, or a specific
     token when the chain starts from an object that is not open to
     everyone, such as a principal that already holds a right);
   - confidence: high (every link shown), medium (one assumed link),
     low (more than one);
   - links: the ordered links, each with the check id, the object tokens,
     what the link gives (the control gained at that step), evidence
     (shown | assumed) and, for an assumed link, the assumption that must
     hold;
   - break_point: the single check whose fix breaks the chain most
     cheaply, and why;
   - checks and objects: the check ids in order and the key object tokens;
   - narrative: the impact in two or three sentences.
   The top-level starting_point is the least access among all the chains;
   never say "any domain user" there when every chain starts from a
   specific account.
11. rejected_chains: up to 4 of the strongest chains you considered and
   dropped in the verification pass. Each: title, the check ids, and the
   reason (which link the input contradicts).
12. verify_next: up to 6 things a defender should check by hand to confirm
   or rule out an assumed link (a patch level, whether a port is reachable,
   whether an account is still used). Each: the question and the check ids
   it concerns.

If no findings are provided, say so plainly and return empty lists.

Respond with one JSON object only, no markdown fences:
{ "executive_summary": "...",
  "remediation_plan": [ { "title": "...", "checks": ["..."], "objects": ["..."],
      "rationale": "...", "effort": "low|medium|high", "caveats": "..." } ],
  "quick_wins": ["..."],
  "monitoring": [ { "checks": ["..."], "event_ids": ["4769"], "guidance": "..." } ],
  "comparison_narrative": "...",
  "attack_paths": [ { "title": "...", "severity": "Critical|High|Medium|Low",
      "steps": ["TOKEN -> technique", "..."], "narrative": "..." } ],
  "remediation_scripts": [ { "check": "...", "powershell": "...", "caveats": "..." } ],
  "triage": [ { "rank": 1, "checks": ["..."], "objects": ["..."], "rationale": "..." } ],
  "known_exploitation": [ { "checks": ["..."], "vector": "...", "public": "...", "relevance": "..." } ],
  "compromise_assessment": { "verdict": "likely|possible|unlikely", "starting_point": "...", "summary": "...",
      "chains": [ { "title": "...", "starting_point": "...", "confidence": "high|medium|low",
          "links": [ { "check": "...", "objects": ["..."], "gives": "...", "evidence": "shown|assumed", "assumption": "..." } ],
          "break_point": { "check": "...", "why": "..." },
          "checks": ["..."], "objects": ["..."], "narrative": "..." } ] },
  "rejected_chains": [ { "title": "...", "checks": ["..."], "reason": "..." } ],
  "verify_next": [ { "question": "...", "checks": ["..."] } ] }
'@

$script:AiSystemPrompt = $script:AiSystemPromptTemplate.Replace('{{METHOD}}', $script:AiMethodFull)
$script:AiSystemPromptDefensive = $script:AiSystemPromptTemplate.Replace('{{METHOD}}', $script:AiMethodDefensive)

# One line per fired check that is in $script:RecentAttackVectors (Reporting.ps1), in list order.
function Get-AiRecentVectorLines {
    param($Findings)
    $fired = @{}; foreach ($f in @($Findings | Where-Object { $_ })) { $fired["$($f.Type)"] = $true }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in $script:RecentAttackVectors.Keys) { if ($fired.ContainsKey($k)) { $out.Add("- ${k}: $($script:RecentAttackVectors[$k])") } }
    if ($out.Count -gt 0) {
        $out.Insert(0, 'Recent attack vectors (fired checks that the local tool links to attacks seen in public incidents or research; start known_exploitation from these):')
        $out.Insert(0, '')
    }
    return , $out.ToArray()
}

# The checks the tool could not evaluate, in catalog order: without them the model would read a
# missing finding as a clean link. Titles only; they name no object.
function Get-AiNotEvaluatedLines {
    param($NotEvaluated, $Catalog)
    $types = @(@($NotEvaluated) | Where-Object { $_ -and $_.Type } | ForEach-Object { "$($_.Type)" } | Select-Object -Unique)
    if ($types.Count -eq 0) { return , @() }
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('')
    $out.Add('Not evaluated (data the tool could not collect; unknown, never clean):')
    foreach ($t in @($types | Sort-Object { Get-CheckPosition $_ }, { $_ })) {
        $title = if ($Catalog -and $Catalog.Contains($t)) { $Catalog[$t].Title } else { '' }
        $out.Add("- ${t}$(if ($title) { ": $title" })")
    }
    return , $out.ToArray()
}

function New-AiPrompt {
    param($Findings, $Pz, $Snapshot, $Score, $Comparison, $NotEvaluated, [int]$MaxObjectsPerCheck = 12)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Domain: $(Protect-AiText $Pz $Snapshot.domain.dnsRoot). Functional level: $($Snapshot.domain.domainMode). Hygiene score: $(if ($Score.Reliable -eq $false) { "not reliable, only $($Score.Coverage)% of the checks were evaluated" } else { "$($Score.Score)/100" }).")
    $lines.Add("Counts: users $(@($Snapshot.users).Count), computers $(@($Snapshot.computers).Count), domain controllers $(@($Snapshot.domainControllers).Count).")
    $lines.Add('')
    $lines.Add('Findings grouped by check (severity, check id, title, affected objects):')
    $groups = $Findings | Group-Object Type | Sort-Object { - ($_.Group | ForEach-Object { $script:SeverityRank[$_.Severity] } | Measure-Object -Maximum).Maximum }, Count, { Get-CheckPosition $_.Name }
    foreach ($g in $groups) {
        $meta = $script:CheckCatalog[$g.Name]
        $worst = ($g.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
        $lines.Add("## [$worst] $($g.Name): $($meta.Title) ($($g.Count) object(s))")
        # Worst first, otherwise the (already fixed) input order: Sort-Object on PS 5.1 isn't stable.
        $bySev = @(foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $g.Group | Where-Object { $_.Severity -eq $s } })
        foreach ($f in ($bySev | Select-Object -First $MaxObjectsPerCheck)) {
            $lines.Add("- [$($f.Severity)] $(Protect-AiText $Pz $f.Object): $(Protect-AiText $Pz $f.Detail)")
        }
        if ($g.Count -gt $MaxObjectsPerCheck) { $lines.Add("- ... and $($g.Count - $MaxObjectsPerCheck) more object(s) with the same issue") }
    }
    if (Get-Command Get-AttackPathLines -ErrorAction SilentlyContinue) {
        $pathLines = @(Get-AttackPathLines -Findings $Findings -Pz $Pz)
        if ($pathLines.Count -gt 0) {
            $lines.Add('')
            $lines.Add('Attack surface toward Tier 0 (source object, then technique; use ONLY these for attack_paths):')
            foreach ($pl in $pathLines) { $lines.Add($pl) }
        }
    }
    foreach ($vl in (Get-AiRecentVectorLines -Findings $Findings)) { $lines.Add($vl) }
    foreach ($nl in (Get-AiNotEvaluatedLines -NotEvaluated $NotEvaluated -Catalog $script:CheckCatalog)) { $lines.Add($nl) }
    if ($Comparison -and (@($Comparison.New).Count + @($Comparison.Resolved).Count) -gt 0) {
        $lines.Add('')
        $lines.Add('Comparison with the previous run (already computed):')
        foreach ($f in @($Comparison.New | Select-Object -First 30)) { $lines.Add("- NEW [$($f.Severity)] $($f.Type): $(Protect-AiText $Pz $f.Object)") }
        foreach ($f in @($Comparison.Resolved | Select-Object -First 30)) { $lines.Add("- RESOLVED [$($f.Severity)] $($f.Type): $(Protect-AiText $Pz $f.Object)") }
        $lines.Add("- Still present: $(@($Comparison.Persisting).Count)")
    }
    return ($lines -join "`n")
}

# The same text that goes into the request: the instructions, then the input. Used by the dry
# run and by the copy kept before a real send. Self-contained on purpose: pasted whole into
# another provider's chat it works as one message, and the reply is the same JSON.
$script:AiInputMarker = '=== INPUT (computed locally by IDWolf; tokens stand for real names) ==='
function Get-AiPasteText {
    param([string]$UserPrompt, [string]$SystemPrompt = $script:AiSystemPrompt)
    return "$($SystemPrompt.TrimEnd())`n`n$script:AiInputMarker`n$UserPrompt`n"
}
function Write-AiPromptFile {
    param([string]$Path, [string]$UserPrompt, [string]$SystemPrompt = $script:AiSystemPrompt)
    [System.IO.File]::WriteAllText($Path, (Get-AiPasteText -UserPrompt $UserPrompt -SystemPrompt $SystemPrompt), (New-Object System.Text.UTF8Encoding($false)))
}

# report_x.html -> report_x_ai_prompt.txt, in the same folder.
function Get-AiSidecarPath {
    param([string]$ReportPath, [string]$Suffix)
    $dir = [System.IO.Path]::GetDirectoryName($ReportPath)
    Join-Path $dir ([System.IO.Path]::GetFileNameWithoutExtension($ReportPath) + $Suffix)
}

# What came back, before the tokens are swapped back to real names.
function Write-AiResponseFile {
    param([string]$Path, $Raw)
    [System.IO.File]::WriteAllText($Path, ($Raw | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
}

# --------------------------------------------------------------------------
# Talking to Gemini: HttpClient, a spinner, retries with backoff.
# --------------------------------------------------------------------------
function Invoke-HttpPostWithSpinner {
    param([string]$Uri, [string]$JsonBody, [string]$Message = "Contacting Gemini", [int]$TimeoutSeconds = 180, [hashtable]$Headers = @{})
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    # Windows PowerShell 5.1 on an older .NET offers only TLS 1.0 by default; Google needs TLS 1.2 or newer.
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    foreach ($h in $Headers.Keys) { [void]$client.DefaultRequestHeaders.Add($h, $Headers[$h]) }
    $content = New-Object System.Net.Http.StringContent($JsonBody, [System.Text.Encoding]::UTF8, 'application/json')
    try {
        $task = $client.PostAsync($Uri, $content)
        $spin = @('|', '/', '-', '\'); $i = 0
        while (-not $task.IsCompleted) { Write-Host -NoNewline "`r$Message $($spin[$i % 4])  "; Start-Sleep -Milliseconds 120; $i++ }
        Write-Host "`r$Message... $(if ($task.IsFaulted) { 'failed.' } elseif ($task.IsCanceled) { 'timed out.' } else { 'done.' })          "
        $resp = $task.GetAwaiter().GetResult()
        return [PSCustomObject]@{ StatusCode = [int]$resp.StatusCode; IsSuccess = $resp.IsSuccessStatusCode; Body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
    }
    finally { $client.Dispose() }
}

# Asks for the Gemini key when there is none. The typing is hidden and the key is only kept for this run
# (nothing is written to disk or to the environment). Empty answer, or no console to ask on: returns ''.
function Request-GeminiApiKey {
    $redirected = $true; try { $redirected = [Console]::IsInputRedirected } catch { }
    if ($redirected) { return '' }
    Write-Host 'No Gemini API key found (-ApiKey / GEMINI_API_KEY).' -ForegroundColor Yellow
    $secure = Read-Host 'Paste your Gemini API key (hidden, kept for this run only), or Enter to skip' -AsSecureString
    if (-not $secure -or $secure.Length -eq 0) { return '' }
    return (New-Object System.Net.NetworkCredential('', $secure)).Password.Trim()
}

# MaxAttempts 0 keeps trying until it works (Ctrl+C to stop). Only timeouts,
# 429 and 5xx are retried; a 400/401/403 won't fix itself.
function Invoke-GeminiAnalysis {
    param([string]$UserPrompt, [string]$ApiKey, [string]$Model, [int]$MaxAttempts = 3, [int]$TimeoutSeconds = 180, [string]$SystemPrompt = $script:AiSystemPrompt)
    $script:AiLastBlocked = $false
    $unlimited = $MaxAttempts -le 0
    $ofText = if ($unlimited) { '' } else { "/$MaxAttempts" }
    $canRetry = { param($n) $unlimited -or $n -lt $MaxAttempts }
    # Wait 2, 4, 8... seconds, at most a minute.
    $backoff = { param($n) [int][Math]::Min(60, [Math]::Pow(2, [Math]::Min($n, 6))) }
    $body = @{
        system_instruction = @{ parts = @(@{ text = $SystemPrompt }) }
        contents           = @(@{ role = 'user'; parts = @(@{ text = $UserPrompt }) })
        # No temperature: Gemini 3 reasons best at its default (1.0); Google warns that lower values
        # can make it loop. Thinking is left at the model's default, high on Gemini 3.
        generationConfig   = @{ responseMimeType = 'application/json' }
    } | ConvertTo-Json -Depth 10
    # Key in a header, not the URL, so it stays out of proxy logs.
    # IDWOLF_GEMINI_BASEURL points at an internal gateway (or the test endpoint).
    $base = if ($env:IDWOLF_GEMINI_BASEURL) { $env:IDWOLF_GEMINI_BASEURL.TrimEnd('/') } else { 'https://generativelanguage.googleapis.com' }
    $uri = "$base/v1beta/models/${Model}:generateContent"
    $transient = @(429, 500, 502, 503, 504)
    $result = $null
    for ($attempt = 1; $unlimited -or $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = Invoke-HttpPostWithSpinner -Uri $uri -JsonBody $body -Headers @{ 'x-goog-api-key' = $ApiKey } -Message "Contacting Gemini (attempt $attempt$ofText)" -TimeoutSeconds $TimeoutSeconds
        }
        catch {
            $inner = $_.Exception; $isTimeout = $false
            while ($inner) { if ($inner -is [System.Threading.Tasks.TaskCanceledException] -or $inner -is [TimeoutException]) { $isTimeout = $true; break }; $inner = $inner.InnerException }
            if ($isTimeout -and (& $canRetry $attempt)) {
                $wait = & $backoff $attempt
                Write-Host "Gemini timed out after $TimeoutSeconds s, retrying in $wait s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $wait; continue
            }
            # The outer message of a failed request is always "An error occurred while sending the request":
            # the useful part (TLS, DNS, proxy, refused) is in the exceptions inside it.
            $chain = @(); $e = $_.Exception
            while ($e) { $m = "$($e.Message)".Trim(); if ($m -and $chain -notcontains $m) { $chain += $m }; $e = $e.InnerException }
            # The first one is only PowerShell's 'Exception calling GetResult' wrapper.
            if ($chain.Count -gt 1) { $chain = @($chain[1..($chain.Count - 1)]) }
            Write-Host "ERROR: Gemini call failed: $($chain -join ' -> ')" -ForegroundColor Red
            # This catch is only reached when no HTTP answer came back at all (an HTTP error is handled below),
            # whatever language the messages are in.
            $hostName = try { ([uri]$uri).Host } catch { 'generativelanguage.googleapis.com' }
            Write-Host "No answer from $hostName. Check: Test-NetConnection $hostName -Port 443 (firewall, proxy, no internet on a lab VM)," -ForegroundColor Yellow
            Write-Host "TLS 1.2 on this Windows, and a proxy that needs credentials. Nothing was sent; the deterministic report is complete." -ForegroundColor Yellow
            return $null
        }
        if ($result.IsSuccess) { break }
        if ($transient -contains $result.StatusCode -and (& $canRetry $attempt)) {
            $wait = & $backoff $attempt
            Write-Host "Gemini HTTP $($result.StatusCode), retrying in $wait s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $wait; $result = $null; continue
        }
        Write-Host "ERROR: Gemini call failed: HTTP $($result.StatusCode). $($result.Body)" -ForegroundColor Red
        if ($result.StatusCode -eq 503) { Write-Host "The model is overloaded. A smaller one often gets through: run again with -Model gemini-3.5-flash-lite (see ai.google.dev/gemini-api/docs/models)." -ForegroundColor Yellow }
        return $null
    }
    if (-not $result) { return $null }
    try { $resp = $result.Body | ConvertFrom-Json } catch { Write-Host 'ERROR: Gemini response is not valid JSON.' -ForegroundColor Red; return $null }
    $reply = Get-GeminiReplyText $resp
    if ($script:AiBlockReasons -contains $reply.FinishReason) {
        $script:AiLastBlocked = $true
        Write-Host "Gemini refused the request ($($reply.FinishReason))." -ForegroundColor Yellow
        return $null
    }
    $raw =($reply.Text -replace '^\s*```(?:json)?', '') -replace '```\s*$', ''
    try { return ($raw | ConvertFrom-Json) }
    catch {
        Write-Host "ERROR: model did not return clean JSON (finishReason: $(if ($reply.FinishReason) { $reply.FinishReason } else { 'none' })):`n$raw" -ForegroundColor Red
        if ($reply.FinishReason -eq 'MAX_TOKENS') { Write-Host "The reply hit the model's output-token limit and was cut off. Run again, or try another model with -Model." -ForegroundColor Yellow }
        elseif ($reply.FinishReason -and $reply.FinishReason -ne 'STOP') { Write-Host "Gemini stopped the reply early ($($reply.FinishReason)). Run again, or try another model with -Model." -ForegroundColor Yellow }
        return $null
    }
}

# Why Gemini stops a reply on safety grounds (candidate finishReason) or refuses the prompt
# (promptFeedback.blockReason, which Get-GeminiReplyText returns as FinishReason).
$script:AiBlockReasons = @('SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII', 'OTHER')
$script:AiLastBlocked = $false

# The full instructions first; if Gemini refuses them, the defensive variant once. The variant
# actually sent is saved next to the report too, so the prompt file always matches what went out.
function Invoke-AiAnalysisWithFallback {
    param([string]$UserPrompt, [string]$ApiKey, [string]$Model, [int]$MaxAttempts = 3, [string]$ReportPath = '')
    $raw = Invoke-GeminiAnalysis -UserPrompt $UserPrompt -ApiKey $ApiKey -Model $Model -MaxAttempts $MaxAttempts -SystemPrompt $script:AiSystemPrompt
    if ($raw -or -not $script:AiLastBlocked) { return [PSCustomObject]@{ Raw = $raw; Variant = 'full' } }
    Write-Host 'Retrying once with the defensive-only instructions (no adversary pass; same output format).' -ForegroundColor Yellow
    if ($ReportPath) {
        $alt = Get-AiSidecarPath $ReportPath '_ai_prompt_defensive.txt'
        Write-AiPromptFile -Path $alt -UserPrompt $UserPrompt -SystemPrompt $script:AiSystemPromptDefensive
        Write-Host "Defensive prompt kept at $alt"
    }
    $raw = Invoke-GeminiAnalysis -UserPrompt $UserPrompt -ApiKey $ApiKey -Model $Model -MaxAttempts $MaxAttempts -SystemPrompt $script:AiSystemPromptDefensive
    if (-not $raw -and $script:AiLastBlocked) { Write-Host 'Gemini refused the defensive variant too. The deterministic report is complete; the prompt file can be pasted into another model.' -ForegroundColor Yellow }
    return [PSCustomObject]@{ Raw = $raw; Variant = 'defensive' }
}

# The reply text of the first candidate. Thinking models can split it over several
# parts (and add thought parts when asked to), so join every non-thought text part.
function Get-GeminiReplyText {
    param($Response)
    $cand = @($Response.candidates | Where-Object { $_ }) | Select-Object -First 1
    if (-not $cand) { return [PSCustomObject]@{ Text = ''; FinishReason = "$($Response.promptFeedback.blockReason)" } }
    $text = (@($cand.content.parts | Where-Object { $_ -and -not $_.thought -and $null -ne $_.text }) | ForEach-Object { "$($_.text)" }) -join ''
    return [PSCustomObject]@{ Text = $text; FinishReason = "$($cand.finishReason)" }
}

# --------------------------------------------------------------------------
# Put the real names back and drop anything about a check that didn't fire:
# the model can't invent findings.
# --------------------------------------------------------------------------
function ConvertFrom-AiResponse {
    param($Raw, $Pz, $Findings, [string]$Model, [string]$Variant = 'full')
    $valid = @{}; foreach ($f in $Findings) { $valid[$f.Type] = $true }
    $u = { param($t) Unprotect-AiText $Pz "$t" }
    $plan = @()
    foreach ($item in @($Raw.remediation_plan | Where-Object { $_ })) {
        $checks = @($item.checks | Where-Object { $valid.ContainsKey("$_") })
        if ($checks.Count -eq 0) { continue }
        $effort = "$($item.effort)".ToLower(); if (@('low', 'medium', 'high') -notcontains $effort) { $effort = '' }
        $plan += [PSCustomObject]@{
            Title     = & $u ($item.title -replace '^\s*\d+[\.\)]\s*', '')
            Checks    = $checks
            Objects   = @($item.objects | Where-Object { $_ } | Select-Object -First 8 | ForEach-Object { & $u $_ })
            Rationale = & $u $item.rationale
            Effort    = $effort
            Caveats   = & $u $item.caveats
        }
    }
    $monitoring = @()
    foreach ($m in @($Raw.monitoring | Where-Object { $_ })) {
        $monitoring += [PSCustomObject]@{
            Checks   = @($m.checks | Where-Object { $valid.ContainsKey("$_") })
            EventIds = @($m.event_ids | Where-Object { "$_" -match '^\d{3,5}$' } | ForEach-Object { "$_" })
            Guidance = & $u $m.guidance
        }
    }
    $attackPaths = @()
    foreach ($ap in @($Raw.attack_paths | Where-Object { $_ })) {
        $steps = @($ap.steps | Where-Object { $_ } | Select-Object -First 12 | ForEach-Object { & $u $_ })
        if ($steps.Count -eq 0 -and -not $ap.narrative) { continue }
        $sev = "$($ap.severity)"; if (@('Critical', 'High', 'Medium', 'Low') -notcontains $sev) { $sev = '' }
        $attackPaths += [PSCustomObject]@{ Title = & $u $ap.title; Severity = $sev; Steps = $steps; Narrative = & $u $ap.narrative }
    }
    $remScripts = @()
    foreach ($rs in @($Raw.remediation_scripts | Where-Object { $_ })) {
        $chk = "$($rs.check)"
        if (-not $valid.ContainsKey($chk)) { continue }
        $ps = & $u $rs.powershell
        if (-not $ps -and -not $rs.caveats) { continue }
        $remScripts += [PSCustomObject]@{ Check = $chk; PowerShell = $ps; Caveats = & $u $rs.caveats }
    }
    $triage = @()
    foreach ($tr in @($Raw.triage | Where-Object { $_ })) {
        $checks = @($tr.checks | Where-Object { $valid.ContainsKey("$_") })
        if ($checks.Count -eq 0) { continue }
        $rank = 0; try { $rank = [int]$tr.rank } catch { $rank = 0 }
        $triage += [PSCustomObject]@{
            Rank      = $rank
            Checks    = $checks
            Objects   = @($tr.objects | Where-Object { $_ } | Select-Object -First 8 | ForEach-Object { & $u $_ })
            Rationale = & $u $tr.rationale
        }
    }
    $triage = @($triage | Sort-Object { if ($_.Rank -gt 0) { $_.Rank } else { 9999 } })
    $known = @()
    foreach ($ke in @($Raw.known_exploitation | Where-Object { $_ })) {
        $checks = @($ke.checks | Where-Object { $valid.ContainsKey("$_") })
        if ($checks.Count -eq 0) { continue }
        $known += [PSCustomObject]@{ Checks = $checks; Vector = & $u $ke.vector; Public = & $u $ke.public; Relevance = & $u $ke.relevance }
    }
    $compromise = $null
    $ca = $Raw.compromise_assessment
    if ($ca) {
        $verdict = "$($ca.verdict)".ToLower(); if (@('likely', 'possible', 'unlikely') -notcontains $verdict) { $verdict = '' }
        $chains = @()
        foreach ($ch in @($ca.chains | Where-Object { $_ })) {
            $checks = @($ch.checks | Where-Object { $valid.ContainsKey("$_") })
            if ($checks.Count -eq 0) { continue }
            # Checked here, not trusted: a link can only be "shown" by a check that fired, and a
            # chain is "high" only when every link is shown.
            $links = @()
            foreach ($l in @($ch.links | Where-Object { $_ } | Select-Object -First 10)) {
                $lc = "$($l.check)"
                $ev = "$($l.evidence)".ToLower(); if (@('shown', 'assumed') -notcontains $ev) { $ev = 'assumed' }
                if ($lc -and -not $valid.ContainsKey($lc)) { $lc = ''; $ev = 'assumed' }
                if (-not $lc -and $ev -eq 'shown') { $ev = 'assumed' }
                $links += [PSCustomObject]@{
                    Check      = $lc
                    Objects    = @($l.objects | Where-Object { $_ } | Select-Object -First 4 | ForEach-Object { & $u $_ })
                    Gives      = & $u $l.gives
                    Evidence   = $ev
                    Assumption = & $u $l.assumption
                }
            }
            $conf = "$($ch.confidence)".ToLower(); if (@('high', 'medium', 'low') -notcontains $conf) { $conf = '' }
            $assumed = @($links | Where-Object { $_.Evidence -eq 'assumed' }).Count
            if ($links.Count -and $assumed -gt 0 -and $conf -eq 'high') { $conf = $(if ($assumed -eq 1) { 'medium' } else { 'low' }) }
            $bp = $null
            if ($ch.break_point -and $valid.ContainsKey("$($ch.break_point.check)")) { $bp = [PSCustomObject]@{ Check = "$($ch.break_point.check)"; Why = & $u $ch.break_point.why } }
            $chains += [PSCustomObject]@{
                Title     = & $u $ch.title
                StartingPoint = & $u $ch.starting_point
                Confidence = $conf
                Links     = $links
                BreakPoint = $bp
                Checks    = $checks
                Objects   = @($ch.objects | Where-Object { $_ } | Select-Object -First 8 | ForEach-Object { & $u $_ })
                Narrative = & $u $ch.narrative
            }
        }
        if ($verdict -or $ca.summary -or $chains.Count) {
            $compromise = [PSCustomObject]@{ Verdict = $verdict; StartingPoint = & $u $ca.starting_point; Summary = & $u $ca.summary; Chains = @($chains | Select-Object -First 4) }
        }
    }

    $rejected = @()
    foreach ($rc in @($Raw.rejected_chains | Where-Object { $_ } | Select-Object -First 4)) {
        if (-not $rc.title -and -not $rc.reason) { continue }
        $rejected += [PSCustomObject]@{ Title = & $u $rc.title; Checks = @($rc.checks | Where-Object { $valid.ContainsKey("$_") }); Reason = & $u $rc.reason }
    }
    $verify = @()
    foreach ($v in @($Raw.verify_next | Where-Object { $_ } | Select-Object -First 6)) {
        if (-not $v.question) { continue }
        $verify += [PSCustomObject]@{ Question = & $u $v.question; Checks = @($v.checks | Where-Object { $valid.ContainsKey("$_") }) }
    }

    return [PSCustomObject]@{
        Model               = $Model
        Variant             = $Variant
        RejectedChains      = $rejected
        VerifyNext          = $verify
        ExecutiveSummary    = & $u $Raw.executive_summary
        RemediationPlan     = $plan
        QuickWins           = @($Raw.quick_wins | Where-Object { $_ } | Select-Object -First 5 | ForEach-Object { & $u $_ })
        Monitoring          = $monitoring
        ComparisonNarrative = if ($Raw.comparison_narrative) { & $u $Raw.comparison_narrative } else { '' }
        AttackPaths         = $attackPaths
        RemediationScripts  = $remScripts
        Triage              = $triage
        KnownExploitation   = $known
        CompromiseAssessment = $compromise
        MaskedIdentifiers   = $Pz.Reverse.Count
    }
}

function ConvertTo-AiSectionHtml {
    param($AiResult)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    # Collapsible like the attack map: open by default, at the top of the dashboard.
    # HTML entity, not a literal emoji: PS 5.1 reads these BOM-less files as ANSI.
    & $w "<details open class='ai-details'><summary><h2><span class='ai-robot' role='img' aria-label='AI' style='margin-right:8px'>&#x1F916;</span>AI summary and remediation plan</h2></summary>"
    & $w "<div class='ai-section'><div class='ai-badge'>AI-assisted &middot; $(& $H $AiResult.Model) &middot; $($AiResult.MaskedIdentifiers) identifiers pseudonymized before sending$(if ($AiResult.Variant -eq 'defensive') { ' &middot; defensive-only instructions (the full prompt was refused)' })</div>"
    & $w "<p>$(& $H $AiResult.ExecutiveSummary)</p>"
    $cmp = $AiResult.CompromiseAssessment
    if ($cmp) {
        & $w '<h3>Can the findings be chained into full compromise?</h3>'
        $facts = @()
        if ($cmp.Verdict) { $facts += "<b>Verdict: $(& $H $cmp.Verdict)</b>" }
        if ($cmp.StartingPoint) { $facts += "least access needed: $(& $H $cmp.StartingPoint)" }
        if ($facts.Count) { & $w "<p>$($facts -join ' &middot; ')</p>" }
        if ($cmp.Summary) { & $w "<p>$(& $H $cmp.Summary)</p>" }
        foreach ($c in @($cmp.Chains)) {
            $objs = if (@($c.Objects).Count -gt 0) { "<br><span class='meta'>Objects: $(& $H ($c.Objects -join ', '))</span>" } else { '' }
            $from = if ($c.StartingPoint) { " <span class='check-id'>from: $(& $H $c.StartingPoint)</span>" } else { '' }
            $conf = if ($c.Confidence) { " <span class='check-id'>confidence: $(& $H $c.Confidence)</span>" } else { '' }
            & $w "<div style='margin:10px 0'><b>$(& $H $c.Title)</b>$from$conf<div class='meta' style='margin:4px 0'>$((@($c.Checks) | ForEach-Object { "<code>$_</code>" }) -join ' &rarr; ')</div><div>$(& $H $c.Narrative)</div>$objs"
            if (@($c.Links).Count -gt 0) {
                & $w "<ol class='meta' style='margin:6px 0 0 18px'>"
                foreach ($l in @($c.Links)) {
                    $chk = if ($l.Check) { "<code>$(& $H $l.Check)</code> " } else { '' }
                    $lo = if (@($l.Objects).Count) { " ($(& $H ($l.Objects -join ', ')))" } else { '' }
                    $ev = if ($l.Evidence -eq 'shown') { "<span class='check-id'>shown by the findings</span>" } else { "<span class='check-id'>assumed</span>$(if ($l.Assumption) { ": $(& $H $l.Assumption)" })" }
                    & $w "<li>$chk$(& $H $l.Gives)$lo &middot; $ev</li>"
                }
                & $w '</ol>'
            }
            if ($c.BreakPoint) { & $w "<div class='meta' style='margin-top:4px'>Break it here: <code>$(& $H $c.BreakPoint.Check)</code> &middot; $(& $H $c.BreakPoint.Why)</div>" }
            & $w '</div>'
        }
    }
    if (@($AiResult.VerifyNext).Count -gt 0) {
        & $w '<h3>Check by hand (assumptions behind the chains)</h3><ul>'
        foreach ($v in $AiResult.VerifyNext) {
            $vc = if (@($v.Checks).Count) { " <span class='meta'>$((@($v.Checks) | ForEach-Object { "<code>$_</code>" }) -join ' ')</span>" } else { '' }
            & $w "<li>$(& $H $v.Question)$vc</li>"
        }
        & $w '</ul>'
    }
    if (@($AiResult.RejectedChains).Count -gt 0) {
        & $w '<h3>Chains considered and ruled out</h3><ul>'
        foreach ($rc in $AiResult.RejectedChains) {
            $rcc = if (@($rc.Checks).Count) { " <span class='meta'>$((@($rc.Checks) | ForEach-Object { "<code>$_</code>" }) -join ' ')</span>" } else { '' }
            & $w "<li><b>$(& $H $rc.Title)</b>$rcc<br>$(& $H $rc.Reason)</li>"
        }
        & $w '</ul>'
    }
    if ($AiResult.ComparisonNarrative) { & $w "<h3>Trend since previous run</h3><p>$(& $H $AiResult.ComparisonNarrative)</p>" }
    if (@($AiResult.QuickWins).Count -gt 0) {
        & $w '<h3>Quick wins</h3><ul>'
        foreach ($q in $AiResult.QuickWins) { & $w "<li>$(& $H $q)</li>" }
        & $w '</ul>'
    }
    if (@($AiResult.RemediationPlan).Count -gt 0) {
        & $w '<h3>Suggested remediation order</h3><ol>'
        foreach ($p in $AiResult.RemediationPlan) {
            $effort = if ($p.Effort) { " <span class='check-id'>effort: $($p.Effort)</span>" } else { '' }
            $objs = if (@($p.Objects).Count -gt 0) { "<br><span class='meta'>Objects: $(& $H ($p.Objects -join ', '))</span>" } else { '' }
            $cav = if ($p.Caveats) { "<br><span class='meta'>Caveats: $(& $H $p.Caveats)</span>" } else { '' }
            & $w "<li><b>$(& $H $p.Title)</b>$effort<br>$(& $H $p.Rationale)<br><span class='meta'>Checks: $(($p.Checks | ForEach-Object { "<code>$_</code>" }) -join ' ')</span>$objs$cav</li>"
        }
        & $w '</ol>'
    }
    if (@($AiResult.Monitoring).Count -gt 0) {
        & $w "<h3>Monitoring until fixed</h3><div class='table-wrap'><table><tr><th>Checks</th><th>Event IDs</th><th>Guidance</th></tr>"
        foreach ($m in $AiResult.Monitoring) {
            & $w "<tr class='data-row'><td>$(($m.Checks | ForEach-Object { "<code>$_</code>" }) -join ' ')</td><td>$(& $H ($m.EventIds -join ', '))</td><td>$(& $H $m.Guidance)</td></tr>"
        }
        & $w '</table></div>'
    }
    if (@($AiResult.Triage).Count -gt 0) {
        & $w "<h3>Exploitability triage (fix order for this environment)</h3><div class='table-wrap'><table class='ai-triage'><tr><th>#</th><th>Checks</th><th>Objects</th><th>Why</th></tr>"
        $i = 0
        foreach ($t in $AiResult.Triage) {
            $i++
            $rank = if ($t.Rank -gt 0) { $t.Rank } else { $i }
            & $w "<tr class='data-row'><td>$rank</td><td>$(($t.Checks | ForEach-Object { "<code>$_</code>" }) -join ' ')</td><td>$(& $H ($t.Objects -join ', '))</td><td>$(& $H $t.Rationale)</td></tr>"
        }
        & $w '</table></div>'
    }
    if (@($AiResult.KnownExploitation).Count -gt 0) {
        & $w "<h3>Attack vectors seen in recent attacks</h3><div class='table-wrap'><table class='ai-triage'><tr><th>Checks</th><th>Vector</th><th>Publicly known</th><th>Why it matters here</th></tr>"
        foreach ($k in $AiResult.KnownExploitation) {
            & $w "<tr class='data-row'><td>$(($k.Checks | ForEach-Object { "<code>$_</code>" }) -join ' ')</td><td>$(& $H $k.Vector)</td><td>$(& $H $k.Public)</td><td>$(& $H $k.Relevance)</td></tr>"
        }
        & $w '</table></div>'
    }
    if (@($AiResult.AttackPaths).Count -gt 0) {
        & $w '<h3>Attack paths toward Tier 0</h3>'
        foreach ($p in $AiResult.AttackPaths) {
            $pill = if ($p.Severity -and (Get-Command Get-SevPill -ErrorAction SilentlyContinue)) { Get-SevPill $p.Severity } else { '' }
            & $w "<div style='margin:10px 0'><b>$(& $H $p.Title)</b> $pill"
            if (@($p.Steps).Count -gt 0) {
                & $w "<div class='meta' style='margin:4px 0'>$((@($p.Steps) | ForEach-Object { & $H $_ }) -join ' &rarr; ')</div>"
            }
            if ($p.Narrative) { & $w "<div>$(& $H $p.Narrative)</div>" }
            & $w '</div>'
        }
    }
    if (@($AiResult.RemediationScripts).Count -gt 0) {
        & $w '<h3>Remediation scripts (review before running)</h3>'
        & $w "<p class='meta'>Generated PowerShell using native cmdlets, with object names as placeholders. Treat as a starting point: read it, substitute the real objects, and test in a lab first.</p>"
        foreach ($s in $AiResult.RemediationScripts) {
            & $w "<div style='margin:10px 0'><span class='check-id'>Fix for <code>$(& $H $s.Check)</code></span>"
            if ($s.PowerShell) { & $w "<div class='ai-script'>$(& $H $s.PowerShell)</div>" }
            if ($s.Caveats) { & $w "<div class='meta'>Caveats: $(& $H $s.Caveats)</div>" }
            & $w '</div>'
        }
    }
    & $w "<p class='meta'>Generated by a language model from findings computed locally. Verify every recommendation before acting; the deterministic sections of this report are authoritative.</p></div></details>"
    return $sb.ToString()
}
