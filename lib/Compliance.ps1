# Regulatory mapping: which controls of NIS2, ISO/IEC 27001:2022, DORA and
# GDPR each check gives evidence for. A check gets one or more themes (from
# its category, then from words in its ID); each control lists the themes it
# covers. The mapping is about the technical, directory-side part of a
# control: a clean row is evidence, not compliance.

$script:ComplianceThemes = [ordered]@{
    auth   = 'Authentication and credentials'
    mfa    = 'Multi-factor and strong authentication'
    priv   = 'Privileged access'
    access = 'Identity lifecycle and access rights'
    config = 'Secure configuration'
    vuln   = 'Unsupported software and known vulnerabilities'
    crypto = 'Cryptography'
    log    = 'Logging and monitoring'
    resil  = 'Backup, redundancy and availability'
    net    = 'Network security'
}

# Category -> default themes.
$script:ComplianceCategoryThemes = @{
    'Kerberos'             = @('auth')
    'Privileged Access'    = @('priv')
    'Account Hygiene'      = @('access')
    'Domain Configuration' = @('config')
    'Operational Health'   = @('resil')
    'Permissions'          = @('priv')
    'Certificate Services' = @('priv', 'config')
    'Host Hardening'       = @('config')
    'Password Quality'     = @('auth')
    'Entra Access Policy'  = @('access')
    'Entra Identity'       = @('priv')
    'Entra Applications'   = @('access')
}

# Words in a check ID -> extra themes.
$script:ComplianceIdThemes = [ordered]@{
    auth   = 'password|kerberoast|asrep|krbtgt|laps|pwq_|des_enabled|spn_account|protected_users|lockout|banned_passwords|unix_password|lm_hash|lmcompat|wdigest|cached_credentials|precreated|credential|auth_methods|authenticator'
    mfa    = 'mfa|phishing_resistant|security_defaults|legacy_auth|device_code|authenticator|auth_methods|system_preferred|security_info_registration|risk_polic|sign_in_risk'
    priv   = 'admin|privileged|uac_|dcsync|delegation|delegable|rbcd|operator|owner|dangerous_ace|gmsa|shadow|laps_readers|sync_laps|rodc|pim|role|silo|sid_history|primary_group|krbtgt|adcs_esc'
    access = 'inactive|never_logged|stale_|guest|orphaned|anonymous|pre_win2000|consent|register_apps|create_tenants|create_security_groups|create_m365|device_join|device_quota|access_review|access_package|b2b|cross_tenant|broad_local_group|machine_account_quota|precreated'
    config = 'policy|functional_level|recycle_bin|gpo|signing|channel_binding|unc_hardening|llmnr|spooler|smb1|netlogon|lsass|wdigest|cached_credentials|armoring|point_and_print|dns_|dhcp|trust_|sysvol_frs|app_management|redirect'
    vuln   = 'obsolete_os|netlogon_vulnerable|smb1|spooler|point_and_print|functional_level|des_enabled|lm_hash|sysvol_frs'
    crypto = 'rc4|des_enabled|lm_hash|lmcompat|reversible|weak_ca_key|ca_cert_expiring|wdigest|signing|channel_binding|armoring|unix_password|token_protection|^bitlocker|trusted_root'
    log    = 'audit|logging|cmdline'
    resil  = 'backup|replication|single_dc|fsmo|dc_unreachable|time_skew|low_disk|service_stopped|recycle_bin|sysvol_frs|emergency_access|global_admins_too_few|sync_stale|ca_cert_expiring'
    net    = 'signing|channel_binding|llmnr|dns_|unc_hardening|anonymous_sam|smb1|dhcp|trust_|anonymous_ldap|trusted_locations|geo_restriction|cross_tenant|b2b|firewall'
}

# Framework -> control -> themes. Ids are short so they fit a CSV column and a SIEM field.
$script:ComplianceFrameworks = [ordered]@{
    NIS2     = [ordered]@{
        Name     = 'NIS2, Directive (EU) 2022/2555, Art. 21(2)'
        Note     = 'In Italy: Art. 24 of Legislative Decree 138/2024. Running IDWolf on a schedule is also evidence for point (f), assessing the effectiveness of the measures.'
        Controls = [ordered]@{
            '21(2)(b)' = @{ Title = 'Incident handling'; Themes = @('log') }
            '21(2)(c)' = @{ Title = 'Business continuity, backup management, disaster recovery'; Themes = @('resil') }
            '21(2)(e)' = @{ Title = 'Security in maintenance of systems, vulnerability handling'; Themes = @('vuln', 'config', 'net') }
            '21(2)(g)' = @{ Title = 'Basic cyber hygiene practices'; Themes = @('config', 'access') }
            '21(2)(h)' = @{ Title = 'Cryptography and encryption'; Themes = @('crypto') }
            '21(2)(i)' = @{ Title = 'Access control policies and asset management'; Themes = @('access', 'priv', 'auth') }
            '21(2)(j)' = @{ Title = 'Multi-factor or continuous authentication'; Themes = @('mfa') }
        }
    }
    ISO27001 = [ordered]@{
        Name     = 'ISO/IEC 27001:2022, Annex A'
        Note     = 'Periodic runs with -CompareTo support the reviews of A.5.35 and A.5.36.'
        Controls = [ordered]@{
            'A.5.15' = @{ Title = 'Access control'; Themes = @('access', 'priv') }
            'A.5.16' = @{ Title = 'Identity management'; Themes = @('access') }
            'A.5.17' = @{ Title = 'Authentication information'; Themes = @('auth') }
            'A.5.18' = @{ Title = 'Access rights'; Themes = @('access', 'priv') }
            'A.8.2'  = @{ Title = 'Privileged access rights'; Themes = @('priv') }
            'A.8.5'  = @{ Title = 'Secure authentication'; Themes = @('auth', 'mfa') }
            'A.8.8'  = @{ Title = 'Management of technical vulnerabilities'; Themes = @('vuln') }
            'A.8.9'  = @{ Title = 'Configuration management'; Themes = @('config') }
            'A.8.13' = @{ Title = 'Information backup'; Themes = @('resil') }
            'A.8.14' = @{ Title = 'Redundancy of information processing facilities'; Themes = @('resil') }
            'A.8.15' = @{ Title = 'Logging'; Themes = @('log') }
            'A.8.16' = @{ Title = 'Monitoring activities'; Themes = @('log') }
            'A.8.20' = @{ Title = 'Networks security'; Themes = @('net') }
            'A.8.24' = @{ Title = 'Use of cryptography'; Themes = @('crypto') }
        }
    }
    DORA     = [ordered]@{
        Name     = 'DORA, Regulation (EU) 2022/2554'
        Note     = 'Applies to financial entities. The detailed access-control and authentication requirements sit in the ICT risk management RTS, Delegated Regulation (EU) 2024/1774.'
        Controls = [ordered]@{
            '9(2)'    = @{ Title = 'ICT security policies and tools for resilience, integrity and confidentiality'; Themes = @('config') }
            '9(4)(b)' = @{ Title = 'Sound network and infrastructure management'; Themes = @('net', 'config') }
            '9(4)(c)' = @{ Title = 'Logical access limited to what is required'; Themes = @('access', 'priv') }
            '9(4)(d)' = @{ Title = 'Strong authentication, protection of cryptographic keys'; Themes = @('auth', 'mfa', 'crypto') }
            '9(4)(f)' = @{ Title = 'Patches and updates'; Themes = @('vuln') }
            '10(1)'   = @{ Title = 'Detection of anomalous activities'; Themes = @('log') }
            '12(1)'   = @{ Title = 'Backup, restoration and recovery'; Themes = @('resil') }
        }
    }
    GDPR     = [ordered]@{
        Name     = 'GDPR, Regulation (EU) 2016/679, Art. 32(1)'
        Note     = 'Running IDWolf regularly is also evidence for point (d), regularly testing and evaluating the effectiveness of the measures.'
        Controls = [ordered]@{
            '32(1)(a)' = @{ Title = 'Pseudonymisation and encryption'; Themes = @('crypto') }
            '32(1)(b)' = @{ Title = 'Ongoing confidentiality, integrity, availability and resilience'; Themes = @('auth', 'mfa', 'priv', 'access', 'config', 'vuln', 'net', 'log') }
            '32(1)(c)' = @{ Title = 'Timely restoration of availability and access'; Themes = @('resil') }
        }
    }
}

$script:ComplianceCache = @{}

function Get-ComplianceCatalogEntry {
    param([string]$Type)
    if ($script:CheckCatalog -and $script:CheckCatalog.Contains($Type)) { return $script:CheckCatalog[$Type] }
    if ($script:EntraCheckCatalog -and $script:EntraCheckCatalog.Contains($Type)) { return $script:EntraCheckCatalog[$Type] }
    return $null
}

function Get-CheckThemes {
    param([string]$Type)
    $meta = Get-ComplianceCatalogEntry $Type
    $themes = New-Object System.Collections.Generic.List[string]
    if ($meta -and $script:ComplianceCategoryThemes.ContainsKey("$($meta.Category)")) {
        foreach ($t in $script:ComplianceCategoryThemes["$($meta.Category)"]) { $themes.Add($t) }
    }
    foreach ($t in $script:ComplianceIdThemes.Keys) {
        if ($Type -match $script:ComplianceIdThemes[$t] -and -not $themes.Contains($t)) { $themes.Add($t) }
    }
    if ($themes.Count -eq 0) { $themes.Add('config') }
    return , $themes.ToArray()
}

# "NIS2 21(2)(i)", "ISO27001 A.8.2"... for one check, in framework order.
function Get-CheckControls {
    param([string]$Type)
    if ($script:ComplianceCache.ContainsKey($Type)) { return , $script:ComplianceCache[$Type] }
    $themes = Get-CheckThemes $Type
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        $ctrls = $script:ComplianceFrameworks[$fw].Controls
        foreach ($c in $ctrls.Keys) {
            if (@($ctrls[$c].Themes | Where-Object { $themes -contains $_ }).Count -gt 0) { $out.Add("$fw $c") }
        }
    }
    $arr = $out.ToArray()
    $script:ComplianceCache[$Type] = $arr
    return , $arr
}

# Same list, grouped for reading: "NIS2 21(2)(i), 21(2)(j); ISO27001 A.8.2".
function Format-CheckControls {
    param([string]$Type)
    $parts = @()
    $all = Get-CheckControls $Type
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        $ids = @($all | Where-Object { $_.StartsWith("$fw ") } | ForEach-Object { $_.Substring($fw.Length + 1) })
        if ($ids.Count) { $parts += "$fw $($ids -join ', ')" }
    }
    return ($parts -join '; ')
}

# One row per control: how many checks give evidence for it, how many could not
# be evaluated, and what was found.
function Get-ComplianceCoverage {
    param($Catalog, $Findings, $NotEvaluated)
    $ne = @{}; foreach ($n in @($NotEvaluated | Where-Object { $_ })) { $ne["$($n.Type)"] = $true }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        foreach ($c in $script:ComplianceFrameworks[$fw].Controls.Keys) {
            $id = "$fw $c"
            $checks = @($Catalog.Keys | Where-Object { (Get-CheckControls $_) -contains $id })
            $hits = @($Findings | Where-Object { $checks -contains $_.Type })
            $worst = ''
            foreach ($s in 'Critical', 'High', 'Medium', 'Low') { if (@($hits | Where-Object { $_.Severity -eq $s }).Count) { $worst = $s; break } }
            $notEval = @($checks | Where-Object { $ne.ContainsKey($_) }).Count
            $status = if ($hits.Count) { 'Gaps found' } elseif ($checks.Count -eq 0) { 'No check' } elseif ($notEval -eq $checks.Count) { 'Not evaluated' } elseif ($notEval) { 'No findings (partly evaluated)' } else { 'No findings' }
            $rows.Add([PSCustomObject]@{
                    Framework = $fw; Control = $c; Title = $script:ComplianceFrameworks[$fw].Controls[$c].Title
                    Checks = $checks.Count; NotEvaluated = $notEval; Triggered = @($hits | ForEach-Object { $_.Type } | Select-Object -Unique).Count
                    Findings = $hits.Count; Worst = $worst; Status = $status
                })
        }
    }
    return $rows.ToArray()
}

function ConvertTo-ComplianceHtml {
    param($Catalog, $Findings, $NotEvaluated)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $rows = Get-ComplianceCoverage -Catalog $Catalog -Findings $Findings -NotEvaluated $NotEvaluated
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<details><summary><h2>Regulatory mapping</h2></summary>')
    [void]$sb.AppendLine('<blockquote>Which controls the checks of this report give evidence for. The mapping covers the technical, directory-side part of each control: a row with no findings is evidence for that part, not compliance with the control. Policies, processes, people and other systems are outside a directory snapshot.</blockquote>')
    foreach ($fw in $script:ComplianceFrameworks.Keys) {
        $def = $script:ComplianceFrameworks[$fw]
        [void]$sb.AppendLine("<h3>$(& $H $def.Name)</h3><p class=`"meta`">$(& $H $def.Note)</p>")
        [void]$sb.AppendLine('<div class="table-wrap"><table><tr><th>Control</th><th>Requirement</th><th>Checks</th><th>Not evaluated</th><th>Checks triggered</th><th>Findings</th><th>Worst</th><th>Status</th></tr>')
        foreach ($r in @($rows | Where-Object { $_.Framework -eq $fw })) {
            $worst = if ($r.Worst) { Get-SevPill $r.Worst } else { '' }
            [void]$sb.AppendLine("<tr class=`"data-row`"><td><b>$(& $H $r.Control)</b></td><td>$(& $H $r.Title)</td><td>$($r.Checks)</td><td>$($r.NotEvaluated)</td><td>$($r.Triggered)</td><td>$($r.Findings)</td><td>$worst</td><td>$(& $H $r.Status)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div>')
    }
    [void]$sb.AppendLine('<p class="meta">Each check lists its controls under "Findings by check"; the CSV and the JSON Lines carry them in the Controls / controls field.</p></details>')
    return $sb.ToString()
}
