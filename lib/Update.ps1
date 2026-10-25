# Is there a newer IDWolf? The launcher asks GitHub once at start and only says so.
#
# One GET to the public tag list of the repository (no account, no token, nothing about this
# machine or the directory in the request), at most a few seconds, silent when offline or when
# the answer can't be read. Nothing is downloaded or run: updating stays in your hands (git pull
# on a clone, or the release zip), so a reviewed copy never changes by itself.
# Off with -NoUpdateCheck on the launcher or IDWOLF_NO_UPDATE_CHECK=1.

$script:UpdateTagsUri = 'https://api.github.com/repos/g4bri-3l3/IDWolf/tags?per_page=100'

# The highest vX.Y[.Z] tag in the JSON of the tag list, as a [version]; $null when there is none.
function Get-IDWolfLatestTag {
    param([string]$TagsJson)
    $best = $null
    # Assigned first: 5.1 ConvertFrom-Json emits a JSON array as one object, and @() around the
    # pipeline would wrap it whole instead of listing the tags.
    try { $parsed = ConvertFrom-Json -InputObject $TagsJson } catch { return $null }
    foreach ($t in @($parsed)) {
        $n = "$($t.name)"
        if ($n -notmatch '^v?(\d+\.\d+(\.\d+)?)$') { continue }
        $v = [version]$Matches[1]
        if (-not $best -or $v -gt $best) { $best = $v }
    }
    return $best
}

# The rel="next" address of a GitHub Link header, only when it stays on api.github.com; $null otherwise.
function Get-IDWolfNextPageUri {
    param([string]$LinkHeader)
    foreach ($part in ($LinkHeader -split ',')) {
        if ($part -notmatch '<([^>]+)>\s*;\s*rel="next"') { continue }
        $u = $null
        if ([Uri]::TryCreate($Matches[1], [UriKind]::Absolute, [ref]$u) -and $u.Scheme -eq 'https' -and $u.Host -eq 'api.github.com') { return $u.AbsoluteUri }
    }
    return $null
}

# The latest released version, or $null when GitHub can't be reached in time.
function Get-IDWolfLatestVersion {
    param([string]$Uri = $script:UpdateTagsUri, [int]$TimeoutMs = 3000)
    $client = $null
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
        # Windows PowerShell 5.1 on an older .NET offers only TLS 1.0 by default; GitHub needs TLS 1.2.
        try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs)
        # GitHub refuses API requests without a User-Agent.
        [void]$client.DefaultRequestHeaders.Add('User-Agent', 'IDWolf-update-check')
        [void]$client.DefaultRequestHeaders.Add('Accept', 'application/vnd.github+json')
        # The tag list comes 100 at a time and not in version order: follow the "next" link for a
        # few pages, all within the same time budget. Only api.github.com links are followed.
        $best = $null; $next = $Uri; $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        for ($page = 0; $page -lt 5 -and $next; $page++) {
            $left = [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
            if ($left -le 0) { break }
            $task = $client.GetAsync($next)
            # Wait() also bounds a DNS lookup that hangs on a machine without internet.
            if (-not $task.Wait($left)) { break }
            $resp = $task.Result
            if (-not $resp.IsSuccessStatusCode) { break }
            $v = Get-IDWolfLatestTag -TagsJson $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($v -and (-not $best -or $v -gt $best)) { $best = $v }
            $next = $null
            $link = $null
            if ($resp.Headers.TryGetValues('Link', [ref]$link)) { $next = Get-IDWolfNextPageUri -LinkHeader (@($link) -join ',') }
        }
        return $best
    }
    catch { return $null }
    finally { if ($client) { $client.Dispose() } }
}

# The lines to show when Latest is newer than Current; empty otherwise.
function Get-IDWolfUpdateNotice {
    param([string]$Current, $Latest, [bool]$IsGitClone = $false)
    if (-not $Latest -or -not $Current) { return @() }
    try { $cur = [version]$Current } catch { return @() }
    if ([version]$Latest -le $cur) { return @() }
    $tag = "v$Latest"
    $how = if ($IsGitClone) { "Update with: git pull   (in this folder; then run .\Test-IDWolfSafety.ps1 on the new code)" }
    else { "Download it from github.com/g4bri-3l3/IDWolf/releases/tag/$tag and review it (.\Test-IDWolfSafety.ps1) before use." }
    return @("A newer IDWolf is out: $tag (this copy is v$Current). See CHANGELOG.md for what changed.", $how)
}

# Launcher entry point: checks unless turned off, prints the notice if any, never throws.
function Show-IDWolfUpdateNotice {
    param([string]$Current, [string]$Root, [switch]$Disabled)
    if ($Disabled -or $env:IDWOLF_NO_UPDATE_CHECK -eq '1') { return }
    try {
        $latest = Get-IDWolfLatestVersion
        $isGit = Test-Path -LiteralPath (Join-Path $Root '.git')
        $lines = @(Get-IDWolfUpdateNotice -Current $Current -Latest $latest -IsGitClone $isGit)
        if ($lines.Count) {
            Write-Host ''
            foreach ($l in $lines) { Write-Host $l -ForegroundColor Yellow }
        }
    }
    catch { }
}
