<#
.SYNOPSIS
    Turns an IDWolf HTML report into an animated GIF of slides, one per section, each with a
    caption that says what you are looking at (for a README, a ticket, a demo).

.DESCRIPTION
    Windows only, in Windows PowerShell 5.1 (it uses the WPF imaging classes to write the GIF) and
    needs Microsoft Edge (or Chrome) installed: the report is rendered by the browser in headless
    mode, the position of each section is read from the page, and one slide is cut for each of
    them: the score and counts, the charts, the attack-path map, the Tier 0 members, the findings...
    Sections a report doesn't have (no AI summary, no coverage gaps) are skipped.

    Each slide stays on screen for -FrameSeconds (default 3). The caption sits under the picture.

    A report built from a real directory shows real names. For a README, build the GIF from a
    synthetic report instead (IDWolf.ps1 -Snapshot examples\synthetic_demo.json ...).

.PARAMETER Report
    The HTML report (AD or Entra: the plan is picked from the page title).
.PARAMETER OutFile
    GIF to write (default: next to the report, same name).
.PARAMETER FrameSeconds
    How long each slide stays (default 3).
.PARAMETER ViewHeight
    Height of the part of the report shown in a slide, in browser pixels (default 640).
.PARAMETER Width
    Browser width in pixels (default 1200). OutWidth is the width of the GIF (default 960).
.PARAMETER MaxHeight
    Highest point of the report that can appear in a slide, in pixels from the top (default 9000).

.EXAMPLE
    powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File .\tests\New-ReportGif.ps1 -Report .\report.html
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$Report,
    [string]$OutFile = '',
    [int]$Width = 1200,
    [int]$ViewHeight = 640,
    [int]$MaxHeight = 9000,
    [double]$FrameSeconds = 3.0,
    [int]$OutWidth = 960,
    [int]$CaptionHeight = 84,
    [string]$Browser = ''
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Run this in Windows PowerShell 5.1 (powershell.exe -STA ...): the GIF writer uses WPF.' }
Add-Type -AssemblyName System.Drawing, PresentationCore, WindowsBase

if (-not (Test-Path -LiteralPath $Report)) { throw "Report not found: $Report" }
$reportFull = (Resolve-Path -LiteralPath $Report).Path
if (-not $OutFile) { $OutFile = [System.IO.Path]::ChangeExtension($reportFull, '.gif') }
$outFull = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path (Get-Location).Path $OutFile }

if (-not $Browser) {
    $Browser = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Browser) { throw 'No Edge or Chrome found. Pass -Browser <path to msedge.exe or chrome.exe>.' }

# What each slide shows. Sel is a CSS selector (Idx picks the n-th match), Text narrows a heading by its text.
$html = [System.IO.File]::ReadAllText($reportFull)
$isEntra = $html -match '(?i)<title>[^<]*Entra'
if ($isEntra) {
    $plan = @(
        @{ Sel = '.cards'; Idx = 0; Text = ''; Caption = 'Score and counts: the hygiene grade, findings by severity, and how many users and service principals were read.' }
        @{ Sel = '.chart-row'; Idx = 0; Text = ''; Caption = 'Findings by severity and by category.' }
        @{ Sel = '.chart-row'; Idx = 1; Text = ''; Caption = 'The tenant itself: users by type and origin, MFA registration, sign-in activity, privileged roles and service principals.' }
        @{ Sel = 'summary h2'; Idx = 0; Text = 'Tenant at a glance'; Caption = 'Tenant at a glance: directory sync, domains, security defaults, Conditional Access policies, licence and app registrations.' }
        @{ Sel = '.ai-section'; Idx = 0; Text = ''; Caption = 'Optional Gemini summary and remediation plan. Names were replaced by tokens before anything was sent.' }
        @{ Sel = '.ai-section h3'; Idx = 0; Text = 'chained into full compromise'; Caption = 'Gemini''s verdict: can the findings be chained into tenant compromise, from what starting access, and which link breaks each chain.' }
        @{ Sel = 'blockquote.warn'; Idx = 0; Text = ''; Caption = 'Incomplete coverage: checks that could not be evaluated are listed, never counted as clean.' }
        @{ Sel = 'summary h2'; Idx = 0; Text = 'Findings by check'; Caption = 'One block per triggered check: why it matters, how to fix it, the MITRE link and the affected objects.' }
    )
}
else {
    $plan = @(
        @{ Sel = '.cards'; Idx = 0; Text = ''; Caption = 'Score and counts: the hygiene grade, findings by severity, and how many users, computers and Tier 0 principals were read.' }
        @{ Sel = '.chart-row'; Idx = 0; Text = ''; Caption = 'Findings by severity and category, who is in Tier 0, and how active the enabled users are.' }
        @{ Sel = '.chart-row'; Idx = 1; Text = ''; Caption = 'The directory itself: accounts by kind, password age and settings, computers by OS and activity, groups by scope, password quality.' }
        @{ Sel = '.ai-section'; Idx = 0; Text = ''; Caption = 'Optional Gemini summary and remediation plan. Names were replaced by tokens before anything was sent.' }
        @{ Sel = '.ai-section h3'; Idx = 0; Text = 'chained into full compromise'; Caption = 'Gemini''s verdict: can the findings be chained into domain compromise, from what starting access, and which link breaks each chain.' }
        @{ Sel = '.ai-section h3'; Idx = 0; Text = 'Attack vectors seen in recent attacks'; Caption = 'Findings that match attack vectors used in publicly known attacks, starting from IDWolf''s own list of recent attacks.' }
        @{ Sel = 'summary h2'; Idx = 0; Text = 'Attack-path map'; Caption = 'Attack-path map: every principal with a path to Tier 0. A chain reads left to right, one column per step; a dashed arrow is an assumption.' }
        @{ Sel = 'h3'; Idx = 0; Text = 'Tier 0 members'; Caption = 'Tier 0 members: the accounts that already hold Tier 0 rights. They are the target of the paths, not a source.' }
        @{ Sel = 'blockquote.warn'; Idx = 0; Text = ''; Caption = 'Incomplete coverage: checks that could not be evaluated are listed, never counted as clean.' }
        @{ Sel = 'summary h2'; Idx = 0; Text = 'Summary by category'; Caption = 'Findings by category and severity.' }
        @{ Sel = 'summary h2'; Idx = 0; Text = 'Findings by check'; Caption = 'One block per triggered check: why it matters, how to fix it, the MITRE link and the affected objects.' }
    )
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("idwolf_gif_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $url = ([System.Uri]$reportFull).AbsoluteUri
    $profileDir = Join-Path $tmp 'profile'

    # ---- 1. Ask the browser where each section is (a copy of the report with a small script added) ----
    $planJson = ($plan | ForEach-Object { @{ sel = $_.Sel; idx = $_.Idx; text = $_.Text } } | ConvertTo-Json -Compress)
    if ($plan.Count -eq 1) { $planJson = "[$planJson]" }
    $probeJs = @'
<script>
(function () {
  var plan = __PLAN__; var out = [];
  plan.forEach(function (p, n) {
    var all = Array.prototype.slice.call(document.querySelectorAll(p.sel));
    if (p.text) { all = all.filter(function (e) { return (e.textContent || '').replace(/\s+/g, ' ').indexOf(p.text) !== -1; }); }
    var e = all[p.idx];
    if (e) { out.push({ n: n, y: Math.round(e.getBoundingClientRect().top + window.pageYOffset) }); }
  });
  var pre = document.createElement('pre'); pre.id = 'idwolf-plan';
  pre.textContent = 'IDWOLFPLAN:' + JSON.stringify({ h: Math.max(document.documentElement.scrollHeight, document.body.scrollHeight), slides: out }) + ':ENDPLAN';
  document.body.appendChild(pre);
})();
</script>
'@.Replace('__PLAN__', $planJson)
    $probe = Join-Path $tmp 'probe.html'
    $idx = $html.LastIndexOf('</body>', [System.StringComparison]::OrdinalIgnoreCase)
    $probeHtml = if ($idx -ge 0) { $html.Insert($idx, $probeJs) } else { $html + $probeJs }
    [System.IO.File]::WriteAllText($probe, $probeHtml, (New-Object System.Text.UTF8Encoding($false)))
    $ErrorActionPreference = 'Continue'
    $dom = & $Browser --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 "--user-data-dir=$profileDir-probe" "--window-size=$Width,900" --virtual-time-budget=4000 --dump-dom ([System.Uri]$probe).AbsoluteUri 2>$null | Out-String
    $ErrorActionPreference = 'Stop'
    $m = [regex]::Match($dom, 'IDWOLFPLAN:(\{.*?\}):ENDPLAN', 'Singleline')
    if (-not $m.Success) { throw 'Could not read the section positions from the page.' }
    $found = [System.Web.HttpUtility]::HtmlDecode($m.Groups[1].Value) | ConvertFrom-Json
    $pageH = [int]$found.h
    $slides = @($found.slides | Where-Object { $_.y -lt $MaxHeight } | Sort-Object { [int]$_.y })
    if ($slides.Count -eq 0) { throw 'No known section found in the report.' }

    # ---- 2. Render the report as one tall picture ----
    $shotH = [Math]::Min([Math]::Max($pageH, $ViewHeight), $MaxHeight + $ViewHeight)
    $png = Join-Path $tmp 'page.png'
    $ErrorActionPreference = 'Continue'
    & $Browser --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 "--user-data-dir=$profileDir" "--window-size=$Width,$shotH" "--screenshot=$png" $url 2>&1 | Out-Null
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path $png)) { throw "The browser produced no screenshot ($Browser)." }

    # ---- 3. One slide per section: the picture, and the caption under it ----
    $page = New-Object System.Drawing.Bitmap($png)
    $frames = New-Object System.Collections.Generic.List[object]
    $delays = New-Object System.Collections.Generic.List[int]   # in hundredths of a second
    try {
        $outH = [int][Math]::Round($ViewHeight * $OutWidth / $Width)
        Write-Host "Report height $($page.Height) px, $($slides.Count) slides of $OutWidth x $($outH + $CaptionHeight), $FrameSeconds s each."
        $captionFont = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
        $counterFont = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
        $bandBrush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#23262A'))
        $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#F1F3F5'))
        $dimBrush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#9AA0A6'))
        $i = 0
        foreach ($s in $slides) {
            $i++
            $top = if ($i -eq 1) { 0 } else { [Math]::Max(0, [int]$s.y - 24) }
            $top = [Math]::Min($top, [Math]::Max(0, $page.Height - $ViewHeight))
            $bmp = New-Object System.Drawing.Bitmap($OutWidth, ($outH + $CaptionHeight))
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
            $g.DrawImage($page, (New-Object System.Drawing.Rectangle(0, 0, $OutWidth, $outH)), (New-Object System.Drawing.Rectangle(0, $top, $Width, [Math]::Min($ViewHeight, $page.Height - $top))), [System.Drawing.GraphicsUnit]::Pixel)
            $g.FillRectangle($bandBrush, 0, $outH, $OutWidth, $CaptionHeight)
            $fmt = New-Object System.Drawing.StringFormat
            $fmt.Trimming = [System.Drawing.StringTrimming]::EllipsisWord
            $g.DrawString([string]$plan[[int]$s.n].Caption, $captionFont, $textBrush, (New-Object System.Drawing.RectangleF(18, ($outH + 12), ($OutWidth - 36), ($CaptionHeight - 28))), $fmt)
            $fmtR = New-Object System.Drawing.StringFormat; $fmtR.Alignment = [System.Drawing.StringAlignment]::Far
            $g.DrawString("$i / $($slides.Count)", $counterFont, $dimBrush, (New-Object System.Drawing.RectangleF(18, ($outH + $CaptionHeight - 20), ($OutWidth - 36), 18)), $fmtR)
            $g.Dispose()
            $ms = New-Object System.IO.MemoryStream
            $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
            $ms.Position = 0
            $dec = New-Object System.Windows.Media.Imaging.PngBitmapDecoder($ms, [System.Windows.Media.Imaging.BitmapCreateOptions]::PreservePixelFormat, [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad)
            $src = $dec.Frames[0]; $src.Freeze()
            $delays.Add([int][Math]::Min(65535, [int]($FrameSeconds * 100)))
            $frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($src))
        }
    }
    finally { $page.Dispose() }

    # ---- 4. Write the GIF, then add the "loop forever" block WPF doesn't write ----
    $enc = New-Object System.Windows.Media.Imaging.GifBitmapEncoder
    foreach ($f in $frames) { $enc.Frames.Add($f) }
    $ms = New-Object System.IO.MemoryStream
    $enc.Save($ms)
    $bytes = $ms.ToArray()
    $gctSize = if (($bytes[10] -band 0x80) -ne 0) { 3 * [Math]::Pow(2, ($bytes[10] -band 0x07) + 1) } else { 0 }
    $insertAt = 13 + [int]$gctSize
    $loop = [byte[]](0x21, 0xFF, 0x0B) + [System.Text.Encoding]::ASCII.GetBytes('NETSCAPE2.0') + [byte[]](0x03, 0x01, 0x00, 0x00, 0x00)
    $final = New-Object byte[] ($bytes.Length + $loop.Length)
    [Array]::Copy($bytes, 0, $final, 0, $insertAt)
    [Array]::Copy($loop, 0, $final, $insertAt, $loop.Length)
    [Array]::Copy($bytes, $insertAt, $final, $insertAt + $loop.Length, $bytes.Length - $insertAt)
    # WPF writes every frame's delay as 0 whatever the metadata says: set them in the graphic control blocks,
    # walking the blocks so the bytes of the picture data are never mistaken for one.
    $p = $insertAt + $loop.Length; $k = 0
    while ($p -lt $final.Length) {
        $t = $final[$p]
        if ($t -eq 0x3B) { break }
        elseif ($t -eq 0x21) {
            if ($final[$p + 1] -eq 0xF9 -and $k -lt $delays.Count) { $final[$p + 4] = [byte]($delays[$k] -band 0xFF); $final[$p + 5] = [byte](($delays[$k] -shr 8) -band 0xFF); $k++ }
            $p += 2; while ($final[$p] -ne 0) { $p += $final[$p] + 1 }; $p++
        }
        elseif ($t -eq 0x2C) {
            $ipk = $final[$p + 9]; $p += 10
            if (($ipk -band 0x80) -ne 0) { $p += 3 * [int][Math]::Pow(2, ($ipk -band 0x07) + 1) }
            $p++; while ($final[$p] -ne 0) { $p += $final[$p] + 1 }; $p++
        }
        else { throw "Unexpected byte 0x{0:X2} in the GIF at $p" -f $t }
    }
    if ($k -ne $delays.Count) { Write-Warning "Set the delay of $k of $($delays.Count) frames." }
    [System.IO.File]::WriteAllBytes($outFull, $final)
    Write-Host ("GIF written: {0} ({1:N1} MB, {2} slides, {3:N0} s per loop)" -f $outFull, ($final.Length / 1MB), $frames.Count, ($frames.Count * $FrameSeconds))
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
