# One zip to carry a collection to another machine (collect on a server,
# analyze and talk to Gemini from a workstation): the snapshot, the
# password-quality report if there is one, and a manifest with their SHA-256.
#
# The names inside are fixed, and reading only ever extracts those names into
# a folder of ours, so a crafted zip can't drop files anywhere else.
# The hashes catch a damaged copy, not a deliberate edit (whoever edits the
# zip can edit the manifest too): move it over a channel you trust.

$script:BundleNames = [ordered]@{ Snapshot = 'snapshot.json'; PasswordQuality = 'passwordquality.json'; Manifest = 'manifest.json' }

function Get-BundleFileHash {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { return (-join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') })) }
    finally { $fs.Dispose(); $sha.Dispose() }
}

function Resolve-BundlePath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path (Get-Location).Path $Path)
}

function New-IDWolfBundle {
    param([Parameter(Mandatory = $true)][string]$Snapshot, [string]$PasswordQuality = '', [Parameter(Mandatory = $true)][string]$OutFile, [string]$ToolVersion = '')
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $files = [ordered]@{}
    $files[$script:BundleNames.Snapshot] = (Resolve-Path -LiteralPath $Snapshot).Path
    if ($PasswordQuality) { $files[$script:BundleNames.PasswordQuality] = (Resolve-Path -LiteralPath $PasswordQuality).Path }
    $manifest = [ordered]@{
        tool = 'IDWolf'; toolVersion = $ToolVersion; createdUtc = (Get-Date).ToUniversalTime().ToString('o')
        files = @(foreach ($k in $files.Keys) { [ordered]@{ name = $k; source = [System.IO.Path]::GetFileName($files[$k]); sha256 = (Get-BundleFileHash $files[$k]) } })
    }
    $full = Resolve-BundlePath $OutFile
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($full, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($k in $files.Keys) { [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $files[$k], $k, [System.IO.Compression.CompressionLevel]::Optimal) }
        $entry = $zip.CreateEntry($script:BundleNames.Manifest)
        $w = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
        try { $w.Write(($manifest | ConvertTo-Json -Depth 4)) } finally { $w.Dispose() }
    }
    finally { $zip.Dispose() }
    return $full
}

# Extracts to a fresh temp folder and checks the hashes. The caller reads the
# files and then calls Remove-IDWolfBundle: the snapshot shouldn't linger in TEMP.
function Expand-IDWolfBundle {
    param([Parameter(Mandatory = $true)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    if (-not (Test-Path -LiteralPath $Path)) { throw "Bundle not found: $Path" }
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('idwolf_bundle_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    $out = [PSCustomObject]@{ Dir = $dir; Snapshot = ''; PasswordQuality = ''; Manifest = $null }
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
        try {
            foreach ($name in $script:BundleNames.Values) {
                $entry = $zip.GetEntry($name)
                if ($entry) { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $dir $name), $true) }
            }
        }
        finally { $zip.Dispose() }
        $snapPath = Join-Path $dir $script:BundleNames.Snapshot
        if (-not (Test-Path -LiteralPath $snapPath)) { throw "$Path is not an IDWolf bundle (no $($script:BundleNames.Snapshot) inside)." }
        $out.Snapshot = $snapPath
        $pqPath = Join-Path $dir $script:BundleNames.PasswordQuality
        if (Test-Path -LiteralPath $pqPath) { $out.PasswordQuality = $pqPath }
        $mPath = Join-Path $dir $script:BundleNames.Manifest
        if (Test-Path -LiteralPath $mPath) {
            $out.Manifest = [System.IO.File]::ReadAllText($mPath) | ConvertFrom-Json
            foreach ($f in @($out.Manifest.files)) {
                $p = Join-Path $dir "$($f.name)"
                if (-not (Test-Path -LiteralPath $p)) { throw "Bundle damaged: $($f.name) is listed in the manifest but missing." }
                if ((Get-BundleFileHash $p) -ne "$($f.sha256)") { throw "Bundle damaged: $($f.name) doesn't match its hash. Copy the zip again." }
            }
        }
        return $out
    }
    catch { Remove-IDWolfBundle $out; throw }
}

function Remove-IDWolfBundle {
    param($Bundle)
    if ($Bundle -and $Bundle.Dir -and (Test-Path -LiteralPath $Bundle.Dir)) { Remove-Item -LiteralPath $Bundle.Dir -Recurse -Force }
}
