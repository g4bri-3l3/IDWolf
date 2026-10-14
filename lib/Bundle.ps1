# One zip to carry a collection to another machine (collect on a server,
# analyze and talk to Gemini from a workstation): the snapshot, the
# password-quality report if there is one, and a manifest with their SHA-256.
#
# The names inside are fixed, and reading only ever extracts those names into
# a folder of ours, so a crafted zip can't drop files anywhere else.
# The hashes catch a damaged copy, not a deliberate edit (whoever edits the
# zip can edit the manifest too): move it over a channel you trust.
#
# With a password the zip is wrapped in an IDWolf container instead (no legacy
# ZipCrypto): PBKDF2 key derivation, AES-256-CBC, and an HMAC-SHA256 over the
# whole file, checked before anything is decrypted, so a wrong password or an
# edited file is refused. Decryption happens in memory; the plain zip never
# touches the disk. Layout: "IDWOLFENC1", KDF id (1 = SHA-256, 2 = SHA-1),
# iterations (int32), salt (16), IV (16), ciphertext, HMAC (32).

$script:BundleNames = [ordered]@{ Snapshot = 'snapshot.json'; PasswordQuality = 'passwordquality.json'; Manifest = 'manifest.json' }

$script:BundleMagic = [System.Text.Encoding]::ASCII.GetBytes('IDWOLFENC1')

# True when the file starts with the encrypted-bundle header.
function Test-IDWolfEncryptedBundle {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $fs = [System.IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
    try {
        $head = New-Object byte[] $script:BundleMagic.Length
        if ($fs.Read($head, 0, $head.Length) -ne $head.Length) { return $false }
        return ([System.Text.Encoding]::ASCII.GetString($head) -eq 'IDWOLFENC1')
    }
    finally { $fs.Dispose() }
}
# A bundle is a .zip or an encrypted container, whatever its extension.
function Test-IDWolfBundleFile {
    param([string]$Path)
    return ($Path -match '(?i)\.zip$') -or (Test-IDWolfEncryptedBundle $Path)
}

# 64 bytes from the password: 32 for AES, 32 for the HMAC. SHA-256 PBKDF2 needs
# .NET 4.7.2; older frameworks (Server 2016 out of the box) fall back to SHA-1
# with more iterations. The password bytes are wiped as soon as they are used.
function Get-BundleKeys {
    param([System.Security.SecureString]$Password, [byte[]]$Salt, [int]$KdfId = 0, [int]$Iterations = 0)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try { $pw = [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    try {
        $kdf = $null
        if ($KdfId -ne 2) {
            try {
                $it = if ($Iterations) { $Iterations } else { 600000 }
                $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $pw, $Salt, $it, ([System.Security.Cryptography.HashAlgorithmName]::SHA256)
                $KdfId = 1; $Iterations = $it
            }
            catch { if ($KdfId -eq 1) { throw "This bundle needs PBKDF2-SHA256 (.NET Framework 4.7.2 or later, or PowerShell 7)." } }
        }
        if (-not $kdf) {
            $it = if ($Iterations) { $Iterations } else { 1300000 }
            $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $pw, $Salt, $it
            $KdfId = 2; $Iterations = $it
        }
        try { $bytes = $kdf.GetBytes(64) } finally { $kdf.Dispose() }
        return [PSCustomObject]@{ Enc = [byte[]]$bytes[0..31]; Mac = [byte[]]$bytes[32..63]; KdfId = $KdfId; Iterations = $Iterations }
    }
    finally { [Array]::Clear($pw, 0, $pw.Length) }
}

function Protect-BundleBytes {
    param([byte[]]$Plain, [System.Security.SecureString]$Password)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16; $rng.GetBytes($salt); $rng.Dispose()
    $k = Get-BundleKeys -Password $Password -Salt $salt
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $k.Enc; $aes.GenerateIV()
        $enc = $aes.CreateEncryptor()
        try { $cipher = $enc.TransformFinalBlock($Plain, 0, $Plain.Length) } finally { $enc.Dispose() }
        $ms = New-Object System.IO.MemoryStream
        $ms.Write($script:BundleMagic, 0, $script:BundleMagic.Length)
        $ms.WriteByte([byte]$k.KdfId)
        $it = [BitConverter]::GetBytes([int]$k.Iterations); $ms.Write($it, 0, 4)
        $ms.Write($salt, 0, 16); $ms.Write($aes.IV, 0, 16); $ms.Write($cipher, 0, $cipher.Length)
        $body = $ms.ToArray(); $ms.Dispose()
        $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $k.Mac)
        try { $tag = $hmac.ComputeHash($body) } finally { $hmac.Dispose() }
        return [byte[]]($body + $tag)
    }
    finally { $aes.Dispose(); [Array]::Clear($k.Enc, 0, 32); [Array]::Clear($k.Mac, 0, 32) }
}

function Unprotect-BundleBytes {
    param([byte[]]$Data, [System.Security.SecureString]$Password)
    $hdr = $script:BundleMagic.Length + 1 + 4 + 16 + 16
    if ($Data.Length -lt $hdr + 16 + 32) { throw 'Encrypted bundle too short: damaged file.' }
    $kdfId = [int]$Data[$script:BundleMagic.Length]
    $iter = [BitConverter]::ToInt32($Data, $script:BundleMagic.Length + 1)
    if ($kdfId -notin 1, 2 -or $iter -lt 100000 -or $iter -gt 10000000) { throw 'Encrypted bundle header not recognised: damaged file or newer IDWolf.' }
    $salt = [byte[]]$Data[($script:BundleMagic.Length + 5)..($script:BundleMagic.Length + 20)]
    $iv = [byte[]]$Data[($script:BundleMagic.Length + 21)..($script:BundleMagic.Length + 36)]
    $k = Get-BundleKeys -Password $Password -Salt $salt -KdfId $kdfId -Iterations $iter
    try {
        $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $k.Mac)
        try { $tag = $hmac.ComputeHash($Data, 0, $Data.Length - 32) } finally { $hmac.Dispose() }
        # Constant-time compare: no early exit on the first different byte.
        $diff = 0; for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($tag[$i] -bxor $Data[$Data.Length - 32 + $i]) }
        if ($diff -ne 0) { throw 'Wrong password, or the encrypted bundle was changed or damaged.' }
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize = 256; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $k.Enc; $aes.IV = $iv
            $dec = $aes.CreateDecryptor()
            try { return , [byte[]]$dec.TransformFinalBlock($Data, $hdr, $Data.Length - $hdr - 32) } finally { $dec.Dispose() }
        }
        finally { $aes.Dispose() }
    }
    finally { [Array]::Clear($k.Enc, 0, 32); [Array]::Clear($k.Mac, 0, 32) }
}

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
    param([Parameter(Mandatory = $true)][string]$Snapshot, [string]$PasswordQuality = '', [Parameter(Mandatory = $true)][string]$OutFile, [string]$ToolVersion = '',
        [System.Security.SecureString]$Password = $null)
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
    # Built in memory: with a password the plain zip never reaches the disk.
    $ms = New-Object System.IO.MemoryStream
    $zip = New-Object System.IO.Compression.ZipArchive -ArgumentList $ms, ([System.IO.Compression.ZipArchiveMode]::Create), $true
    try {
        foreach ($k in $files.Keys) { [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $files[$k], $k, [System.IO.Compression.CompressionLevel]::Optimal) }
        $entry = $zip.CreateEntry($script:BundleNames.Manifest)
        $w = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
        try { $w.Write(($manifest | ConvertTo-Json -Depth 4)) } finally { $w.Dispose() }
    }
    finally { $zip.Dispose() }
    $bytes = $ms.ToArray(); $ms.Dispose()
    if ($Password -and $Password.Length -gt 0) { $bytes = Protect-BundleBytes -Plain $bytes -Password $Password }
    [System.IO.File]::WriteAllBytes($full, $bytes)
    return $full
}

# Extracts to a fresh temp folder and checks the hashes. The caller reads the
# files and then calls Remove-IDWolfBundle: the snapshot shouldn't linger in TEMP.
function Expand-IDWolfBundle {
    param([Parameter(Mandatory = $true)][string]$Path, [System.Security.SecureString]$Password = $null)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    if (-not (Test-Path -LiteralPath $Path)) { throw "Bundle not found: $Path" }
    $encrypted = Test-IDWolfEncryptedBundle $Path
    if ($encrypted -and (-not $Password -or $Password.Length -eq 0)) { throw "$Path is an encrypted bundle: a password is needed (-BundlePassword, or answer the prompt)." }
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('idwolf_bundle_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    $out = [PSCustomObject]@{ Dir = $dir; Snapshot = ''; PasswordQuality = ''; Manifest = $null }
    try {
        if ($encrypted) {
            $plain = Unprotect-BundleBytes -Data ([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).Path)) -Password $Password
            $zip = New-Object System.IO.Compression.ZipArchive -ArgumentList (New-Object System.IO.MemoryStream -ArgumentList (, $plain)), ([System.IO.Compression.ZipArchiveMode]::Read)
        }
        else { $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Path).Path) }
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
