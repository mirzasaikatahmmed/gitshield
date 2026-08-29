# Bootstrap installer for gitshield on Windows.
#
#   irm https://raw.githubusercontent.com/mirzasaikatahmmed/gitshield/main/install.ps1 | iex
#
# Downloads the latest release binary when available. If no Windows release
# asset exists yet, installs Go locally (when missing) and builds from source.
param()

$ErrorActionPreference = "Stop"

$Repo = "mirzasaikatahmmed/gitshield"
$Module = "github.com/mirzasaikatahmmed/gitshield/cmd/gitshield@latest"
$Prefix = if ($env:GITSHIELD_INSTALL_DIR) { $env:GITSHIELD_INSTALL_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }
$Dest = Join-Path $Prefix "gitshield.exe"

function Write-Gitshield([string]$Message) {
    Write-Host "gitshield: $Message"
}

function Get-WindowsArch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { throw "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
    }
}

function Add-ToUserPath([string]$Dir) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($userPath) { $parts = $userPath -split ';' | Where-Object { $_ -ne "" } }
    if ($parts -contains $Dir) { return }
    $newPath = if ($parts.Count -gt 0) { "$Dir;" + ($parts -join ";") } else { $Dir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    if ($env:Path -notlike "*$Dir*") {
        $env:Path = "$Dir;$env:Path"
    }
}

function Test-Sha256File([string]$Path, [string]$ChecksumFile, [string]$WantName) {
    $hash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
    $matched = $false
    foreach ($line in Get-Content $ChecksumFile) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $fields = $trimmed -split '\s+', 2
        if ($fields.Count -lt 2) { continue }
        $digest = $fields[0].ToLower()
        $name = $fields[1].TrimStart('*')
        if ($name -ne $WantName) { continue }
        if ($digest -ne $hash) {
            throw "checksum mismatch for $WantName"
        }
        $matched = $true
        break
    }
    if (-not $matched) {
        throw "checksum file has no entry for $WantName"
    }
}

function Ensure-GoInstalled {
    if (Get-Command go -ErrorAction SilentlyContinue) { return }

    $goRoot = Join-Path $env:USERPROFILE ".local\go"
    $goBin = Join-Path $goRoot "bin"
    $goExe = Join-Path $goBin "go.exe"
    if (Test-Path $goExe) {
        $env:GOROOT = $goRoot
        if ($env:Path -notlike "*$goBin*") {
            $env:Path = "$goBin;$env:Path"
        }
        return
    }

    Write-Gitshield "Go not found; installing a local toolchain to $goRoot"
    $release = Invoke-RestMethod "https://go.dev/dl/?mode=json"
    $arch = Get-WindowsArch
    $file = $release[0].files | Where-Object { $_.os -eq "windows" -and $_.arch -eq $arch -and $_.kind -eq "archive" } | Select-Object -First 1
    if (-not $file) {
        throw "could not find a Go archive for windows/$arch"
    }

    $tmpdir = Join-Path ([System.IO.Path]::GetTempPath()) ("gitshield-go-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tmpdir -Force | Out-Null
    try {
        $zipPath = Join-Path $tmpdir $file.filename
        Invoke-WebRequest -Uri "https://go.dev/dl/$($file.filename)" -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $tmpdir -Force
        $extracted = Join-Path $tmpdir "go"
        if (-not (Test-Path $extracted)) {
            throw "unexpected Go archive layout"
        }
        if (Test-Path $goRoot) {
            Remove-Item -Recurse -Force $goRoot
        }
        Move-Item $extracted $goRoot
    }
    finally {
        Remove-Item -Recurse -Force $tmpdir -ErrorAction SilentlyContinue
    }

    $env:GOROOT = $goRoot
    $env:Path = "$goBin;$env:Path"
    Add-ToUserPath $goBin
    Write-Gitshield "installed Go $($release[0].version) -> $goRoot"
}

function Install-FromRelease([string]$Arch) {
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "gitshield-installer" }
    $tag = $release.tag_name
    if (-not $tag) {
        throw "could not determine the latest release tag for $Repo"
    }

    $assetName = "gitshield-windows-$Arch.zip"
    $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
    if (-not $asset) {
        return $false
    }

    $tmpdir = Join-Path ([System.IO.Path]::GetTempPath()) ("gitshield-install-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tmpdir -Force | Out-Null
    try {
        $zipPath = Join-Path $tmpdir $assetName
        $sumPath = Join-Path $tmpdir "$assetName.sha256"
        Write-Gitshield "downloading $assetName ($tag)..."
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing
        Invoke-WebRequest -Uri ($asset.browser_download_url + ".sha256") -OutFile $sumPath -UseBasicParsing
        Write-Gitshield "verifying checksum..."
        Test-Sha256File $zipPath $sumPath $assetName
        Expand-Archive -Path $zipPath -DestinationPath $tmpdir -Force
        $built = Join-Path $tmpdir "gitshield-windows-$Arch.exe"
        if (-not (Test-Path $built)) {
            throw "release archive is missing gitshield-windows-$Arch.exe"
        }
        New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
        Copy-Item $built $Dest -Force
    }
    finally {
        Remove-Item -Recurse -Force $tmpdir -ErrorAction SilentlyContinue
    }
    return $true
}

function Install-FromSource {
    Ensure-GoInstalled
    Write-Gitshield "building from source with go install..."
    & go install $Module
    if ($LASTEXITCODE -ne 0) {
        throw "go install failed"
    }
    $gopath = (& go env GOPATH).Trim()
    if (-not $gopath) {
        throw "go env GOPATH returned empty output"
    }
    $built = Join-Path $gopath "bin\gitshield.exe"
    if (-not (Test-Path $built)) {
        throw "expected built binary at $built"
    }
    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    Copy-Item $built $Dest -Force
}

$arch = Get-WindowsArch
$installed = $false
try {
    $installed = Install-FromRelease $arch
}
catch {
    Write-Gitshield "release install failed: $($_.Exception.Message)"
}

if (-not $installed) {
    Write-Gitshield "no Windows release asset found; falling back to source build"
    Install-FromSource
}

Add-ToUserPath $Prefix
Write-Gitshield "installed -> $Dest"
if ($env:Path -notlike "*$Prefix*") {
    Write-Gitshield "NOTE: $Prefix is not on your PATH yet. Restart the terminal or run:"
    Write-Host "  `$env:Path = `"$Prefix;`$env:Path`""
}
Write-Gitshield "run 'gitshield update' in the future to update in place."
