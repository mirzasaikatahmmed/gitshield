# Bootstrap uninstaller for gitshield on Windows.
#
#   irm https://raw.githubusercontent.com/mirzasaikatahmmed/gitshield/main/uninstall.ps1 | iex
#
# If gitshield still runs, prefer: gitshield uninstall [--purge]
param(
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

$Prefix = if ($env:GITSHIELD_INSTALL_DIR) { $env:GITSHIELD_INSTALL_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }
$candidates = @(
    (Join-Path $Prefix "gitshield.exe"),
    (Join-Path $env:ProgramFiles "gitshield\gitshield.exe")
)

$removed = $false
foreach ($path in $candidates) {
    if (-not (Test-Path $path)) { continue }
    Remove-Item $path -Force
    Write-Host "gitshield: removed $path"
    $removed = $true
}

if (-not $removed) {
    Write-Host "gitshield: no installed binary found in: $($candidates -join ', ')"
}

$configDir = Join-Path $env:USERPROFILE ".gitshield"
if ($Purge) {
    if (Test-Path $configDir) {
        Remove-Item -Recurse -Force $configDir
        Write-Host "gitshield: removed $configDir (config, signatures, AND the audit log)"
    }
}
else {
    Write-Host "gitshield: kept $configDir (config + audit log). Re-run with -Purge to remove it."
}
