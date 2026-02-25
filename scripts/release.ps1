param(
    [string]$Version = "",
    [string]$OutputDir = "dist"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

if ([string]::IsNullOrWhiteSpace($Version)) {
    if (Test-Path "VERSION") {
        $Version = (Get-Content "VERSION" -Raw).Trim()
    }
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw "Version is required. Pass -Version or create VERSION file."
}

$releaseVersion = if ($Version.StartsWith("v")) { $Version.Substring(1) } else { $Version }
if ([string]::IsNullOrWhiteSpace($releaseVersion)) {
    throw "Invalid version value: $Version"
}
$versionTag = "v$releaseVersion"
$releaseDir = Join-Path $OutputDir $versionTag
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" },
    @{ GOOS = "windows"; GOARCH = "arm64"; Ext = ".exe" },
    @{ GOOS = "linux";   GOARCH = "amd64"; Ext = ""     },
    @{ GOOS = "linux";   GOARCH = "arm64"; Ext = ""     },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Ext = ""     },
    @{ GOOS = "darwin";  GOARCH = "arm64"; Ext = ""     }
)

$originalGoos = $env:GOOS
$originalGoarch = $env:GOARCH
$originalCgo = $env:CGO_ENABLED

try {
    foreach ($target in $targets) {
        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH
        $env:CGO_ENABLED = "0"

        $binaryName = "docker-otty-$versionTag-$($target.GOOS)-$($target.GOARCH)$($target.Ext)"
        $binaryPath = Join-Path $releaseDir $binaryName

        Write-Host "Building $binaryName ..."
        & go build -trimpath -ldflags "-s -w -X main.appVersion=$releaseVersion" -o $binaryPath .

        if (-not (Test-Path $binaryPath)) {
            throw "Build failed for $binaryName"
        }

        $zipPath = "$binaryPath.zip"
        if (Test-Path $zipPath) {
            Remove-Item $zipPath -Force
        }
        Compress-Archive -Path $binaryPath -DestinationPath $zipPath -CompressionLevel Optimal
        Remove-Item $binaryPath -Force
    }
}
finally {
    $env:GOOS = $originalGoos
    $env:GOARCH = $originalGoarch
    $env:CGO_ENABLED = $originalCgo
}

$checksumsFile = Join-Path $releaseDir "checksums.txt"
if (Test-Path $checksumsFile) {
    Remove-Item $checksumsFile -Force
}

$archives = Get-ChildItem -Path $releaseDir -Filter "*.zip" | Sort-Object Name
foreach ($archive in $archives) {
    $hash = (Get-FileHash -Path $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Content -Path $checksumsFile -Value "$hash  $($archive.Name)"
}

Copy-Item README.md, CHANGELOG.md, LICENSE, VERSION -Destination $releaseDir -Force

Write-Host ""
Write-Host "Release artifacts created at: $releaseDir"
Write-Host "Files:"
Get-ChildItem $releaseDir | Select-Object Name, Length | Format-Table -AutoSize
