# Install the balerx CLI for the current user. No administrator rights.
# Asset names and the download path match packaging/install.ps1.
# Tests set BALERX_INSTALL_LIB=1 and call Get-BalerxTarget.
$ErrorActionPreference = 'Stop'

function Get-BalerxTarget {
  $os = if ($env:BALERX_INSTALL_OS) { $env:BALERX_INSTALL_OS } else { 'windows' }
  $arch = if ($env:BALERX_INSTALL_ARCH) { $env:BALERX_INSTALL_ARCH } else { $env:PROCESSOR_ARCHITECTURE }
  switch -Regex ($arch) {
    '^(AMD64|x64|x86_64)$' { $archName = 'x86_64' }
    '^(ARM64|aarch64|arm64)$' { $archName = 'aarch64' }
    default { throw "Unsupported architecture: $arch" }
  }
  if ($os -notmatch '^(windows|Windows|Win32NT)$') {
    throw "install.ps1 supports Windows. On macOS or Linux, use install.sh."
  }
  return "$archName-pc-windows-msvc"
}

if ($env:BALERX_INSTALL_LIB -eq '1') {
  return
}

$repo = if ($env:BALERX_REPO) { $env:BALERX_REPO } elseif ($env:BALERX_GITHUB_REPO) { $env:BALERX_GITHUB_REPO } else { 'wrjewski/balerx' }
$target = Get-BalerxTarget
$asset = "balerx-$target.zip"
$base = if ($env:BALERX_RELEASE_BASE_URL) { $env:BALERX_RELEASE_BASE_URL } else { "https://github.com/$repo/releases/latest/download" }
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("balerx-install-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $work | Out-Null

try {
  $sumsPath = Join-Path $work 'SHA256SUMS'
  $assetPath = Join-Path $work $asset
  Write-Host "Downloading $asset"
  try {
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
  } catch {
    Write-Error "No Balerx Gate release checksum was found. Install from source until a release tag exists: cargo install --git https://github.com/$repo.git --path balerx-sensor/crates/balerx-cli"
    exit 1
  }
  Invoke-WebRequest -Uri "$base/$asset" -OutFile $assetPath -UseBasicParsing
  $expected = $null
  foreach ($line in Get-Content -Path $sumsPath) {
    $parts = $line -split '\s+'
    if ($parts.Length -ge 2 -and $parts[1] -eq $asset) {
      $expected = $parts[0].ToLowerInvariant()
      break
    }
  }
  $actual = (Get-FileHash -Algorithm SHA256 -Path $assetPath).Hash.ToLowerInvariant()
  if (-not $expected -or $expected -ne $actual) {
    Write-Error "Checksum verification failed for $asset."
    exit 1
  }
  Expand-Archive -Path $assetPath -DestinationPath $work -Force
  $dest = Join-Path $env:LOCALAPPDATA 'balerx'
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item -Force -Path (Join-Path $work 'balerx.exe') -Destination (Join-Path $dest 'balerx.exe')
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not $userPath) { $userPath = '' }
  if ($userPath -notlike "*$dest*") {
    $updated = if ($userPath) { "$userPath;$dest" } else { $dest }
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    Write-Host "Added $dest to your user PATH. Open a new terminal before running balerx."
  }
  Write-Host "Installed $dest\balerx.exe"
  Write-Host "Run: balerx --version"
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
