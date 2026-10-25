# Install the balerx CLI for the current user. No administrator rights.
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

function Test-BalerxPathEntry([string]$PathValue, [string]$Directory) {
  if ([string]::IsNullOrWhiteSpace($PathValue) -or [string]::IsNullOrWhiteSpace($Directory)) {
    return $false
  }
  $wanted = $Directory.Trim().TrimEnd('\')
  foreach ($part in ($PathValue -split ';')) {
    $entry = $part.Trim().TrimEnd('\')
    if ($entry -and ($entry -ieq $wanted)) {
      return $true
    }
  }
  return $false
}

function Add-BalerxPathEntry([string]$PathValue, [string]$Directory) {
  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    return $Directory
  }
  return ($PathValue.TrimEnd(';') + ';' + $Directory)
}

function Get-BalerxReleaseBase([string]$Repo) {
  if ($env:BALERX_RELEASE_BASE_URL) { return $env:BALERX_RELEASE_BASE_URL }
  if ($env:BALERX_VERSION) {
    $version = $env:BALERX_VERSION
    if ($version.StartsWith('v')) { $version = $version.Substring(1) }
    return "https://github.com/$Repo/releases/download/v$version"
  }
  return "https://github.com/$Repo/releases/latest/download"
}

function Confirm-BalerxSignature([string]$Repo, [string]$Base, [string]$Work) {
  $cosign = Get-Command cosign -ErrorAction SilentlyContinue
  if (-not $cosign) {
    Write-Host "cosign is not installed. Checked SHA256SUMS only."
    return
  }
  $bundle = Join-Path $Work 'SHA256SUMS.bundle'
  try {
    Invoke-WebRequest -Uri "$Base/SHA256SUMS.bundle" -OutFile $bundle -UseBasicParsing
  } catch {
    Write-Error "cosign is installed, but SHA256SUMS.bundle was not downloaded."
    exit 1
  }
  $identity = "^https://github.com/$Repo/\.github/workflows/release\.yml@refs/tags/v"
  $sums = Join-Path $Work 'SHA256SUMS'
  & cosign verify-blob --bundle $bundle --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity-regexp $identity $sums
  if ($LASTEXITCODE -ne 0) {
    Write-Error "Signature verification failed for SHA256SUMS."
    exit 1
  }
}

# Banner matches balerx-cli banner.rs for v0.1.8. Pipes, NO_COLOR, and a code page other than UTF-8 or OEM US stay plain ASCII.
function Write-BalerxBanner {
  $cols = 80
  if ($env:COLUMNS -match '^\d+$') {
    $parsed = [int]$env:COLUMNS
    if ($parsed -gt 0) { $cols = $parsed }
  } elseif ($Host.UI -and $Host.UI.RawUI) {
    try {
      $width = $Host.UI.RawUI.WindowSize.Width
      if ($width -gt 0) { $cols = $width }
    } catch {}
  }
  $plain = $false
  if ($null -ne $env:NO_COLOR) { $plain = $true }
  try {
    if ([Console]::IsOutputRedirected) { $plain = $true }
  } catch {
    $plain = $true
  }
  $unicode = $false
  if (-not $plain) {
    $cp = 0
    try { $cp = [Console]::OutputEncoding.CodePage } catch {}
    if ($cp -eq 65001 -or $cp -eq 437) { $unicode = $true }
  }
  if ($plain -or -not $unicode) {
    if ($cols -lt 70) {
      Write-Host '>< Balerx Gate  v0.1.8'
    } else {
      Write-Host 'Balerx Gate'
      Write-Host 'Security for AI agents'
      Write-Host 'v0.1.8'
    }
    return
  }
  $truecolor = $env:COLORTERM -eq 'truecolor' -or $env:COLORTERM -eq '24bit'
  $esc = [string][char]27
  $narrowTrue = @(
    '\033[38;2;176;18;46m▟█▙\033[0m Balerx Gate  \033[38;2;176;18;46mv0.1.8\033[0m'
  )
  $narrowAnsi = @(
    '\033[38;5;124m▟█▙\033[0m Balerx Gate  \033[38;5;124mv0.1.8\033[0m'
  )
  $wideTrue = @(
    ' \033[38;2;176;18;46m        ▄██▄      \033[0m  \033[38;2;142;16;36m█\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▄\033[0m \033[38;2;153;16;39m▄\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m▄\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m \033[38;2;187;35;62m█\033[38;2;190;39;66m▀\033[38;2;192;43;69m▀\033[38;2;195;46;72m▄\033[0m \033[38;2;199;53;79m█\033[0m  \033[38;2;207;64;89m█\033[0m  '
    ' \033[38;2;176;18;46m      ▄██████▄    \033[0m  \033[38;2;142;16;36m█\033[0m  \033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[0m    \033[38;2;187;35;62m█\033[0m  \033[38;2;195;46;72m█\033[0m \033[38;2;199;53;79m▀\033[38;2;202;57;82m▄\033[38;2;204;61;86m▄\033[38;2;207;64;89m▀\033[0m  '
    ' \033[38;2;176;18;46m    ▄██████████▄  \033[0m  \033[38;2;142;16;36m█\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▄\033[0m \033[38;2;153;16;39m█\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[0m  \033[38;2;187;35;62m█\033[38;2;190;39;66m▀\033[38;2;192;43;69m▀\033[38;2;195;46;72m▄\033[0m  \033[38;2;202;57;82m█\033[38;2;204;61;86m█\033[0m   '
    ' \033[38;2;176;18;46m  ▄███▀▀  ▀▀████▄ \033[0m  \033[38;2;142;16;36m█\033[0m  \033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[0m    \033[38;2;187;35;62m█\033[0m \033[38;2;192;43;69m▀\033[38;2;195;46;72m▄\033[0m \033[38;2;199;53;79m▄\033[38;2;202;57;82m▀\033[38;2;204;61;86m▀\033[38;2;207;64;89m▄\033[0m  '
    ' \033[38;2;176;18;46m █████      ▀████ \033[0m  \033[38;2;142;16;36m█\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▀\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[38;2;171;17;44m▀\033[0m \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m \033[38;2;187;35;62m█\033[0m  \033[38;2;195;46;72m█\033[0m \033[38;2;199;53;79m█\033[0m  \033[38;2;207;64;89m█\033[0m  '
    ' \033[38;2;176;18;46m ████        ▀███ \033[0m  \033[38;2;142;16;36m▄\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m▄\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m▄\033[0m \033[38;2;164;17;42m█\033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[38;2;171;17;44m█\033[0m \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m            '
    ' \033[38;2;176;18;46m ███▀       ▄████ \033[0m  \033[38;2;142;16;36m█\033[0m    \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[0m               '
    ' \033[38;2;176;18;46m ███          ▀██ \033[0m  \033[38;2;142;16;36m█\033[0m \033[38;2;146;16;37m▀\033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[0m             '
    ' \033[38;2;176;18;46m ███     ▄█▄   ██ \033[0m  \033[38;2;142;16;36m█\033[0m  \033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[0m               '
    ' \033[38;2;176;18;46m ███     ▀███▄▄██ \033[0m  \033[38;2;142;16;36m▀\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▀\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m            '
    ' \033[38;2;176;18;46m ███       ██████ \033[0m                                 '
    ' \033[38;2;176;18;46m████        ██████\033[0m  \033[38;2;168;132;138mSecurity\033[0m \033[38;2;168;132;138mfor\033[0m \033[38;2;168;132;138mAI\033[0m \033[38;2;168;132;138magents\033[0m   \033[38;2;176;18;46mv0.1.8\033[0m'
  )
  $wideAnsi = @(
    ' \033[38;5;124m        ▄██▄      \033[0m  \033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▄\033[0m \033[38;5;88m▄\033[38;5;124m█\033[38;5;124m█\033[38;5;124m▄\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m \033[38;5;125m█\033[38;5;125m▀\033[38;5;125m▀\033[38;5;161m▄\033[0m \033[38;5;167m█\033[0m  \033[38;5;167m█\033[0m  '
    ' \033[38;5;124m      ▄██████▄    \033[0m  \033[38;5;88m█\033[0m  \033[38;5;88m█\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[0m    \033[38;5;125m█\033[0m  \033[38;5;161m█\033[0m \033[38;5;167m▀\033[38;5;167m▄\033[38;5;167m▄\033[38;5;167m▀\033[0m  '
    ' \033[38;5;124m    ▄██████████▄  \033[0m  \033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▄\033[0m \033[38;5;88m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[0m  \033[38;5;125m█\033[38;5;125m▀\033[38;5;125m▀\033[38;5;161m▄\033[0m  \033[38;5;167m█\033[38;5;167m█\033[0m   '
    ' \033[38;5;124m  ▄███▀▀  ▀▀████▄ \033[0m  \033[38;5;88m█\033[0m  \033[38;5;88m█\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[0m    \033[38;5;125m█\033[0m \033[38;5;125m▀\033[38;5;161m▄\033[0m \033[38;5;167m▄\033[38;5;167m▀\033[38;5;167m▀\033[38;5;167m▄\033[0m  '
    ' \033[38;5;124m █████      ▀████ \033[0m  \033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▀\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m \033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m▀\033[0m \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m \033[38;5;125m█\033[0m  \033[38;5;161m█\033[0m \033[38;5;167m█\033[0m  \033[38;5;167m█\033[0m  '
    ' \033[38;5;124m ████        ▀███ \033[0m  \033[38;5;88m▄\033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[0m \033[38;5;88m▄\033[38;5;124m█\033[38;5;124m█\033[38;5;124m▄\033[0m \033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[0m \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m            '
    ' \033[38;5;124m ███▀       ▄████ \033[0m  \033[38;5;88m█\033[0m    \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[0m               '
    ' \033[38;5;124m ███          ▀██ \033[0m  \033[38;5;88m█\033[0m \033[38;5;88m▀\033[38;5;88m█\033[0m \033[38;5;88m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[0m             '
    ' \033[38;5;124m ███     ▄█▄   ██ \033[0m  \033[38;5;88m█\033[0m  \033[38;5;88m█\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[0m               '
    ' \033[38;5;124m ███     ▀███▄▄██ \033[0m  \033[38;5;88m▀\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▀\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m            '
    ' \033[38;5;124m ███       ██████ \033[0m                                 '
    ' \033[38;5;124m████        ██████\033[0m  \033[38;5;138mSecurity\033[0m \033[38;5;138mfor\033[0m \033[38;5;138mAI\033[0m \033[38;5;138magents\033[0m   \033[38;5;124mv0.1.8\033[0m'
  )
  if ($cols -lt 70 -and $truecolor) { $chosen = $narrowTrue }
  elseif ($cols -lt 70) { $chosen = $narrowAnsi }
  elseif ($truecolor) { $chosen = $wideTrue }
  else { $chosen = $wideAnsi }
  foreach ($line in $chosen) {
    Write-Host ($line.Replace('\033', $esc))
  }
}

if ($env:BALERX_INSTALL_LIB -eq '1') {
  return
}

$repo = if ($env:BALERX_REPO) { $env:BALERX_REPO } elseif ($env:BALERX_GITHUB_REPO) { $env:BALERX_GITHUB_REPO } else { 'wrjewski/balerx' }
$target = Get-BalerxTarget
$asset = "balerx-$target.zip"
$base = Get-BalerxReleaseBase $repo
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
  Confirm-BalerxSignature $repo $base $work
  Expand-Archive -Path $assetPath -DestinationPath $work -Force
  $dest = Join-Path $env:LOCALAPPDATA 'balerx'
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item -Force -Path (Join-Path $work 'balerx.exe') -Destination (Join-Path $dest 'balerx.exe')
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not (Test-BalerxPathEntry $userPath $dest)) {
    [Environment]::SetEnvironmentVariable('Path', (Add-BalerxPathEntry $userPath $dest), 'User')
  }
  # $env:Path is the process environment, including when this file is run with iex.
  if (-not (Test-BalerxPathEntry $env:Path $dest)) {
    $env:Path = Add-BalerxPathEntry $env:Path $dest
  }
  Write-BalerxBanner
  Write-Host ""
  Write-Host "Installed $dest\balerx.exe"
  Write-Host "balerx is ready to use in this window. New terminals will pick it up automatically."
  Write-Host ""
  Write-Host "Next steps:"
  Write-Host "  balerx setup"
  Write-Host "  balerx scan"
  Write-Host "  balerx scan --json scan.json --sarif scan.sarif --html report.html"
  Write-Host "  `$env:BALERX_API_KEY = `"<key>`""
  Write-Host "  balerx upload --api-url https://balerxgate.com --scan scan.json"
  Write-Host "Create an ingest key in Settings or Onboarding. It is shown once. See https://balerxgate.com/docs/upload"
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
