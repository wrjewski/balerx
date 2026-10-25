#!/bin/sh
# Install the balerx CLI for the current user. No admin rights.
# Internal tests set BALERX_INSTALL_LIB=1 and call balerx_target.
set -eu

balerx_target() {
  os=${BALERX_INSTALL_OS:-$(uname -s)}
  arch=${BALERX_INSTALL_ARCH:-$(uname -m)}
  case "$os" in
    Linux | linux) os_name=linux ;;
    Darwin | macOS | macos) os_name=darwin ;;
    MINGW* | MSYS* | CYGWIN* | Windows | windows) os_name=windows ;;
    *)
      echo "Unsupported operating system: $os" >&2
      return 1
      ;;
  esac
  case "$arch" in
    x86_64 | amd64 | AMD64 | x64) arch_name=x86_64 ;;
    aarch64 | arm64 | ARM64) arch_name=aarch64 ;;
    *)
      echo "Unsupported architecture: $arch" >&2
      return 1
      ;;
  esac
  case "$os_name" in
    # Public releases are GNU for both Linux architectures. See wrjewski/balerx release.yml.
    linux) echo "${arch_name}-unknown-linux-gnu" ;;
    darwin) echo "${arch_name}-apple-darwin" ;;
    windows) echo "${arch_name}-pc-windows-msvc" ;;
  esac
}

balerx_asset() {
  target=$1
  case "$target" in
    *windows*) echo "balerx-${target}.zip" ;;
    *) echo "balerx-${target}.tar.gz" ;;
  esac
}

balerx_release_base() {
  repo=$1
  if [ -n "${BALERX_RELEASE_BASE_URL:-}" ]; then
    printf '%s\n' "$BALERX_RELEASE_BASE_URL"
    return 0
  fi
  if [ -n "${BALERX_VERSION:-}" ]; then
    version=${BALERX_VERSION#v}
    printf 'https://github.com/%s/releases/download/v%s\n' "$repo" "$version"
    return 0
  fi
  printf 'https://github.com/%s/releases/latest/download\n' "$repo"
}

# Verify SHA256SUMS with keyless cosign when the tool is installed.
# Without cosign, the caller has already checked the archive checksum.
balerx_verify_signature() {
  repo=$1
  base=$2
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is not installed. Checked SHA256SUMS only."
    return 0
  fi
  if ! curl --fail --location --silent --show-error "${base}/SHA256SUMS.bundle" --output SHA256SUMS.bundle; then
    echo "cosign is installed, but SHA256SUMS.bundle was not downloaded." >&2
    return 1
  fi
  identity="^https://github.com/${repo}/\\.github/workflows/release\\.yml@refs/tags/v"
  cosign verify-blob \
    --bundle SHA256SUMS.bundle \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-identity-regexp "$identity" \
    SHA256SUMS
}

# Banner matches balerx-cli banner.rs for v0.1.7. Pipes, NO_COLOR, and a non-UTF-8 locale stay plain ASCII.
balerx_banner() {
  cols=${COLUMNS:-}
  if [ -z "$cols" ]; then
    cols=$(tput cols 2>/dev/null || true)
  fi
  case "$cols" in
    ''|*[!0-9]*) cols=80 ;;
  esac
  plain=0
  if [ ! -t 1 ] || [ -n "${NO_COLOR+x}" ]; then
    plain=1
  fi
  unicode=0
  if [ "$plain" = 0 ]; then
    charmap=$(locale charmap 2>/dev/null || printf '%s' UTF-8)
    case "$charmap" in
      UTF-8|utf8|utf-8|UTF8) unicode=1 ;;
    esac
  fi
  if [ "$plain" = 1 ] || [ "$unicode" = 0 ]; then
    if [ "$cols" -lt 70 ]; then
      printf '%s\n' '>< Balerx Gate  v0.1.7'
    else
      printf '%s\n' 'Balerx Gate' 'Security for AI agents' 'v0.1.7'
    fi
    return 0
  fi
  truecolor=0
  case "${COLORTERM:-}" in
    truecolor|24bit) truecolor=1 ;;
  esac
  if [ "$cols" -lt 70 ]; then
    if [ "$truecolor" = 1 ]; then
  printf '\033[38;2;176;18;46m▟█▙\033[0m Balerx Gate  \033[38;2;176;18;46mv0.1.7\033[0m\n'
    else
  printf '\033[38;5;124m▟█▙\033[0m Balerx Gate  \033[38;5;124mv0.1.7\033[0m\n'
    fi
    return 0
  fi
  if [ "$truecolor" = 1 ]; then
  printf ' \033[38;2;176;18;46m        ▄██▄      \033[0m  \033[38;2;142;16;36m█\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▄\033[0m \033[38;2;153;16;39m▄\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m▄\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m \033[38;2;187;35;62m█\033[38;2;190;39;66m▀\033[38;2;192;43;69m▀\033[38;2;195;46;72m▄\033[0m \033[38;2;199;53;79m█\033[0m  \033[38;2;207;64;89m█\033[0m  \n'
  printf ' \033[38;2;176;18;46m      ▄██████▄    \033[0m  \033[38;2;142;16;36m█\033[0m  \033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[0m    \033[38;2;187;35;62m█\033[0m  \033[38;2;195;46;72m█\033[0m \033[38;2;199;53;79m▀\033[38;2;202;57;82m▄\033[38;2;204;61;86m▄\033[38;2;207;64;89m▀\033[0m  \n'
  printf ' \033[38;2;176;18;46m    ▄██████████▄  \033[0m  \033[38;2;142;16;36m█\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▄\033[0m \033[38;2;153;16;39m█\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[0m  \033[38;2;187;35;62m█\033[38;2;190;39;66m▀\033[38;2;192;43;69m▀\033[38;2;195;46;72m▄\033[0m  \033[38;2;202;57;82m█\033[38;2;204;61;86m█\033[0m   \n'
  printf ' \033[38;2;176;18;46m  ▄███▀▀  ▀▀████▄ \033[0m  \033[38;2;142;16;36m█\033[0m  \033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[0m    \033[38;2;176;18;46m█\033[0m    \033[38;2;187;35;62m█\033[0m \033[38;2;192;43;69m▀\033[38;2;195;46;72m▄\033[0m \033[38;2;199;53;79m▄\033[38;2;202;57;82m▀\033[38;2;204;61;86m▀\033[38;2;207;64;89m▄\033[0m  \n'
  printf ' \033[38;2;176;18;46m █████      ▀████ \033[0m  \033[38;2;142;16;36m█\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▀\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m \033[38;2;164;17;42m█\033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[38;2;171;17;44m▀\033[0m \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m \033[38;2;187;35;62m█\033[0m  \033[38;2;195;46;72m█\033[0m \033[38;2;199;53;79m█\033[0m  \033[38;2;207;64;89m█\033[0m  \n'
  printf ' \033[38;2;176;18;46m ████        ▀███ \033[0m  \033[38;2;142;16;36m▄\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m▄\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m▄\033[0m \033[38;2;164;17;42m█\033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[38;2;171;17;44m█\033[0m \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m            \n'
  printf ' \033[38;2;176;18;46m ███▀       ▄████ \033[0m  \033[38;2;142;16;36m█\033[0m    \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[0m               \n'
  printf ' \033[38;2;176;18;46m ███          ▀██ \033[0m  \033[38;2;142;16;36m█\033[0m \033[38;2;146;16;37m▀\033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[38;2;155;16;40m█\033[38;2;157;16;40m█\033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[0m             \n'
  printf ' \033[38;2;176;18;46m ███     ▄█▄   ██ \033[0m  \033[38;2;142;16;36m█\033[0m  \033[38;2;148;16;38m█\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[0m               \n'
  printf ' \033[38;2;176;18;46m ███     ▀███▄▄██ \033[0m  \033[38;2;142;16;36m▀\033[38;2;144;16;36m█\033[38;2;146;16;37m█\033[38;2;148;16;38m▀\033[0m \033[38;2;153;16;39m█\033[0m  \033[38;2;160;17;41m█\033[0m  \033[38;2;166;17;43m█\033[38;2;169;17;44m█\033[0m  \033[38;2;176;18;46m█\033[38;2;178;21;49m█\033[38;2;180;25;52m█\033[38;2;183;28;56m█\033[0m            \n'
  printf ' \033[38;2;176;18;46m ███       ██████ \033[0m                                 \n'
  printf ' \033[38;2;176;18;46m████        ██████\033[0m  \033[38;2;168;132;138mSecurity\033[0m \033[38;2;168;132;138mfor\033[0m \033[38;2;168;132;138mAI\033[0m \033[38;2;168;132;138magents\033[0m   \033[38;2;176;18;46mv0.1.7\033[0m\n'
  else
  printf ' \033[38;5;124m        ▄██▄      \033[0m  \033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▄\033[0m \033[38;5;88m▄\033[38;5;124m█\033[38;5;124m█\033[38;5;124m▄\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m \033[38;5;125m█\033[38;5;125m▀\033[38;5;125m▀\033[38;5;161m▄\033[0m \033[38;5;167m█\033[0m  \033[38;5;167m█\033[0m  \n'
  printf ' \033[38;5;124m      ▄██████▄    \033[0m  \033[38;5;88m█\033[0m  \033[38;5;88m█\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[0m    \033[38;5;125m█\033[0m  \033[38;5;161m█\033[0m \033[38;5;167m▀\033[38;5;167m▄\033[38;5;167m▄\033[38;5;167m▀\033[0m  \n'
  printf ' \033[38;5;124m    ▄██████████▄  \033[0m  \033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▄\033[0m \033[38;5;88m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[0m  \033[38;5;125m█\033[38;5;125m▀\033[38;5;125m▀\033[38;5;161m▄\033[0m  \033[38;5;167m█\033[38;5;167m█\033[0m   \n'
  printf ' \033[38;5;124m  ▄███▀▀  ▀▀████▄ \033[0m  \033[38;5;88m█\033[0m  \033[38;5;88m█\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m \033[38;5;124m█\033[0m    \033[38;5;124m█\033[0m    \033[38;5;125m█\033[0m \033[38;5;125m▀\033[38;5;161m▄\033[0m \033[38;5;167m▄\033[38;5;167m▀\033[38;5;167m▀\033[38;5;167m▄\033[0m  \n'
  printf ' \033[38;5;124m █████      ▀████ \033[0m  \033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▀\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m \033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m▀\033[0m \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m \033[38;5;125m█\033[0m  \033[38;5;161m█\033[0m \033[38;5;167m█\033[0m  \033[38;5;167m█\033[0m  \n'
  printf ' \033[38;5;124m ████        ▀███ \033[0m  \033[38;5;88m▄\033[38;5;88m█\033[38;5;88m█\033[38;5;88m█\033[0m \033[38;5;88m▄\033[38;5;124m█\033[38;5;124m█\033[38;5;124m▄\033[0m \033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[0m \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m            \n'
  printf ' \033[38;5;124m ███▀       ▄████ \033[0m  \033[38;5;88m█\033[0m    \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[0m               \n'
  printf ' \033[38;5;124m ███          ▀██ \033[0m  \033[38;5;88m█\033[0m \033[38;5;88m▀\033[38;5;88m█\033[0m \033[38;5;88m█\033[38;5;124m█\033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[0m             \n'
  printf ' \033[38;5;124m ███     ▄█▄   ██ \033[0m  \033[38;5;88m█\033[0m  \033[38;5;88m█\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[0m               \n'
  printf ' \033[38;5;124m ███     ▀███▄▄██ \033[0m  \033[38;5;88m▀\033[38;5;88m█\033[38;5;88m█\033[38;5;88m▀\033[0m \033[38;5;88m█\033[0m  \033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;124m█\033[0m  \033[38;5;124m█\033[38;5;125m█\033[38;5;125m█\033[38;5;125m█\033[0m            \n'
  printf ' \033[38;5;124m ███       ██████ \033[0m                                 \n'
  printf ' \033[38;5;124m████        ██████\033[0m  \033[38;5;138mSecurity\033[0m \033[38;5;138mfor\033[0m \033[38;5;138mAI\033[0m \033[38;5;138magents\033[0m   \033[38;5;124mv0.1.7\033[0m\n'
  fi
}

if [ "${BALERX_INSTALL_LIB:-}" = "1" ]; then
  return 0 2>/dev/null || exit 0
fi

repo=${BALERX_REPO:-${BALERX_GITHUB_REPO:-wrjewski/balerx}}
target=$(balerx_target)
asset=$(balerx_asset "$target")
base=$(balerx_release_base "$repo")
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
cd "$workdir"

echo "Downloading ${asset}"
if ! curl --fail --location --silent --show-error "${base}/SHA256SUMS" --output SHA256SUMS; then
  echo "No Balerx Gate release checksum was found." >&2
  echo "Install from source until a release tag exists:" >&2
  echo "  cargo install --git https://github.com/${repo}.git --path balerx-sensor/crates/balerx-cli" >&2
  exit 1
fi
curl --fail --location --silent --show-error "${base}/${asset}" --output "$asset"

expected=$(awk -v name="$asset" '$2 == name { print $1; exit }' SHA256SUMS)
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$asset" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "$asset" | awk '{ print $1 }')
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "Checksum verification failed for ${asset}." >&2
  exit 1
fi
balerx_verify_signature "$repo" "$base"

case "$asset" in
  *.zip)
    unzip -q "$asset"
    binary=balerx.exe
    ;;
  *)
    tar --extract --gzip --file "$asset"
    binary=balerx
    ;;
esac

dest=${HOME}/.local/bin
mkdir -p "$dest"
chmod 755 "$binary"
mv "$binary" "${dest}/balerx"
balerx_banner
echo ""
echo "Installed ${dest}/balerx"
case ":${PATH}:" in
  *":${dest}:"*)
    echo "balerx is ready to use in this window. New terminals will pick it up automatically."
    ;;
  *)
    echo "This window does not have ${dest} on PATH yet. Run:"
    echo "  export PATH=\"${dest}:\$PATH\""
    echo "New terminals pick it up after that directory is in your shell profile."
    ;;
esac
echo ""
echo "Next steps:"
echo "  balerx setup"
echo "  balerx scan"
echo "  balerx scan --json scan.json --sarif scan.sarif --html report.html"
echo "  export BALERX_API_KEY=<key>"
echo "  balerx upload --api-url https://balerxgate.com --scan scan.json"
echo "Create an ingest key in Settings or Onboarding. It is shown once. See https://balerxgate.com/docs/upload"
