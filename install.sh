#!/bin/sh
# Install the balerx CLI for the current user. No admin rights.
# Asset names and the download path match packaging/install.sh.
# BALERX_INSTALL_LIB=1 loads balerx_target and balerx_asset without downloading.
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
    # Public releases are GNU for both Linux architectures.
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
echo "Installed ${dest}/balerx"
case ":${PATH}:" in
  *":${dest}:"*) ;;
  *) echo "Add ${dest} to PATH to run balerx from a new terminal." ;;
esac
echo "Run: balerx --version"
