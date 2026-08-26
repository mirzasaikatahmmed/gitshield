#!/usr/bin/env bash
# Bootstrap installer for gitshield: downloads the latest release binary for
# this OS/arch from GitHub, verifies its checksum, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/mirzasaikatahmmed/gitshield/main/install.sh | sh
#
# Once installed, `gitshield update` handles future updates in place —
# this script only needs to run once, to bootstrap the binary itself.
set -eu

REPO="mirzasaikatahmmed/gitshield"
PREFIX="${GITSHIELD_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "gitshield: unsupported architecture: $arch" >&2; exit 1 ;;
esac

case "$os" in
  linux|darwin) ;;
  *) echo "gitshield: unsupported OS: $os" >&2; exit 1 ;;
esac

command -v curl >/dev/null 2>&1 || { echo "gitshield: curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "gitshield: tar is required" >&2; exit 1; }

tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -m1 '"tag_name"' \
  | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [ -z "$tag" ]; then
  echo "gitshield: could not determine the latest release tag for $REPO" >&2
  echo "gitshield: (has a release been published yet? see https://github.com/$REPO/releases)" >&2
  exit 1
fi

asset="gitshield-${os}-${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$asset"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "gitshield: downloading $asset ($tag)..."
curl -fsSL "$url" -o "$tmpdir/$asset"
curl -fsSL "$url.sha256" -o "$tmpdir/$asset.sha256"

echo "gitshield: verifying checksum..."
(
  cd "$tmpdir"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$asset.sha256"
  else
    sha256sum -c "$asset.sha256"
  fi
) || { echo "gitshield: checksum verification FAILED — refusing to install" >&2; exit 1; }

tar -xzf "$tmpdir/$asset" -C "$tmpdir"

mkdir -p "$PREFIX"
install -m 0755 "$tmpdir/gitshield-${os}-${arch}" "$PREFIX/gitshield"

echo "gitshield: installed -> $PREFIX/gitshield"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *)
    echo "gitshield: NOTE: $PREFIX is not on your PATH. Add this to your shell profile:"
    echo "  export PATH=\"$PREFIX:\$PATH\""
    ;;
esac

echo "gitshield: run 'gitshield update' in the future to update in place."
