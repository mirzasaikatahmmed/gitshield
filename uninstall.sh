#!/usr/bin/env bash
# Bootstrap uninstaller for gitshield, for use without a working gitshield
# binary (e.g. a broken install). If gitshield still runs, prefer:
#   gitshield uninstall [--purge]
#
#   curl -fsSL https://raw.githubusercontent.com/mirzasaikatahmmed/gitshield/main/uninstall.sh | sh -s -- [--purge]
set -eu

purge=0
for arg in "$@"; do
  case "$arg" in
    --purge) purge=1 ;;
  esac
done

candidates="${GITSHIELD_INSTALL_DIR:-$HOME/.local/bin}/gitshield /usr/local/bin/gitshield"

removed=0
for c in $candidates; do
  if [ -f "$c" ]; then
    rm -f "$c"
    echo "gitshield: removed $c"
    removed=1
  fi
done
if [ "$removed" -eq 0 ]; then
  echo "gitshield: no installed binary found in: $candidates"
fi

if [ "$purge" -eq 1 ]; then
  if [ -d "$HOME/.gitshield" ]; then
    rm -rf "$HOME/.gitshield"
    echo "gitshield: removed $HOME/.gitshield (config, signatures, AND the audit log)"
  fi
else
  echo "gitshield: kept ~/.gitshield (config + audit log). Re-run with --purge to remove it."
fi
