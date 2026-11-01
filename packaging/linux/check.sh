#!/bin/bash
set -euo pipefail
deb="$1"
smoke="$2"
version="$3"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tracehound-package-check.XXXXXX")"
dpkg-deb --info "$deb"
dpkg-deb --extract "$deb" "$work/unpacked"
test -s "$work/unpacked/opt/tracehound/licenses/catalog.json"
desktop-file-validate "$work/unpacked/usr/share/applications/io.github.bader-a-tech.tracehound.desktop"
"$smoke" "$work/unpacked/opt/tracehound" "v$version" "$work/backend verification"
xvfb-run -a "$work/unpacked/opt/tracehound/tracehound-desktop" --smoke-test
