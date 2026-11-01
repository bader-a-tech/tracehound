#!/bin/bash
set -euo pipefail
deb="$(realpath "$1")"
smoke="$(realpath "$2")"
version="$3"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tracehound-package-check.XXXXXX")"
dpkg-deb --info "$deb"
dpkg-deb --extract "$deb" "$work/unpacked"
test -s "$work/unpacked/opt/tracehound/licenses/catalog.json"
desktop-file-validate "$work/unpacked/usr/share/applications/io.github.bader-a-tech.tracehound.desktop"

# This check runs on a disposable native runner and uses the same package
# manager dependency resolution as an end-user installation.
if [ -e /opt/tracehound ] || dpkg-query -W -f='${Status}' tracehound 2>/dev/null | grep -q '^install ok installed$'; then
  echo 'Package check requires a clean disposable runner, not an existing installation' >&2
  exit 1
fi
attempted=false
cleanup() {
  if $attempted; then sudo apt-get remove -y tracehound; fi
}
trap cleanup EXIT
attempted=true
sudo apt-get install -y "$deb"
test -s /opt/tracehound/licenses/catalog.json
"$smoke" /opt/tracehound "v$version" "$work/backend verification"
xvfb-run -a /opt/tracehound/tracehound-desktop --smoke-test
sudo apt-get remove -y tracehound
attempted=false
test ! -e /opt/tracehound/tracehound-desktop
