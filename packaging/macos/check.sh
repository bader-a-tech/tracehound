#!/bin/bash
set -euo pipefail
dmg="$1"
smoke="$2"
version="$3"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tracehound-package-check.XXXXXX")"
mount="$work/mount"
mkdir "$mount"
attached=false
cleanup() { if $attached; then hdiutil detach "$mount"; fi; }
trap cleanup EXIT
hdiutil verify "$dmg"
hdiutil attach -nobrowse -noautoopen -mountpoint "$mount" "$dmg"
attached=true
app="$mount/Tracehound.app"
plutil -lint "$app/Contents/Info.plist"
codesign --verify --strict "$app"
test -s "$app/Contents/Resources/licenses/catalog.json"
"$smoke" "$app/Contents/MacOS" "v$version" "$work/backend verification"
"$app/Contents/MacOS/tracehound-desktop" --smoke-test
