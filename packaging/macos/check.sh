#!/bin/bash
set -euo pipefail
dmg="$1"
smoke="$2"
version="$3"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tracehound-package-check.XXXXXX")"
mount="$work/mount"
mkdir "$mount"
attached=false
cleanup() {
  local status=$?
  trap - EXIT
  if $attached; then
    # Native launch services can briefly retain the mounted application after
    # its process exits. Retry only this cleanup step after successful checks.
    local attempts=1
    if [ "$status" -eq 0 ]; then attempts=10; fi
    local attempt
    for ((attempt=1; attempt<=attempts; attempt++)); do
      if hdiutil detach "$mount"; then
        attached=false
        break
      fi
      if [ "$attempt" -lt "$attempts" ]; then sleep 1; fi
    done
    if $attached; then
      echo "Unable to detach the verification disk image after $attempts attempt(s)." >&2
      if [ "$status" -eq 0 ]; then status=1; fi
    fi
  fi
  exit "$status"
}
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
