#!/bin/bash
set -euo pipefail
stage="$1"
output="$2"
version="$3"
arch="$4"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tracehound-package.XXXXXX")"
app="$work/Tracehound.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
identity="-"
signed=false
notarized=false
keychain=""
certificate=""
original_keychains=()
cleanup() {
  if [ -n "$keychain" ]; then
    security list-keychains -d user -s "${original_keychains[@]}" || true
    security delete-keychain "$keychain" || true
  fi
  if [ -n "$certificate" ]; then rm -f -- "$certificate"; fi
}
trap cleanup EXIT
if [ -n "${MACOS_CERTIFICATE_P12_BASE64:-}" ]; then
  : "${MACOS_CERTIFICATE_PASSWORD:?Certificate password is missing}"
  : "${MACOS_SIGNING_IDENTITY:?Developer ID Application identity is missing}"
  while IFS= read -r line; do
    line="${line#*\"}"; line="${line%\"*}"; original_keychains+=("$line")
  done < <(security list-keychains -d user)
  certificate="$work/certificate.p12"
  printf '%s' "$MACOS_CERTIFICATE_P12_BASE64" | /usr/bin/base64 -D > "$certificate"
  keychain="$work/build.keychain-db"
  keychain_password="$(uuidgen)"
  printf '::add-mask::%s\n' "$keychain_password"
  security create-keychain -p "$keychain_password" "$keychain"
  security set-keychain-settings -lut 21600 "$keychain"
  security unlock-keychain -p "$keychain_password" "$keychain"
  security import "$certificate" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign -t cert -f pkcs12 -k "$keychain"
  security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain"
  security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
  identity="$MACOS_SIGNING_IDENTITY"
  signed=true
fi
sign() {
  if $signed; then codesign --force --options runtime --timestamp --sign "$identity" "$1";
  else codesign --force --sign - "$1"; fi
  codesign --verify --strict "$1"
}
for name in tracehound tracehound-eval tracehound-desktop; do
  sign "$stage/$name"
  cp "$stage/$name" "$app/Contents/MacOS/$name"
done
for path in README.md LICENSE SECURITY.md docs licenses; do cp -R "$stage/$path" "$app/Contents/Resources/"; done
numeric_version="${version%%-*}"
sed -e "s/@VERSION@/$version/g" -e "s/@BUILD_VERSION@/$numeric_version/g" "$root/packaging/macos/Info.plist" > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
iconset="$work/tracehound.iconset"
mkdir "$iconset"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$stage/tracehound.png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
  twice=$((size*2))
  sips -z "$twice" "$twice" "$stage/tracehound.png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/tracehound.icns"
sign "$app"
notary_requested=false
notarize() {
  local response="$work/notary-response.json"
  xcrun notarytool submit "$1" --apple-id "$MACOS_NOTARY_APPLE_ID" --team-id "$MACOS_NOTARY_TEAM_ID" --password "$MACOS_NOTARY_PASSWORD" --wait --timeout 20m --output-format json > "$response"
  jq -e '.status == "Accepted"' "$response" >/dev/null || { echo 'Apple notarization was not accepted; inspect the private notary log before retrying.' >&2; exit 1; }
}
if [ -n "${MACOS_NOTARY_APPLE_ID:-}${MACOS_NOTARY_TEAM_ID:-}${MACOS_NOTARY_PASSWORD:-}" ]; then
  $signed || { echo 'Notarization requires Developer ID signing credentials' >&2; exit 1; }
  : "${MACOS_NOTARY_APPLE_ID:?Notarization Apple ID is missing}"
  : "${MACOS_NOTARY_TEAM_ID:?Notarization team ID is missing}"
  : "${MACOS_NOTARY_PASSWORD:?Notarization app-specific password is missing}"
  notary_requested=true
  ditto -c -k --keepParent "$app" "$work/application.zip"
  notarize "$work/application.zip"
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
  notarized=true
fi
state=unsigned
if $signed; then state=signed; fi
if $notarized; then state=notarized; fi
dmg="$output/tracehound-v$version-darwin-$arch-$state.dmg"
test ! -e "$dmg"
mkdir "$work/image"
cp -R "$app" "$work/image/Tracehound.app"
ln -s /Applications "$work/image/Applications"
hdiutil create -ov -format UDZO -volname 'Tracehound' -srcfolder "$work/image" "$dmg"
if $signed; then
  codesign --force --timestamp --sign "$identity" "$dmg"
  codesign --verify "$dmg"
fi
if $notary_requested; then
  notarize "$dmg"
  xcrun stapler staple "$dmg"
  xcrun stapler validate "$dmg"
fi
printf '{"schema_version":1,"platform":"darwin","architecture":"%s","application_binaries_signed":%s,"package_signed":%s,"notarized":%s,"ad_hoc_only":%s}\n' "$arch" "$signed" "$signed" "$notarized" "$([ "$signed" = false ] && echo true || echo false)" > "$output/tracehound-v$version-darwin-$arch-signing.json"
echo "Built $state application disk image"
