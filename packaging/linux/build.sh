#!/bin/bash
set -euo pipefail
stage="$1"
output="$2"
version="$3"
arch="$4"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tracehound-package.XXXXXX")"
package="$work/package"
mkdir -p "$package/DEBIAN" "$package/opt/tracehound" "$package/usr/share/applications" "$package/usr/share/icons/hicolor/scalable/apps"
cp -a "$stage/." "$package/opt/tracehound/"
cp "$root/packaging/linux/io.github.bader-a-tech.tracehound.desktop" "$package/usr/share/applications/"
cp "$root/packaging/tracehound.svg" "$package/usr/share/icons/hicolor/scalable/apps/io.github.bader-a-tech.tracehound.svg"
installed_kib="$(du -sk "$package/opt/tracehound" | awk '{print $1}')"
cat > "$package/DEBIAN/control" <<EOF
Package: tracehound
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: Tracehound contributors <bader-a-tech@users.noreply.github.com>
Homepage: https://github.com/bader-a-tech/tracehound
Installed-Size: $installed_kib
Depends: libc6 (>= 2.39), libgcc-s1, libx11-6, libx11-xcb1, libxcursor1, libxi6, libxrandr2, libxkbcommon0, libxkbcommon-x11-0, libwayland-client0, libwayland-cursor0, libwayland-egl1, libegl1, libgl1
Description: Local network capture investigation
 A passive network sensor, Rust capture backend, and native desktop interface.
 Analyse local PCAP/PCAPNG files, inspect evidence, and evaluate labelled traces.
 Capture drivers and third-party capture helpers are not installed by this package.
EOF
chmod 0755 "$package/DEBIAN" "$package/opt/tracehound/tracehound" "$package/opt/tracehound/tracehound-eval" "$package/opt/tracehound/tracehound-desktop"
deb="$output/tracehound-v$version-linux-$arch.deb"
test ! -e "$deb"
dpkg-deb --root-owner-group --build "$package" "$deb"
printf '{"schema_version":1,"platform":"linux","architecture":"%s","application_binaries_signed":false,"package_signed":false,"notarized":false}\n' "$arch" > "$output/tracehound-v$version-linux-$arch-signing.json"
