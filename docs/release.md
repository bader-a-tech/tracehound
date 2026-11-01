# Install and release Tracehound

The native application analyses local PCAP/PCAPNG files with the Rust backend.
Installers and portable bundles also retain the legacy `tracehound` Go executable
for explicit compatibility comparisons. Ordinary Rust analysis requires no Go
runtime, compiler, browser server, or packet capture driver.

## Choose a package

Published artifacts are listed on the
[releases page](https://github.com/bader-a-tech/tracehound/releases). Current
packages are prepared unsigned because publisher credentials are not configured.
Their filenames and accompanying `*-signing.json` describe the actual signing
state. PR artifacts are always unsigned and are review builds, rather than
published releases.

| Platform | Native package | Portable alternative | Native build/test environment |
| --- | --- | --- | --- |
| Windows amd64 | Per-user `.msi` | `.zip` | Windows x64 hosted runner |
| macOS Intel | `Tracehound.app` in `.dmg` | `.tar.gz` | macOS 15 Intel |
| macOS Apple silicon | `Tracehound.app` in `.dmg` | `.tar.gz` | macOS 15 ARM64 |
| Linux amd64 | `.deb` with desktop launcher | `.tar.gz` | Ubuntu 24.04 x64 |
| Linux arm64 | `.deb` with desktop launcher | `.tar.gz` | Ubuntu 24.04 ARM64 |

These are the build/test environments; older operating-system compatibility is
not implied. Linux packages require glibc 2.39 or newer, an X11/Wayland session,
and OpenGL libraries. Their dependency declarations include the distinct Xcursor,
XInput, Xlib/XCB, XKB/X11, and Wayland/EGL runtime libraries used by the GUI.
The Debian package is not a distro-independent installer.

Verify the selected download against `SHA256SUMS.txt`. Linux can use
`sha256sum --check SHA256SUMS.txt`, macOS `shasum -a 256 --check SHA256SUMS.txt`, and
Windows `Get-FileHash .\PACKAGE.msi -Algorithm SHA256`. If only one artifact was
downloaded, checksum commands may report the other files missing; the selected
file's line must match. Signing metadata is checksummed with the packages.

On Windows, run the MSI to install under the current user's
`LocalAppData\Programs\Tracehound` and add a Start menu shortcut. It needs no
administrator access. It registers an Open With choice for PCAP/PCAPNG without
replacing an existing default application. Uninstall removes application files;
separately stored captures, cases, and history remain user data.

On macOS, open the DMG and drag Tracehound to Applications. The app includes
backend executables in `Contents/MacOS` and documentation/notices in
`Contents/Resources`. An unsigned/ad-hoc package does not have verified publisher
identity or notarization, so macOS may require an explicit user trust decision.
Open a capture inside the app or drop it into the app window. Finder Open With
registration is not claimed where the GUI framework does not forward that event.

On compatible Debian/Ubuntu systems, install the `.deb` with the system package
manager. It adds the application under `/opt/tracehound` and a desktop-menu
launcher/icon. A working graphical session is required for the GUI; the CLI also
works without a window. Live capture permissions and optional helpers are
separate requirements described in the [capture guide](capture-evaluation.md).
No installer automatically installs Wireshark, Npcap, or packet drivers.

For a portable bundle, extract everything into one folder. The GUI, CLI,
documentation, notices, and optional legacy sensor stay together. For example:

```sh
./tracehound-eval analyze /path/to/capture.pcap --json
```

```powershell
.\tracehound-eval.exe analyze C:\Captures\traffic.pcap --json
```

`--engine sensor --sensor PATH` selects the legacy engine explicitly. Default
analysis remains local Rust. External corpus/feed downloads occur only when
requested; their sources and limits are documented separately.

## Native build and review checks

The [release workflow](https://github.com/bader-a-tech/tracehound/blob/main/.github/workflows/release.yml)
builds all five native targets. PR runs build reviewable unsigned installers and
archives with read-only repository permissions; they never create a release or
receive signing credentials. Tag/manual runs require an existing version tag
matching the Rust package version and can assemble a draft after all checks pass.
No workflow run publishes a draft automatically.

The pipeline runs Go and Rust/GUI checks, builds the real binaries, and preserves
`LICENSE`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, documentation, and dependency notices.
`release-notices` collects upstream license/copyright/font files and standard
library notices from installed sources. Version-specific missing-workspace
license fallbacks are digest-checked and recorded with their source/exception in
the catalog. Upstream attribution is retained verbatim.

Windows packages use the WiX 3 tools already present on native hosted runners.
The payload uses stable component identities and per-user registry keypaths;
Windows Rust release binaries link the C runtime statically. macOS uses native
`codesign`, `sips`, `iconutil`, and `hdiutil`; Linux uses `dpkg-deb` and a desktop
entry. A dependency-free Rust helper renders launcher assets. These scripts do
not install build tools on the user's computer.

Native package checks exercise the actual artifact:

- Windows silently installs the MSI on its disposable runner, verifies the
  installed backend and real GUI startup, then uninstalls it.
- macOS verifies/mounts the DMG, checks the app's structure/signature/notices, and
  executes its backend and GUI from inside the mounted app.
- Linux extracts the Debian package, validates its desktop entry, verifies the
  backend, and renders the GUI under Xvfb.

`--smoke-test` opens the real native renderer, verifies a nonblank rendered frame,
and exits. The separate product-validation job renders an actual externally
captured case and verified packet view. Local checks do not launch a window on
the user's desktop implicitly.

`release-smoke` constructs valid independent wire-level PCAP bytes and requires
the packaged Rust analyzer to identify the independent 128-port input as `TH-0003`, evaluate labels,
create/reopen an indexed case, and export/reopen verified evidence. The legacy
sensor is checked separately. Rust evidence describes the qualifying emission
window (20 through 128 ports); legacy end-of-file evidence can report all 128.
This is integration evidence, not a claim of field
accuracy; the independent corpus and its retained benign findings provide
additional, limited evidence.

Archives are also extracted into paths containing spaces and checked. Checksums
are computed after signatures and final packaging mutations. Only after every
native job passes can a tag/manual run assemble a draft. A maintainer reviews
native installation, rendered UI evidence, corpus results, notices, and release
notes before publication.

## Optional signing and notarization

Unsigned builds require no signing secrets. To enable signing for future trusted
tag/manual release jobs, configure repository secrets explicitly. Do not put
private keys, certificate passwords, or notarization passwords in source control.
PR jobs ignore these credentials even when they exist.

| Platform | Secret or variable | Purpose |
| --- | --- | --- |
| Windows | `WINDOWS_CERTIFICATE_PFX_BASE64` | Base64-encoded publisher code-signing PFX |
| Windows | `WINDOWS_CERTIFICATE_PASSWORD` | PFX password |
| Windows | `WINDOWS_TIMESTAMP_URL` repository variable, optional | HTTPS RFC 3161 timestamp service; defaults to DigiCert |
| macOS | `MACOS_CERTIFICATE_P12_BASE64` | Base64-encoded Developer ID Application certificate/private key |
| macOS | `MACOS_CERTIFICATE_PASSWORD` | PKCS#12 password |
| macOS | `MACOS_SIGNING_IDENTITY` | Exact Developer ID Application signing identity |
| macOS | `MACOS_NOTARY_APPLE_ID` | Apple account used for notarization |
| macOS | `MACOS_NOTARY_TEAM_ID` | Developer team identifier |
| macOS | `MACOS_NOTARY_PASSWORD` | App-specific notarization password |

Windows imports the certificate into the disposable runner's current-user store,
signs/verifies the three executables and MSI, and removes the imported key and
PFX afterward. macOS creates a temporary keychain, restores the original search
list, signs the executable leaves and app with hardened runtime/timestamps,
submits the app for notarization, staples its ticket, then builds/signs/notarizes
and staples the DMG. The workflow verifies an `Accepted` notarization response
rather than treating command completion as acceptance. Temporary certificate and
keychain files are cleaned up.

If no certificate is supplied, Windows produces an `unsigned.msi`; macOS uses an
ad-hoc integrity signature and produces an `unsigned.dmg`, with
`ad_hoc_only: true`. This does not claim publisher trust. Configured-but-invalid
credentials or rejected notarization fail the job rather than silently labelling
an artifact signed. Linux packages currently carry checksums rather than package
repository signing.

Certificate acquisition and account setup remain maintainer responsibilities.
The scripts follow the native platform tools and GitHub's
[temporary Apple certificate/keychain workflow](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications).
Their unsigned path remains usable until credentials are deliberately configured.
