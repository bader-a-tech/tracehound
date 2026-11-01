# Install and release the desktop application

Release archives contain the complete local application: the `tracehound` sensor,
the `tracehound-eval` command-line backend, and the `tracehound-desktop` native GUI.
Extract the archive into one folder and keep the three executables together. The
desktop application discovers the adjacent sensor automatically. Capture analysis
does not require a compiler, a browser server, or a demo capture.

## Choose an archive

The [releases page](https://github.com/baldoseri/tracehound/releases) contains
published versions. Builds use native runners for each supported combination:

| Archive suffix | Computer | Build and verification environment |
| --- | --- | --- |
| `linux-amd64.tar.gz` | Linux, Intel or AMD 64-bit | Ubuntu 24.04 x64 |
| `linux-arm64.tar.gz` | Linux, ARM 64-bit | Ubuntu 24.04 ARM64 |
| `darwin-amd64.tar.gz` | macOS, Intel | macOS 15 Intel |
| `darwin-arm64.tar.gz` | macOS, Apple silicon | macOS 15 ARM64 |
| `windows-amd64.zip` | Windows, Intel or AMD 64-bit | Windows hosted x64 runner |

These are the environments used to compile and verify the bundles; older
operating-system compatibility is not implied. Linux desktop use requires a
working X11 or Wayland session and OpenGL libraries. Offline capture analysis does
not require administrator access. Live capture has platform-specific driver and
permission requirements described in the [capture guide](capture-evaluation.md).
Windows and macOS builds do not yet include publisher code signing. The
application is distributed as a portable archive rather than an operating-system
installer.

Verify the downloaded archive against the accompanying `SHA256SUMS.txt` before
extracting it. On Linux, use `sha256sum --check SHA256SUMS.txt` in a folder containing
the release archives. On macOS, use `shasum -a 256 --check SHA256SUMS.txt`. If only
one archive was downloaded, missing-file messages for the other platforms are
expected; the line for the chosen archive must say `OK`. On Windows, compare
`Get-FileHash .\tracehound-vVERSION-windows-amd64.zip -Algorithm SHA256` with its
line in the checksum file.

Open `tracehound-desktop` (`tracehound-desktop.exe` on Windows), then drop your PCAP
or PCAPNG into the window or select its path. Use the bundled CLI for scripts and
labelled evaluation. For example, from the extracted folder:

```sh
./tracehound-eval analyze /path/to/capture.pcap --sensor ./tracehound --json
```

On Windows:

```powershell
.\tracehound-eval.exe analyze C:\Captures\traffic.pcap --sensor .\tracehound.exe --json
```

Captures are read locally. The optional external validation corpus downloads
captures only when explicitly requested; its provenance and current results are
documented in [validation-corpus.md](validation-corpus.md).

## Build a candidate release

The [release workflow](https://github.com/baldoseri/tracehound/blob/main/.github/workflows/release.yml) runs on a pushed `v*` tag
or a manual dispatch for an existing tag. The tag must use `vMAJOR.MINOR.PATCH`,
with an optional prerelease suffix, and the Rust package version must match the
tag without `v`. Update `tools/capture-eval/Cargo.toml` and its lockfile together
before tagging.

Each native job runs the Go checks, builds the sensor with the exact release tag,
and builds the Rust CLI and GUI with the committed Cargo lockfile. Linux jobs
install the desktop development libraries on their disposable runners. The Rust
tests run against the newly built sensor. The stage contains the three binaries,
`LICENSE`, `README.md`, `SECURITY.md`, `docs/`, and `licenses/`; no captured traffic is included.
The Rust `release-notices` helper reads offline Cargo metadata for the native
target and the Go dependency module list, then copies upstream license, copyright, and notice
files from the dependency sources already present after the builds. Its catalog
records package versions, declared Rust licenses, source locations, and source
archive links. Missing notice files fail the release job for review. Third-party
copyright and authorship notices are preserved verbatim. Version-specific,
digest-checked workspace license fallbacks cover crates whose archives omit those
documents. The catalog records any such exception. Font licenses and standard
library notices are included. Windows release builds link the Rust C runtime
statically to avoid requiring a separate Visual C++ runtime installation.

The job then creates an archive, extracts it into a directory containing spaces,
and runs the Rust `release-smoke` helper against the extracted binaries. That
helper checks both version strings and constructs a valid Ethernet/IPv4/TCP PCAP
directly from wire fields, with IP and TCP checksums. It requires the packaged
backend to identify 128 distinct destination ports from `10.7.0.99` to
`10.7.0.10` as `TH-0003`, then requires labelled evaluation to report one match,
no misses, and no unexpected findings. The desktop executable is checked for
presence and compiled on its target platform; this headless release step does
not exercise window interactions.

The independent fixture verifies packaging and integration. It does not establish
field detection accuracy. The separate external corpus provides that additional,
limited evidence without including real capture bytes in the repository.

Only after every native bundle passes does the assembly job combine SHA-256
checksums and create or update a **draft** GitHub release. A maintainer reviews the
notes, native GUI behaviour, installation requirements, and corpus report before
publishing that draft. A workflow run alone does not publish a release.

For a local packaging check, build `release-smoke` and run it against an extracted
bundle. The final argument must name a new directory; existing contents are never
reused or removed:

```sh
cargo run --release --locked --bin release-smoke --manifest-path tools/capture-eval/Cargo.toml -- /path/to/unpacked-bundle vVERSION /path/to/new-verification-directory
```
