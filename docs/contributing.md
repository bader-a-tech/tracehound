# Contributor guide

Backend and native-application development uses Rust or C++. The existing Go
sensor remains available as a compatibility engine. New work does not require
Python. Ordinary analysis runs the Rust backend directly, without a Go child
process or a network service.

## Development setup

Use Rust 1.88 or newer for the backend and Rust 1.95 or newer for the optional
native GUI. Go 1.26 is needed only when building or comparing the legacy sensor.
The Cargo lockfile is committed. GUI dependencies are optional for CLI-only
builds; Linux GUI builds need the X11/Wayland/OpenGL development packages listed
in the CI workflow.

```sh
cargo build --locked --manifest-path tools/capture-eval/Cargo.toml
cargo run --locked --manifest-path tools/capture-eval/Cargo.toml --bin tracehound-eval -- analyze /path/to/capture.pcap --json
cargo run --locked --manifest-path tools/capture-eval/Cargo.toml --features gui --bin tracehound-desktop
```

Windows executables use an `.exe` suffix. Keep local build output, downloaded
captures, stress fixtures, and private reports under ignored `dist/` or a private
directory outside the checkout. Do not install packet drivers as part of tests.
Live-capture tests that need an existing capture helper or operating-system
permission are explicitly configured and are separate from offline checks.

## Checks that match the change

Run the relevant unit/integration targets while developing, then the repository
checks before requesting review:

```sh
cargo fmt --manifest-path tools/capture-eval/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets --features gui -- -D warnings
cargo test --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets --features gui
```

Changes to the compatibility sensor also need `go vet ./...` and `go test ./...`.
`TRACEHOUND_TEST_SENSOR` selects an already-built sensor for compatibility tests.
Tests requiring loopback sockets must run in an environment that permits local
binding; a sandbox denial is an environment failure rather than evidence of a
decoder defect. Do not silently skip mandatory checks after a failure.

Tests should exercise meaningful behaviour: independent wire fields, original
packet references, malformed input, cancellation, process cleanup, bounded
memory, and externally sourced expectations. A detector's own packet builder and
output must not be its only oracle. Protocol conformance claims must name the
covered variants and any remaining limits.

## Captures and ground truth

Real captures must never be committed. Publish source URLs, exact byte lengths,
SHA-256 digests, provenance, terms, and reviewed expectations in a corpus
manifest. Download the bytes only into an ignored local directory. Do not run
captured content or replay it onto a network during offline evaluation.

Distinguish three cases: explicit positive/negative labels, publisher-labelled
traffic with incomplete rule-level labels, and observation-only traces. Keep
missed and unexpected findings in the report; investigate them before changing
labels, thresholds, or exceptions. A successful parser run does not establish
detection accuracy.

Per-rule recall describes the supplied labelled behaviours. Benign alert rates
require an identified normal host, reviewed monitored interval, declared rule
scope, source, and explicit assumptions. Do not infer host-hours from a trace's
first/last packet or idle gaps alone. Repeated alert records and unique finding
groups must remain separate. Unreviewed exposure yields null rates, and these
rates are not a true-negative-based false-positive probability.

## Reports, cases, and privacy

Preserve versioned formats, strict validation, and refusal to overwrite existing
outputs. A completed report or database must not survive as a usable partial
result after cancellation or an input/execution failure. The original capture
stays immutable; case databases store verified references and decoded facts.
Packet exports authenticate the source and selected offsets before copying
bytes. Preserve section/interface identity, timestamps, and link types.

Host correlation and process snapshots have different evidentiary strength from
directly decoded packet facts. A live tuple match does not prove which process
owned historical traffic. Keep those distinctions visible in the UI and exports.
Reports may contain addresses, domains, source paths, and selected packet bytes;
review an export before sharing it outside its intended audience.

## Performance and native packages

Use the [resource harness](performance.md) for large-input measurements. Generated
1/5/10 GiB stress captures are separate from the independent accuracy corpus.
Publish only clean-revision runs with executable hashes and stated cache/memory
sampling limits. Measure Rust analysis, the legacy sensor, and case indexing
separately. Never replace a failed safety check with an invented benchmark value.

Packaging changes run native PR checks for Windows MSI, macOS app/DMG, and Linux
Debian packages. They verify installed/extracted backends and launch a real GUI
with `--smoke-test` on disposable runners; Linux uses Xvfb. Local contributor
tests do not launch or capture the user's desktop implicitly. The optional rich
GUI smoke mode renders an actual case and verified packet view for review.

Preserve upstream copyright, license, and font notices. Update the notice ledger
when a dependency's version or missing-workspace-license mapping changes. PR
packages use unsigned paths without release credentials; signing and notarization
are explicit release configuration, documented in the release guide. CI builds
and uploads reviewable artifacts, and only tag/manual release jobs can assemble
a draft. Publication remains a separate maintainer action.
