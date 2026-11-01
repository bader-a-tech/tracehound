# Analyse and evaluate your captures

`tracehound-eval` is a Rust command-line tool and reusable backend for analysing
user-supplied PCAP and PCAPNG files with the Tracehound sensor. An optional native
Rust desktop application uses the same background-job backend. The CLI has two
workflows:

- **Analyse a capture:** collect findings and evidence without needing labels.
- **Evaluate labelled captures:** compare the findings with your expected
  behaviours and report missed and unexpected detections.

Neither workflow depends on the demo capture. The sensor processes your capture
locally. Real captures remain outside version control, as described in the
[capture policy](../SECURITY.md#captures).

## Build

The CLI and backend require Rust 1.85 or newer. The optional desktop GUI requires
Rust 1.95 or newer. Install a supported Rust toolchain and the Tracehound sensor.
From the repository root, build the CLI and sensor:

```sh
go build -o bin/tracehound ./cmd/tracehound
cargo build --release --locked --manifest-path tools/capture-eval/Cargo.toml
```

The Rust executable is `tools/capture-eval/target/release/tracehound-eval`. Windows
builds of the Rust executable have an `.exe` suffix. On Windows, build the sensor
with `go build -o bin/tracehound.exe ./cmd/tracehound` and pass that `.exe` path to
`--sensor`. The examples below assume `tracehound-eval` is on your `PATH`;
otherwise use its full path.

The tool runs the Go sensor as a child process. `--sensor` selects that executable;
when omitted, it looks for `tracehound` on `PATH`. No Python is required.

## Desktop application

Build and launch the optional native GUI from the repository root:

```sh
cargo run --release --locked --features gui --bin tracehound-desktop --manifest-path tools/capture-eval/Cargo.toml
```

The built executable is
`tools/capture-eval/target/release/tracehound-desktop`, with an `.exe` suffix on
Windows. GUI dependencies are optional; ordinary CLI builds do not include them.

Drop your PCAP or PCAPNG file into the window, or paste its full path, then choose
**Analyse capture**. The application looks for the Tracehound sensor beside the
desktop executable and in checkout build locations such as `bin`, then falls back
to `PATH`. Set its full path in **Analysis settings** if needed. That panel also
provides the reporting severity, timeout, alert limit, custom rules, and internal
network settings.

Analysis runs in the background. The window shows whether it is starting,
analysing, cancelling, completed, cancelled, timed out, or failed. The live alert
record count measures sensor findings read, not packets processed or a completion
percentage. **Cancel analysis** stops the job without marking a partial result
complete. Closing the window during analysis requests cancellation and waits for
the sensor to stop; an active export is allowed to finish before closing.

After analysis, search findings by host, domain, rule, or evidence, filter by
severity, and select a finding to inspect its explanation and measurements. The
analysis reporting floor determines which severities were collected; a view
filter cannot recover lower-severity findings excluded from the report.

Use **Export report** to save the complete analysis as JSON. View filters do not
change the exported findings. Export preserves existing files, so choose a new
filename when a report already exists. This desktop version analyses one capture
at a time; labelled suites remain available through the CLI.

## Analyse a capture

```sh
tracehound-eval analyze /captures/office.pcapng --sensor ./bin/tracehound
```

The text report lists findings, their severity, source and destination, and the
number of occurrences. It retains the sensor's evidence in its structured report.
Successful analysis does not mean that the capture is benign: it means the sensor
finished processing it. Without labels, the tool makes no claim about precision,
recall, or false positives.

Write the machine-readable report to a new JSON file:

```sh
tracehound-eval analyze /captures/office.pcapng --sensor ./bin/tracehound --output office-report.json
```

Use `--json` to send JSON to standard output instead of the text report. `--output`
always writes JSON and refuses to replace an existing file.

Optional sensor configuration applies to either workflow:

```sh
tracehound-eval analyze /captures/office.pcapng --sensor ./bin/tracehound --rules ./rules --home-nets 10.0.0.0/8,192.168.0.0/16 --min-severity medium
```

The default reporting floor is `low`. Informational inventory events are counted
as ignored when they fall below the selected floor. Accepted severity names are
`info`, `low`, `medium`, `high`, and `critical`.

## Evaluate labelled captures

Create a JSON suite describing the captures and the behaviours you expect. For
example, save this as `/captures/office-suite.json`:

```json
{
  "schema_version": 1,
  "captures": [
    {
      "name": "Workstation beacon investigation",
      "capture": "office.pcapng",
      "expected": [
        {
          "rule_id": "TH-0001",
          "src": "10.0.0.42",
          "dst": "198.51.100.23"
        }
      ],
      "benign_hosts": ["10.0.0.10", "10.0.0.11"],
      "min_severity": "low"
    },
    {
      "name": "Benign baseline",
      "capture": "baseline.pcap",
      "expected": [],
      "benign_hosts": ["10.0.0.10"],
      "min_severity": "medium"
    }
  ]
}
```

Capture paths in a suite are relative to the suite file's directory, so the
example resolves to `/captures/office.pcapng` and `/captures/baseline.pcap`.
Absolute capture paths are also accepted. Paths supplied through command-line
options, such as `--rules`, are relative to the current working directory.

Run the suite:

```sh
tracehound-eval evaluate /captures/office-suite.json --sensor ./bin/tracehound --output office-evaluation.json
```

Every capture requires an `expected` list. An explicit empty list asserts that no
findings at or above its severity floor are expected; it does not mean that the
capture is unlabelled. Use `analyze` when the expected outcome is unknown.

An expectation matches `rule_id` and source address, plus the destination when
provided. Omit `dst` when any destination is acceptable. IPv4 and IPv6 addresses
are supported. Each capture has its own severity floor, defaulting to `low`;
`--min-severity` is only available for `analyze`.

The manifest rejects unknown fields, unsupported schema versions, duplicate case
names and expectations, and contradictions such as a source appearing in both
the expected behaviours and `benign_hosts`.

## Interpret the result

A labelled capture passes only when all expectations match and no unexpected
findings appear at or above its severity floor. Any qualifying finding attributed
to a listed benign source is also recorded as a benign-host violation.

Alerts that repeat as evidence accumulates are grouped by rule, source, and
destination. Reports retain an occurrence count so repeats do not inflate the
number of unique findings. The report lists matched expectations, missed
expectations, unexpected findings, and benign-host violations separately.

- **Precision:** matched unique findings divided by all unique findings.
- **Recall:** matched expectations divided by the number of expected behaviours.

A metric is JSON `null` when its denominator is zero. These measurements describe
the supplied labels; they are not a guarantee of detection quality on other
traffic. The tool does not invent a true-negative count or a false-positive rate.

Exit codes are suitable for CI and batch scripts:

| Code | Meaning |
|---|---|
| `0` | Analysis completed, or every labelled capture passed |
| `1` | Labelled evaluation found missed or unexpected detections |
| `2` | Invalid input, unavailable sensor, sensor failure, timeout, or report error |
| `130` | Interrupted analysis, after sensor cancellation and cleanup |

The default timeout is 300 seconds per capture. Set `--timeout 0` to disable it or
choose a larger number of seconds for large captures. `--max-alerts` limits the
number of sensor alerts collected per capture and defaults to 1,000,000. Exceeding
a limit produces an error rather than a partial success report.

Ctrl-C requests cancellation, waits for the sensor process to stop, and exits
with code `130`. On Unix, SIGTERM and SIGHUP follow the same cleanup path. An
interrupted analysis does not write a completed report.

## Reusable background-job backend

`tracehound_eval::runtime::CaptureJob` owns execution for both the CLI and desktop
application. `CaptureJob::analyze` starts an unlabelled capture analysis;
`CaptureJob::evaluate` starts a labelled case. Each returns an immediately claimed
job while its worker launches the sensor, parses output, and assembles the report.

- `snapshot()` returns cheap lifecycle metadata, elapsed milliseconds, alert
  records read, unique findings received so far, output bytes read, and any
  terminal error. Finding counts are provisional until the sensor succeeds.
  Output bytes describe the sensor's JSONL stream, not capture bytes or packet
  progress.
- `cancel()` requests cancellation without blocking the caller. Repeated
  cancellation is safe; a terminal job remains terminal.
- `try_result()` polls for a completed result without waiting.
- `wait()` blocks until the job finishes and returns its report or a typed error.

Terminal reports are shared through `Arc`, so polling does not clone the complete
finding list. Execution failures, timeouts, and cancellation remain distinct from
a completed labelled evaluation whose detections do not match expectations. The
worker kills and reaps its sensor and joins output readers before publishing a
terminal result. Dropping an active job requests cancellation without blocking;
applications must keep running until cleanup completes before exiting. The
desktop application handles that close sequence.

The existing `analyze` and `evaluate` functions remain available when a caller
already has sensor alerts. Versioned JSON reports retain findings and evidence
for investigation and export.

## Streaming and memory use

The Rust job backend groups alert records as they arrive. It retains the latest
eligible record for each rule/source/destination combination and its occurrence
count, instead of buffering every raw alert until the sensor finishes. Records
below the reporting floor contribute to counters without being retained. A later
below-floor update does not replace evidence collected above the floor.

Memory therefore scales with unique retained findings and their evidence. It is
not a constant memory bound: captures with many unique findings can still use
substantial memory. The existing `--max-alerts` guard still counts every alert
record, including repeated findings and ignored informational events. A limit,
parse error, cancellation, or sensor failure does not produce a completed report.

Library clients receiving alerts incrementally can use `AlertAccumulator`:
construct it with the reporting severity, transfer each alert through `push`,
read its cheap counters, then consume it with `finish` or `finish_evaluation`.
Rejected eligible records leave its counters and findings unchanged. Labelled
evaluation requires the accumulator's reporting floor to match the case's floor.
The slice-based APIs and JSON report schema remain compatible.

## Saved reports, history, and comparisons

Use `--output PATH` to export an analysis, evaluation, suite, or corpus report. An existing
path is never replaced. `--save-history` additionally stores a validated report in
private local history; `--history-dir DIRECTORY` selects a different location.
The default uses `LOCALAPPDATA`, then `XDG_STATE_HOME`, with a home-directory state
folder fallback. On Unix, history directories are restricted to the owner and
saved files use owner-only permissions. Windows files inherit the chosen local
directory's access controls.

```sh
tracehound-eval analyze capture.pcap --sensor ./bin/tracehound --save-history --output first.json
tracehound-eval history
tracehound-eval open first.json
tracehound-eval compare first.json second.json
```

`open` validates a report without executing the sensor or reopening its capture.
Imports reject unsupported versions, inconsistent counters, and evaluation
summaries that do not match their labels and findings. Comparison reports added,
removed, changed, and unchanged finding groups. Suite comparisons preserve case
identity, so the same rule and endpoints in two different cases remain separate.
Stored reports include evidence, addresses, and capture paths; apply the same
privacy care as to the original investigation. History contains reports rather
than copies of capture files.

Labelled suites now use `suite::SuiteJob`. Its snapshot includes the current
case, total and completed cases, alert records, and unique findings. A detection
mismatch completes normally with `passed: false`; cancellation and execution
failures return no completed suite report. The CLI and GUI share that lifecycle.

## Rust capture preparation and protocol evidence

The Rust offline path prepares real PCAP/PCAPNG traffic before passing it to the
sensor. IPv4 and IPv6 fragment reassembly is bounded by memory, age, and the number
of active fragment sets. Overlaps, incomplete sets, expired sets, and exhausted
budgets are discarded and counted. Report `enrichment` records input/output
packet counts, fragment statistics, protocol observations, and warnings. Mixed
link types within one PCAPNG are rejected rather than decoded under one assumed
link type.

Bounded TCP buffering handles segmented ClientHello/ServerHello records and the
first cleartext HTTP/1.x request per flow. TLS observations include client/server
fingerprints and the server name where available; HTTP observations include the
method, host, ordered-header/cookie fingerprint, and header count. Encrypted HTTP,
HTTP/2, and HTTP/3 headers are not decoded. The TLS server algorithm is checked
against the independently published RFC 8448 handshake bytes, and HTTP component
hashes have independent reference checks. These tests establish the covered
wire formats, rather than universal protocol conformance. Both the Rust and Go
server implementations match the normal TLS 1.3, no-ALPN handshake in RFC 8448
section 3. Rust follows the published JA4 field rules for unusual ALPN values;
the legacy Go path differs for some such encodings, so these implementations are
not claimed interchangeable across every ALPN case.

Offline DNS scoring uses the full Public Suffix List embedded by the locked
`psl` dependency, including private suffixes. It scores captured UDP DNS queries
from the configured home networks and makes no online DNS lookups. The normal
YAML rule policy still controls `TH-0002` thresholds, exceptions, severity, and
enablement. The direct Go replay and native live sensor paths retain their
earlier fragment handling and smaller suffix table; they do not silently inherit
the Rust offline preparation.

## Source-attributed TLS-pair feeds

Known client/server fingerprint pairs are opt-in. `--pair-feed PATH` loads a
local, versioned feed whose entries identify both fingerprints, an association,
source URL, classification, and confidence. A match emits `TH-0008` with that
provenance. Shared TLS implementations can produce the same pair, so a match
calls for investigation of the surrounding activity.

```sh
tracehound-eval feed-update new-pair-feed.json
tracehound-eval analyze capture.pcap --sensor ./bin/tracehound --pair-feed new-pair-feed.json --json
```

`feed-update` explicitly fetches the publisher's public mapping over HTTPS,
records its SHA-256 digest and terms, and writes a new feed without overwriting
an existing one. Its importer selects source-attributed entries for named
malware/C2 associations and does not classify ordinary browsers as malicious.
Publisher data is not bundled in the application, and no feed is downloaded
during ordinary capture analysis. Review the source terms and entries before
using an imported feed for a different purpose.

## Live capture and bounded recording

On Linux, the native live session uses the Go sensor and a loopback-only read API
for current statistics, device inventory, flows, and a bounded recent-findings
view. Listing interfaces needs no capture privilege; starting packet capture
requires the operating system's packet-capture permission, such as `CAP_NET_RAW`.
The backend distinguishes starting, running, stopping, stopped, and failed states.

Windows and macOS use an existing `dumpcap` installation for
**record-then-analyse**. The backend discovers common Wireshark locations or
accepts an explicit helper path, lists the helper's capture interfaces, and
records with a size/time limit and optional capture filter. The defaults are
64 MiB and one hour. Stopping finishes the recording and starts offline analysis;
cancelling stops the operation without publishing a completed analysis. A
completed recording can be saved explicitly to a new capture path.

The helper and capture driver are separate system dependencies. On Windows,
Wireshark commonly uses Npcap. Tracehound does not install either automatically.
Recording status does not imply real-time detection: findings appear after the
recording ends and offline analysis succeeds. Existing offline captures remain
usable without these dependencies.

## External validation and release bundles

```sh
tracehound-eval corpus dist/corpus --sensor ./bin/tracehound --json --output corpus-report.json
```

The corpus command fetches or verifies pinned independent captures and evaluates
their explicit labels. `--manifest PATH` selects a custom reviewed manifest.
Each source retains its provenance, digest, terms, and home-network assumptions
in the JSON report. Corpus reports can be saved in history, reopened, and compared;
the GUI retains their source provenance alongside the evaluation. Ctrl-C cancels
between files and during buffered reads; a blocked HTTPS request is bounded by a
30-second timeout. Completed verified downloads remain cached, while partial
downloads created by the cancelled operation are removed. The current three-case result and its coverage limits are
documented in [validation-corpus.md](validation-corpus.md). Capture bytes remain
outside source control and release archives.

The [release process](release.md) builds portable sensor/CLI/GUI bundles natively
on Linux, macOS, and Windows, includes dependency notices and checksums, and
checks the extracted artifacts against independent wire-level PCAP labels. It
assembles a draft for review before publication.

## Development checks

```sh
cargo fmt --manifest-path tools/capture-eval/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets
```

Check and link the optional GUI without opening a window:

```sh
cargo clippy --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets --features gui -- -D warnings
cargo build --locked --manifest-path tools/capture-eval/Cargo.toml --features gui --bin tracehound-desktop
```

The CLI integration tests use `TRACEHOUND_TEST_SENSOR` to locate a built sensor.
Set it to the absolute executable path to run those checks locally. CI builds the
sensor and runs these checks on Linux, macOS, and Windows. Its packet fixtures are
generated by the Rust tests and do not depend on Tracehound's demo generator.
Background-job tests exercise progress, cancellation, process cleanup, and
terminal outcomes. CI also checks and builds the GUI on all three operating
systems without launching it.
