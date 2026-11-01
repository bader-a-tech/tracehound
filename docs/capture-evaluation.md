# Analyse and evaluate your captures

`tracehound-eval` reads users' PCAP and PCAPNG files locally with the Rust analysis
engine. The native desktop application uses the same backend. Analysis needs no
labels; labelled evaluation compares observed behaviours with reviewed ground
truth. Indexed investigations add host timelines, connection views, and verified
references back to the immutable original capture. See the
[investigation guide](investigations.md) for those workflows.

Real captures stay outside source control. Follow the
[capture policy](../SECURITY.md#captures) when storing or sharing evidence.

## Build and choose an engine

The CLI/backend requires Rust 1.88 or newer. The optional GUI requires Rust 1.95
or newer. Build the CLI from the repository root:

```sh
cargo build --release --locked --manifest-path tools/capture-eval/Cargo.toml --bin tracehound-eval
```

The executable is `tools/capture-eval/target/release/tracehound-eval`, with an
`.exe` suffix on Windows. Examples assume it is on `PATH`; otherwise use its full
path. Ordinary Rust analysis requires no Go executable, browser server, packet
capture driver, or network access.

A compatibility engine remains available when comparing existing Go sensor
behaviour. Build it with Go 1.26 and explicitly select it:

```sh
go build -o bin/tracehound ./cmd/tracehound
tracehound-eval analyze /captures/office.pcapng --engine sensor --sensor ./bin/tracehound
```

On Windows, build/select `bin/tracehound.exe`. Supplying `--sensor PATH` also
selects the sensor engine. For a comparison, keep capture, rules, network
assumptions, and severity floor identical and retain each engine's metadata and
coverage limits. Go and Rust results are not claimed identical for every protocol
or unusual fingerprint encoding.

## Desktop application

```sh
cargo run --release --locked --features gui --bin tracehound-desktop --manifest-path tools/capture-eval/Cargo.toml
```

Drop a PCAP/PCAPNG into the window or select its path, then start analysis or
build an indexed investigation. A positional capture path selects that input
without starting analysis automatically. Settings provide reporting severity,
timeout, alert limits, rules, home networks, and an optional local TLS-pair feed.
The default Rust path does not require the adjacent legacy sensor.

Analysis and case preparation run in background jobs. Progress distinguishes
packet/byte work, provisional finding counts, completed results, cancellation,
and failure. Search/filter findings, inspect their explanation and evidence,
reopen saved reports/cases, compare results, and inspect an indexed host's
connections and timeline. The investigation guide explains verified packet views
and exports. A reporting floor excludes lower-severity findings from collection;
a view filter cannot recover them later.

Closing an active job requests cancellation and waits for cleanup. Exports never
replace existing files. View filters do not alter the complete JSON report.
The portable archives and native installers are described in the
[release guide](release.md).

## Analyse a capture

```sh
tracehound-eval analyze /captures/office.pcapng
tracehound-eval analyze /captures/office.pcapng --json --output office-report.json
tracehound-eval analyze /captures/office.pcapng --rules ./rules --home-nets 10.0.0.0/8,192.168.0.0/16 --min-severity medium
```

`--json` writes the machine-readable report to standard output. `--output` writes
JSON to a new path. The default floor is `low`; accepted severities are `info`,
`low`, `medium`, `high`, and `critical`. A successful analysis means processing
completed; it does not assert that a capture is benign or infer precision/recall
without labels.

An indexed investigation uses a separate, new database path:

```sh
tracehound-eval investigate /captures/office.pcapng --index office.case.db --json
tracehound-eval case office.case.db --offset 0 --limit 100 --search 10.0.0.42
tracehound-eval timeline office.case.db 10.0.0.42 --after 0 --limit 100
```

These paged queries avoid retaining an entire large investigation in the UI.
Original packet bytes stay in their capture; the database records authenticated
references, decoded observations, findings, diagnostics, and analysis context.

## Evaluate labelled captures

Save a suite such as `/captures/office-suite.json`:

```json
{
  "schema_version": 1,
  "captures": [
    {
      "name": "Workstation beacon investigation",
      "capture": "office.pcapng",
      "expected": [{"rule_id": "TH-0001", "src": "10.0.0.42", "dst": "198.51.100.23"}],
      "benign_hosts": ["10.0.0.10", "10.0.0.11"],
      "min_severity": "low"
    },
    {
      "name": "Reviewed benign baseline",
      "capture": "baseline.pcap",
      "expected": [],
      "benign_hosts": ["10.0.0.10"],
      "min_severity": "medium"
    }
  ]
}
```

```sh
tracehound-eval evaluate /captures/office-suite.json --output office-evaluation.json
```

Relative capture paths resolve from the suite directory. Command-line paths such
as `--rules` resolve from the working directory. Every case requires `expected`:
an empty list explicitly expects no qualifying findings, rather than representing
unknown ground truth. Use analysis or an observation-only corpus entry when rule
labels are unavailable.

An expectation matches rule and source, plus destination when provided. Omitting
`dst` allows any destination for that rule/source. IPv4 and IPv6 are supported.
Each case has its own floor; `--min-severity` is for unlabelled analysis. Validation
rejects unknown suite fields, unsupported versions, duplicate/overlapping labels,
and contradictions between positive labels and explicitly benign sources.

A case passes only when every expectation matches and no unexpected finding
appears above the floor. Benign-host violations are a subset of unexpected
findings. Repeated emissions are grouped by rule/source/destination, retaining
occurrence counts and the latest eligible evidence. Precision uses matched unique
findings/all unique findings; recall uses matched behaviours/expected behaviours.
A zero denominator produces JSON `null`. These are label-scoped measurements,
not representative field accuracy or a true-negative-based false-positive rate.

Suite jobs expose current case, completed/total cases, and provisional counters.
A detection mismatch completes with `passed: false`; cancellation or execution
failure does not produce a completed suite report.

## External validation and reviewed exposure

```sh
tracehound-eval corpus dist/corpus --json --output corpus-report.json
tracehound-eval corpus dist/corpus --manifest tools/capture-eval/data/corpus-extended.json --json --output extended-report.json
```

The default manifest pins independently published normal DNS/web traffic,
periodic/semi-periodic connections, a malicious sweep, a DNS tunnel, and an
observation-only malicious trace. The extended manifest explicitly opts into a
larger normal P2P capture. Provenance, byte length, SHA-256, terms, network
assumptions, and reviewed labels stay in each source entry; capture bytes are
never bundled in the application. See [validation-corpus.md](validation-corpus.md)
for sources, observed results, and coverage limits.

The `validation` summary reports recall per rule. Benign alert-record and unique
finding rates per monitored host-hour appear only when an entry has explicit,
reviewed benign exposure metadata. Other cases retain null rates. A trace's
first/last packet and idle gaps alone do not establish monitored host-hours.
Repeated alerts and unique groups remain separate, and these rates do not become
false-positive probabilities. Source assumptions and observable rule scope must
remain attached to comparisons.

Ctrl-C cancels file verification/download loops and analysis. HTTPS blocking is
bounded by a 30-second request timeout. Previously verified downloads remain
cached; partial downloads owned by the cancelled operation are removed.

## Saved reports, history, and comparisons

```sh
tracehound-eval analyze capture.pcap --save-history --output first.json
tracehound-eval history
tracehound-eval open first.json
tracehound-eval compare first.json second.json
```

`--save-history` stores a validated report in private local history;
`--history-dir DIRECTORY` chooses another location. The default uses
`LOCALAPPDATA`, then `XDG_STATE_HOME`, with a home state-folder fallback. Unix
history directories/files use owner-only permissions; Windows inherits the
chosen directory's access controls. History stores reports rather than capture
copies. Corpus reports retain provenance when saved, reopened, and compared.

Opening a saved report does not execute an engine or reopen its capture.
Unsupported versions, inconsistent counters, and forged evaluation summaries are
rejected. Comparisons distinguish added, removed, changed, and unchanged findings;
suite case identity is preserved. Reports can contain addresses, domains, source
paths, and other investigation details, so review them before sharing.

## Protocol and evidence scope

The shared Rust decoder handles bounded IPv4/IPv6 fragment reassembly and TCP
buffering. Incomplete, overlapping, expired, and over-budget fragment sets are
discarded and counted. Diagnostics identify truncation, malformed transport,
discarded streams, untracked packets, and dropped evidence references. Hard
limits can reduce retained evidence; a complete run does not imply every protocol
or every byte was decoded.

HTTP fingerprints cover the first cleartext HTTP/1.x request per flow. Encrypted
HTTP and HTTP/2/3 headers are not decoded. TCP TLS observations cover completed
ClientHello/ServerHello records and server names where available. Both Rust and
Go server fingerprints match the independently published RFC 8448 section 3 normal
TLS 1.3/no-ALPN handshake; that test does not establish all-variant conformance.
Rust follows published JA4 rules for unusual ALPN encodings; the legacy Go path
has differences for some such values. The Go engine retains its separate QUIC
Initial fingerprint support; it is not implied for the Rust TCP-only TLS decoder.

Peer protocol context recognizes a complete 68-byte
[BEP 3 BitTorrent handshake](https://www.bittorrent.org/beps/bep_0003.html) at the
captured contiguous TCP prefix, independently of its port. It records the
direction, timestamp, and original packet references without storing the torrent
info-hash or peer ID. A one-direction header does not establish a response, a
successful two-way exchange, or the protocol of opaque sessions to the same peer.
Encrypted peer negotiation and uTP are not decoded.

Rust `TH-0001` timing uses sessions with observed outbound application payload.
Control-only TCP attempts remain counted separately and can contribute to scan
detection, but do not qualify as application check-ins. Outbound-only payload is
eligible: a partial capture can miss replies. Findings therefore report observed
responses, bidirectional payload, and SYN-ACK counts separately from qualifying
sessions. None of those counters establishes maliciousness.

Timing, payload-size measurements, and protocol context use the same bounded
session window. Repeated starts at an identical timestamp do not create measured
intervals. Analysis metadata records the qualification policy and retention
limits; statistics expose excluded candidate groups and dropped session records.
Current-window counters describe the last scoring tick, while cumulative drop and
retransmission counters describe the run. The displayed score is a heuristic
pattern measurement, rather than a probability of infection. Older reports lack
these session facts and display them as unknown in the desktop application.

Rust DNS scoring uses the full Public Suffix List embedded by the locked `psl`
dependency, including private suffixes, without online DNS lookups. Home-network
filters and YAML rule settings control eligibility, thresholds, exceptions,
severity, and enabled rules. The direct legacy Go replay/sniff path retains its
older fragment handling and smaller suffix table. Report engine/policy metadata
makes those differences explicit.

TLS-pair intelligence is opt-in through `--pair-feed PATH`. Each entry identifies
client/server fingerprints, an association, source, classification, and
confidence. `feed-update NEW.json` explicitly fetches the publisher mapping and
records its digest/terms without overwriting an existing feed. Ordinary analysis
never downloads it. A `TH-0008` pair match is an association needing surrounding
evidence; common stacks can share fingerprints.

## Live capture

The default live backend feeds captured packets to the same incremental Rust
analyzer while capture is running. Linux can use its native packet capture;
other platforms can stream classic PCAP from an explicitly selected, existing
capture helper such as `dumpcap`. The GUI exposes lifecycle and bounded counters,
findings, devices/flows, configured limits, capture filters, and any drops/errors.
Capture permission or an installed driver is a separate operating-system
requirement; Tracehound does not install drivers or Wireshark implicitly.

Optional recording preserves the locally captured traffic within size/time
limits. Local process/socket snapshots are allowed only for local live capture
and remain time-bounded correlation context. They do not prove historical packet
ownership. File replay does not attribute captured traffic to processes currently
running on the analyst's computer.

The earlier bounded **record-then-analyse** operation remains available through
its compatibility backend. Its status is distinct from streaming detection:
findings are available after recording ends and offline processing succeeds.
Existing offline captures need none of these capture dependencies.

## Limits and development checks

Exit codes are `0` for completed analysis/passing evaluation, `1` for a detection
mismatch, `2` for input/execution/export failure, and `130` after interruption and
cleanup. The default timeout is 300 seconds per capture; `--timeout 0` disables it.
`--max-alerts` defaults to 1,000,000 detector records per capture. Limits, malformed
input, cancellation, and execution failure do not produce a partial success.

```sh
cargo fmt --manifest-path tools/capture-eval/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets --features gui -- -D warnings
cargo test --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets --features gui
```

Native CI also tests the installed/extracted app, including a real GUI frame via
`--smoke-test` on disposable runners. See the [contributor guide](contributing.md)
for focused checks and [resource measurements](performance.md) for stress tests
kept separate from accuracy evaluation.
