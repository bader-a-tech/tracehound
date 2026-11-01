# Analyse and evaluate your captures

`tracehound-eval` is a Rust command-line tool and reusable library for analysing
user-supplied PCAP and PCAPNG files with the Tracehound sensor. It has two workflows:

- **Analyse a capture:** collect findings and evidence without needing labels.
- **Evaluate labelled captures:** compare the findings with your expected
  behaviours and report missed and unexpected detections.

Neither workflow depends on the demo capture. The sensor processes your capture
locally. Real captures remain outside version control, as described in the
[capture policy](../SECURITY.md#captures).

## Build

Install a supported Rust toolchain and the Tracehound sensor. From the repository
root, build both executables:

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

The default timeout is 300 seconds per capture. Set `--timeout 0` to disable it or
choose a larger number of seconds for large captures. `--max-alerts` limits the
number of sensor alerts collected per capture and defaults to 1,000,000. Exceeding
a limit produces an error rather than a partial success report.

## Library and GUI integration

The crate exposes analysis and evaluation functions separately from the CLI. Its
versioned JSON reports include findings and evidence that a future GUI can use
for investigation and export. There is no GUI in this crate yet.

## Development checks

```sh
cargo fmt --manifest-path tools/capture-eval/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path tools/capture-eval/Cargo.toml --all-targets
```

The CLI integration tests use `TRACEHOUND_TEST_SENSOR` to locate a built sensor.
Set it to the absolute executable path to run those checks locally. CI builds the
sensor and runs these checks on Linux, macOS, and Windows. Its packet fixtures are
generated by the Rust tests and do not depend on Tracehound's demo generator.
