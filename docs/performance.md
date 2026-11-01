# Reproducible resource measurements

`tracehound-bench` runs the real capture-job backend against bounded, locally
constructed PCAP stress fixtures. These fixtures measure resource behaviour;
they have no detection-accuracy labels and are separate from the
[external validation corpus](validation-corpus.md).

Build the benchmark from an identified clean checkout with a release profile:

```sh
cargo build --release --locked --manifest-path tools/capture-eval/Cargo.toml --bin tracehound-bench
./tools/capture-eval/target/release/tracehound-bench --engine rust --work-dir ./dist/performance --output ./dist/performance/report.json --sizes-gib 1,5,10
```

Windows executable names have an `.exe` suffix. The output path must be new.
The default engine is Rust and needs no Go executable. A separate compatibility
comparison can select `--engine sensor --sensor PATH`; build that sensor from
the same clean revision. `--skip-index` measures capture analysis without the
separate case-index pass.
`--retain-fixtures` keeps the generated inputs for further investigation; by
default, each input is removed after its measurements. Sizes are binary GiB, and
the final complete record can put the actual file up to 1,529 bytes above the
nominal size. The JSON records the actual byte and packet counts.

The default workload contains valid Ethernet/IPv4/UDP frames of 1,514 bytes across
64 fixed flows. IP checksums are valid; the zero UDP checksum is permitted for
IPv4 by [RFC 768](https://www.rfc-editor.org/rfc/rfc768). Addresses come from private
and documentation ranges. A 1 MiB writer buffer and 64 packet templates keep
fixture generation bounded. Files are produced one at a time, and the backend's
normalized captures use an isolated temporary directory under the chosen work
root. Allow space for the original, normalized capture, and SQLite index; the
10 GiB case needs substantially more than 10 GiB of free space.

For each size the harness records complete analysis elapsed time, MiB/s, packets/s,
alert counts, protocol counters, sampled process-tree resident memory, cancellation
cleanup latency, truncated-input rejection, and leftover preparation files. Case
indexing is measured separately with its elapsed time, database size, indexed
packet count, reopen latency, cancellation outcome, and memory. Cancelling or
rejecting an input must not produce a completed report or usable partial database.

## Clean Windows candidate measurements

These runs used source revision
[`8f030b25a90be1564669c1fc16bc029854adcba1`](https://github.com/bader-a-tech/tracehound/commit/8f030b25a90be1564669c1fc16bc029854adcba1)
on 1 November 2026, Rust 1.99.1, the release profile, and a Windows x64 machine
reporting 24 logical processors (`AMD64 Family 23 Model 113 Stepping 0,
AuthenticAMD`). Both reports record the same revision at start and end, all dirty
flags false, executable hashes, and `checks_passed: true`.

The workload was freshly written fixed-flow UDP traffic. Operating-system file
cache state and other workstation activity were not controlled. These results
measure the backend process tree, excluding a GUI and the system file cache.
They do not describe arbitrary traffic, cold storage, or detection accuracy.

| Nominal input | Packets | Rust analysis | MiB/s | Sampled peak tree RSS | Analysis cancellation cleanup |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 GiB | 701,793 | 2.114 s | 484.35 | 7.55 MiB | 5 ms |
| 5 GiB | 3,508,961 | 10.301 s | 497.03 | 10.36 MiB | 5 ms |
| 10 GiB | 7,017,921 | 21.131 s | 484.59 | 11.30 MiB | 5 ms |

The separate index-only `CaseIndex::build` pass retained every accepted packet:

| Nominal input | Index build | Sampled peak tree RSS | Database size | Reopen | Cancelled index total elapsed |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 GiB | 16.776 s | 43.64 MiB | 91,729,920 bytes | 1 ms | 254 ms |
| 5 GiB | 86.722 s | 44.36 MiB | 463,429,632 bytes | 1 ms | 257 ms |
| 10 GiB | 170.899 s | 45.15 MiB | 929,947,648 bytes | 1 ms | 258 ms |

Index cancellation totals include the configured 250 ms delay before the
request; they are not cleanup-after-request measurements. The `investigate` CLI
also runs detectors during its pass, so its combined duration is not measured by
this index-only table. Reopen measures opening/validating the database, rather
than loading every host/event or authenticating original packet bytes.

All full-input packet counts matched. Cancelled analysis produced no completed
report, cancelled indexing left no usable partial database, truncated inputs
were rejected, and no preparation files remained.

For a separate compatibility comparison, the same clean source built the legacy
sensor with version `v0.6.0-candidate.8f030b2` and ran `--skip-index`:

| Nominal input | Legacy analysis | MiB/s | Sampled peak tree RSS | Analysis cancellation cleanup |
| --- | ---: | ---: | ---: | ---: |
| 1 GiB | 4.615 s | 221.87 | 84.12 MiB | 15 ms |
| 5 GiB | 28.491 s | 179.71 | 45.03 MiB | 10 ms |
| 10 GiB | 78.370 s | 130.66 | 44.88 MiB | 5 ms |

The runs were sequential and cache state was uncontrolled; this comparison is
not a universal speedup claim. Raw reports preserve sampling counts, per-process
lifetime peaks, preparation and truncation outcomes, and exact input sizes:
[Rust](benchmarks/windows-rust-v0.6.0.json),
[legacy sensor](benchmarks/windows-sensor-v0.6.0.json).

## Publishing comparable results

Only runs built from an identified clean source revision are published as final
reproducible results. Diagnostic working reports remain under ignored
`dist/performance`. A final report records executable hashes, source revision,
processor, platform, sampling interval, outcomes, and limitations. Keep the JSON
beside any published table and identify Rust analysis, legacy sensor analysis,
and case indexing separately.

Newly written files can be served from the operating-system cache. Cache state,
storage, and other machine activity must be stated; throughput alone does not
identify a detector, CPU, or storage bottleneck. The fixed-flow workload does not
exercise millions of unique flows, adversarial fragmentation, or all protocol
decoders. Use additional workload profiles before drawing deployment capacity
conclusions.

## Memory measurement and interpretation

The sampler observes this benchmark process and its descendants. Windows uses
the native [process snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w)
and [process memory counters](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex);
Linux reads `/proc` resident/high-water counters; macOS samples `ps` resident
memory and excludes the sampler's own `ps` process. No administrator access or
system profiler installation is required.

`sampled_peak_tree_rss_bytes` is the largest simultaneously sampled sum of
resident memory. It includes the benchmark harness, worker threads, and any
observed sensor child. Sampling can miss a very short-lived child or a brief
peak between observations. Windows/Linux also report the sum of observed
per-process lifetime high-water marks; those peaks can occur at different times,
and the benchmark process's lifetime includes previous measurements. That field
must not be presented as a simultaneous tree peak. Missing samples and the number
of observed processes remain visible in the report.

Preserve the JSON alongside any published table, specify the workload and cache
conditions, and compare like-for-like source, configuration, and machines.
Throughput, bounded resident memory, cancellation, and input rejection measure
engineering behaviour; they do not establish detection precision or recall.
