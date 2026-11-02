# Legacy sensor reference

The `tracehound` executable is the retained Go compatibility sensor. It provides
the embedded web dashboard, a JSON/SSE API, Linux AF_PACKET capture, and its
separate QUIC Initial fingerprinting path.

For ordinary capture investigation, start with the
[native desktop application or Rust CLI](../README.md). Their workflow and
coverage are described in the [capture guide](capture-evaluation.md) and
[investigation guide](investigations.md). Using the desktop application does not
require a Go runtime, a web server, or this sensor process.

## Choose the engine explicitly

Release bundles contain three different executables:

| Executable | Purpose |
| --- | --- |
| `tracehound-desktop` | Native application using the Rust backend by default |
| `tracehound-eval` | Rust CLI for analysis, investigations, evaluation, and exports |
| `tracehound` | Go compatibility sensor and embedded dashboard |

Windows executables have an `.exe` suffix. The Rust CLI can select the sensor
explicitly when you need a compatibility comparison:

```sh
tracehound-eval analyze /captures/traffic.pcap --engine sensor --sensor /path/to/tracehound --output compatibility.json
```

Rust and Go have different detector, rule-pack, reassembly, and protocol coverage.
Record the engine when comparing results. The Rust session-qualified beacon
changes in 0.6.1 do not change the Go detector.

## Replay a capture

```sh
tracehound replay /captures/traffic.pcap
tracehound replay /captures/traffic.pcapng -json -min-severity medium
tracehound replay /captures/traffic.pcap -home-nets 10.0.0.0/8,192.168.0.0/16
tracehound version
```

Replay reads the file offline; it does not send captured packets onto a network.
Set home networks to the internal prefixes visible at the capture point. Use
`tracehound replay -h` for all options.

| Option | Effect |
| --- | --- |
| `-json` | Emit alerts as JSON Lines |
| `-min-severity high` | Show only alerts at or above that severity |
| `-rules ./rules` | Load a YAML rule directory |
| `-speed 120` | Pace replay at 120 times capture speed; `0` runs as fast as possible |
| `-db findings.db` | Persist findings and inventory in SQLite |
| `-listen 127.0.0.1:8080` | Serve the dashboard and API on loopback |
| `-tick 30s` | Set the scoring interval in capture time |
| `-flow-timeout 2m` | Close idle flows after the selected interval |

Alerts can repeat as evidence changes. Grouped findings and alert records are
different counts. A periodic pattern, unusual fingerprint, or ATT&CK mapping
requires investigation; none establishes that traffic is malicious.

## Tune the compatibility sensor

Copy the built-in rules into an editable directory:

```sh
tracehound rules -dump ./rules
tracehound rules
tracehound replay /captures/traffic.pcap -rules ./rules
```

For example, a beacon rule can set its reporting severity and tuning:

```yaml
id: TH-0001
name: Periodic connection pattern
detector: beaconing
enabled: true
severity: medium
tuning:
  min_connections: 8
  min_interval: 2s
  max_interval: 6h
  threshold: 0.75
```

Unknown YAML fields and invalid tuning fail when the pack loads. Omitted tuning
values use the detector defaults. Exceptions can match source, destination,
port, domain suffix, or JA4; every exception needs a description. Keep exceptions
narrow and verify changes with labelled traffic.

The Go sensor constructs its detector set using default tuning where a custom
pack has no settings. Its policy permits alerts whose IDs are absent from that
pack. Disable an unwanted rule explicitly with `enabled: false`. The Rust
replacement-pack behaviour enables only listed rules, so omission has different
effects between engines. See the [rule implementation](../internal/rules/policy.go).

## Persist and query findings

```sh
tracehound replay /captures/traffic.pcap -db findings.db
tracehound query -db findings.db -min-severity high
tracehound query -db findings.db -rule TH-0001 -json
tracehound query -db findings.db -devices
```

`query` reads an existing database and refuses to create an empty one for a
missing path. Its filters include `-limit`, `-src`, `-rule`, `-min-severity`, and
`-since`. A `-since 24h` filter is relative to the current time; omit it when
reviewing old captures.

The compatibility database stores findings and device inventory. Its active flow
table is transient; it is separate from the Rust investigation index. The
dashboard reloads stored findings on startup. Inventory is saved periodically.
Background writes use a bounded queue, and pressure drops are counted.

For a long-running Linux sensor, set both age and count limits:

```sh
tracehound sniff -i eth0 -db findings.db -db-retention 720h -db-max-alerts 500000 -listen 127.0.0.1:8080
tracehound query -db findings.db -vacuum
```

Retention runs at startup and periodically. `-vacuum` explicitly compacts the
database to return free space; ordinary retention leaves SQLite pages reusable.
Do not publish sensor databases or reports without reviewing their contents.

## Linux live capture

The compatibility sensor captures directly through Linux AF_PACKET. Capture
requires appropriate permissions. Grant capabilities to the installed executable
when appropriate for your deployment:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/tracehound
tracehound sniff -i eth0 -listen 127.0.0.1:8080
```

`-promiscuous=false` disables promiscuous mode. Stop with Ctrl+C. This direct
capture path is Linux-only. The native application's Rust live path instead uses
an existing capture helper such as `dumpcap`; see the [capture guide](capture-evaluation.md).
No installer automatically installs packet drivers or capture helpers.

## Dashboard and HTTP API

To view a replay in the embedded dashboard, start it with a loopback listener and
open `http://127.0.0.1:8080` in your browser:

```sh
tracehound replay /captures/traffic.pcap -listen 127.0.0.1:8080
```

The dashboard and API have no authentication. They expose addresses, inventory,
fingerprints, and findings. Keep the listener on loopback; remote access needs an
authenticating reverse proxy and an appropriate trust boundary. `-listen :8080`
binds all interfaces. See [SECURITY.md](../SECURITY.md).

| Endpoint | Response |
| --- | --- |
| `GET /api/alerts?limit=100&min_severity=medium` | Alerts, newest first |
| `GET /api/devices` | Passive device inventory and fingerprints |
| `GET /api/flows?limit=100` | Current active flows |
| `GET /api/stats` | Throughput, detector, and available capture/storage counters |
| `GET /api/session` | Analysis lifecycle, times, failure details, counters, and rule summary |
| `GET /api/attack` | Observed ATT&CK techniques and counts |
| `GET /api/stream` | Server-sent alert events |
| `GET /healthz` | HTTP service health |

For example, read the lifecycle separately from the event connection:

```sh
curl http://127.0.0.1:8080/api/session
curl -N http://127.0.0.1:8080/api/stream
```

A completed replay keeps serving results. An open event stream does not mean
analysis is still running. HTTP lifecycle status is read-only; the API does not
start or stop analyses. `/api/session` returns 404 for a lower-level server
constructed without a session.

## Internal integration and development

Adapters inside this Go module can use [`internal/session`](../internal/session).
`session.New` validates the rule pack and creates a fresh engine, inventory, and
pipeline. Its synchronous `Run` consumes a capture source once; use a worker
goroutine when a client must stay responsive. `Snapshot` and `Stop` may be called
concurrently. Alert sinks run on the analysis goroutine and must return promptly.
The caller owns the source and closes it after `Run` returns. Create a new session
for every analysis so detector history does not cross captures. These `internal`
packages are not a stable external SDK.

Building or changing the sensor requires the Go toolchain described in the
[contributor guide](contributing.md). Its optional `gen-demo` command creates a
synthetic regression fixture. Checked sample output remains in the
[README's compatibility appendix](../README.md#legacy-sensor-reference); it is
not the native application's first-use workflow or independent accuracy corpus.

Fingerprints describe handshake features shared by multiple applications and
hosts; they do not prove application identity or malware attribution. The Go
QUIC path covers supported client Initial handshakes, including versions 1 and
2, rather than arbitrary encrypted application traffic. Rust and Go protocol
limits differ; consult the [capture guide](capture-evaluation.md) and
[independent validation results](validation-corpus.md) before drawing conclusions.
