# Investigate a capture from host to packet

The desktop application and `tracehound-eval` use the same Rust analysis engine.
Offline analysis accepts your own PCAP or PCAPNG and needs no sensor executable,
capture driver, or labels. A case index adds searchable, paged host investigations
while packet bytes remain in the original capture.

## Create and open a case

In the desktop application, open a capture and choose the investigation page.
Choose a new database path and build the index. Analysis and indexing run in a
background worker; cancellation removes the incomplete database. Keep the original
capture alongside the case so packet evidence remains available.

The CLI performs the same operation:

```sh
tracehound-eval investigate /captures/office.pcapng --index office.db --home-nets 10.0.0.0/8
tracehound-eval case office.db --limit 100
tracehound-eval case office.db --search 10.0.0.42 --limit 100
```

Set home networks to the internal prefixes visible at the capture point. Detector
direction and inventory depend on that choice. Analysis context records the engine
version, rule-pack digest, reporting floor, capture digest, and resource limits.
Custom rule directories replace the Rust built-in pack: only listed, enabled
rules run. The legacy Go engine has different replacement semantics and coverage.

The index stores original packet metadata, connection counters, decoded DNS,
TLS and cleartext HTTP events, and findings. It uses disk-backed SQLite with a
bounded cache. Case size grows with captured packets and events; it is separate
from the bounded inline context in an ordinary JSON analysis report.

## Follow a host timeline

Hosts are ranked by findings and traffic volume. Search operates across the host
index, and pages keep large lists out of the UI. Select a host to inspect its
chronological events, connections, and original frame references.

```sh
tracehound-eval timeline office.db 10.0.0.42 --limit 100
tracehound-eval timeline office.db 10.0.0.42 --after 123 --limit 100
```

Use the returned `next_id` as the next page's `--after` cursor. The order is capture
timestamp followed by event ID, including when input timestamps arrive out of
order. A cursor from another host is rejected.

Packet facts, detector evidence, and contextual associations have different
meanings. A decoded DNS name comes from referenced bytes. A finding may depend on
many packets across a time window. Traffic sharing an address or a time window
does not establish causation. Evidence lists have explicit caps; truncation flags
remain visible. The packet table still indexes every accepted original frame.

## Verify and export evidence

Select a frame in the GUI to see its original timestamp, interface, lengths,
SHA-256, and bounded hex preview. Source verification hashes the original file and
checks its container metadata before reading the selected bytes. This also catches
case database references altered to point to a different original frame.

Open Wireshark from an explicit GUI action to inspect the original capture with a
host/frame display filter. Wireshark must already be installed. Tracehound passes
arguments directly rather than constructing a shell command.

Export selected frames to a new PCAPNG:

```sh
tracehound-eval packet-export office.db 12,45,46 selected.pcapng
```

The export preserves captured bytes, on-wire lengths, timestamps, and link types,
and records original frame numbers and capture digest in comments. Packet numbers
in the exported file start again at one; use the comments to trace them back.

If the capture moved, choose its new path in the GUI or pass `--source`:

```sh
tracehound-eval packet-export office.db 12,45 selected.pcapng --source /archive/office.pcapng
tracehound-eval case-export office.db 10.0.0.42 host-report --include-packets --source /archive/office.pcapng
```

A host export creates `investigation.html`, `investigation.json`, and
`SHA256SUMS.txt` in a new directory. `--include-packets` explicitly adds
`evidence.pcapng`; packet bytes are excluded by default. The HTML is standalone,
escaped, and contains no scripts or remote assets. Exports are limited to 10,000
events and 10,000 selected frames, with truncation recorded. Existing output
files and directories are preserved.

Addresses, domains, paths, and other capture metadata can appear in HTML and JSON
even when packet bytes are excluded. Review exports before sharing them. Keep
case databases, captures, and reports outside the public repository.

## Compare comparable windows

Open two case databases in the behavioural comparison view, choose the same host
IP, and optionally limit the duration. The CLI provides the same comparison:

```sh
tracehound-eval behavior-compare morning.db afternoon.db 10.0.0.42 --seconds 300
```

Both windows begin at their capture's first packet and use the same elapsed
duration, shortened to the shared coverage. They are not aligned by clock time.
Both window endpoints are included, retaining final-packet facts and findings
emitted at EOF; rates use the elapsed duration between those endpoints. The
comparison reports packet and byte rates plus added and removed destinations,
services, DNS domains, TLS pairs, client fingerprints, HTTP hosts, and finding rules. Undefined rate
ratios remain null, including when the baseline rate is zero.

Capture timestamps alone do not prove continuous observation. Gaps, packet loss,
different capture points, NAT, and DHCP can change results. A new destination or
fingerprint is an observed change, not a malware verdict. An IP address is not a
persistent device identity. Feature sets have explicit size limits and flag
incomplete comparisons when those limits are reached.

## Live analysis and Windows ownership

Choose the Rust live engine in the GUI, select an interface from an existing
`dumpcap` installation, and set the capture filter and resource bounds. The helper
streams packets to the same Rust decoder and detectors used for files. Stop waits
for the helper and readers to finish. Saving the retained bounded capture is an
explicit action; retained traffic can then be indexed as a case.

Optional Windows process attribution reads native socket ownership and process
creation identities locally. Matches require a fresh, compatible local tuple;
uncertain matches remain unattributed. Imported captures cannot recover earlier
process ownership. No executable contents or process memory are collected.

Rust currently decodes TCP TLS handshakes and cleartext HTTP/1.x. Encrypted HTTP
headers, HTTP/2, HTTP/3, and Rust QUIC fingerprints are outside this path. The
legacy Go engine retains its QUIC Initial support. Protocol gaps and bounded
tracking/reassembly counters are analysis limits, not evidence of benign traffic.
