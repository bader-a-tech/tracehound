# Independent capture validation

Tracehound analyses users' captures directly. The external corpus is a separate,
repeatable check against independently published bytes and reviewed behaviour
labels. The [default manifest](https://github.com/bader-a-tech/tracehound/blob/main/tools/capture-eval/data/corpus.json)
records source/download URLs, exact length, SHA-256, terms, network assumptions,
classification, and expectations. The optional
[extended manifest](https://github.com/bader-a-tech/tracehound/blob/main/tools/capture-eval/data/corpus-extended.json)
adds a larger reviewed normal P2P capture. Raw traffic remains in ignored local
storage and is never committed or included in app packages.

## Sources and reviewed scope

| Case | Independent source | Label scope |
| --- | --- | --- |
| `ctu-normal-dns` | CTU/Stratosphere real home-network DNS, 5,966 packets; other protocols removed for privacy | Explicit negative case; benign source 10.0.0.34 |
| `ctu-normal-web` | CTU normal Windows browser access to HSBC, 949 packets; relative/anonymized timestamps | Explicit negative case; benign source 192.168.1.112 |
| `stratosphere-periodic-c2` | Slips independently captured controlled `curl` timing every 2 seconds | `TH-0001`, 147.32.80.37→141.193.213.21 |
| `stratosphere-jittered-c2` | Slips controlled `curl` timing with 2–3 second delays | `TH-0001`, 147.32.80.37→141.193.213.20 |
| `stratosphere-malware-sweep` | Slips `test7-malicious.pcap`, with separately verified SYN sweep | `TH-0004`, source 192.168.2.16; destination wildcard |
| `graphtunnel-dnscat2-mx` | GraphTunnel researcher's dnscat2 MX tunnel capture | `TH-0002`, source 192.168.68.62 |
| `stratosphere-malware-observation-8` | Slips `test8-malicious.pcap`,534 packets over 12.821131s | Observation only; no invented rule-level labels or accuracy denominator |
| `ctu-normal-p2p` (extended) | CTU manually checked Debian host using Deluge, Chrome, Jabber and normal `mtr` | Explicit negative case; benign source 10.0.0.46 and reviewed monitored interval |

Normal-source descriptions come from the publisher's
[DNS capture](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/),
[web capture](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-13/), and
[P2P capture](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7/).
Slips bytes are pinned to
[commit b5061a961b8348353070e168e8ea3c9101961f4b](https://github.com/stratosphereips/StratosphereLinuxIPS/tree/b5061a961b8348353070e168e8ea3c9101961f4b/dataset),
with timing described in the [publisher documentation](https://stratospherelinuxips.readthedocs.io/en/develop/datasets.html).
GraphTunnel bytes are pinned to
[commit e3dccb8a9481cc984592bcc6a018a376dc8e5fac](https://github.com/ggyggy666/DNS-Tunnel-Datasets/tree/e3dccb8a9481cc984592bcc6a018a376dc8e5fac),
whose authors describe the independently collected research corpus and request
citation to *GraphTunnel: Robust DNS Tunnel Detection Based on DNS Recursive
Resolution Graph*.

The curl traces are controlled timing experiments, not recorded malware
infections. The DNS-tunnel case is independently captured research traffic using
an actual tunnelling tool. Neither is Tracehound's generated demo or resource
stress fixture.

A separate byte-level reader, without the production Go/Rust packet parsers,
verified the sweep: among 2,000 records, 192.168.2.16 sent 255 SYN-without-ACK packets
to 54 destination addresses on TCP/23 over 133.019129 seconds. It also sent 180 SYNs to
40 hosts on 8080 and 128 to 27 hosts on 2323. The label covers that observed sweep,
rather than claiming exhaustive malware behaviour labels.

Independent DNS wire inspection verified the dnscat2 case: 25,687 unique MX queries
from 192.168.68.62 under `ggy666.tk`, mean full-name length 151.851 bytes, among
51,371 packets. The positive DNS-tunnel label comes from publisher scenario and
wire evidence, not from Tracehound's output.

## Fetch, verify, and evaluate

```sh
tracehound-eval corpus dist/corpus --json --output corpus-report.json
tracehound-eval corpus dist/corpus --manifest tools/capture-eval/data/corpus-extended.json --json --output extended-report.json
```

The default engine is Rust. Use `--engine sensor --sensor PATH` only for an
explicit compatibility comparison. The extended download adds 417,195,191 bytes;
it is opt-in to avoid an unexpected large default download.

The Rust fetcher verifies exact length and SHA-256 before returning a capture.
Existing valid files are reused, invalid files are preserved with an error, and
outputs never replace a concurrently created file. HTTPS-only requests have a
30-second blocking bound; cancellation is checked between files and buffered
reads/copies. Owned partials are removed; completed verified caches remain.
Manifests are limited to 1 MiB and captures to 2 GiB each. The CLI's JSON retains
sources, labelled evaluation, observation-only reports, and validation metrics.
Reports can be saved to history, reopened, and compared with provenance intact.

| Filename | Exact bytes | SHA-256 |
| --- | ---: | --- |
| `ctu-normal-dns.pcap` | 772,961 | `7fbefbe1a18867bc683f59890cbc0124e5f6166e5aa13035fcf1ccf2f06f7ae4` |
| `ctu-normal-web.pcap` | 506,351 | `ebd495484e66dea49a7ff95f9ae7415b6a51a963713014ac0e822d2828afb2c7` |
| `stratosphere-periodic-c2.pcap` | 2,072,846 | `2276e5ac0303296b71d3363c6e844cd94adcac6b256d2b2d4b1c7aa3ccaed035` |
| `stratosphere-jittered-c2.pcap` | 264,119 | `03e3e0b3e47fcb8801870fc00fd8f7e8f1924bb5398c4ecf28f811eaaf62cdbc` |
| `stratosphere-malware-observation.pcap` | 339,844 | `cd864709778a7449955671315d1ccc3c6694bb120732c6f60fa9ba01e5c962cb` |
| `graphtunnel-dnscat2-mx.pcap` | 13,012,503 | `e035355338ff4e432ce7c15d39947bd3e254c20f01b90e1272b4f645b0201be2` |
| `stratosphere-malware-eight.pcap` | 31,513 | `191da8b6eba7846750df8b8d2dbca9664cabdcce0f51978349de5c764e3e6361` |
| `ctu-normal-p2p.pcap` | 417,195,191 | `9daf9c1746dae37a234bac32090e8bc925e837af78cfffc3b4cc7c46d901542b` |

## Results, benign exposure, and limits

The local Rust run matched all 4 reviewed positive behaviours: `TH-0001` 2/2,
`TH-0002` 1/1, and `TH-0004` 1/1. All 6 labelled default cases passed with no
unexpected or explicitly benign findings; the seventh case is observation only.
Those counts cover this small supplied label set, not general malware recall.
The [published JSON summary](benchmarks/corpus-v0.6.0.json) records the Windows
candidate's source revision, executable/manifest hashes, case counts, measurements,
and source-backed exposure assumptions without packet bytes or local capture paths.

The extended P2P case deliberately retains an important negative result. It
produced 18 unexpected unique `TH-0001` findings, 36 alert records, from the
publisher-verified normal host. With the publisher's rounded 1,282-second monitored
window, that is 101.09 alert records and 50.55 unique findings per monitored host-hour.
The extended labelled evaluation therefore has 6 passing cases and 1 failing case;
its 4 positive expectations still match. Labels and thresholds were not changed to
make this trace pass. Periodic peer-to-peer activity can trigger the heuristic,
so a pattern finding requires surrounding host/application context rather than
proving malicious command-and-control activity.

Per-rule recall uses only explicit positive behaviour labels. Benign rates are
calculated only for declared source-backed normal-host monitoring windows and
observable rules. The P2P publisher
[README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7/README.html)
identifies a manually checked normal host and continuous host capture; its
[capinfos](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7/2013-12-17_capture1.capinfos)
reports 1,282 seconds. This is monitored-host time, not an assumption of constant
user activity. Explicit assumptions record that no independent sensor uptime log
is available, broadcast/multicast were removed, and packet timestamps are not
strictly ordered. Other normal cases do not automatically acquire host-hour
denominators from packet spans or idle gaps.

The P2P bytes contain 471,237 records. Independent header-only inspection found
minimum Unix timestamp 1387314559500617 microseconds and maximum
1387315841386125 microseconds, spanning 1,281.885508 seconds. The rate denominator
uses the publisher's rounded interval, with that precision distinction retained.
The web trace uses relative timestamps, so its publisher wall-clock timeline is
not treated as exposure ground truth.

Repeated alert records and unique finding groups are separate numerators. Neither
host-hour rate is a true-negative-based false-positive probability. Missing
exposure yields null rates. Labels may be incomplete, hard stream limits can
reduce retained evidence, and this corpus is too small for production calibration
or representative precision. Preserve missed, unexpected, and benign findings in
reports and investigate them before changing labels or tuning rules.

## Terms and privacy

The Slips repository is [GPL-2.0](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/b5061a961b8348353070e168e8ea3c9101961f4b/LICENSE).
Its capture bytes are downloaded locally rather than incorporated into project
releases. CTU normal-web documentation permits use with citation; other adjacent
normal-capture descriptions do not declare a separate redistribution license, so
this project does not infer one from unrelated CTU datasets. GraphTunnel requests
citation to its dataset/paper. Each manifest records its own source terms and no
capture bytes are redistributed here.

Packet captures may contain sensitive or harmful payloads. Evaluation reads them
offline and does not execute content. Follow the [capture policy](../SECURITY.md#captures)
and review reports/exports before sharing them. Do not attach real captures to
public issues or package them with the application.
