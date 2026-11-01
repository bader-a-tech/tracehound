# External capture validation

Tracehound accepts users' PCAP and PCAPNG files directly. The validation corpus is
a separate, repeatable check using captures published independently of this
project. Its [manifest](https://github.com/baldoseri/tracehound/blob/main/tools/capture-eval/data/corpus.json) records the download
URL, source description, exact length, SHA-256 digest, network assumptions, and
behaviour labels for every file. Capture bytes stay in a local directory such as
`dist/corpus`; they are excluded from source control and release archives.

## Sources and labels

| Case | Independent source and scope | Evaluation expectation |
| --- | --- | --- |
| `ctu-normal-dns` | CTU/Stratosphere publisher-labelled normal home-network DNS traffic, 5,966 packets over 1.9 hours. The publisher removed other protocols for privacy. | No findings at `low` or above; host `10.0.0.34` is explicitly benign for this case. |
| `stratosphere-periodic-c2` | Stratosphere Linux IPS controlled capture, documented upstream as `curl` connections every two seconds. This is recorded traffic from an independent timing experiment. | `TH-0001` from `147.32.80.37` to `141.193.213.21`, with home network `147.32.0.0/16`. |
| `stratosphere-malware-sweep` | Upstream `test7-malicious.pcap`. Separate byte-level inspection of its Ethernet/IPv4/TCP SYN traffic supports the sweep label below. | `TH-0004` from `192.168.2.16`; destination is a wildcard because the behaviour spans multiple hosts. |

The normal capture's description comes from its
[publisher README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/README.md).
The periodic case is described in the
[upstream dataset documentation](https://stratospherelinuxips.readthedocs.io/en/develop/datasets.html#test-cc-capture-1-pcap).
The two Stratosphere Linux IPS files are pinned to
[repository commit b5061a961b8348353070e168e8ea3c9101961f4b](https://github.com/stratosphereips/StratosphereLinuxIPS/tree/b5061a961b8348353070e168e8ea3c9101961f4b/dataset).

The periodic case is controlled traffic, rather than a recorded infection. The
malicious case's expected sweep was independently checked without using the Go
sensor's packet parser or detector: among 2,000 records, `192.168.2.16` sent 255
TCP SYN packets without ACK to 54 destination addresses on port 23 over
133.019129 seconds. The same source also sent 180 SYN packets to 40 destinations
on port 8080, and 128 to 27 destinations on port 2323. These observations establish
the horizontal sweep expectation; they do not claim exhaustive labels for every
possible behaviour in the capture.

## Fetch and reproduce

The Rust backend's `corpus::CorpusManifest::builtin()` loads the pinned manifest;
`corpus::fetch_verified(&manifest, directory)` fetches missing files over HTTPS
and checks length and SHA-256 before making them available. Valid existing files
are reused. A hash mismatch or changed file produces an error without overwriting
the existing capture. Custom manifests use the same schema and checks. Downloads
are bounded by their declared length and a 2 GiB per-file ceiling; manifests are
limited to 1 MiB.

The CLI corpus command uses those same checks and evaluates each case with its
recorded home-network setting. Run it with the sensor built from the same checkout:

```sh
tracehound-eval corpus dist/corpus --sensor ./bin/tracehound --json
```

The default manifest is included in the executable, so the command also works
from an extracted release. `--manifest PATH` selects a reviewed custom manifest.
Review source terms before downloading a corpus for a different purpose.

| Local filename | Bytes | SHA-256 |
| --- | ---: | --- |
| `ctu-normal-dns.pcap` | 772,961 | `7fbefbe1a18867bc683f59890cbc0124e5f6166e5aa13035fcf1ccf2f06f7ae4` |
| `stratosphere-periodic-c2.pcap` | 2,072,846 | `2276e5ac0303296b71d3363c6e844cd94adcac6b256d2b2d4b1c7aa3ccaed035` |
| `stratosphere-malware-observation.pcap` | 339,844 | `cd864709778a7449955671315d1ccc3c6694bb120732c6f60fa9ba01e5c962cb` |

## Observed results and limits

The pinned bytes were downloaded and replayed on 1 November 2026. With the
manifest's reporting floor and network assumptions, the sensor produced:

| Case | Matched expectations | Missed | Unexpected | Evidence |
| --- | ---: | ---: | ---: | --- |
| Normal DNS | 0 of 0 | 0 | 0 | No qualifying alert records. |
| Periodic connections | 1 of 1 | 0 | 0 | Two emissions grouped into one `TH-0001` finding; the latest reported 70 connections, 2.229-second interval, and 4.016% jitter. |
| Malicious sweep | 1 of 1 | 0 | 0 | One `TH-0004` finding reported 32 distinct hosts on TCP/23 within the detector's time window. The full capture contains 54 such destinations. |

This is a small regression set covering normal DNS, a controlled periodic pattern,
and one externally recorded malicious sweep. It does not measure representative
production precision, a false-positive rate, or recall across all malware
families. The evaluator treats supplied positive labels as complete when counting
unexpected findings; the malicious case's label is specifically the independently
observed sweep. Keep any newly observed missed or unexpected findings in reports
and investigate them before changing labels or thresholds.

## Capture terms and privacy

The Stratosphere Linux IPS repository is published under
[GPL-2.0](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/b5061a961b8348353070e168e8ea3c9101961f4b/LICENSE).
Its captures are fetched locally from the upstream repository; neither its code
nor capture bytes are incorporated into Tracehound releases. The normal DNS
capture is publicly provided for research, but its adjacent README does not state
a separate redistribution license. This project does not infer one from licenses
applied to other CTU datasets and does not redistribute that capture. The manifest
records these distinctions instead of claiming all upstream data is MIT licensed.

Published packet captures can contain sensitive or harmful payload bytes. The
corpus command reads traffic offline and does not execute extracted content.
Follow the [capture policy](../SECURITY.md#captures) for local storage and reports;
do not commit the downloaded files or attach them to public issues.
