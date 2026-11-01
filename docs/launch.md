# Release announcement materials

Use these materials after the matching release assets and validation checks are
published. Replace the version and screenshot links with that release's verified
URLs. Community submissions remain a maintainer action.

## Suggested title

Tracehound: investigate network captures from a suspicious host to the original packet

## Short announcement

Tracehound is an open-source local network investigation tool with a native Rust
desktop application and CLI. Open a PCAP or PCAPNG, investigate host timelines,
follow a finding to its original frame, and open that traffic in Wireshark. Export
a standalone HTML/JSON case, optionally including selected original packets, or
compare the same host over equal capture windows.

The offline and live paths share a Rust analysis engine. Findings include the
measurements behind periodic connections, DNS tunnelling, scans, outbound transfer
imbalances, and TLS inventory changes. Independent captures are pinned by hash;
per-rule labelled recall and reviewed benign exposure remain separate from
performance measurements. Downloads include native packages, portable bundles,
checksums, and notices. Installers are currently unsigned.

Source and downloads: [Tracehound](https://github.com/bader-a-tech/tracehound).

## Maintainer walkthrough

1. Download the native package and verify its checksum. Show the actual GUI opening
   a reviewed capture whose publication terms permit the planned presentation.
2. Build an investigation index and select a host with a labelled behaviour. Show
   the finding measurements and the distinction between facts and context.
3. Select an original frame, verify its source, and open it in Wireshark. Show its
   original frame number and capture digest rather than a fabricated result.
4. Export HTML/JSON without packet bytes, then explicitly export selected evidence
   to PCAPNG. Review metadata before publishing screenshots or reports.
5. Compare two captures over equal windows and explain why a changed destination
   needs investigation rather than automatically proving malware.
6. Link the release, investigation guide, independent validation report, and
   contributor guide. Name current limits, including unsigned installers and
   rules that still lack external recall coverage.

## Feedback to request

Ask users which capture workflows are difficult, whether packet links and exports
are understandable, and which benign patterns trigger findings. For bug reports,
request version, OS, command/settings, diagnostics, and a small independently
shareable reproducer. Do not request private production captures in public issues.

Good first contributions include a reviewed benign or malicious corpus manifest,
a wire-level parser regression, a native package check, or a small GUI usability
fix. Follow [CONTRIBUTING.md](../CONTRIBUTING.md) for development and validation.
