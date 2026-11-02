# Make the first investigation worth sharing

Tracehound's focus is a local desktop workflow for analysts, incident responders,
and students who already have a capture: understand what deserves attention,
inspect the original evidence, and hand a clear case to someone else.

This is a proposed development order. Items marked planned are not current
features or a release-date promise. Backend and native-app implementation use
Rust or C++.

## Available today

- Native desktop app and CLI for PCAP/PCAPNG, with local Rust analysis.
- Grouped, explained findings; ranked hosts; paged timelines and connections.
- Original frame references, source authentication, packet previews, and exports.
- DNS, TCP TLS, cleartext HTTP, and one-direction BitTorrent header observations.
- Equal-window comparisons, local history, and cancellable background work.
- Standalone HTML/JSON case exports with optional selected original packets.
- Optional installed-helper live capture and fresh local Windows socket ownership.
- Windows, macOS, and Linux installers checked on their target platforms.

The [validation report](validation-corpus.md) records reviewed positive cases,
remaining benign findings, retention limits, and source-backed assumptions.

## First: a clear path from capture to case

The first-use improvement makes **Investigate this capture** visible on the
Analyse page, carries the selected source to the investigation view, suggests a
case filename, and exposes **Create investigation**. Selecting a source does not
start analysis or overwrite a case. Existing output protections stay in place.

The README leads with downloads, three GUI steps, and an actual native screenshot.
Compatibility-engine internals and build instructions stay available separately.

Success means a first-time user can open a capture, find a host, inspect an original
packet, and export a case without needing a terminal or a maintainer to explain
the screen. Observe that workflow with outside users before expanding the menu.

## Next: Investigation Brief — planned

Current HTML exports contain chronological events, measurements, and frame
references. The proposed brief adds a readable overview above that evidence.

It should answer:

1. What was observed for this host, and during which capture window?
2. Why did each selected finding appear?
3. Which original frames support each statement?
4. What legitimate explanations or missing observations affect interpretation?
5. What did the analyst choose to record or investigate next?

The backend should build a typed, deterministic summary from indexed facts and
existing finding measurements. Clearly labelled analyst notes remain separate
from captured facts and detector interpretations. A sequence of events does not
become a proven attack chain just because it appears on a timeline.

The GUI should provide a visual activity timeline, selectable findings, and
bookmarks/notes, then export the same brief to standalone HTML. A reader should
be able to follow each claim back to its original frame references. Large cases
need paging and cancellation rather than collecting every event in memory.

Acceptance criteria:

- The brief works on the user's own capture and requires no external account.
- Every generated claim has source facts or explicitly labelled uncertainty.
- Timing, payload direction, protocol context, and unknowns retain their current
  meanings; a recognized protocol is not a benign verdict.
- The summary and exported HTML agree, preserve frame identity, and expose limits.
- Independent positive and benign captures remain in validation, including the
  six known P2P false positives until a justified correction removes them.
- A real application walkthrough shows the complete investigation and export.

## Then: sharing preview and change explanation — planned

**Sharing preview.** Let users preview and mask addresses, domains, and local
paths in the report copy. Mark the report as redacted, keep the original capture
immutable, and explain which evidence can still be verified. Packet bytes remain
an explicit choice; hiding text metadata does not sanitize exported packets.

**Before/after explanation.** Build a clearer presentation around the existing
comparison backend: new destinations, changed fingerprints, traffic-rate changes,
and the corresponding events. Preserve equal-window and capture-coverage limits;
DHCP and NAT can make an address a poor device identity.

**Detection quality.** Expand independently labelled benign and positive traffic,
address mixed resolver/P2P timing, and develop Rust QUIC and other protocol coverage
with independent wire fixtures. Show missed cases and unexpected findings instead
of changing labels to improve a headline number.

Publisher signing and notarization remain distribution work when credentials
become available. [Current package and signing status](release.md).

## Earn adoption with a usable workflow

Use a short recording of the actual app and a reproducible public-capture
walkthrough to show the full outcome. The product continues to accept the user's
own files; a canned demonstration is not a substitute for that workflow.

Start by watching ten outside users attempt a first investigation. Record where
they stop, which findings they cannot explain, and whether they return with a
second capture. Use those observations to prioritize fixes. Stars and downloads
can show interest, but do not establish that the tool is useful or accurate.

Prepare a substantive launch only when people can try it directly. Follow the
[Show HN guidelines](https://news.ycombinator.com/showhn.html) or the rules of the
chosen community, share useful technical findings, and answer questions. Do not
organize votes or post the same promotion repeatedly. Community posts and outreach
are maintainer actions, separate from implementation.
