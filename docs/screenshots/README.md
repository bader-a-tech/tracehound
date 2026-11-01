# Native investigation screenshot

`investigation-linux.png` is an unedited screenshot returned by the actual native
application on the Ubuntu 24.04 CI runner. The screenshot mode opens a case,
selects the highest-ranked host, loads its timeline and original packet,
authenticates the source, renders three frames, saves the screenshot, and closes.

Source: `stratosphere-periodic-c2` from the
[reviewed corpus manifest](../../tools/capture-eval/data/corpus.json). The publisher
records this as a controlled periodic-connection experiment; it is not an infection
label or a general accuracy claim. Capture bytes are downloaded locally and are
not included in this directory.

- Source revision: `7f6b8d86d078f561a4c8b9f799a23900a28879d1`.
- [Successful CI run](https://github.com/bader-a-tech/tracehound/actions/runs/41292904532).
- Artifact: `product-validation-linux`, ID `13077818893`.
- Downloaded ZIP SHA-256: `5909321983f4e88a60656d3ed04a177cbc16e109cf4d6e801022276cc73bad66`.
- Screenshot SHA-256: `4795b7a0e02362af0bf227700de70d5264d400d1567d64c4ff33b5f98d63607e`.

Reproduce with the built Rust executables, a Linux graphical session or Xvfb,
and the documented desktop runtime dependencies:

```sh
tracehound-eval corpus dist/corpus --json --output corpus.json
tracehound-eval investigate dist/corpus/stratosphere-periodic-c2.pcap --index periodic.db --home-nets 147.32.0.0/16
tracehound-desktop --smoke-case periodic.db --smoke-output investigation-linux.png --smoke-exit
```

Output paths must be new. Desktop theme, scaling, fonts, paths, and platform can
change pixels, so screenshot hashes identify these recorded bytes rather than a
cross-machine golden image. The screenshot contains addresses and frame metadata
from the independently published source; review capture terms and metadata before
sharing your own investigation screenshots.
