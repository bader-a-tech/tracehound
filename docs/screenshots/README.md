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

- Source revision: `f3d7fee41c5c5a6ad00484bdf6d9c8845274df38`.
- [Successful CI run](https://github.com/bader-a-tech/tracehound/actions/runs/41293685067).
- Artifact: `product-validation-linux`, ID `13078071896`.
- Downloaded ZIP SHA-256: `f9fa7f60925e6f887b8fc3f272d5664802f95ea70a4d3dee92427423b55a07c1`.
- Screenshot SHA-256: `3b8f5c93104e65d37e4e1856a79e60d15a52d5ad9ae3096851a46e84657da27e`.

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
