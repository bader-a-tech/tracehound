# Upstream release notices

These files fill gaps in dependency source archives that omit their workspace
license documents. `manifest.json` identifies the exact locked crate versions,
package VCS revisions, source URLs, and SHA-256 digests. `release-notices` verifies
that ledger against the installed sources before copying notices into an archive.
Normal dependency notices are copied directly from the downloaded source cache.

License and copyright text is preserved as published. The MIT-only `dispatch`
crate has no separate license file at its published VCS revision. Its original
published Cargo manifest preserves the license declaration and authors, and the
unmodified SPDX MIT reference text is included with an explicit explanation in
the ledger and release catalog.

Several egui 0.37.0 crates name a VCS revision that is unavailable in the public
upstream repository. Their MIT and Apache license documents come from the
published upstream 0.37.0 release tag, resolved to a fixed commit; the ledger
records that distinction. No source code or capture data is vendored here.

When dependencies change, review these version-specific mappings. Do not apply a
fallback to a different version automatically. Font OFL/UFL and custom copyright
files remain in the original crate sources and are collected separately.
