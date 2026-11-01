# Contributing to Tracehound

Start with the [contributor guide](docs/contributing.md) for development setup,
focused checks, capture privacy, independently reviewed labels, and changes that
touch the Rust backend or native application. The
[capture guide](docs/capture-evaluation.md), [investigation guide](docs/investigations.md),
[validation corpus](docs/validation-corpus.md), and [release process](docs/release.md)
describe the current behaviour and evidence.

Discuss a substantial change in an issue before changing public report formats
or detector semantics. A useful pull request explains the triggering input,
resulting behaviour, relevant limits, and the focused checks used to verify it.
Never attach real capture bytes or private investigation reports to a public
issue; follow [SECURITY.md](SECURITY.md) for sensitive reports.
