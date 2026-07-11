<!-- SPDX-License-Identifier: Apache-2.0 -->
# Vendored conformance artifacts

This directory implements the ADR-021 consumption model for the
[spec repository's](https://github.com/semver-trust/spec) conformance
vectors: `vendor/` holds byte-exact copies, and `manifest.json` records the
pin — the source commit, a SHA-256 per file, and the spec draft version.
The manifest is the **single place this implementation pins the spec version
it claims conformance against**, surfaced by `semver-trust --version`.

- **Refreshing:** `python3 scripts/sync-conformance.py <spec-commit-sha>` is
  the only sanctioned way to change `vendor/` or the manifest. Updates are
  deliberate, reviewable diffs against a stated spec version — never silent
  drift.
- **Verifying:** `task conformance` runs the digest check (every vendored
  byte must hash to its manifest pin) plus every conformance test in the
  module against the vendored vectors; CI runs it on every PR.
- **Consuming:** the per-package conformance tests default to
  `conformance/vendor/`; a `SEMVER_TRUST_*_VECTORS` environment variable or a
  package `testdata/` drop-in overrides the vendored copy for testing against
  unreleased vectors.

`vendor/LICENSE` is the spec repository's Apache-2.0 text, vendored alongside
the vectors so copies stay self-describing.
