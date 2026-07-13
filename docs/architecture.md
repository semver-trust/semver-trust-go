<!-- SPDX-License-Identifier: Apache-2.0 -->
# Architecture

semver-trust-go is a language-agnostic core with pluggable, ecosystem-specific
seams (specification
[ADR-011](https://github.com/semver-trust/spec/blob/main/docs/adr/0011-language-agnostic-core-ecosystem-plugins-lossy-registry-projections.md)).
The core reads git and computes trust; the seams supply the workspace
dependency graph and the compatibility evidence. This document maps the
packages and states the two invariants that shape the whole tree: **the clock
and the trust roots are injected at the CLI boundary and nowhere else**, and
**the conformance vectors are vendored and never hand-edited**.

## The command boundary

**`cmd/semver-trust`** — the cobra CLI. Every user-facing command lives here:
`verify`, `release`, `attest review`, `policy validate|explain`, the plain-mode
`list|latest|next|tag`, and the hidden `docs` generator. This layer is a thin
adapter. It parses flags, reads the wall clock **once** at the process boundary,
loads the trust material (keyrings, allowed-signers and attestation-signer
registries) from flags or from the policy, and hands all of it — the injected
`time.Time` and the injected roots — down to `internal`. It then renders what
`internal` returns. Deliberately, no decision logic lives here; the boundary
exists so that everything below it is pure and testable against a fixed clock
and fixed roots.

## The core (`internal/`)

**`internal/version`** — the version types and parsers. It carries the *strict*
§7.1 trust-version parser (which fails closed: a trust-shaped-but-malformed tag
like `t10.1` or `t1.0` is rejected, never reinterpreted as a plain pre-release)
and, alongside it, the *lenient* plain-mode layer that tolerates the donor
`go-semver` forms (v-less, short, coerced) for display parity. Increment
semantics (node-semver parity) live here too.

**`internal/plain`** — the zero-configuration plain-mode operations the
`list|latest|next|tag` commands drive: classify a repository's raw tags into the
lenient-valid set, sort by SemVer precedence, pick the latest, compute the next.
It reads tags and never a policy — strict trust shapes still fail closed, but
out-of-grammar tags are surfaced with a reason rather than silently dropped.

**`internal/vcs`** — the git seam (go-git). Tag enumeration, the two-dot range
walk (`FROM..TO`), reading a commit's `Provenance:` trailers, verifying commit
signatures and resolving the signer, and creating signed annotated tags. All git
access funnels through here.

**`internal/sshsig`** and **`internal/pgp`** — the two commit/attestation signing
key families. `sshsig` implements SSHSIG over the DSSE PAE with purpose-binding
namespaces (specification
[ADR-022](https://github.com/semver-trust/spec/blob/main/docs/adr/0022-attestation-signatures-are-sshsig-over-the-dsse-pae-with-purpose-binding-namespaces.md))
and the allowed-signers registry; `pgp` verifies GPG-signed commits against an
armored public keyring. Both are a **fail-closed seam**: when the corresponding
trust material is absent, the key family is *unverifiable*, which is not a pass —
verification aborts rather than waving the commit through.

**`internal/trust`** — the trust model, free of git and clocks. Per-commit
classification from authorship × review (§3.2), the weakest-link own-trust floor
per scope (§5.1–5.2), transitive propagation over the workspace graph with SCC
collapse (§5.3), and the release decision — semantic floor, blast radius, and
the §6.4 table with the `demote`/`inflate` strategies (§6). Given the classified
inputs, this package is a pure function to a decision.

**`internal/policy`** — the strict TOML policy loader. The policy file is the
**root of trust** (§5.4): the loader recognizes exactly the schema's fields,
validates them, and round-trips them; unknown or malformed input is an error,
not a shrug. Optional fields (`adoption_boundary`, `gpg_keyring`,
`attestation_signers`) follow the same strict discipline.

**`internal/attest`** — the attestation machinery: DSSE envelope verification and
emission for review and release attestations, and the git-ref store that reads
and writes them under `refs/attestations/*`. Per specification §8.2 the store is
never the trust anchor — the signature inside the envelope is — so this package
validates signatures and subject digests regardless of where an envelope was
fetched from.

**Derivation claims** are non-authoritative metadata. The verifier never
executes policy-declared derivation commands — running a repository's commands
to level its own outputs both fails to prove derivation (a fixed point is not
provenance) and hands the verifier host to the repository it verifies. A
declared rule is recorded in the report and supplies no trust elevation; its
outputs classify by their commits' own provenance under ordinary weakest-link
flooring. See spec repository ADR-033 (which retired the executable-proof
mechanism of ADR-004/ADR-015).

**`internal/verify`** — the §10 pipeline that composes all of the above into the
verification algorithm: load and self-check the policy, enumerate the range,
classify each commit, partition by scope and compute
own trust, propagate to effective trust, collect evidence, and render the report
(human table or `--json`). `release` extends the same pipeline through the emit
steps (create the tag, sign and store the attestation). This is where "fails
closed" becomes concrete: any unverifiable commit or under-leveled meta-path
commit aborts the run with a one-line reason naming the step.

## The public seams

These are the two importable, non-`internal` packages — the ecosystem plug
points (ADR-011).

**`evidence/`** — the compatibility-evidence provider interface (`evidence.go`)
and the Go implementation (`apidiff`). A provider supplies the semantic floor
and blast-radius inputs for an ecosystem; the core consumes the interface, not
the tool.

**`graph/`** — the workspace-graph adapter interface (`graph.go`) and the Go
module implementation (`gomod`). Propagation (§5.3) walks whatever graph the
adapter returns, so npm/pnpm/Cargo/Bazel adapters slot in without touching the
core.

## Conformance (`conformance/`)

The acceptance suite is the specification's conformance vectors, consumed as
**vendored, digest-pinned copies** (specification
[ADR-021](https://github.com/semver-trust/spec/blob/main/docs/adr/0021-implementations-consume-conformance-artifacts-as-vendored-digest-pinned-copies.md)).
`conformance/vendor/` holds the copied vector files and crypto fixtures;
`conformance/manifest.json` pins each by digest; `manifest_test.go` fails if a
vendored byte drifts from its pin. **Never hand-edit anything under
`conformance/vendor/` or the manifest** — the only sanctioned refresh path is
`python3 scripts/sync-conformance.py <spec-main-sha>`, which re-copies and
re-pins from a stated spec commit. The manifest is also the single spec-version
pin: `--version` reads the draft version and source commit from it. Because a
single draft version pins vector *provenance* but not per-capability coverage,
[conformance-coverage.md](conformance-coverage.md) records which suites are
enforced versus pending as the v0.10 model is adopted.

## Invariant: injected clocks and trust roots (ADR-018)

Verification interfaces accept an injectable clock and injectable trust roots
from day one (specification
[ADR-018](https://github.com/semver-trust/spec/blob/main/docs/adr/0018-verification-interfaces-accept-injectable-trust-roots-and-clock-from-day-one.md)).
No package under `internal/{vcs,trust,attest,sshsig}` may call
`time.Now()`; the wall clock is read exactly once in `cmd/` and threaded through
as a `time.Time`. This is not a stylistic preference — it is what makes the
scheme reproducible. The maintainer's temporary signing key expires 2026-08-01,
so verifying history signed by it requires injecting a verification instant that
predates the expiry; the release attestation *records* the instant it used, and
a reproducing outsider injects **that** instant, not their own wall clock. Same
inputs, same clock, same decision — which is exactly why `v0.1.0` reproduces
from a fresh clone. CI enforces the rule with a grep guard: a `time.Now(` under
the guarded packages fails the build.

## Fixture strategy

Trust tests need repositories with signed history, review attestations, and
known-bad tampering — but committing opaque `.git` blobs would be both
unreadable and non-reproducible. Instead, fixtures are **built by a deterministic
script**: `conformance/vendor/crypto/build-fixture-repos.sh <dest>` constructs
the scenario repositories (signed-history, unknown-signer, revoked-signer,
gpg-signed, tampered, release) from scratch, signing with **vendored test-only
keys** (`conformance/vendor/crypto/keys/`) at a **pinned epoch**
(`2026-01-01T00:00:00Z`). Because the clock, the keys, and the commands are all
fixed, every run yields byte-identical repositories, so signatures and digests
are stable across machines. The test-only keys sign only the fixture tree and
carry the real predicate-type URIs with fake subjects — a compliant test double
that cannot escape the test tree.
