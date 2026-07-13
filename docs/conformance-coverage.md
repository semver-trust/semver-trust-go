<!-- SPDX-License-Identifier: Apache-2.0 -->
# Conformance coverage

This implementation vendors the SemVer-Trust conformance vectors digest-pinned
(ADR-021; see [`conformance/`](../conformance/) and
[architecture.md](architecture.md)). `semver-trust --version` reports the spec
draft version of the vendored vectors — currently **v0.10**.

A single draft version pins the *provenance* of the vendored vectors; it is not
a claim that every v0.10 protocol capability is implemented. The spec's draft
v0.10 introduced the audit-hardening model (ADR-027 through ADR-035) as several
large new vector suites. This table states exactly which suites the
implementation **enforces** (loads and passes) versus which remain **pending**
while the model is adopted incrementally (tracked in
[semver-trust-go#76](https://github.com/semver-trust/semver-trust-go/issues/76)).

| Suite | Spec area | Status |
|---|---|---|
| levels | §3.2 per-commit classification | **enforced** |
| precedence | §7.1 trust-version ordering | **enforced** |
| grammar | §7.1 trust-version parsing | **enforced** |
| aggregation | §5.1–5.2 scope floors (derivation non-authoritative, ADR-033) | **enforced** |
| propagation | §5.3 transitive propagation | **enforced** |
| decision | §6.2–6.4 threshold gate + decision table (ADR-032) | **enforced** |
| signature | §4.2 / §10 commit-signature verification | **enforced** |
| attestation | §8.2 DSSE verify + v0.1/v0.2 predicate **schema** validation | **enforced** |
| review-qualification | §4.3 qualified review + canonical actors (ADR-031) | pending |
| range | §5.2 exact release intervals (ADR-027) | pending |
| policy-transition | §5.4 bootstrap + policy transitions (ADR-028) | pending |
| version-ancestry | §7.5 authenticated version state (ADR-029) | pending |
| source-evidence | §8.3 SLSA Source profiles (ADR-035) | pending |
| publishing-profile | §7.4 ecosystem routing (ADR-034) | pending |
| predicate-v0.2 | §8.1 release/v0.2 payload validation (ADR-030) | pending |

**What "attestation enforced" covers today:** the DSSE verification path
verifies signatures against the injected attestation-signer registry and
validates release/v0.1, review/v0.1, **and** release/v0.2, review/v0.2 envelopes
against their JSON Schemas at the injected instant. It does not yet consume the
full v0.4+ release semantics the v0.2 predicate carries (interval, policy-state,
version-state); that lands with the range / policy-transition / version-ancestry
suites above.

Each pending suite is enforced by a dedicated PR under #76 that vendors the
suite, adds its Go loader, implements the ADR behavior, and flips its row here.
