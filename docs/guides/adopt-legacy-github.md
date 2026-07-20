<!-- SPDX-License-Identifier: Apache-2.0 -->
# Adopting SemVer-Trust on an existing GitHub repository

Your repository has years of history: unsigned commits, departed
contributors, merges made through the web UI. This guide is the adoption
path — what can be recovered, what must be exempted, and how the first
verified release gets cut. The command transcripts are real, produced against
a fabricated legacy repository (two unsigned commits, a release tag `v0.9.4`,
and one commit GPG-signed by a departed developer).

Everything the [bootstrap guide](bootstrap-github.md) sets up — keys, trust
material, policy, hardening, CI — applies here unchanged; this guide covers
only the deltas that history forces on you.

## 1. The adoption decision

One question decides the whole approach: **can every historical commit's
signature be verified with keys you can still obtain?**

- **Yes** → declare no boundary; verify from the root, like a greenfield
  repository. This is more achievable than it looks — see the key archaeology
  below, and note that the reference implementation itself adopted this way:
  its "unverifiable" early key turned out to be GitHub's published web-flow
  key, and spec repository **ADR-026** exists precisely because a boundary
  was almost declared where none was needed. Exhaust archaeology first.
- **No — some history is genuinely unverifiable** (unsigned commits, a truly
  lost key, a platform migration that re-wrote committers) → declare an
  **adoption boundary**: a policy-pinned commit before which history is
  exempt and disclosed as such.

The line between the two remedies is sharp, and worth stating precisely:

> **Post-hoc review lifts *classification*; it cannot repair
> *unverifiability*.** A signed-but-untrailered pre-scheme commit classifies
> as ambiguous (T0) and a review attestation lifts it to T2. An *unsigned*
> commit verifies as nothing at all — no attestation can change that; only
> the boundary can honestly exempt it.

## 2. Key archaeology

Work the loop: run `verify`, read the abort, hunt the key, enroll it, repeat.
Each abort names exactly one problem
([reading verify output](../reference/verify-output.md)).

Add the scheme's trust material as in the
[bootstrap guide §2–3](bootstrap-github.md) — including a `gpg_keyring`
declaration, since legacy history is usually GPG-signed — then:

```console
$ semver-trust verify --repo . --from '' --to HEAD --verify-time 2026-07-13T00:00:00Z
Error: §10 step 1 (load policy): gpg-keyring: pgp: keyring contains no keys
```

(First lesson free: a declared-but-empty registry fails closed. Trust-shaped
input is never half-valid.) Recover the departed developer's public key and
enroll it:

- **GitHub serves every user's GPG keys** at `https://github.com/<user>.gpg`
  and their SSH keys at `https://github.com/<user>.keys` — departed
  contributors included.
- **GitHub's own web-flow key** — the signer of every web-UI merge commit in
  your history — is published at <https://github.com/web-flow.gpg>.
- Old release artifacts, keyservers, and the contributor themselves are all
  fair sources: you need only *public* keys.

```console
$ curl -s https://github.com/departed-dev.gpg >> .semver-trust/gpg-keyring.asc
$ git add .semver-trust/gpg-keyring.asc && git commit -m "chore: enroll Pat's historical signing key" -m "Provenance: human"
$ semver-trust verify --repo . --from '' --to HEAD --verify-time 2026-07-13T00:00:00Z
Error: §10 step 3 (verify signature): verify 9a4617d...: commit is unsigned
```

Progress: the GPG-signed commit now verifies, and the abort has moved to a
commit no key can ever fix. That's the boundary's job.

## 3. The web-flow key, specifically

If your history contains web-UI merges, two entries work together
([why both](../reference/trust-material.md#gpg-keyringasc--the-openpgp-counterpart)):

- The key itself into the keyring — making those merges *verifiable*:

  ```sh
  curl -s https://github.com/web-flow.gpg >> .semver-trust/gpg-keyring.asc
  ```

- Its identity into the policy — keeping them honestly *machine-class*
  (a merge clicked in a UI is not a human authorship claim):

  ```toml
  [identity.agent]
  bot_accounts = ["noreply@github.com"]
  ```

Machine-class commits floor at T0 unreviewed and lift to T2 under your signed
review, like any agent commit. And going forward, stop minting them: merges
are created locally and signed by a maintainer
([bootstrap guide §5](bootstrap-github.md)).

## 4. Declaring the boundary

Name the earliest commit from which everything verifies — here the legacy
release tag `v0.9.4`, whose predecessors are the unsigned commits:

```toml
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
adoption_boundary = "v0.9.4"
```

The boundary is **policy-pinned**: moving it is itself a meta-path commit at the
required level, and the attestation's policy digest freezes which boundary
produced each decision (the three binding properties:
[policy reference](../reference/policy.md#policy--threshold-and-strategy)).
Make sure `.semver-trust/**` is in your meta-paths *before* this commit lands.

Under the opt-in **v0.10 path** (spec ADR-028) the boundary's *authority* is an
out-of-band **bootstrap descriptor** — the authenticated document a verifier
supplies with `--bootstrap-descriptor`, held from *outside* the repository
(distinct from "bootstrapping a repo," the greenfield setup its
[sibling guide](bootstrap-github.md) walks). It does not weaken the "a verifier
cannot move the boundary" property — it *authenticates* it: the in-policy
`adoption_boundary` must match the descriptor's. Absent a descriptor, the
policy-pinned value governs, exactly as this walkthrough shows.

Verification now discloses the anchor on every run — and look at what the
range contains:

```console
$ semver-trust verify --repo . --from '' --to HEAD --verify-time 2026-07-13T00:00:00Z

[§10 steps 2–3] commits
  range: v0.9.4..HEAD (FROM is the adoption boundary declared in policy — history before it is exempt and makes no claim; ADR-026)
  SHA      LEVEL  AUTHORSHIP  REVIEW  SIGNER
  da4f9d8  T2     human       none    alex@example.com
  6ab4e98  T2     human       none    alex@example.com
  d7f9fea  T2     human       none    alex@example.com
  eed5ae3  T0     ambiguous   none    pat@legacy.example
```

The unsigned commits are *outside the range* — exempt and disclosed, not T0
(unverifiable is never T0). Pat's signed-but-untrailered commit is inside it,
classified ambiguous at T0: recoverable, which is the next step.

## 5. Lift what review can lift

Review the boundary-anchored range and attest it — this is your
accountability act over history you've inspected and now stand behind:

```console
$ semver-trust attest review --repo . --from v0.9.4 --to HEAD \
    --reviewer alex@example.com --verdict approved \
    --pr https://github.com/you/oldproj/pulls \
    --key ~/.ssh/semver-trust-attest --store
$ semver-trust verify --repo . --from '' --to HEAD --verify-time 2026-07-13T00:00:00Z
  ...
  eed5ae3  T2     ambiguous   human_distinct  pat@legacy.example
```

Classification lifted, exactly as promised — and exactly as far as promised:
had `eed5ae3` been unsigned, no attestation would have touched it.

## 6. The first boundary-anchored release

```console
$ semver-trust release --repo . --from '' --to HEAD \
    --claimed-bump minor --blast low \
    --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
    --verify-time 2026-07-13T00:00:00Z
```

The release attestation records the anchor honestly (spec §8.1) — a consumer
can always distinguish "verified since the boundary" from "verified since
inception":

```json
"range": {
  "from": "v0.9.4",
  "to": "da4f9d8a5d6d3ca40182d45929ac4af87a0b7837",
  "from_is_adoption_boundary": true
}
```

**The version line, continued** (spec ADR-029;
[issue #70](https://github.com/semver-trust/semver-trust-go/issues/70), resolved).
The walkthrough above ran the default v0.3 path (`--from ''`), which derives the
version fresh — producing `v0.1.0`, which sorts *below* the legacy `v0.9.4` line —
and forced an either/or between a continued version line and the boundary
disclosure. The **v0.10 opt-in path removes the tradeoff**: supply a bootstrap
descriptor whose `version_predecessor` binds the legacy tag (`v0.9.4`, with its
raw ref and peeled commit OIDs), and the authenticated ancestry continues the line
to `v0.10.0` **while** the boundary disclosure still rides into the attestation —
both are independent authenticated facts, no longer a function of `--from`
spelling. The v0.10 adoption release adds three flags (illustrative — this
sub-step is not part of the executed walkthrough above; the descriptor is supplied
from *outside* the repository):

```sh
semver-trust release --repo . --to HEAD \
  --bootstrap-descriptor ../widget-descriptor.json \
  --predicate v0.2 --repository-digest sha256:<repo-identity-digest> \
  --claimed-bump minor --blast low \
  --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
  --verify-time 2026-07-13T00:00:00Z
```

The v0.3 `--from ''` release above stays valid — it is how the published
v0.1.x–v0.2.x chain verifies — but it carries the old tradeoff; the descriptor
path is the one that continues the legacy line cleanly.

## 7. Moving the boundary later

Don't plan to. The boundary is an admission recorded once, not a dial: moving
it is a meta-path policy commit like any other (gated, visible in history) — and
under the v0.10 path the out-of-band bootstrap descriptor must be re-issued to
match, so the boundary cannot drift on the repo side alone (ADR-028). ADR-026
carries a standing revisit trigger — repeated re-baselining is the abuse
signature reviewers should look for. If more history later becomes
verifiable (a key resurfaces), you *may* move the boundary earlier and
disclose why; there is rarely a legitimate reason to move it later.
