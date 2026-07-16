## semver-trust attest review

Emit a signed review attestation over commits (spec §4.3)

### Synopsis

attest review emits a §4.3 review attestation: an in-toto Statement whose
subjects are the covered commit SHAs, signed per ADR-022 as an OpenSSH SSHSIG
over the DSSE pre-authentication encoding in the attestation namespace.

The payload is schema-validated before signing (signed bytes are frozen; an
invalid payload is refused, never signed), and the finished envelope is
verified before it is output. By default the envelope is stored in the
repository under refs/attestations/<sha>/... for every covered commit, where
verify's per-commit lookup finds it.

Commits come from --commits and/or a --from/--to range (the same two-dot
semantics verify walks). The signing key must be enrolled — for the
attestation namespace — in the registry verify is given via
--attestation-signers, or the attestation verifies as an unknown signer and
aborts the run.

```
semver-trust attest review [flags]
```

### Options

```
      --agent string                     v0.2: optional reviewing agent tool/version
      --approval-state string            v0.2: approval state: active, stale, withdrawn, or dismissed (default "active")
      --approved-diff-digest string      v0.2: approved-content digest for final_diff coverage, as algo:hex
      --approved-revision string         v0.2: revision the reviewer approved; defaults to the target revision
      --capture-mode string              v0.2: merge capture mode: native or pre_rewrite (default "native")
      --commits strings                  commit SHAs (or revisions) the review covers, comma-separated
      --coverage string                  v0.2: review coverage: final_revision or final_diff (default "final_revision")
      --effective-at-merge               v0.2: whether the approval was still effective at merge (default true)
      --from string                      range start (exclusive); with --from/--to the covered commits are the FROM..TO range
  -h, --help                             help for review
      --independent-context              v0.2: agent review ran in a separate execution context (§3.3)
      --independent-evidence string      v0.2: evidence string backing --independent-context
      --key string                       OpenSSH private key to sign with (required; passphrase-protected keys unsupported)
      --merge-context string             v0.2: target ref the change merges into (default "refs/heads/main")
      --merge-strategy string            merge strategy: merge, squash, or rebase (default "merge")
      --model string                     v0.2: optional reviewing model identifier
      --out string                       also write the envelope JSON to this file
      --pr string                        pull/merge request reference, URL or id (required); the v0.2 review_target.change
      --predicate string                 review predicate to emit: v0.1 (legacy) or v0.2 (qualified review, ADR-030/ADR-031) (default "v0.1")
      --repo string                      repository holding the commits (and the attestation store) (default ".")
      --repository-digest string         v0.2: repository identity digest as algo:hex (required for v0.2)
      --repository-id string             v0.2: canonical repository id, e.g. repo:semver-trust.test/auth (required for v0.2)
      --repository-origin string         v0.2: optional human-facing repository origin (e.g. a clone URL)
      --result-revision string           v0.2: merge result revision; defaults to the target revision
      --reviewer string                  verified reviewer identity (required); for v0.2 this is the credential_identity that resolves to --reviewer-actor
      --reviewer-actor string            v0.2: canonical actor id the reviewer credential resolves to (§4.2), e.g. actor:human:alice (required for v0.2)
      --reviewer-actor-digest string     v0.2: canonical actor identity digest as algo:hex (required for v0.2)
      --reviewer-class string            reviewer class: human or agent (default "human")
      --source-revision strings          v0.2: reviewed source-branch revision(s); defaults to the first covered commit
      --source-to-result-digest string   v0.2: digest binding reviewed source to merge result, as algo:hex (required for v0.2)
      --store                            store the envelope under refs/attestations/<sha>/... for each subject (default true)
      --target-revision string           v0.2: revision the change targets; defaults to --to or the last covered commit
      --timestamp string                 review timestamp (RFC3339); empty = now at the CLI boundary
      --to string                        range end (inclusive); defaults to HEAD when a range is requested
      --verdict string                   review verdict: approved, changes_requested, or commented (default "approved")
```

### SEE ALSO

* [semver-trust attest](semver-trust_attest.md)	 - Emit signed SemVer-Trust attestations

