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
      --commits strings         commit SHAs (or revisions) the review covers, comma-separated
      --from string             range start (exclusive); with --from/--to the covered commits are the FROM..TO range
  -h, --help                    help for review
      --key string              OpenSSH private key to sign with (required; passphrase-protected keys unsupported)
      --merge-strategy string   merge strategy: merge, squash, or rebase (default "merge")
      --out string              also write the envelope JSON to this file
      --pr string               pull/merge request reference, URL or id (required)
      --repo string             repository holding the commits (and the attestation store) (default ".")
      --reviewer string         verified reviewer identity (required)
      --reviewer-class string   reviewer class: human or agent (default "human")
      --store                   store the envelope under refs/attestations/<sha>/... for each subject (default true)
      --timestamp string        review timestamp (RFC3339); empty = now at the CLI boundary
      --to string               range end (inclusive); defaults to HEAD when a range is requested
      --verdict string          review verdict: approved, changes_requested, or commented (default "approved")
```

### SEE ALSO

* [semver-trust attest](semver-trust_attest.md)	 - Emit signed SemVer-Trust attestations

