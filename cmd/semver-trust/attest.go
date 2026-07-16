// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// newAttestCmd is the `attest` command group: emitting signed SemVer-Trust
// attestations (the production side of what `verify` consumes).
func newAttestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Emit signed SemVer-Trust attestations",
	}
	cmd.AddCommand(newAttestReviewCmd())
	return cmd
}

// newAttestReviewCmd is `attest review`: the post-hoc review machinery of
// spec §4.3/§7.3 (Appendix A step 3). A reviewer reviews commits, this
// command emits the signed review attestation as an ADR-022 DSSE envelope
// and stores it under each covered commit, and `verify` then lifts those
// commits' levels per §3.2.
// reviewV02Flags groups the review/v0.2-only inputs (ADR-030/ADR-031): the
// canonical-actor and repository identities, the reviewed revisions, the
// approval/coverage surface, and the merge outcome. They are consulted only
// when --predicate is v0.2.
type reviewV02Flags struct {
	actorID              string
	actorDigest          string
	repositoryID         string
	repositoryOrigin     string
	repositoryDigest     string
	mergeContext         string
	approvalState        string
	coverage             string
	captureMode          string
	sourceRevs           []string
	targetRev            string
	approvedRev          string
	resultRev            string
	sourceToResultDigest string
	approvedDiffDigest   string
	effectiveAtMerge     bool
	independentContext   bool
	independentEvidence  string
	agent                string
	model                string
}

func newAttestReviewCmd() *cobra.Command {
	var (
		repoPath      string
		commits       []string
		from          string
		to            string
		predicate     string
		reviewer      string
		reviewerClass string
		verdict       string
		pr            string
		mergeStrategy string
		keyPath       string
		timestamp     string
		storeEnvelope bool
		outPath       string
		v2            reviewV02Flags
	)

	cmd := &cobra.Command{
		Use:   "review",
		Short: "Emit a signed review attestation over commits (spec §4.3)",
		Long: `attest review emits a §4.3 review attestation: an in-toto Statement whose
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
aborts the run.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The review timestamp is read once, here at the process boundary,
			// and injected (ADR-018 keeps internal/* free of time.Now).
			ts := time.Now().UTC()
			if timestamp != "" {
				parsed, err := time.Parse(time.RFC3339, timestamp)
				if err != nil {
					return fmt.Errorf("--timestamp: %w", err)
				}
				ts = parsed
			}

			subjects, err := resolveSubjects(repoPath, commits, from, to)
			if err != nil {
				return err
			}
			if len(subjects) == 0 {
				return errors.New("no commits to attest: give --commits and/or --from/--to")
			}

			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("--key: %w", err)
			}
			signer, err := sshsig.LoadSigner(keyBytes)
			if err != nil {
				return err
			}

			var (
				emission     attest.Emission
				predicateURI string
			)
			switch predicate {
			case "v0.1", "":
				predicateURI = attest.PredicateReview
				emission, err = emitReviewV01(signer, subjects, reviewer, reviewerClass, verdict, pr, mergeStrategy, ts)
			case "v0.2":
				predicateURI = attest.PredicateReviewV02
				emission, err = emitReviewV02(repoPath, signer, subjects, reviewer, reviewerClass, verdict, pr, mergeStrategy, ts, v2)
			default:
				return fmt.Errorf("--predicate: %q not supported (want v0.1 or v0.2)", predicate)
			}
			if err != nil {
				return err
			}

			var refs []string
			if storeEnvelope {
				refs, err = attest.StoreForSubjects(attest.GitRefStore{Path: repoPath}, subjects, emission.Envelope)
				if err != nil {
					return err
				}
			}
			if outPath != "" {
				if err := os.WriteFile(outPath, emission.Envelope, 0o644); err != nil {
					return fmt.Errorf("--out: %w", err)
				}
			}

			w := &errWriter{w: cmd.OutOrStdout()}
			w.printf("review attestation emitted (predicate %s)\n", predicateURI)
			w.printf("  reviewer: %s (%s, %s)\n", reviewer, reviewerClass, verdict)
			if predicate == "v0.2" {
				w.printf("  actor:    %s\n", v2.actorID)
			}
			w.printf("  signer:   %s\n", emission.KeyID)
			w.printf("  subjects:\n")
			for i, s := range subjects {
				w.printf("    %s\n", s)
				if i < len(refs) {
					w.printf("      stored: %s\n", refs[i])
				}
			}
			if !storeEnvelope {
				w.printf("  stored:   no (--store=false)\n")
			}
			if outPath != "" {
				w.printf("  written:  %s\n", outPath)
			}
			return w.err
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository holding the commits (and the attestation store)")
	f.StringSliceVar(&commits, "commits", nil, "commit SHAs (or revisions) the review covers, comma-separated")
	f.StringVar(&from, "from", "", "range start (exclusive); with --from/--to the covered commits are the FROM..TO range")
	f.StringVar(&to, "to", "", "range end (inclusive); defaults to HEAD when a range is requested")
	f.StringVar(&predicate, "predicate", "v0.1", "review predicate to emit: v0.1 (legacy) or v0.2 (qualified review, ADR-030/ADR-031)")
	f.StringVar(&reviewer, "reviewer", "", "verified reviewer identity (required); for v0.2 this is the credential_identity that resolves to --reviewer-actor")
	f.StringVar(&reviewerClass, "reviewer-class", "human", "reviewer class: human or agent")
	f.StringVar(&verdict, "verdict", "approved", "review verdict: approved, changes_requested, or commented")
	f.StringVar(&pr, "pr", "", "pull/merge request reference, URL or id (required); the v0.2 review_target.change")
	f.StringVar(&mergeStrategy, "merge-strategy", "merge", "merge strategy: merge, squash, or rebase")
	f.StringVar(&keyPath, "key", "", "OpenSSH private key to sign with (required; passphrase-protected keys unsupported)")
	f.StringVar(&timestamp, "timestamp", "", "review timestamp (RFC3339); empty = now at the CLI boundary")
	f.BoolVar(&storeEnvelope, "store", true, "store the envelope under refs/attestations/<sha>/... for each subject")
	f.StringVar(&outPath, "out", "", "also write the envelope JSON to this file")

	// review/v0.2-only flags (ADR-030/ADR-031); consulted only with --predicate v0.2.
	f.StringVar(&v2.actorID, "reviewer-actor", "", "v0.2: canonical actor id the reviewer credential resolves to (§4.2), e.g. actor:human:alice (required for v0.2)")
	f.StringVar(&v2.actorDigest, "reviewer-actor-digest", "", "v0.2: canonical actor identity digest as algo:hex (required for v0.2)")
	f.StringVar(&v2.repositoryID, "repository-id", "", "v0.2: canonical repository id, e.g. repo:semver-trust.test/auth (required for v0.2)")
	f.StringVar(&v2.repositoryOrigin, "repository-origin", "", "v0.2: optional human-facing repository origin (e.g. a clone URL)")
	f.StringVar(&v2.repositoryDigest, "repository-digest", "", "v0.2: repository identity digest as algo:hex (required for v0.2)")
	f.StringVar(&v2.mergeContext, "merge-context", "refs/heads/main", "v0.2: target ref the change merges into")
	f.StringVar(&v2.approvalState, "approval-state", "active", "v0.2: approval state: active, stale, withdrawn, or dismissed")
	f.StringVar(&v2.coverage, "coverage", "final_revision", "v0.2: review coverage: final_revision or final_diff")
	f.StringVar(&v2.captureMode, "capture-mode", "native", "v0.2: merge capture mode: native or pre_rewrite")
	f.StringSliceVar(&v2.sourceRevs, "source-revision", nil, "v0.2: reviewed source-branch revision(s); defaults to the first covered commit")
	f.StringVar(&v2.targetRev, "target-revision", "", "v0.2: revision the change targets; defaults to --to or the last covered commit")
	f.StringVar(&v2.approvedRev, "approved-revision", "", "v0.2: revision the reviewer approved; defaults to the target revision")
	f.StringVar(&v2.resultRev, "result-revision", "", "v0.2: merge result revision; defaults to the target revision")
	f.StringVar(&v2.sourceToResultDigest, "source-to-result-digest", "", "v0.2: digest binding reviewed source to merge result, as algo:hex (required for v0.2)")
	f.StringVar(&v2.approvedDiffDigest, "approved-diff-digest", "", "v0.2: approved-content digest for final_diff coverage, as algo:hex")
	f.BoolVar(&v2.effectiveAtMerge, "effective-at-merge", true, "v0.2: whether the approval was still effective at merge")
	f.BoolVar(&v2.independentContext, "independent-context", false, "v0.2: agent review ran in a separate execution context (§3.3)")
	f.StringVar(&v2.independentEvidence, "independent-evidence", "", "v0.2: evidence string backing --independent-context")
	f.StringVar(&v2.agent, "agent", "", "v0.2: optional reviewing agent tool/version")
	f.StringVar(&v2.model, "model", "", "v0.2: optional reviewing model identifier")

	for _, required := range []string{"reviewer", "pr", "key"} {
		if err := cmd.MarkFlagRequired(required); err != nil {
			panic(err)
		}
	}
	return cmd
}

// emitReviewV01 emits the legacy §4.3 review/v0.1 attestation: a single
// reviewer entry (identity/class/verdict) over the covered subjects.
func emitReviewV01(signer ssh.Signer, subjects []string, reviewer, reviewerClass, verdict, pr, mergeStrategy string, ts time.Time) (attest.Emission, error) {
	reviewSchema, err := conformance.Vector("schemas/review-v0.1.json")
	if err != nil {
		return attest.Emission{}, err
	}
	emitter, err := attest.NewReviewEmitter(signer, reviewSchema)
	if err != nil {
		return attest.Emission{}, err
	}
	return emitter.Emit(attest.ReviewInput{
		Subjects: subjects,
		Reviewers: []attest.Reviewer{{
			Identity: reviewer,
			Class:    reviewerClass,
			Verdict:  verdict,
		}},
		PullRequest:   pr,
		MergeStrategy: mergeStrategy,
		Timestamp:     ts,
	})
}

// emitReviewV02 assembles and emits a §4.3 review/v0.2 attestation (ADR-030/
// ADR-031): the canonical-actor reviewer, the reviewed revisions, and the merge
// outcome. The identity and content digests are asserted facts the caller
// supplies (the CLI invents no digest derivation); revisions default to the
// range/subject tips when their flags are unset.
func emitReviewV02(repoPath string, signer ssh.Signer, subjects []string, credential, reviewerClass, verdict, change, mergeStrategy string, ts time.Time, v2 reviewV02Flags) (attest.Emission, error) {
	missing := []string{}
	for name, val := range map[string]string{
		"--reviewer-actor":          v2.actorID,
		"--reviewer-actor-digest":   v2.actorDigest,
		"--repository-id":           v2.repositoryID,
		"--repository-digest":       v2.repositoryDigest,
		"--source-to-result-digest": v2.sourceToResultDigest,
	} {
		if val == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return attest.Emission{}, fmt.Errorf("--predicate v0.2 requires: %s", strings.Join(missing, ", "))
	}
	if v2.independentContext && v2.independentEvidence == "" {
		return attest.Emission{}, errors.New("--independent-context requires --independent-evidence (§3.3 independence must carry evidence)")
	}

	actorDigest, err := parseDigestFlag("--reviewer-actor-digest", v2.actorDigest)
	if err != nil {
		return attest.Emission{}, err
	}
	repoDigest, err := parseDigestFlag("--repository-digest", v2.repositoryDigest)
	if err != nil {
		return attest.Emission{}, err
	}
	sourceToResult, err := parseDigestFlag("--source-to-result-digest", v2.sourceToResultDigest)
	if err != nil {
		return attest.Emission{}, err
	}

	// Revisions default to the range/subject tips. Subjects are already
	// resolved full SHAs; caller-supplied revisions resolve through the repo.
	firstSubject := attest.ReviewRevision{ID: commitRef(subjects[0])}
	lastSubject := attest.ReviewRevision{ID: commitRef(subjects[len(subjects)-1])}

	sources := []attest.ReviewRevision{firstSubject}
	if len(v2.sourceRevs) > 0 {
		sources = nil
		for _, rev := range v2.sourceRevs {
			r, err := resolveRevisionRef(repoPath, rev)
			if err != nil {
				return attest.Emission{}, fmt.Errorf("--source-revision: %w", err)
			}
			sources = append(sources, r)
		}
	}

	target := lastSubject
	if v2.targetRev != "" {
		if target, err = resolveRevisionRef(repoPath, v2.targetRev); err != nil {
			return attest.Emission{}, fmt.Errorf("--target-revision: %w", err)
		}
	}
	approved := target
	if v2.approvedRev != "" {
		if approved, err = resolveRevisionRef(repoPath, v2.approvedRev); err != nil {
			return attest.Emission{}, fmt.Errorf("--approved-revision: %w", err)
		}
	}
	result := target
	if v2.resultRev != "" {
		if result, err = resolveRevisionRef(repoPath, v2.resultRev); err != nil {
			return attest.Emission{}, fmt.Errorf("--result-revision: %w", err)
		}
	}

	var approvedDiff map[string]string
	if v2.approvedDiffDigest != "" {
		if approvedDiff, err = parseDigestFlag("--approved-diff-digest", v2.approvedDiffDigest); err != nil {
			return attest.Emission{}, err
		}
	}
	var independent *attest.ReviewIndependentContext
	if v2.independentEvidence != "" {
		independent = &attest.ReviewIndependentContext{
			SeparateExecution: v2.independentContext,
			Evidence:          v2.independentEvidence,
		}
	}

	schema, err := conformance.Vector("schemas/review-v0.2.json")
	if err != nil {
		return attest.Emission{}, err
	}
	emitter, err := attest.NewReviewV02Emitter(signer, schema)
	if err != nil {
		return attest.Emission{}, err
	}
	return emitter.Emit(attest.ReviewV02Input{
		Subjects: subjects,
		Repository: attest.ReviewV02Repository{
			ID:     v2.repositoryID,
			Origin: v2.repositoryOrigin,
			Digest: repoDigest,
		},
		Change:          change,
		MergeContext:    v2.mergeContext,
		SourceRevisions: sources,
		TargetRevision:  target,
		Reviewers: []attest.ReviewerV02{{
			ActorID:          v2.actorID,
			ActorClass:       reviewerClass,
			ActorDigest:      actorDigest,
			Credential:       credential,
			Class:            reviewerClass,
			Verdict:          verdict,
			ApprovalState:    v2.approvalState,
			Coverage:         v2.coverage,
			ApprovedRevision: &approved,
			ApprovedDiff:     approvedDiff,
			EffectiveAtMerge: v2.effectiveAtMerge,
			Independent:      independent,
			Agent:            v2.agent,
			Model:            v2.model,
		}},
		MergeStrategy:  mergeStrategy,
		CaptureMode:    v2.captureMode,
		ResultRevision: result,
		SourceToResult: sourceToResult,
		Timestamp:      ts,
	})
}

// commitRef renders a full commit SHA as the review/v0.2 object-identity id.
func commitRef(sha string) string { return "commit:" + sha }

// resolveRevisionRef resolves a git revision to a review/v0.2 object identity
// (commit:<full-sha>), so tags and abbreviated hashes never leak into the
// reviewed-revision fields.
func resolveRevisionRef(repoPath, rev string) (attest.ReviewRevision, error) {
	sha, err := vcs.ResolveCommit(repoPath, rev)
	if err != nil {
		return attest.ReviewRevision{}, err
	}
	return attest.ReviewRevision{ID: commitRef(sha)}, nil
}

// parseDigestFlag parses an "algo:hex" digest flag into the single-entry digest
// set the schema's digestSet expects. Both halves must be non-empty.
func parseDigestFlag(flag, value string) (map[string]string, error) {
	algo, hex, ok := strings.Cut(value, ":")
	if !ok || algo == "" || hex == "" {
		return nil, fmt.Errorf("%s: %q is not algo:hex (e.g. sha256:<hex>)", flag, value)
	}
	return map[string]string{algo: hex}, nil
}

// resolveSubjects turns --commits entries and an optional --from/--to range
// into a deduplicated, order-preserving list of full commit SHAs. Every
// entry resolves through the repository, so tags and abbreviated hashes
// never leak into storage keys or attestation subjects.
func resolveSubjects(repoPath string, commits []string, from, to string) ([]string, error) {
	var subjects []string
	seen := map[string]bool{}
	add := func(sha string) {
		if !seen[sha] {
			seen[sha] = true
			subjects = append(subjects, sha)
		}
	}

	for _, rev := range commits {
		sha, err := vcs.ResolveCommit(repoPath, rev)
		if err != nil {
			return nil, fmt.Errorf("--commits: %w", err)
		}
		add(sha)
	}
	if from != "" || to != "" {
		rangeTo := to
		if rangeTo == "" {
			rangeTo = "HEAD"
		}
		rcs, err := vcs.Range(repoPath, from, rangeTo)
		if err != nil {
			return nil, err
		}
		for _, rc := range rcs {
			add(rc.Hash)
		}
	}
	return subjects, nil
}
