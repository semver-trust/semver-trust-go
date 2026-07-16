// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// reviewPredicate is the subset of the §4.3 review predicate classification
// consumes: the first reviewer's verified identity and class, and the
// asserted separate-execution-context flag (§3.3 condition 1).
type reviewPredicate struct {
	Predicate struct {
		Reviewers []struct {
			Identity string `json:"identity"`
			Class    string `json:"class"`
			Verdict  string `json:"verdict"`
		} `json:"reviewers"`
		Independence *struct {
			SeparateExecutionContext bool `json:"separate_execution_context"`
		} `json:"independence"`
	} `json:"predicate"`
}

// reviewV02Predicate is the subset of the §4.3/ADR-031 review/v0.2 predicate the
// qualified-review path consumes: the first reviewer's canonical actor, class,
// verdict, approval state, coverage, and reviewed revision/diff, plus the merge
// outcome. credential_identity is deliberately NOT read for actor resolution —
// the CredentialActor is derived from the cryptographically verified attestation
// SIGNER (stmt.Signer), never a self-asserted wire string.
type reviewV02Predicate struct {
	Predicate struct {
		Reviewers []struct {
			Actor struct {
				ID    string `json:"id"`
				Class string `json:"class"`
			} `json:"actor"`
			Class            string `json:"class"`
			Verdict          string `json:"verdict"`
			ApprovalState    string `json:"approval_state"`
			Coverage         string `json:"coverage"`
			ApprovedRevision *struct {
				ID string `json:"id"`
			} `json:"approved_revision"`
			ApprovedDiff       map[string]string `json:"approved_diff"`
			EffectiveAtMerge   bool              `json:"effective_at_merge"`
			IndependentContext *struct {
				SeparateExecution bool `json:"separate_execution"`
			} `json:"independent_context"`
		} `json:"reviewers"`
		Merge struct {
			Strategy       string `json:"strategy"`
			CaptureMode    string `json:"capture_mode"`
			ResultRevision struct {
				ID string `json:"id"`
			} `json:"result_revision"`
			SourceToResult map[string]string `json:"source_to_result"`
		} `json:"merge"`
	} `json:"predicate"`
}

// reviewResolution is resolveReview's outcome. facts feeds the raw-identity
// review/v0.1 path; qual feeds the ADR-031 qualified review/v0.2 path (at most
// one is non-nil). ref is the storage ref of the consumed attestation (empty
// when none was consumed); note is the honest-degradation message.
type reviewResolution struct {
	facts *trust.ReviewFacts
	qual  *trust.ReviewQualification
	ref   string
	note  string
}

// resolveReview locates and verifies the review attestation covering a commit
// (§10 step 3, §4.3). Its three outcomes are deliberate:
//
//   - No stored envelopes → no review (nil facts).
//   - Envelopes stored but no attestation-signer registry given → they cannot
//     be verified, so review classifies none — honest degradation (§4.3). The
//     returned note records that a review was present but unverifiable, so the
//     degradation is visible rather than silent.
//   - Envelopes stored and a registry given → each is verified; any that fails
//     to verify aborts (a stored attestation that does not verify is a
//     fail-closed stop, §8.2), and the first verified review predicate whose
//     subject covers the commit supplies the review facts and is recorded as
//     the consumed attestation ref.
//
// The author identity threaded in is the commit's verified signer principal,
// used for the §3.2/§3.3 distinct-identity tests and, for review/v0.2, for
// canonical-actor resolution against the policy actor map.
//
// Predicate dispatch is by type: a review/v0.1 statement takes the raw-identity
// path (reviewFacts); a review/v0.2 statement takes the ADR-031 qualified path
// (reviewQualification). The v0.2 qualification is built from the FIRST covering
// v0.2 attestation and handed to QualifyReview in the trust layer, which renders
// the final verdict — so a v0.2 review that ultimately does not qualify is not
// retried against later attestations (one review per commit is the norm).
func resolveReview(store attest.GitRefStore, v *attest.Verifier, pol *policy.Policy, sha, authorIdentity string, at time.Time) (reviewResolution, error) {
	envelopes, err := store.List(sha)
	if err != nil {
		return reviewResolution{}, err
	}
	if len(envelopes) == 0 {
		return reviewResolution{}, nil
	}
	if v == nil {
		return reviewResolution{
			note: "review attestation present but unverifiable (no --attestation-signers); classified none",
		}, nil
	}

	var skipNote string
	for _, env := range envelopes {
		stmt, err := v.Verify(env, at)
		if err != nil {
			return reviewResolution{}, err // a stored attestation that fails verification aborts (§8.2)
		}
		if !subjectCovers(stmt.Subjects, sha) {
			continue
		}
		switch stmt.PredicateType {
		case attest.PredicateReview:
			facts, note, err := reviewFacts(stmt, authorIdentity)
			if err != nil {
				return reviewResolution{}, err
			}
			if facts == nil {
				// A covering review that does not raise trust (e.g. a
				// non-approved verdict) records why, so the last such note
				// surfaces if no qualifying review is found.
				if note != "" {
					skipNote = note
				}
				continue
			}
			return reviewResolution{facts: facts, ref: attest.EnvelopeRef(sha, env)}, nil
		case attest.PredicateReviewV02:
			qual, note, err := reviewQualification(stmt, pol, sha, authorIdentity)
			if err != nil {
				return reviewResolution{}, err // unmapped credential is fail-closed (§4.2)
			}
			if qual == nil {
				if note != "" {
					skipNote = note
				}
				continue
			}
			return reviewResolution{qual: qual, ref: attest.EnvelopeRef(sha, env)}, nil
		default:
			continue // e.g. a release attestation filed under the commit — not a review
		}
	}
	return reviewResolution{note: skipNote}, nil
}

// reviewFacts builds the trust.ReviewFacts from a verified review statement.
// The first reviewer is authoritative for the scalar classification (§3.2 maps
// a single review class); a signed, verified attestation sets SignedAttestation.
//
// Only an approved verdict raises trust (spec repository ADR-031): a comment or
// a changes-requested review does not establish that the reviewer accepted the
// merged content, so it classifies as no review. A non-approved covering
// review returns nil facts plus a note, so the honest degradation is visible
// rather than silent (and cannot be mistaken for an absent review). Finer
// qualification — canonical actors, final-revision binding, approval state —
// arrives with the review/v0.2 predicate (semver-trust-go#76).
func reviewFacts(stmt attest.Statement, authorIdentity string) (*trust.ReviewFacts, string, error) {
	var rp reviewPredicate
	if err := json.Unmarshal(stmt.Payload, &rp); err != nil {
		return nil, "", err
	}
	if len(rp.Predicate.Reviewers) == 0 {
		return nil, "", nil
	}
	reviewer := rp.Predicate.Reviewers[0]
	if reviewer.Verdict != "approved" {
		return nil, "review verdict " + strconv.Quote(reviewer.Verdict) +
			" does not raise trust (only approved counts, §4.3/ADR-031); classified none", nil
	}
	class := trust.IdentityHuman
	if reviewer.Class == "agent" {
		class = trust.IdentityAgent
	}
	separate := rp.Predicate.Independence != nil && rp.Predicate.Independence.SeparateExecutionContext
	return &trust.ReviewFacts{
		Reviewer:          class,
		ReviewerIdentity:  reviewer.Identity,
		SignerIdentity:    authorIdentity,
		SeparateContext:   separate,
		SignedAttestation: true,
	}, "", nil
}

// reviewQualification builds the ADR-031 trust.ReviewQualification from a
// verified review/v0.2 statement. It is the wire→facts derivation the qualified
// review path (§4.3, ADR-031) runs on; QualifyReview then decides.
//
// Gating (maintainer decision): qualified review is POLICY ACTOR-MAP-gated. When
// the active policy declares no [identity.actor.<id>], a v0.2 review cannot be
// resolved to canonical actors, so it is declined with a note (honest
// degradation, never a lift) — the published v0.1-review chain is unaffected.
//
// Canonical actors are resolved from the CRYPTOGRAPHICALLY VERIFIED principals:
// CredentialActor from the attestation signer (stmt.Signer), AuthorActor from
// the commit signer — never from a self-asserted wire credential string. §4.2:
// an unmapped credential needed to classify a counted review is unverifiable, so
// it fails closed (an error that aborts the run), distinct from a review that
// verifies but simply does not qualify (a note).
//
// The predicate is bound to the commit being classified: sha is the merge
// result, so FinalRevision is that commit and PostApprovalChange holds when the
// predicate's own merge result names a different revision — the merged content
// then differs from what the attestation describes.
func reviewQualification(stmt attest.Statement, pol *policy.Policy, sha, authorIdentity string) (*trust.ReviewQualification, string, error) {
	if len(pol.Identity.Actors) == 0 {
		return nil, "review/v0.2 attestation requires a policy actor map ([identity.actor.*]) to resolve canonical actors; classified none (ADR-031)", nil
	}
	var rp reviewV02Predicate
	if err := json.Unmarshal(stmt.Payload, &rp); err != nil {
		return nil, "", err
	}
	if len(rp.Predicate.Reviewers) == 0 {
		return nil, "", nil
	}
	r := rp.Predicate.Reviewers[0]
	m := rp.Predicate.Merge

	credentialActor, _, ok := pol.ResolveActor(stmt.Signer)
	if !ok {
		return nil, "", fmt.Errorf(
			"review/v0.2 signing credential %q maps to no canonical actor (§4.2 [identity.actor.*]); fail closed",
			stmt.Signer)
	}
	authorActor, _, ok := pol.ResolveActor(authorIdentity)
	if !ok {
		return nil, "", fmt.Errorf(
			"commit signer %q maps to no canonical actor (§4.2 [identity.actor.*]) but a review/v0.2 counts its review; fail closed",
			authorIdentity)
	}

	class := trust.IdentityHuman
	if r.Class == "agent" {
		class = trust.IdentityAgent
	}
	approvedRevision := ""
	if r.ApprovedRevision != nil {
		approvedRevision = r.ApprovedRevision.ID
	}
	separate := r.IndependentContext != nil && r.IndependentContext.SeparateExecution

	classified := "commit:" + sha
	return &trust.ReviewQualification{
		ReviewerClass:      class,
		ReviewerActor:      r.Actor.ID,
		AuthorActor:        authorActor,
		CredentialActor:    credentialActor,
		Verdict:            r.Verdict,
		ApprovalState:      r.ApprovalState,
		EffectiveAtMerge:   r.EffectiveAtMerge,
		Coverage:           r.Coverage,
		ApprovedRevision:   approvedRevision,
		FinalRevision:      classified,
		ApprovedDiff:       canonicalDigest(r.ApprovedDiff),
		ResultDiff:         canonicalDigest(m.SourceToResult),
		MergeStrategy:      m.Strategy,
		CaptureMode:        m.CaptureMode,
		SeparateContext:    separate,
		PostApprovalChange: m.ResultRevision.ID != classified,
		SignedAttestation:  true,
	}, "", nil
}

// canonicalDigest renders a digest set as a stable, comparable string
// (algorithm-sorted "algo:value" pairs). Two digest sets compare equal via this
// form iff they are equal, which is what QualifyReview's final_diff coverage
// needs when binding the approved diff to the merge result.
func canonicalDigest(d map[string]string) string {
	if len(d) == 0 {
		return ""
	}
	algos := make([]string, 0, len(d))
	for algo := range d {
		algos = append(algos, algo)
	}
	sort.Strings(algos)
	pairs := make([]string, 0, len(algos))
	for _, algo := range algos {
		pairs = append(pairs, algo+":"+d[algo])
	}
	return strings.Join(pairs, " ")
}

// subjectCovers reports whether an attestation's subjects bind the commit SHA
// (§8.2: verifiers validate subject digests, not just where the attestation
// was fetched from). A subject matches by name or by any digest value equal to
// the commit hash.
func subjectCovers(subjects []attest.Subject, sha string) bool {
	for _, s := range subjects {
		if s.Name == sha {
			return true
		}
		for _, digest := range s.Digest {
			if digest == sha {
				return true
			}
		}
	}
	return false
}
