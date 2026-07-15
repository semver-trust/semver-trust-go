// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file is the emission half for the review/v0.2 predicate (ADR-030,
// ADR-031): the successor to review/v0.1, a structural rewrite that carries the
// full qualified-review surface — canonical actors, approval state, coverage,
// the reviewed revisions, and the merge outcome — that trust.QualifyReview
// decides on. It reuses the emit.go core verbatim: the payload is
// schema-validated against review-v0.2.json BEFORE signing (signed bytes are
// frozen), and the finished envelope is run back through the real Verifier
// before it is output. No wall clock is read here (ADR-018): the timestamp and
// verification instant are injected by the caller.

// ReviewV02Repository is the §4.3/ADR-030 canonical repository identity: a
// stable id, an optional human-facing origin, and an identity digest set (at
// least one algorithm→value).
type ReviewV02Repository struct {
	ID     string
	Origin string // optional
	Digest map[string]string
}

// ReviewRevision is a §4.3 object identity — a revision reference (e.g.
// "commit:<sha>") with an optional digest set pinning its content.
type ReviewRevision struct {
	ID     string
	Digest map[string]string // optional
}

// ReviewIndependentContext is the §3.3 independent-execution evidence for an
// agent reviewer: whether the review ran in a separate execution context, and
// the evidence string backing that assertion.
type ReviewIndependentContext struct {
	SeparateExecution bool
	Evidence          string
}

// ReviewerV02 is one §4.3/ADR-031 reviewer entry keyed to a canonical actor.
// Actor{ID,Class,Digest} is the policy-bound accountable identity (§4.2);
// Credential is the signing/review credential identity that resolves to that
// actor. Coverage is "final_revision" (ApprovedRevision binds the final commit)
// or "final_diff" (ApprovedDiff binds the captured squash/rebase content).
// Independent is set only for agent reviewers (§3.3). Agent/Model annotate an
// agent reviewer and are omitted when empty.
type ReviewerV02 struct {
	ActorID     string
	ActorClass  string // "human" | "agent"
	ActorDigest map[string]string
	Credential  string // credential_identity resolving to ActorID

	Class         string // "human" | "agent"
	Verdict       string // "approved" | "changes_requested" | "commented"
	ApprovalState string // "active" | "withdrawn" | "dismissed" | "stale"
	Coverage      string // "final_revision" | "final_diff"

	// ApprovedRevision is the revision the reviewer approved. It is a required
	// wire field but nullable: nil emits JSON null (the approval predates a
	// captured-diff flow that carries no single approved revision).
	ApprovedRevision *ReviewRevision
	// ApprovedDiff is the approved-content digest for final_diff coverage; nil
	// emits JSON null.
	ApprovedDiff     map[string]string
	EffectiveAtMerge bool

	// Independent carries the §3.3 independent-context evidence; nil emits JSON
	// null (not an agent review, or no evidence recorded).
	Independent *ReviewIndependentContext

	Agent string // optional agent tool/version
	Model string // optional model identifier
}

// ReviewV02Input is everything a §4.3 review/v0.2 statement is built from. The
// boilerplate profile block (spec/predicate/evaluator/identity/source/time
// profile declarations) is defaulted; the caller supplies the review facts. The
// timestamp is injected (ADR-018): callers read the clock at the process
// boundary, never here.
type ReviewV02Input struct {
	// Subjects are the covered commit SHAs; each becomes an in-toto subject
	// binding the SHA as both name and gitCommit digest.
	Subjects []string

	// Repository is the canonical repository the review is scoped to.
	Repository ReviewV02Repository

	// Change is the pull/merge request reference (e.g. "pull-request:7").
	Change string
	// MergeContext is the target ref the change merges into (e.g.
	// "refs/heads/main").
	MergeContext string
	// SourceRevisions are the reviewed source-branch tip(s) (at least one).
	SourceRevisions []ReviewRevision
	// TargetRevision is the revision the change targets/produces.
	TargetRevision ReviewRevision

	// Reviewers is the §4.3 canonical-actor reviewer list (at least one).
	Reviewers []ReviewerV02

	// MergeStrategy is "merge", "squash", or "rebase".
	MergeStrategy string
	// CaptureMode is "native" (the merge preserves the reviewed commits) or
	// "pre_rewrite" (a squash/rebase whose reviewed content is captured before
	// the rewrite).
	CaptureMode string
	// ResultRevision is the merge outcome revision.
	ResultRevision ReviewRevision
	// SourceToResult is the digest binding the reviewed source content to the
	// merge result (at least one algorithm→value).
	SourceToResult map[string]string

	// Timestamp is the merge/review instant, injected by the caller.
	Timestamp time.Time
	// VerificationInstant is the profile's evaluation instant; defaults to
	// Timestamp when zero.
	VerificationInstant time.Time
	// Extensions optionally carries additional predicate extensions.
	Extensions map[string]any
}

// The wire shapes of the review/v0.2 statement. Field order here is the
// payload's byte order: encoding/json marshals struct fields in declaration
// order, so the serialized statement is stable across runs — which matters,
// because the signed bytes are frozen the moment Sign covers them. The default
// profile is fixed (no runtime build info), so the same input always produces
// the same bytes (ADR-018).
type reviewV02StatementJSON struct {
	Type          string                 `json:"_type"`
	Subject       []Subject              `json:"subject"`
	PredicateType string                 `json:"predicateType"`
	Predicate     reviewV02PredicateJSON `json:"predicate"`
}

type reviewV02PredicateJSON struct {
	Profile      reviewProfileJSON      `json:"profile"`
	Repository   repositoryIdentityJSON `json:"repository"`
	ReviewTarget reviewTargetJSON       `json:"review_target"`
	Reviewers    []reviewerV02JSON      `json:"reviewers"`
	Merge        mergeStateJSON         `json:"merge"`
	Timestamp    string                 `json:"timestamp"`
	Extensions   map[string]any         `json:"extensions,omitempty"`
}

type profileJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Digest  map[string]string `json:"digest,omitempty"`
}

type reviewProfileJSON struct {
	Specification       profileJSON `json:"specification"`
	PredicateContract   profileJSON `json:"predicate_contract"`
	Evaluator           profileJSON `json:"evaluator"`
	RepositoryIdentity  profileJSON `json:"repository_identity"`
	ActorIdentity       profileJSON `json:"actor_identity"`
	SourceControl       profileJSON `json:"source_control"`
	VerificationTime    profileJSON `json:"verification_time"`
	VerificationInstant string      `json:"verification_instant"`
}

type repositoryIdentityJSON struct {
	ID     string            `json:"id"`
	Origin string            `json:"origin,omitempty"`
	Digest map[string]string `json:"digest"`
}

type objectIdentityJSON struct {
	ID     string            `json:"id"`
	Digest map[string]string `json:"digest,omitempty"`
}

type reviewTargetJSON struct {
	Change          string               `json:"change"`
	MergeContext    string               `json:"merge_context"`
	SourceRevisions []objectIdentityJSON `json:"source_revisions"`
	TargetRevision  objectIdentityJSON   `json:"target_revision"`
}

type actorIdentityJSON struct {
	ID     string            `json:"id"`
	Class  string            `json:"class"`
	Digest map[string]string `json:"digest"`
}

type independentContextJSON struct {
	SeparateExecution bool   `json:"separate_execution"`
	Evidence          string `json:"evidence"`
}

// reviewerV02JSON field order mirrors the vendored fixture. approved_revision
// and (optionally) approved_diff / independent_context are required-or-nullable
// wire fields, so they are pointers WITHOUT omitempty: nil marshals to JSON
// null, which the schema's oneOf(null, …) accepts. agent/model are omitempty —
// the schema requires minLength 1, so an empty string must be absent, not "".
type reviewerV02JSON struct {
	Actor              actorIdentityJSON       `json:"actor"`
	CredentialIdentity string                  `json:"credential_identity"`
	Class              string                  `json:"class"`
	Verdict            string                  `json:"verdict"`
	ApprovalState      string                  `json:"approval_state"`
	Coverage           string                  `json:"coverage"`
	ApprovedRevision   *objectIdentityJSON     `json:"approved_revision"`
	ApprovedDiff       map[string]string       `json:"approved_diff"`
	IndependentContext *independentContextJSON `json:"independent_context"`
	EffectiveAtMerge   bool                    `json:"effective_at_merge"`
	Agent              string                  `json:"agent,omitempty"`
	Model              string                  `json:"model,omitempty"`
}

type mergeStateJSON struct {
	Strategy       string             `json:"strategy"`
	CaptureMode    string             `json:"capture_mode"`
	ResultRevision objectIdentityJSON `json:"result_revision"`
	SourceToResult map[string]string  `json:"source_to_result"`
}

// defaultReviewProfile is the fixed profile block the emitter declares. The
// values are constants, not runtime build info: the signed bytes must be
// reproducible for a given input (ADR-018), and no verifier consumes the review
// profile identity strings (they are conformance declarations, schema-validated
// for structure only). instant is the injected verification instant.
func defaultReviewProfile(instant time.Time) reviewProfileJSON {
	return reviewProfileJSON{
		Specification:       profileJSON{Name: "semver-trust", Version: "0.10"},
		PredicateContract:   profileJSON{Name: "review", Version: "0.2"},
		Evaluator:           profileJSON{Name: "semver-trust-go", Version: "0.10"},
		RepositoryIdentity:  profileJSON{Name: "git", Version: "0.1"},
		ActorIdentity:       profileJSON{Name: "policy-actor-map", Version: "0.1"},
		SourceControl:       profileJSON{Name: "git", Version: "0.1"},
		VerificationTime:    profileJSON{Name: "injected-clock", Version: "0.1"},
		VerificationInstant: instant.UTC().Format(time.RFC3339),
	}
}

func revisionJSON(r ReviewRevision) objectIdentityJSON {
	return objectIdentityJSON(r)
}

// BuildReviewV02Statement builds the serialized §4.3 in-toto Statement for a
// review/v0.2 predicate: subjects are the covered commit SHAs (name + gitCommit
// digest), the predicate type is the frozen PredicateReviewV02 URI, the profile
// block is the fixed default, and the timestamp/verification instant are the
// injected instants in RFC 3339 UTC. It only shapes bytes — schema validation
// happens in Emit, before any signing. The "at least one" preconditions are
// checked here for a friendly error; every other structural rule (required
// digests, enum values) is enforced by the schema at emit time.
func BuildReviewV02Statement(in ReviewV02Input) ([]byte, error) {
	if len(in.Subjects) == 0 {
		return nil, errors.New("attest: review/v0.2 statement needs at least one subject commit")
	}
	if len(in.Reviewers) == 0 {
		return nil, errors.New("attest: review/v0.2 statement needs at least one reviewer")
	}
	if len(in.SourceRevisions) == 0 {
		return nil, errors.New("attest: review/v0.2 statement needs at least one source revision")
	}
	if in.Timestamp.IsZero() {
		return nil, errors.New("attest: review/v0.2 statement needs an injected timestamp (ADR-018: no wall clock here)")
	}

	instant := in.VerificationInstant
	if instant.IsZero() {
		instant = in.Timestamp
	}

	subjects := make([]Subject, 0, len(in.Subjects))
	for _, sha := range in.Subjects {
		subjects = append(subjects, Subject{Name: sha, Digest: map[string]string{"gitCommit": sha}})
	}

	sources := make([]objectIdentityJSON, 0, len(in.SourceRevisions))
	for _, r := range in.SourceRevisions {
		sources = append(sources, revisionJSON(r))
	}

	reviewers := make([]reviewerV02JSON, 0, len(in.Reviewers))
	for _, r := range in.Reviewers {
		var approvedRev *objectIdentityJSON
		if r.ApprovedRevision != nil {
			rev := revisionJSON(*r.ApprovedRevision)
			approvedRev = &rev
		}
		var independent *independentContextJSON
		if r.Independent != nil {
			independent = &independentContextJSON{
				SeparateExecution: r.Independent.SeparateExecution,
				Evidence:          r.Independent.Evidence,
			}
		}
		reviewers = append(reviewers, reviewerV02JSON{
			Actor: actorIdentityJSON{
				ID:     r.ActorID,
				Class:  r.ActorClass,
				Digest: r.ActorDigest,
			},
			CredentialIdentity: r.Credential,
			Class:              r.Class,
			Verdict:            r.Verdict,
			ApprovalState:      r.ApprovalState,
			Coverage:           r.Coverage,
			ApprovedRevision:   approvedRev,
			ApprovedDiff:       r.ApprovedDiff,
			IndependentContext: independent,
			EffectiveAtMerge:   r.EffectiveAtMerge,
			Agent:              r.Agent,
			Model:              r.Model,
		})
	}

	return json.Marshal(reviewV02StatementJSON{
		Type:          StatementType,
		Subject:       subjects,
		PredicateType: PredicateReviewV02,
		Predicate: reviewV02PredicateJSON{
			Profile: defaultReviewProfile(instant),
			Repository: repositoryIdentityJSON{
				ID:     in.Repository.ID,
				Origin: in.Repository.Origin,
				Digest: in.Repository.Digest,
			},
			ReviewTarget: reviewTargetJSON{
				Change:          in.Change,
				MergeContext:    in.MergeContext,
				SourceRevisions: sources,
				TargetRevision:  revisionJSON(in.TargetRevision),
			},
			Reviewers: reviewers,
			Merge: mergeStateJSON{
				Strategy:       in.MergeStrategy,
				CaptureMode:    in.CaptureMode,
				ResultRevision: revisionJSON(in.ResultRevision),
				SourceToResult: in.SourceToResult,
			},
			Timestamp:  in.Timestamp.UTC().Format(time.RFC3339),
			Extensions: in.Extensions,
		},
	})
}

// ReviewV02Emitter signs review/v0.2 statements into DSSE envelopes per
// ADR-022, through the same core as review/v0.1 and release: the payload is
// schema-validated against review-v0.2.json BEFORE signing, and the finished
// envelope is verified before it is output.
type ReviewV02Emitter struct {
	core *emitter
}

// NewReviewV02Emitter builds an emitter from a signer and the raw review-v0.2
// JSON Schema bytes (injected, like every other piece of trust material — the
// CLI wires the vendored conformance copy).
func NewReviewV02Emitter(signer ssh.Signer, reviewSchema []byte) (*ReviewV02Emitter, error) {
	core, err := newEmitter(signer, PredicateReviewV02, reviewSchema)
	if err != nil {
		return nil, err
	}
	return &ReviewV02Emitter{core: core}, nil
}

// Emit builds, validates, signs, and self-verifies a review/v0.2 attestation —
// the emit.go riders, applied to the §4.3 successor predicate.
func (e *ReviewV02Emitter) Emit(in ReviewV02Input) (Emission, error) {
	payload, err := BuildReviewV02Statement(in)
	if err != nil {
		return Emission{}, err
	}
	return e.core.emit(payload, in.Timestamp)
}

// Signer returns the emitter's signing-key fingerprint — the untrusted keyid
// hint its envelopes carry (ADR-022).
func (e *ReviewV02Emitter) Signer() string {
	return ssh.FingerprintSHA256(e.core.signer.PublicKey())
}
