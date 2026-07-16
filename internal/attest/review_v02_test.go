// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

func reviewV02SchemaBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vendorDir(t), "schemas", "review-v0.2.json"))
	if err != nil {
		t.Fatalf("reading review-v0.2 schema: %v", err)
	}
	return data
}

// validReviewV02Input mirrors the vendored predicate-v0.2/review-valid fixture:
// a single human canonical actor approving the final revision of a native
// merge. Digests are the fixture's placeholder content-addresses — the emitter
// records asserted facts, and no digest derivation is invented here.
func validReviewV02Input() ReviewV02Input {
	return ReviewV02Input{
		Subjects: []string{"cccccccccccccccccccccccccccccccccccccccc"},
		Repository: ReviewV02Repository{
			ID:     "repo:semver-trust.test/auth",
			Digest: map[string]string{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		Change:       "pull-request:7",
		MergeContext: "refs/heads/main",
		SourceRevisions: []ReviewRevision{
			{ID: "commit:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
		TargetRevision: ReviewRevision{ID: "commit:cccccccccccccccccccccccccccccccccccccccc"},
		Reviewers: []ReviewerV02{
			{
				ActorID:          "actor:human:alice",
				ActorClass:       "human",
				ActorDigest:      map[string]string{"sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
				Credential:       "alice@semver-trust.test",
				Class:            "human",
				Verdict:          "approved",
				ApprovalState:    "active",
				Coverage:         "final_revision",
				ApprovedRevision: &ReviewRevision{ID: "commit:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
				EffectiveAtMerge: true,
			},
		},
		MergeStrategy:  "merge",
		CaptureMode:    "native",
		ResultRevision: ReviewRevision{ID: "commit:cccccccccccccccccccccccccccccccccccccccc"},
		SourceToResult: map[string]string{"sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
		Timestamp:      emitEpoch,
	}
}

// An emitted review/v0.2 envelope must verify against an INDEPENDENT verifier
// enrolling the signing key for the attestation namespace — the same path
// verify takes — and yield the qualified-review surface it was built from. This
// is the surface trust.QualifyReview (and M4-PR3's consumer) reads.
func TestEmitReviewV02VerifiesIndependently(t *testing.T) {
	signer := newEmitTestSigner(t)
	emitter, err := NewReviewV02Emitter(signer, reviewV02SchemaBytes(t))
	if err != nil {
		t.Fatalf("NewReviewV02Emitter: %v", err)
	}

	in := validReviewV02Input()
	emission, err := emitter.Emit(in)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if emission.KeyID != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Errorf("KeyID = %q, want the signer's SHA256 fingerprint", emission.KeyID)
	}

	verifier, err := NewVerifier([]sshsig.AllowedSigner{{
		Principals: []string{"alice@semver-trust.test"},
		Namespaces: []string{Namespace},
		Key:        signer.PublicKey(),
	}}, map[string][]byte{PredicateReviewV02: reviewV02SchemaBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := verifier.Verify(emission.Envelope, emitEpoch)
	if err != nil {
		t.Fatalf("independent Verify: %v", err)
	}
	if stmt.PredicateType != PredicateReviewV02 {
		t.Errorf("predicateType = %q, want %q", stmt.PredicateType, PredicateReviewV02)
	}
	if stmt.Signer != "alice@semver-trust.test" {
		t.Errorf("signer = %q, want alice@semver-trust.test", stmt.Signer)
	}
	if len(stmt.Subjects) != 1 || stmt.Subjects[0].Digest["gitCommit"] != in.Subjects[0] {
		t.Errorf("subjects = %+v, want name+gitCommit digest per covered SHA", stmt.Subjects)
	}

	// The payload round-trips the full qualified-review surface.
	var payload struct {
		Predicate struct {
			Profile struct {
				PredicateContract struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"predicate_contract"`
				VerificationInstant string `json:"verification_instant"`
			} `json:"profile"`
			Repository struct {
				ID string `json:"id"`
			} `json:"repository"`
			Reviewers []struct {
				Actor struct {
					ID    string `json:"id"`
					Class string `json:"class"`
				} `json:"actor"`
				CredentialIdentity string `json:"credential_identity"`
				Verdict            string `json:"verdict"`
				ApprovalState      string `json:"approval_state"`
				Coverage           string `json:"coverage"`
				EffectiveAtMerge   bool   `json:"effective_at_merge"`
			} `json:"reviewers"`
			Merge struct {
				Strategy    string `json:"strategy"`
				CaptureMode string `json:"capture_mode"`
			} `json:"merge"`
			Timestamp string `json:"timestamp"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(emission.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	p := payload.Predicate
	if p.Profile.PredicateContract.Name != "review" || p.Profile.PredicateContract.Version != "0.2" {
		t.Errorf("predicate_contract = %+v, want review/0.2", p.Profile.PredicateContract)
	}
	if p.Profile.VerificationInstant != "2026-01-01T00:00:00Z" {
		t.Errorf("verification_instant = %q, want the injected instant", p.Profile.VerificationInstant)
	}
	if p.Repository.ID != in.Repository.ID {
		t.Errorf("repository.id = %q, want %q", p.Repository.ID, in.Repository.ID)
	}
	if len(p.Reviewers) != 1 {
		t.Fatalf("reviewers = %+v, want one", p.Reviewers)
	}
	r := p.Reviewers[0]
	if r.Actor.ID != "actor:human:alice" || r.Actor.Class != "human" {
		t.Errorf("reviewer.actor = %+v, want canonical actor:human:alice", r.Actor)
	}
	if r.CredentialIdentity != "alice@semver-trust.test" {
		t.Errorf("credential_identity = %q, want the resolving credential", r.CredentialIdentity)
	}
	if r.Verdict != "approved" || r.ApprovalState != "active" || r.Coverage != "final_revision" || !r.EffectiveAtMerge {
		t.Errorf("reviewer decision surface = %+v, want approved/active/final_revision/effective", r)
	}
	if p.Merge.Strategy != "merge" || p.Merge.CaptureMode != "native" {
		t.Errorf("merge = %+v, want merge/native", p.Merge)
	}
	if p.Timestamp != "2026-01-01T00:00:00Z" {
		t.Errorf("timestamp = %q, want the injected instant", p.Timestamp)
	}
}

// The emitted payload validates against the vendored review-v0.2 schema through
// the same ValidatePayload path verify uses — a second, schema-explicit proof
// beyond the emitter's refuse-to-sign gate.
func TestEmitReviewV02ValidatesAgainstVendoredSchema(t *testing.T) {
	payload, err := BuildReviewV02Statement(validReviewV02Input())
	if err != nil {
		t.Fatalf("BuildReviewV02Statement: %v", err)
	}
	verifier, err := NewVerifier(nil, map[string][]byte{PredicateReviewV02: reviewV02SchemaBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.ValidatePayload(payload); err != nil {
		t.Errorf("ValidatePayload against vendored review-v0.2 schema: %v", err)
	}
}

// An agent reviewer with independent-context evidence and a captured
// squash/rebase final-diff flow emits and validates: the alternate coverage
// path and the §3.3 independence surface both round-trip.
func TestEmitReviewV02AgentFinalDiff(t *testing.T) {
	in := validReviewV02Input()
	in.MergeStrategy = "squash"
	in.CaptureMode = "pre_rewrite"
	in.Reviewers = []ReviewerV02{{
		ActorID:          "actor:agent:review-bot",
		ActorClass:       "agent",
		ActorDigest:      map[string]string{"sha256": "3333333333333333333333333333333333333333333333333333333333333333"},
		Credential:       "oidc:repo:acme/platform:environment:review",
		Class:            "agent",
		Verdict:          "approved",
		ApprovalState:    "active",
		Coverage:         "final_diff",
		ApprovedRevision: nil, // final_diff carries no single approved revision → JSON null
		ApprovedDiff:     map[string]string{"sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
		EffectiveAtMerge: true,
		Independent:      &ReviewIndependentContext{SeparateExecution: true, Evidence: "ci-run:9be21"},
		Agent:            "claude-code/2.1.208",
		Model:            "claude-opus-4-8",
	}}

	emitter, err := NewReviewV02Emitter(newEmitTestSigner(t), reviewV02SchemaBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	emission, err := emitter.Emit(in)
	if err != nil {
		t.Fatalf("Emit (agent final_diff): %v", err)
	}

	// approved_revision emits as JSON null; independent_context and the agent
	// annotations round-trip.
	var payload struct {
		Predicate struct {
			Reviewers []struct {
				ApprovedRevision   json.RawMessage `json:"approved_revision"`
				ApprovedDiff       map[string]string `json:"approved_diff"`
				IndependentContext *struct {
					SeparateExecution bool   `json:"separate_execution"`
					Evidence          string `json:"evidence"`
				} `json:"independent_context"`
				Agent string `json:"agent"`
				Model string `json:"model"`
			} `json:"reviewers"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(emission.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	r := payload.Predicate.Reviewers[0]
	if string(r.ApprovedRevision) != "null" {
		t.Errorf("approved_revision = %s, want JSON null for a final_diff review", r.ApprovedRevision)
	}
	if r.ApprovedDiff["sha256"] == "" {
		t.Errorf("approved_diff not carried: %+v", r.ApprovedDiff)
	}
	if r.IndependentContext == nil || !r.IndependentContext.SeparateExecution || r.IndependentContext.Evidence != "ci-run:9be21" {
		t.Errorf("independent_context = %+v, want the §3.3 evidence", r.IndependentContext)
	}
	if r.Agent != "claude-code/2.1.208" || r.Model != "claude-opus-4-8" {
		t.Errorf("agent/model annotations = %q/%q", r.Agent, r.Model)
	}
}

// A final_revision review that carries no approved_diff / independent_context
// emits them as explicit JSON null (the vendored fixture's shape), not omitted.
func TestEmitReviewV02NullableFieldsEmitNull(t *testing.T) {
	payload, err := BuildReviewV02Statement(validReviewV02Input())
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Predicate struct {
			Reviewers []map[string]json.RawMessage `json:"reviewers"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	r := raw.Predicate.Reviewers[0]
	for _, field := range []string{"approved_diff", "independent_context"} {
		v, present := r[field]
		if !present {
			t.Errorf("%s absent, want explicit JSON null", field)
			continue
		}
		if string(v) != "null" {
			t.Errorf("%s = %s, want JSON null", field, v)
		}
	}
}

func TestBuildReviewV02Preconditions(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ReviewV02Input)
		wantSub string
	}{
		{"no subjects", func(in *ReviewV02Input) { in.Subjects = nil }, "at least one subject"},
		{"no reviewers", func(in *ReviewV02Input) { in.Reviewers = nil }, "at least one reviewer"},
		{"no source revisions", func(in *ReviewV02Input) { in.SourceRevisions = nil }, "at least one source revision"},
		{"zero timestamp", func(in *ReviewV02Input) { in.Timestamp = time.Time{} }, "injected timestamp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := validReviewV02Input()
			c.mutate(&in)
			_, err := BuildReviewV02Statement(in)
			if err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("error = %v, want substring %q", err, c.wantSub)
			}
		})
	}
}
