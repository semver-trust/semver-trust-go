// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// The ADR-031 payoff: a review/v0.2 attestation, under a policy that declares a
// canonical-actor map, is consumed via trust.QualifyReview — replacing the
// raw-string reviewer-vs-author comparison. These tests exercise the three
// outcomes the raw-string model could not express: distinct canonical actors
// lift, one actor under two credentials (key rotation) does not double-count,
// and an unmapped credential fails closed.

// distinctActorPolicy maps alice and bob to two distinct human actors.
const distinctActorPolicy = `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.actor.alice]
class       = "human"
credentials = ["alice@semver-trust.test"]

[identity.actor.bob]
class       = "human"
credentials = ["bob@semver-trust.test"]
`

// rotatedActorPolicy folds bob's signing credential into alice's actor — the
// key-rotation / alias case §4.2 collapses to one canonical actor.
const rotatedActorPolicy = `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.actor.alice]
class       = "human"
credentials = ["alice@semver-trust.test", "bob@semver-trust.test"]
`

// unmappedReviewerPolicy maps only alice; bob's review credential resolves to no
// actor.
const unmappedReviewerPolicy = `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.actor.alice]
class       = "human"
credentials = ["alice@semver-trust.test"]
`

// buildActorMapRepo builds a one-commit repo authored+signed by alice, whose
// tree carries the given actor-map policy at .semver-trust/policy.toml.
func buildActorMapRepo(t *testing.T, policyTOML string) (repo, sha string) {
	t.Helper()
	return sshSignedRepoWithTree(t, map[string]string{
		".semver-trust/policy.toml": policyTOML,
		"main.go":                   "package main\n",
	}, "alice@semver-trust.test", "human-alice", "feat: initial commit")
}

// emitReviewV02Signed emits a review/v0.2 approving the final revision of sha,
// signed by keyName and claiming canonical actor actorID. resultRevID sets
// merge.result_revision (pass "commit:"+sha for the bound case).
func emitReviewV02Signed(t *testing.T, keyName, actorID, sha, resultRevID string) attest.Emission {
	t.Helper()
	keyBytes, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "keys", keyName))
	if err != nil {
		t.Fatalf("reading vendored key %s: %v", keyName, err)
	}
	signer, err := sshsig.LoadSigner(keyBytes)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	schema, err := conformance.Vector("schemas/review-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := attest.NewReviewV02Emitter(signer, schema)
	if err != nil {
		t.Fatal(err)
	}
	commitRef := "commit:" + sha
	emission, err := emitter.Emit(attest.ReviewV02Input{
		Subjects:     []string{sha},
		Repository:   attest.ReviewV02Repository{ID: "repo:semver-trust.test/unit", Digest: map[string]string{"sha256": strings.Repeat("a", 64)}},
		Change:       "pull-request:1",
		MergeContext: "refs/heads/main",
		SourceRevisions: []attest.ReviewRevision{
			{ID: commitRef},
		},
		TargetRevision: attest.ReviewRevision{ID: commitRef},
		Reviewers: []attest.ReviewerV02{{
			ActorID:          actorID,
			ActorClass:       "human",
			ActorDigest:      map[string]string{"sha256": strings.Repeat("1", 64)},
			Credential:       "review@semver-trust.test",
			Class:            "human",
			Verdict:          "approved",
			ApprovalState:    "active",
			Coverage:         "final_revision",
			ApprovedRevision: &attest.ReviewRevision{ID: commitRef},
			EffectiveAtMerge: true,
		}},
		MergeStrategy:  "merge",
		CaptureMode:    "native",
		ResultRevision: attest.ReviewRevision{ID: resultRevID},
		SourceToResult: map[string]string{"sha256": strings.Repeat("2", 64)},
		Timestamp:      pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("Emit review/v0.2: %v", err)
	}
	return emission
}

func verifyActorMapRepo(t *testing.T, repo, policyPath string) (*Report, error) {
	t.Helper()
	return Verify(Options{
		RepoPath:               repo,
		From:                   "",
		To:                     "main",
		PolicyPath:             policyPath,
		AllowedSignersPath:     allowedSignersPath(t),
		AttestationSignersPath: bobAttestationRegistry(t),
		VerifyTime:             pinnedEpoch,
	})
}

// A v0.2 approval from a canonical actor distinct from the (human) author lifts
// the commit to T3 — two accountable humans, expressed over canonical actors.
func TestReviewV02DistinctActorLiftsT3(t *testing.T) {
	repo, sha := buildActorMapRepo(t, distinctActorPolicy)

	// Baseline: alice authors alone → T2.
	before, err := verifyActorMapRepo(t, repo, ".semver-trust/policy.toml")
	if err != nil {
		t.Fatalf("baseline verify: %v", err)
	}
	if before.Commits[0].Level != "T2" {
		t.Fatalf("baseline level = %s, want T2", before.Commits[0].Level)
	}

	// bob (a distinct canonical actor) approves.
	emission := emitReviewV02Signed(t, "human-bob", "bob", sha, "commit:"+sha)
	if _, err := attest.StoreForSubjects(attest.GitRefStore{Path: repo}, []string{sha}, emission.Envelope); err != nil {
		t.Fatalf("storing envelope: %v", err)
	}

	after, err := verifyActorMapRepo(t, repo, ".semver-trust/policy.toml")
	if err != nil {
		t.Fatalf("after verify: %v", err)
	}
	c := after.Commits[0]
	if c.Level != "T3" || c.Review != "human_distinct" {
		t.Errorf("commit = %s/%s, want T3/human_distinct (author alice + distinct human bob)", c.Level, c.Review)
	}
	if c.ReviewIdentity != "bob" {
		t.Errorf("ReviewIdentity = %q, want the canonical actor bob", c.ReviewIdentity)
	}
}

// A v0.2 approval whose signing credential resolves to the AUTHOR's canonical
// actor (a rotated key / alias) does not add a second accountable human: the
// commit stays T2, and the report names same_canonical_actor. This is the
// double-count the raw-string model could not prevent.
func TestReviewV02SameCanonicalActorDoesNotLift(t *testing.T) {
	repo, sha := buildActorMapRepo(t, rotatedActorPolicy)

	// bob's key is alice's rotated credential; the review claims actor alice.
	emission := emitReviewV02Signed(t, "human-bob", "alice", sha, "commit:"+sha)
	if _, err := attest.StoreForSubjects(attest.GitRefStore{Path: repo}, []string{sha}, emission.Envelope); err != nil {
		t.Fatalf("storing envelope: %v", err)
	}

	report, err := verifyActorMapRepo(t, repo, ".semver-trust/policy.toml")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	c := report.Commits[0]
	if c.Level != "T2" || c.Review != "none" {
		t.Errorf("commit = %s/%s, want T2/none (one canonical actor, no second human)", c.Level, c.Review)
	}
	if !strings.Contains(c.ReviewNote, "same_canonical_actor") {
		t.Errorf("ReviewNote = %q, want same_canonical_actor named", c.ReviewNote)
	}
}

// A v0.2 review signed by a credential that maps to no canonical actor is
// unverifiable under the §4.2 actor map — the run fails closed (an abort), never
// a silent skip.
func TestReviewV02UnmappedCredentialAborts(t *testing.T) {
	repo, sha := buildActorMapRepo(t, unmappedReviewerPolicy)

	// bob is enrolled to ATTEST (so the envelope verifies) but is absent from the
	// actor map — the abort is the unmapped-actor stop, not an unknown signer.
	emission := emitReviewV02Signed(t, "human-bob", "bob", sha, "commit:"+sha)
	if _, err := attest.StoreForSubjects(attest.GitRefStore{Path: repo}, []string{sha}, emission.Envelope); err != nil {
		t.Fatalf("storing envelope: %v", err)
	}

	_, err := verifyActorMapRepo(t, repo, ".semver-trust/policy.toml")
	assertAbortStep(t, err, stepAttestation)
	if err == nil || !strings.Contains(err.Error(), "no canonical actor") {
		t.Errorf("error = %v, want the unmapped-credential fail-closed message", err)
	}
}

// reviewQualification unit tests: the wire→facts derivation, exercised without a
// full repository.
func TestReviewQualificationDerivation(t *testing.T) {
	pol, err := policy.Parse([]byte(distinctActorPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sha := strings.Repeat("c", 40)
	commitRef := "commit:" + sha

	payload, err := attest.BuildReviewV02Statement(attest.ReviewV02Input{
		Subjects:        []string{sha},
		Repository:      attest.ReviewV02Repository{ID: "repo:x", Digest: map[string]string{"sha256": strings.Repeat("a", 64)}},
		Change:          "pull-request:1",
		MergeContext:    "refs/heads/main",
		SourceRevisions: []attest.ReviewRevision{{ID: commitRef}},
		TargetRevision:  attest.ReviewRevision{ID: commitRef},
		Reviewers: []attest.ReviewerV02{{
			ActorID: "bob", ActorClass: "human", ActorDigest: map[string]string{"sha256": strings.Repeat("1", 64)},
			Credential: "review@x", Class: "human", Verdict: "approved", ApprovalState: "active",
			Coverage: "final_revision", ApprovedRevision: &attest.ReviewRevision{ID: commitRef}, EffectiveAtMerge: true,
		}},
		MergeStrategy:  "merge",
		CaptureMode:    "native",
		ResultRevision: attest.ReviewRevision{ID: commitRef},
		SourceToResult: map[string]string{"sha256": strings.Repeat("2", 64)},
		Timestamp:      pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("BuildReviewV02Statement: %v", err)
	}

	// Actors resolve from the verified principals; the qualification binds to sha.
	stmt := attest.Statement{PredicateType: attest.PredicateReviewV02, Payload: payload, Signer: "bob@semver-trust.test"}
	q, note, err := reviewQualification(stmt, pol, sha, "alice@semver-trust.test")
	if err != nil {
		t.Fatalf("reviewQualification: %v (note %q)", err, note)
	}
	if q == nil {
		t.Fatalf("nil qualification, note %q", note)
	}
	if q.CredentialActor != "bob" || q.AuthorActor != "alice" || q.ReviewerActor != "bob" {
		t.Errorf("actors = cred %q author %q reviewer %q, want bob/alice/bob", q.CredentialActor, q.AuthorActor, q.ReviewerActor)
	}
	if q.FinalRevision != commitRef || q.ApprovedRevision != commitRef {
		t.Errorf("revisions = final %q approved %q, want both %q", q.FinalRevision, q.ApprovedRevision, commitRef)
	}
	if q.PostApprovalChange {
		t.Error("post_approval_change set for a merge result that names the classified commit")
	}
	if q.ResultDiff != "sha256:"+strings.Repeat("2", 64) {
		t.Errorf("ResultDiff = %q, want the canonical source_to_result digest", q.ResultDiff)
	}
	if !q.SignedAttestation {
		t.Error("SignedAttestation not set for a verified attestation")
	}
	if r, reason := trust.QualifyReview(trust.AuthorshipHuman, *q); r != trust.ReviewHumanDistinct || reason != "" {
		t.Errorf("QualifyReview = %v/%q, want human_distinct", r, reason)
	}

	// A merge whose result names a different revision than the classified commit
	// derives post_approval_change (the merged content changed).
	other := "commit:" + strings.Repeat("d", 40)
	moved := attest.Statement{PredicateType: attest.PredicateReviewV02, Payload: mustRebuildResult(t, other, sha), Signer: "bob@semver-trust.test"}
	q2, _, err := reviewQualification(moved, pol, sha, "alice@semver-trust.test")
	if err != nil {
		t.Fatal(err)
	}
	if !q2.PostApprovalChange {
		t.Error("post_approval_change not derived when merge result != classified commit")
	}
}

// A v0.2 review under a policy with no actor map is declined (not aborted): the
// qualified path is actor-map-gated, and the raw-identity chain is preserved.
func TestReviewQualificationNoActorMapDeclines(t *testing.T) {
	pol, err := policy.Parse([]byte(minimalNoActorPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stmt := attest.Statement{PredicateType: attest.PredicateReviewV02, Payload: []byte(`{"predicate":{}}`), Signer: "bob@semver-trust.test"}
	q, note, err := reviewQualification(stmt, pol, strings.Repeat("c", 40), "alice@semver-trust.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q != nil {
		t.Errorf("qualification = %+v, want nil (no actor map)", q)
	}
	if !strings.Contains(note, "actor map") {
		t.Errorf("note = %q, want the missing-actor-map degradation", note)
	}
}

// An unmapped signing credential returns an error (fail-closed), not a decline.
func TestReviewQualificationUnmappedSignerErrors(t *testing.T) {
	pol, err := policy.Parse([]byte(distinctActorPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sha := strings.Repeat("c", 40)
	commitRef := "commit:" + sha
	payload := mustRebuildResult(t, commitRef, sha)
	stmt := attest.Statement{PredicateType: attest.PredicateReviewV02, Payload: payload, Signer: "mallory@semver-trust.test"}
	if _, _, err := reviewQualification(stmt, pol, sha, "alice@semver-trust.test"); err == nil {
		t.Fatal("unmapped signer resolved; want a fail-closed error")
	} else if !strings.Contains(err.Error(), "no canonical actor") {
		t.Errorf("error = %v, want the unmapped-credential message", err)
	}
}

const minimalNoActorPolicy = `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
`

// mustRebuildResult builds a review/v0.2 payload whose merge.result_revision is
// resultRevID and whose reviewer approves commit:sha (actor bob).
func mustRebuildResult(t *testing.T, resultRevID, sha string) []byte {
	t.Helper()
	commitRef := "commit:" + sha
	payload, err := attest.BuildReviewV02Statement(attest.ReviewV02Input{
		Subjects:        []string{sha},
		Repository:      attest.ReviewV02Repository{ID: "repo:x", Digest: map[string]string{"sha256": strings.Repeat("a", 64)}},
		Change:          "pull-request:1",
		MergeContext:    "refs/heads/main",
		SourceRevisions: []attest.ReviewRevision{{ID: commitRef}},
		TargetRevision:  attest.ReviewRevision{ID: commitRef},
		Reviewers: []attest.ReviewerV02{{
			ActorID: "bob", ActorClass: "human", ActorDigest: map[string]string{"sha256": strings.Repeat("1", 64)},
			Credential: "review@x", Class: "human", Verdict: "approved", ApprovalState: "active",
			Coverage: "final_revision", ApprovedRevision: &attest.ReviewRevision{ID: commitRef}, EffectiveAtMerge: true,
		}},
		MergeStrategy:  "merge",
		CaptureMode:    "native",
		ResultRevision: attest.ReviewRevision{ID: resultRevID},
		SourceToResult: map[string]string{"sha256": strings.Repeat("2", 64)},
		Timestamp:      pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("BuildReviewV02Statement: %v", err)
	}
	return payload
}
