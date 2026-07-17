// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

// A fixed 64-hex repository digest the §4.3 identity binds (operator-supplied).
const repoDigestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// releaseV02PayloadJSON is the subset of the §8.1 release/v0.2 payload the tests
// assert on.
type releaseV02PayloadJSON struct {
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		Repository struct {
			ID     string            `json:"id"`
			Digest map[string]string `json:"digest"`
		} `json:"repository"`
		Interval struct {
			Mode           string            `json:"mode"`
			SourceIdentity map[string]string `json:"source_identity"`
		} `json:"interval"`
		PolicyState struct {
			Authority         string `json:"authority"`
			AuthorityIdentity struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"authority_identity"`
		} `json:"policy_state"`
		VersionState struct {
			Action         string           `json:"action"`
			Genesis        bool             `json:"genesis"`
			Predecessor    *json.RawMessage `json:"predecessor"`
			PriorState     *json.RawMessage `json:"prior_state"`
			ResultingState struct {
				ID     string            `json:"id"`
				Digest map[string]string `json:"digest"`
			} `json:"resulting_state"`
			TargetCore string `json:"target_core"`
			TargetBump string `json:"target_bump"`
			Emission   struct {
				Kind string `json:"kind"`
				Tag  *struct {
					Name            string `json:"name"`
					RawRefOID       string `json:"raw_ref_oid"`
					PeeledCommitOID string `json:"peeled_commit_oid"`
				} `json:"tag"`
			} `json:"emission"`
			Iteration *int `json:"iteration"`
		} `json:"version_state"`
		Decision struct {
			Threshold string `json:"threshold"`
			Channel   string `json:"channel"`
		} `json:"decision"`
	} `json:"predicate"`
}

// TestReleaseV02GenesisInception is the M6 Phase B payoff: a genesis v0.10
// release with --predicate v0.2 emits a schema-valid, self-verifying release/v0.2
// whose resulting_state.digest reproduces via version.StateDigest and whose
// emission.tag carries the real signed-tag OIDs — and a subsequent verify accepts
// the stored attestation (it no longer fails closed on an unsupported predicate).
func TestReleaseV02GenesisInception(t *testing.T) {
	repo := buildInceptionRepo(t)
	descPath := writeDescriptorFile(t, inceptionDescriptor(t, repo))

	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "alice",
		"--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("release --predicate v0.2: %v\n%s", err, out)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Channel != "clean" || result.Tag != "v0.1.0" {
		t.Fatalf("decision = channel %s tag %s; want clean v0.1.0 (fresh inception line)", result.Channel, result.Tag)
	}
	if len(result.StoredRefs) != 2 {
		t.Errorf("stored_refs = %v, want two (commit + tag subjects)", result.StoredRefs)
	}

	// Read the stored envelope by tag subject and validate it against the vendored
	// release-v0.2 schema (belt-and-suspenders: Emit already self-verified it).
	byTag, err := attest.GitRefStore{Path: repo}.List("v0.1.0")
	if err != nil || len(byTag) != 1 {
		t.Fatalf("stored envelopes under tag = %d (%v), want 1", len(byTag), err)
	}
	payload := envelopePayload(t, byTag[0])
	validateReleaseV02Payload(t, payload)

	var stmt releaseV02PayloadJSON
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatal(err)
	}
	if stmt.PredicateType != attest.PredicateReleaseV02 {
		t.Errorf("predicateType = %q, want %q", stmt.PredicateType, attest.PredicateReleaseV02)
	}

	// Repository / interval identity.
	if stmt.Predicate.Repository.Digest["sha256"] != repoDigestHex {
		t.Errorf("repository.digest = %v, want the operator-supplied %s", stmt.Predicate.Repository.Digest, repoDigestHex)
	}
	if stmt.Predicate.Interval.Mode != "inception" ||
		stmt.Predicate.Interval.SourceIdentity["gitCommit"] != result.ToCommit {
		t.Errorf("interval = %+v, want inception bound to %s", stmt.Predicate.Interval, result.ToCommit[:7])
	}

	// Genesis version_state: no predecessor, no prior state, advance.
	vs := stmt.Predicate.VersionState
	if vs.Action != "advance" || !vs.Genesis {
		t.Errorf("version_state action=%q genesis=%v, want advance/true", vs.Action, vs.Genesis)
	}
	if vs.Predecessor != nil || vs.PriorState != nil {
		t.Errorf("genesis predecessor=%v prior_state=%v, want both null", vs.Predecessor, vs.PriorState)
	}
	if vs.Iteration != nil {
		t.Errorf("iteration = %v, want null for a clean cut", *vs.Iteration)
	}

	// The emission.tag binds the REAL signed-tag OIDs: the peeled commit is TO, and
	// the raw ref OID is the annotated tag object (distinct from the commit).
	if vs.Emission.Kind != "tag" || vs.Emission.Tag == nil {
		t.Fatalf("emission = %+v, want a real tag binding after CreateSignedTag", vs.Emission)
	}
	if vs.Emission.Tag.Name != "v0.1.0" || vs.Emission.Tag.PeeledCommitOID != result.ToCommit {
		t.Errorf("emission.tag = %+v, want name v0.1.0 peeled to %s", *vs.Emission.Tag, result.ToCommit[:7])
	}
	if vs.Emission.Tag.RawRefOID == "" || vs.Emission.Tag.RawRefOID == result.ToCommit {
		t.Errorf("emission.tag.raw_ref_oid = %q, want the annotated tag object OID (distinct from the commit)", vs.Emission.Tag.RawRefOID)
	}

	// resulting_state.digest reproduces: rebuild the genesis-inception state the
	// CLI canonicalized (ADR-036) and re-hash it. A future recurring verifier does
	// exactly this to authenticate the chain link.
	state := version.VersionState{
		Baseline:        nil,
		BaselineCore:    "0.0.0",
		TargetCore:      "0.1.0",
		TargetBump:      "minor",
		CleanAccepted:   true,
		TargetIntervals: []string{version.GenesisIntervalID("default", "inception")},
		Iterations:      map[string]int{},
	}
	want, err := version.StateDigest(version.CanonicalStateMap("default", "", state, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := vs.ResultingState.Digest["sha256"]; got != want {
		t.Errorf("resulting_state.digest = %s, does not reproduce via StateDigest (%s)", got, want)
	}
	if vs.ResultingState.ID != "version-state:default:v0.1.0" {
		t.Errorf("resulting_state.id = %q, want version-state:default:v0.1.0", vs.ResultingState.ID)
	}

	// policy_state authenticated under the bootstrap authority.
	if stmt.Predicate.PolicyState.Authority != "bootstrap" ||
		stmt.Predicate.PolicyState.AuthorityIdentity.URI != "bootstrap:default" {
		t.Errorf("policy_state authority = %+v, want bootstrap / bootstrap:default", stmt.Predicate.PolicyState)
	}
	if stmt.Predicate.Decision.Threshold != "T2" || stmt.Predicate.Decision.Channel != "clean" {
		t.Errorf("decision = %+v, want threshold T2 / clean", stmt.Predicate.Decision)
	}

	// verify accepts the stored release/v0.2: resolveReview verifies every envelope
	// under the release commit, so an unregistered predicate would fail closed here.
	// Registration (buildAttestationVerifier, shared by both modes) makes it
	// validate and be skipped as a non-review — the run completes without aborting.
	// (Run in the v0.3 path so --attestation-signers can supply bob's key; v0.10
	// mode forbids that override, resolving trust material from TO's tree only.)
	vout, verr := runCommand(t, "verify",
		"--repo", repo, "--from", "", "--to", "main",
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", releaseEpoch, "--json")
	if verr != nil {
		t.Fatalf("verify rejected the stored release/v0.2 (registration regression?): %v\n%s", verr, vout)
	}
}

// TestReleaseV02DryRunEmitsNullTag confirms the dry-run preview creates no tag:
// version_state.emission.tag is null (the OID is unknowable without a real tag),
// while the kind stays "tag".
func TestReleaseV02DryRunEmitsNullTag(t *testing.T) {
	repo := buildInceptionRepo(t)
	descPath := writeDescriptorFile(t, inceptionDescriptor(t, repo))

	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err != nil {
		t.Fatalf("release --predicate v0.2 --dry-run: %v\n%s", err, out)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	var stmt releaseV02PayloadJSON
	if err := json.Unmarshal(result.Statement, &stmt); err != nil {
		t.Fatal(err)
	}
	if stmt.Predicate.VersionState.Emission.Kind != "tag" {
		t.Errorf("emission.kind = %q, want tag", stmt.Predicate.VersionState.Emission.Kind)
	}
	if stmt.Predicate.VersionState.Emission.Tag != nil {
		t.Errorf("emission.tag = %+v, want null in a dry-run preview (no tag created)", *stmt.Predicate.VersionState.Emission.Tag)
	}
	if len(result.StoredRefs) != 0 {
		t.Errorf("dry-run stored %v, want nothing written", result.StoredRefs)
	}
}

// TestReleaseV02RequiresDescriptorAndDigest confirms the opt-in preconditions:
// v0.2 needs the bootstrap descriptor (the authenticated policy/version state) and
// the operator-supplied §4.3 repository digest.
func TestReleaseV02RequiresDescriptorAndDigest(t *testing.T) {
	repo := buildInceptionRepo(t)
	descPath := writeDescriptorFile(t, inceptionDescriptor(t, repo))

	// No descriptor.
	_, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--predicate", "v0.2",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil || !strings.Contains(err.Error(), "bootstrap-descriptor") {
		t.Errorf("v0.2 without a descriptor: error = %v, want a --bootstrap-descriptor requirement", err)
	}

	// Descriptor but no repository digest.
	_, err = runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2",
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil || !strings.Contains(err.Error(), "repository-digest") {
		t.Errorf("v0.2 without a repository digest: error = %v, want a --repository-digest requirement", err)
	}
}

// validateReleaseV02Payload validates payload against the vendored release-v0.2
// JSON Schema.
func validateReleaseV02Payload(t *testing.T, payload []byte) {
	t.Helper()
	schemaBytes, err := conformance.Vector("schemas/release-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("release-v0.2.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("release-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("payload does not validate against release-v0.2.json: %v", err)
	}
}
