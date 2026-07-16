// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// runCommand executes the root command with args, returning stdout and the
// error (stderr folded into the error path by cobra).
func runCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err := root.Execute()
	if err != nil && errBuf.Len() > 0 {
		t.Logf("stderr: %s", errBuf.String())
	}
	return out.String(), err
}

func bobKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(cryptoVendorDir(t), "keys", "human-bob")
}

// bobAttestationSigners writes a registry enrolling bob's vendored public key
// for the attestation namespace, for verify's --attestation-signers.
func bobAttestationSigners(t *testing.T) string {
	t.Helper()
	pub, err := os.ReadFile(bobKeyPath(t) + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "attestation_signers")
	line := "bob@semver-trust.test namespaces=\"" + attest.Namespace + "\" " + strings.TrimSpace(string(pub)) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The CLI end of Appendix A step 3: `attest review` emits and stores bob's
// review over root..main of the release fixture, and `verify --json` then
// reports the lifted levels — the same history that verified at own floor T0
// (and aborted outright over root..main) before the attestation landed.
func TestAttestReviewCommandLiftsVerify(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	envelopePath := filepath.Join(t.TempDir(), "review.dsse.json")

	out, err := runCommand(t,
		"attest", "review",
		"--repo", repo,
		"--to", "main", // root..main: every commit, setup included
		"--reviewer", "bob@semver-trust.test",
		"--pr", "https://forge.semver-trust.test/release/pull/3",
		"--key", bobKeyPath(t),
		"--timestamp", "2026-01-01T00:00:00Z",
		"--out", envelopePath,
	)
	if err != nil {
		t.Fatalf("attest review: %v", err)
	}
	for _, want := range []string{
		"review attestation emitted",
		"bob@semver-trust.test (human, approved)",
		"signer:   SHA256:",
		"stored: refs/attestations/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("confirmation output missing %q:\n%s", want, out)
		}
	}

	// --out wrote the same envelope; it parses as a DSSE envelope.
	envBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("--out file: %v", err)
	}
	var env attest.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil || env.PayloadType != attest.PayloadType {
		t.Fatalf("--out envelope: err=%v payloadType=%q", err, env.PayloadType)
	}

	// verify over v0.1.0..main: alice T3, ci-bot T2, own floor T2.
	verifyOut, err := runCommand(t,
		"verify",
		"--repo", repo,
		"--from", "v0.1.0",
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", "2026-01-01T00:00:00Z",
		"--json",
	)
	if err != nil {
		t.Fatalf("verify after attest review: %v", err)
	}
	var report verify.Report
	if err := json.Unmarshal([]byte(verifyOut), &report); err != nil {
		t.Fatalf("decoding report: %v", err)
	}
	levels := map[string]string{}
	for _, c := range report.Commits {
		levels[c.Signer] = c.Level
	}
	if levels["alice@semver-trust.test"] != "T3" || levels["ci-bot@semver-trust.test"] != "T2" {
		t.Errorf("levels = %v, want alice T3 and ci-bot T2", levels)
	}
	if len(report.Scopes) != 1 || report.Scopes[0].OwnFloor != "T2" {
		t.Errorf("own floor = %+v, want T2", report.Scopes)
	}

	// And the root..main run that aborted before the attestation now
	// completes §10 steps 1-7.
	if _, err := runCommand(t,
		"verify",
		"--repo", repo,
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", "2026-01-01T00:00:00Z",
		"--json",
	); err != nil {
		t.Errorf("root..main after attest review: %v", err)
	}
}

// --store=false emits without touching the repository: the envelope goes to
// --out only, and no attestation refs appear.
func TestAttestReviewNoStore(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	envelopePath := filepath.Join(t.TempDir(), "review.dsse.json")

	out, err := runCommand(t,
		"attest", "review",
		"--repo", repo,
		"--commits", "main",
		"--reviewer", "bob@semver-trust.test",
		"--pr", "1",
		"--key", bobKeyPath(t),
		"--timestamp", "2026-01-01T00:00:00Z",
		"--store=false",
		"--out", envelopePath,
	)
	if err != nil {
		t.Fatalf("attest review --store=false: %v", err)
	}
	if !strings.Contains(out, "stored:   no (--store=false)") {
		t.Errorf("output does not state that nothing was stored:\n%s", out)
	}
	if strings.Contains(out, "refs/attestations/") {
		t.Errorf("output names a stored ref despite --store=false:\n%s", out)
	}
	if _, err := os.Stat(envelopePath); err != nil {
		t.Errorf("--out envelope missing: %v", err)
	}
}

// Failure modes surface as errors, not as signed output.
func TestAttestReviewErrors(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")

	cases := map[string][]string{
		"no commits": {
			"attest", "review", "--repo", repo,
			"--reviewer", "bob@semver-trust.test", "--pr", "1", "--key", bobKeyPath(t),
		},
		"bad timestamp": {
			"attest", "review", "--repo", repo, "--to", "main",
			"--reviewer", "bob@semver-trust.test", "--pr", "1", "--key", bobKeyPath(t),
			"--timestamp", "yesterday",
		},
		"schema-invalid verdict refused before signing": {
			"attest", "review", "--repo", repo, "--to", "main",
			"--reviewer", "bob@semver-trust.test", "--pr", "1", "--key", bobKeyPath(t),
			"--verdict", "lgtm",
		},
		"missing key file": {
			"attest", "review", "--repo", repo, "--to", "main",
			"--reviewer", "bob@semver-trust.test", "--pr", "1",
			"--key", filepath.Join(repo, "no-such-key"),
		},
		"missing required flags": {
			"attest", "review", "--repo", repo, "--to", "main",
		},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := runCommand(t, args...); err == nil {
				t.Error("command succeeded, want error")
			}
		})
	}
}

// attest review --predicate v0.2 emits the qualified-review successor predicate
// (ADR-030/ADR-031): the envelope carries a review/v0.2 statement that
// validates against the vendored schema and round-trips the canonical actor —
// the surface M4-PR3's verify path will consume.
func TestAttestReviewV02Command(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	envelopePath := filepath.Join(t.TempDir(), "review-v02.dsse.json")

	out, err := runCommand(t,
		"attest", "review",
		"--repo", repo,
		"--predicate", "v0.2",
		"--commits", "main",
		"--reviewer", "bob@semver-trust.test",
		"--reviewer-actor", "actor:human:bob",
		"--reviewer-actor-digest", "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"--repository-id", "repo:semver-trust.test/release",
		"--repository-digest", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--source-to-result-digest", "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		"--pr", "pull-request:3",
		"--key", bobKeyPath(t),
		"--timestamp", "2026-01-01T00:00:00Z",
		"--store=false",
		"--out", envelopePath,
	)
	if err != nil {
		t.Fatalf("attest review --predicate v0.2: %v", err)
	}
	for _, want := range []string{
		"predicate " + attest.PredicateReviewV02,
		"actor:    actor:human:bob",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("confirmation output missing %q:\n%s", want, out)
		}
	}

	envBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("--out file: %v", err)
	}
	var env attest.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("--out envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decoding envelope payload: %v", err)
	}

	v02Schema, err := conformance.Vector("schemas/review-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := attest.NewVerifier(nil, map[string][]byte{attest.PredicateReviewV02: v02Schema})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.ValidatePayload(payload); err != nil {
		t.Fatalf("emitted payload does not validate against vendored review-v0.2 schema: %v", err)
	}

	var stmt struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Reviewers []struct {
				Actor struct {
					ID string `json:"id"`
				} `json:"actor"`
				Coverage string `json:"coverage"`
			} `json:"reviewers"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatal(err)
	}
	if stmt.PredicateType != attest.PredicateReviewV02 {
		t.Errorf("predicateType = %q, want %q", stmt.PredicateType, attest.PredicateReviewV02)
	}
	if len(stmt.Predicate.Reviewers) != 1 ||
		stmt.Predicate.Reviewers[0].Actor.ID != "actor:human:bob" ||
		stmt.Predicate.Reviewers[0].Coverage != "final_revision" {
		t.Errorf("reviewer = %+v, want the canonical actor:human:bob at final_revision coverage", stmt.Predicate.Reviewers)
	}
}

// PR2 introduced a store guard as a stopgap because verify could not yet
// consume review/v0.2; PR3 wires consumption, so the guard is gone and storing
// is safe. A v0.2 review stored under a policy with no actor map is DECLINED
// (honest degradation, ADR-031) rather than aborting the run — this is the
// regression for PR2's poisoning hazard, now resolved by consumption.
func TestAttestReviewV02StoredThenVerifiedNoAbort(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")

	if _, err := runCommand(t,
		"attest", "review",
		"--repo", repo,
		"--predicate", "v0.2",
		"--commits", "main",
		"--reviewer", "bob@semver-trust.test",
		"--reviewer-actor", "actor:human:bob",
		"--reviewer-actor-digest", "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"--repository-id", "repo:semver-trust.test/release",
		"--repository-digest", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--source-to-result-digest", "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		"--pr", "pull-request:3",
		"--key", bobKeyPath(t),
		"--timestamp", "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("attest review --predicate v0.2 (default store): %v", err)
	}

	// verify over the covered commit now completes — the stored v0.2 review no
	// longer aborts the run (§10 step 3). The release fixture's policy declares
	// no actor map, so the review is declined, not counted.
	if _, err := runCommand(t,
		"verify",
		"--repo", repo,
		"--from", "v0.1.0",
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", "2026-01-01T00:00:00Z",
		"--json",
	); err != nil {
		t.Fatalf("verify over a commit with a stored v0.2 review aborted: %v", err)
	}
}

// --predicate v0.2 fails fast, before signing, when the required canonical-actor
// / repository / digest facts are absent.
func TestAttestReviewV02RequiresFlags(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	_, err := runCommand(t,
		"attest", "review",
		"--repo", repo,
		"--predicate", "v0.2",
		"--commits", "main",
		"--reviewer", "bob@semver-trust.test",
		"--pr", "pull-request:3",
		"--key", bobKeyPath(t),
		"--timestamp", "2026-01-01T00:00:00Z",
	)
	if err == nil {
		t.Fatal("v0.2 emit succeeded without the required actor/repository/digest flags")
	}
	if !strings.Contains(err.Error(), "--predicate v0.2 requires") {
		t.Errorf("error = %v, want the v0.2 required-flags message", err)
	}
}

// An unknown --predicate value is refused.
func TestAttestReviewUnknownPredicate(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	_, err := runCommand(t,
		"attest", "review",
		"--repo", repo,
		"--predicate", "v9",
		"--commits", "main",
		"--reviewer", "bob@semver-trust.test",
		"--pr", "1",
		"--key", bobKeyPath(t),
	)
	if err == nil || !strings.Contains(err.Error(), "--predicate") {
		t.Errorf("error = %v, want an unknown-predicate refusal", err)
	}
}
