// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

func releaseEpochTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, releaseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// bobV02Verifier builds the attestation verifier SupersedeHead needs: bob enrolled
// for the attestation namespace + the release-v0.2 schema.
func bobV02Verifier(t *testing.T) *attest.Verifier {
	t.Helper()
	pub, err := os.ReadFile(bobKeyPath(t) + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	signers, err := sshsig.ParseAllowedSigners([]byte(
		"bob@semver-trust.test namespaces=\"" + attest.Namespace + "\" " + strings.TrimSpace(string(pub)) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := conformance.Vector("schemas/release-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewVerifier(signers, map[string][]byte{attest.PredicateReleaseV02: schema})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// setupSupersedeChain builds a repo whose genesis release/v0.2 is an UNPROMOTED
// prerelease (v0.1.0-t0.1, floored to T0 by an unreviewed agent commit) at HEAD —
// the release a promotion supersedes. Returns the repo, descriptor path, and the
// genesis (prerelease) commit.
func setupSupersedeChain(t *testing.T) (repo, descPath, genesisCommit string) {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo = t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/policy.toml":         recurringPolicy,
		".semver-trust/allowed_signers":     treeAllowedSigners(t),
		".semver-trust/attestation_signers": treeAttestationSigners(t),
	}, "feat: adopt semver-trust\n\nProvenance: human")
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget\n", "feat: widget core\n\n"+agentTrailer)

	descPath = writeDescriptorFile(t, recurringDescriptor(t, repo))
	genesisCommit = gitOut(t, repo, "rev-parse", "HEAD")

	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
		"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("genesis prerelease: %v\n%s", err, out)
	}
	return repo, descPath, genesisCommit
}

// TestSupersedeHeadAndVerifyMode is the C5b (verify-side) payoff: a supersede
// re-evaluates the accepted prerelease at its OWN commit. Normal v0.10 verify at
// that commit discovers the head and aborts promotion_required (the interval would
// be P..P); the Supersede mode instead re-runs the superseded's own interval so new
// evidence can be picked up. SupersedeHead resolves the superseded + its anchor.
func TestSupersedeHeadAndVerifyMode(t *testing.T) {
	repo, descPath, genesisCommit := setupSupersedeChain(t)

	// A plain v0.10 verify at the superseded commit discovers the head → recurring
	// P..P → promotion_required.
	_, rerr := runCommand(t, "verify",
		"--repo", repo, "--to", genesisCommit,
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if rerr == nil || !strings.Contains(rerr.Error(), "promotion_required") {
		t.Fatalf("plain verify at the superseded commit: error = %v, want promotion_required", rerr)
	}

	// SupersedeHead resolves the superseded (the prerelease head) and its anchor
	// (nil — the superseded is a genesis release).
	superseded, anchor, err := chain.SupersedeHead(repo, "repo:test/widget", "default", bobV02Verifier(t), releaseEpochTime(t))
	if err != nil {
		t.Fatalf("SupersedeHead: %v", err)
	}
	if superseded == nil || superseded.Tag() != "v0.1.0-t0.1" || superseded.To() != genesisCommit {
		t.Fatalf("superseded = %v, want v0.1.0-t0.1 @ %s", superseded, genesisCommit[:7])
	}
	if anchor != nil {
		t.Errorf("anchor = %+v, want nil (the superseded is a genesis release)", anchor)
	}

	// The Supersede-mode verify re-runs the superseded's own (genesis) interval at
	// the same commit WITHOUT tripping promotion_required.
	desc, err := chain.LoadBootstrapDescriptor(descPath, repo)
	if err != nil {
		t.Fatal(err)
	}
	report, err := verify.Verify(verify.Options{
		RepoPath:    repo,
		To:          genesisCommit,
		PolicyPath:  ".semver-trust/policy.toml",
		Component:   "default",
		VerifyTime:  releaseEpochTime(t),
		Bootstrap:   desc,
		Supersede:   true,
		Predecessor: anchor, // nil → the descriptor's genesis interval
	})
	if err != nil {
		t.Fatalf("Supersede-mode verify: %v", err)
	}
	// A genesis-superseded re-evaluation runs under the bootstrap authority (its own
	// original authority), not a recurring predecessor.
	if report.PolicyState == nil || report.PolicyState.Authority != "bootstrap" {
		t.Errorf("supersede policy authority = %+v, want bootstrap (genesis-superseded)", report.PolicyState)
	}
	if len(report.Commits) == 0 {
		t.Error("supersede re-evaluation classified no commits; the genesis interval should be re-run")
	}
}
