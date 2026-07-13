// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// derivationPolicyFmt declares a derivation rule whose command would create a
// sentinel file if it were ever executed. Pre-ADR-033 the verify pipeline ran
// policy-declared commands via `sh -c` with ambient host capabilities — the
// exact primitive a hostile repository would use against whoever verifies it.
// The %s is the absolute sentinel path the command would `touch`.
const derivationPolicyFmt = `# semver-trust TEST POLICY - in-test derivation-claim repo (ADR-033)
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[[derivation]]
name    = "codegen"
inputs  = ["spec/api.txt"]
command = "touch %s"
outputs = ["gen/**"]
`

// TestVerifyNeverExecutesDerivationCommands is the ADR-033 security
// regression. A policy-declared derivation rule MUST:
//
//  1. never execute — the sentinel file its command would create must not
//     exist after verification (the verifier host is never handed to the
//     repository it verifies); and
//  2. never re-level — the agent-authored commit touching the rule's outputs
//     floors its scope at T0, even though the rule's inputs were last touched
//     by a T2 human commit. The retired executable-proof path would have run
//     the command, "verified" the fixed point, and inherited T2 onto the
//     outputs; the claim is now non-authoritative metadata and elevates
//     nothing.
func TestVerifyNeverExecutesDerivationCommands(t *testing.T) {
	keys := stageKeys(t)
	repo := t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	sentinel := filepath.Join(t.TempDir(), "pwned")
	policyBody := fmt.Sprintf(derivationPolicyFmt, sentinel)

	// Human alice touches the rule inputs (spec/api.txt) and the policy: T2.
	commitSigned(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"spec/api.txt", "openapi: 3.1.0\n", "feat: api contract\n\nProvenance: human")
	commitSigned(t, repo, keys, "human-alice", "alice@semver-trust.test",
		".semver-trust/policy.toml", policyBody, "chore: adopt semver-trust\n\nProvenance: human")

	// Agent ci-bot touches the rule outputs (gen/**), unreviewed: T0. Under the
	// retired path this commit's gen/** paths would have inherited alice's T2.
	commitSigned(t, repo, keys, "agent-ci-bot", "ci-bot@semver-trust.test",
		"gen/out.txt", "// generated\n", "chore: regenerate\n\nProvenance: agent\nProvenance-Agent: ci/1.0")

	report, err := Verify(Options{
		RepoPath:           repo,
		From:               "",
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// (1) The command never ran.
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("derivation command executed: sentinel %s exists (err=%v)", sentinel, err)
	}

	// (2) No elevation: the agent commit's scope floors to T0.
	if got := effectiveOf(t, report); got != "T0" {
		t.Errorf("effective trust = %s, want T0 (derivation must not re-level the agent outputs)", got)
	}

	// The rule is recorded as a non-authoritative claim, never verified.
	if len(report.Derivations) != 1 {
		t.Fatalf("derivation reports = %d, want 1", len(report.Derivations))
	}
	if d := report.Derivations[0]; d.Verified || d.Rule != "codegen" || d.Note == "" {
		t.Errorf("derivation report = %+v, want {Rule:codegen Verified:false Note:non-empty}", d)
	}
}

// effectiveOf returns the effective trust of the report's target component,
// falling back to the first component — the same selection the renderer and
// release evaluator use.
func effectiveOf(t *testing.T, report *Report) string {
	t.Helper()
	comps := report.Propagation.Components
	if len(comps) == 0 {
		t.Fatal("propagation has no components")
	}
	for _, c := range comps {
		if c.Name == report.Propagation.Target {
			return c.Effective
		}
	}
	return comps[0].Effective
}
