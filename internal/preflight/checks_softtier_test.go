// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// stage writes rel under the repo and adds it to the index, so the --staged
// simulate checks see it.
func stage(t *testing.T, repo, rel, content string) {
	t.Helper()
	p := filepath.Join(repo, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "add", rel).CombinedOutput(); err != nil {
		t.Fatalf("git add %s: %v\n%s", rel, err, out)
	}
}

func TestConfiguredVsEnrolled(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	// The doctorRepo signing key is enrolled for alex@example.com → PASS.
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	if r := checkConfiguredVsEnrolled(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("configured-vs-enrolled (enrolled) = %s %q, want PASS", r.Severity, r.Message)
	}
}

func TestSignRoundtrip(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	// doctorRepo now writes the private half alongside the .pub → a real round-trip.
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	if r := checkSignRoundtrip(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("sign-roundtrip = %s %q, want PASS", r.Severity, r.Message)
	}

	// Remove the private half → the round-trip cannot run and must SKIP (not FAIL):
	// an agent-held or hardware-token key is a normal, non-erroneous state.
	env := envFor(t, repo, Maintainer)
	if err := os.Remove(env.Git.SigningKey[:len(env.Git.SigningKey)-len(".pub")]); err != nil {
		t.Fatal(err)
	}
	if r := checkSignRoundtrip(env); r.Severity != SKIP {
		t.Errorf("sign-roundtrip (no private half) = %s %q, want SKIP", r.Severity, r.Message)
	}
}

func TestMetaTouch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// No --staged → SKIP.
	if r := checkMetaTouch(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("meta-touch (no --staged) = %s, want SKIP", r.Severity)
	}

	// Staged meta-path change → WARN for a maintainer, FAIL for an agent.
	stage(t, repo, ".semver-trust/note.txt", "x")
	mEnv := envFor(t, repo, Maintainer)
	mEnv.Staged = true
	if r := checkMetaTouch(mEnv); r.Severity != WARN {
		t.Errorf("meta-touch (staged meta, maintainer) = %s %q, want WARN", r.Severity, r.Message)
	}
	aEnv := envFor(t, repo, Agent)
	aEnv.Staged = true
	r := checkMetaTouch(aEnv)
	if r.Severity != FAIL {
		t.Errorf("meta-touch (staged meta, agent) = %s %q, want FAIL", r.Severity, r.Message)
	}
	if r.Preempts == "" {
		t.Errorf("meta-touch FAIL should name the meta-path gate; Preempts empty")
	}
}

func TestStagedPurity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// Pure meta staged → PASS.
	stage(t, repo, ".semver-trust/note.txt", "x")
	pureEnv := envFor(t, repo, Maintainer)
	pureEnv.Staged = true
	if r := checkStagedPurity(pureEnv); r.Severity != PASS {
		t.Errorf("staged-purity (pure meta) = %s %q, want PASS", r.Severity, r.Message)
	}

	// Add an ordinary staged path → mixed → WARN.
	stage(t, repo, "README.md", "hi")
	mixEnv := envFor(t, repo, Maintainer)
	mixEnv.Staged = true
	if r := checkStagedPurity(mixEnv); r.Severity != WARN {
		t.Errorf("staged-purity (mixed) = %s %q, want WARN", r.Severity, r.Message)
	}
}

func TestAgentProvenance(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// The adopt commit carries no Provenance trailer → no agent-authored meta → PASS.
	if r := checkAgentProvenance(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("agent-provenance (none) = %s %q, want PASS", r.Severity, r.Message)
	}

	// Add a meta-path commit stamped Provenance: agent → WARN.
	run := func(args ...string) {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".semver-trust", "note.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".semver-trust/note.txt")
	run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "tweak\n\nProvenance: agent")
	if r := checkAgentProvenance(envFor(t, repo, Maintainer)); r.Severity != WARN {
		t.Errorf("agent-provenance (agent meta commit) = %s %q, want WARN", r.Severity, r.Message)
	}
}

func TestPreAdoption(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}

	// An adopted repo (a policy is present) → SKIP.
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	if r := checkPreAdoption(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("pre-adoption (adopted) = %s, want SKIP", r.Severity)
	}

	// A repo with commits but no policy at HEAD → the triage WARN.
	bare := t.TempDir()
	run := func(args ...string) {
		if out, err := exec.Command("git", append([]string{"-C", bare}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "a@example.com")
	run("config", "user.name", "A")
	if err := os.WriteFile(filepath.Join(bare, "README.md"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")
	git, err := LoadGitConfig(bare)
	if err != nil {
		t.Fatal(err)
	}
	env := &Env{Repo: bare, Persona: Maintainer, At: time.Now(), Git: git}
	if r := checkPreAdoption(env); r.Severity != WARN {
		t.Errorf("pre-adoption (no policy) = %s %q, want WARN", r.Severity, r.Message)
	}
}

func TestChainHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	// No --bootstrap-descriptor → the accepted chain head is not projectable → SKIP.
	if r := checkChainHead(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("chain-head (no descriptor) = %s %q, want SKIP", r.Severity, r.Message)
	}
}

func TestFetchRefspec(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// No attestation refspec configured → WARN with the git config --add fix.
	env := envFor(t, repo, Maintainer)
	if r := checkFetchRefspec(env); r.Severity != WARN {
		t.Errorf("fetch-refspec (unconfigured) = %s %q, want WARN", r.Severity, r.Message)
	}

	// Configure it and reload git config → PASS (exercises the --get-all reader).
	if out, err := exec.Command("git", "-C", repo, "config", "--add",
		"remote.origin.fetch", "+refs/attestations/*:refs/attestations/*").CombinedOutput(); err != nil {
		t.Fatalf("git config: %v\n%s", err, out)
	}
	if r := checkFetchRefspec(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("fetch-refspec (configured) = %s %q, want PASS", r.Severity, r.Message)
	}
}

func TestRulesets(t *testing.T) {
	if r := checkRulesets(&Env{}); r.Severity != SKIP {
		t.Errorf("rulesets = %s, want SKIP (always)", r.Severity)
	}
}

func TestReleaseBaseline(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// No tags → SKIP.
	if r := checkReleaseBaseline(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("release-baseline (no tags) = %s, want SKIP", r.Severity)
	}

	// A tag → the informational reproduction line.
	if out, err := exec.Command("git", "-C", repo, "tag", "v0.1.0").CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v\n%s", err, out)
	}
	if r := checkReleaseBaseline(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("release-baseline (tagged) = %s %q, want PASS", r.Severity, r.Message)
	}
}
