// SPDX-License-Identifier: Apache-2.0

package gitconfig

import (
	"os/exec"
	"strings"
	"testing"
)

func gitInit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "alex@example.com"},
		{"config", "user.name", "Alex"},
		{"config", "gpg.format", "ssh"},
		{"config", "commit.gpgsign", "true"},
		{"config", "user.signingkey", "/keys/commit.pub"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestLoad(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := gitInit(t)

	g, err := Load(repo)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g.GitPath == "" {
		t.Error("GitPath should be the resolved git executable (PATH-hijack visibility)")
	}
	if g.UserEmail != "alex@example.com" || g.UserName != "Alex" {
		t.Errorf("identity = %q / %q", g.UserName, g.UserEmail)
	}
	if g.GPGFormat != "ssh" || g.CommitGPGSign != "true" {
		t.Errorf("signing config = %q / %q", g.GPGFormat, g.CommitGPGSign)
	}
	if g.SigningKey != "/keys/commit.pub" {
		t.Errorf("user.signingkey = %q, want the locally-set value", g.SigningKey)
	}
	if !g.InsideWorkTree || g.Bare {
		t.Errorf("worktree facts wrong: inside=%v bare=%v", g.InsideWorkTree, g.Bare)
	}
}

// gitOut runs a git read against repo and returns trimmed stdout (test helper).
func gitOut(t *testing.T, repo string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func mustGitPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGitWriter(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := gitInit(t)
	g := Git{Path: mustGitPath(t), Repo: repo}

	// Set → the value round-trips through a fresh read.
	if err := g.Set("gpg.ssh.allowedsignersfile", ".semver-trust/allowed_signers"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := gitOut(t, repo, "config", "--get", "gpg.ssh.allowedsignersfile"); got != ".semver-trust/allowed_signers" {
		t.Errorf("after Set = %q", got)
	}

	// Unset removes it.
	if err := g.Unset("gpg.ssh.allowedsignersfile"); err != nil {
		t.Fatalf("Unset: %v", err)
	}
	if got := gitOut(t, repo, "config", "--get", "gpg.ssh.allowedsignersfile"); got != "" {
		t.Errorf("after Unset = %q, want empty", got)
	}

	// AddFetch appends; FetchRefspecs reads it back.
	if err := g.AddFetch("origin", "+refs/attestations/*:refs/attestations/*"); err != nil {
		t.Fatalf("AddFetch: %v", err)
	}
	specs, err := g.FetchRefspecs("origin")
	if err != nil {
		t.Fatalf("FetchRefspecs: %v", err)
	}
	found := false
	for _, s := range specs {
		if s == "+refs/attestations/*:refs/attestations/*" {
			found = true
		}
	}
	if !found {
		t.Errorf("FetchRefspecs = %v, want the appended attestation refspec", specs)
	}

	// A remote with no URL reads as "" (not an error).
	if url, err := g.RemoteURL("nonexistent"); err != nil || url != "" {
		t.Errorf("RemoteURL(nonexistent) = %q, %v; want \"\", nil", url, err)
	}
}
