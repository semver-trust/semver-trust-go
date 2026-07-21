// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"os/exec"
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

func TestLoadGitConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := gitInit(t)

	g, err := LoadGitConfig(repo)
	if err != nil {
		t.Fatalf("LoadGitConfig: %v", err)
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
