// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// rangeByHash indexes a full root..HEAD Range walk by commit hash — the oracle
// IntervalCommits must reproduce for any subset.
func rangeByHash(t *testing.T, repo string) map[string]RangeCommit {
	t.Helper()
	all, err := Range(repo, "", "HEAD")
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	m := make(map[string]RangeCommit, len(all))
	for _, c := range all {
		m[c.Hash] = c
	}
	return m
}

// TestIntervalCommitsMatchesRange checks that IntervalCommits builds byte-for-byte
// the same RangeCommits as a Range walk over the merge DAG — including the merge
// flag and preorder-independent per-commit facts — for the full commit set.
func TestIntervalCommitsMatchesRange(t *testing.T) {
	repo := buildGraphRepo(t)
	all, err := Range(repo, "", "HEAD")
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	ids := make([]string, len(all))
	for i, c := range all {
		ids[i] = c.Hash
	}
	got, err := IntervalCommits(repo, ids)
	if err != nil {
		t.Fatalf("IntervalCommits: %v", err)
	}
	if !reflect.DeepEqual(got, all) {
		t.Errorf("IntervalCommits over the full set != Range:\n got %+v\nwant %+v", got, all)
	}
	var merges int
	for _, c := range got {
		if c.Merge {
			merges++
		}
	}
	if merges != 1 {
		t.Errorf("expected the one merge commit flagged, saw %d", merges)
	}
}

// TestIntervalCommitsPathsAndTrailers exercises the non-empty diff-path and
// trailer construction against a Range walk of a file-changing, trailered repo.
func TestIntervalCommitsPathsAndTrailers(t *testing.T) {
	repo := t.TempDir()
	gitCmd(t, repo, "init", "--quiet")
	writeAndCommit(t, repo, "a.txt", "one\n", "feat: add a", "Provenance: human")
	writeAndCommit(t, repo, "b.txt", "two\n", "fix: add b", "Provenance: agent\nProvenance-Agent: x/1")

	byHash := rangeByHash(t, repo)
	root := gitCmd(t, repo, "rev-parse", "HEAD~1")
	head := gitCmd(t, repo, "rev-parse", "HEAD")

	got, err := IntervalCommits(repo, []string{root, head})
	if err != nil {
		t.Fatalf("IntervalCommits: %v", err)
	}
	if len(got) != 2 || got[0].Hash != root || got[1].Hash != head {
		t.Fatalf("order/identity wrong: %+v", got)
	}
	// Each must equal the Range-produced commit (paths + trailers included).
	for _, c := range got {
		if !reflect.DeepEqual(c, byHash[c.Hash]) {
			t.Errorf("commit %s != Range:\n got %+v\nwant %+v", c.Hash[:7], c, byHash[c.Hash])
		}
	}
	// Sanity: the paths were actually populated (not a vacuous match).
	if len(got[0].Paths) == 0 || got[1].Paths[0] != "b.txt" {
		t.Errorf("paths not populated: %+v", got)
	}
	if got[0].Trailers.Provenance() != "human" || got[1].Trailers.Provenance() != "agent" {
		t.Errorf("trailers not parsed: %q / %q", got[0].Trailers.Provenance(), got[1].Trailers.Provenance())
	}
}

// TestIntervalCommitsPreservesOrder confirms the result follows the input ID
// order, not the repository's history order.
func TestIntervalCommitsPreservesOrder(t *testing.T) {
	repo := buildGraphRepo(t)
	head := gitCmd(t, repo, "rev-parse", "HEAD")
	root := gitCmd(t, repo, "rev-parse", "HEAD~2^") // some ancestor
	ids := []string{head, root}                     // deliberately head-first
	got, err := IntervalCommits(repo, ids)
	if err != nil {
		t.Fatalf("IntervalCommits: %v", err)
	}
	if len(got) != 2 || got[0].Hash != head || got[1].Hash != root {
		t.Errorf("order not preserved: got %s,%s want %s,%s", got[0].Hash[:7], got[1].Hash[:7], head[:7], root[:7])
	}
}

func TestIntervalCommitsUnknownID(t *testing.T) {
	repo := buildGraphRepo(t)
	if _, err := IntervalCommits(repo, []string{"0000000000000000000000000000000000000000"}); err == nil {
		t.Error("expected an error for an unknown commit ID")
	}
	if _, err := IntervalCommits(t.TempDir(), []string{"deadbeef"}); err == nil {
		t.Error("expected an error opening a non-repository directory")
	}
}

func writeAndCommit(t *testing.T, repo, file, content, subject, trailer string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, file), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", file)
	gitCmd(t, repo, "commit", "--quiet", "-m", subject, "-m", trailer)
}
