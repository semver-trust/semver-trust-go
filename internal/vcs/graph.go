// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// CommitGraph returns the parent-annotated reachability graph of every commit
// reachable from the revision `to` (git rev-list to), as CommitNode{ID,Parents}
// with full 40-hex SHAs. It is the production adapter that materializes the
// ground-truth graph the ADR-027 interval (SelectInterval) and ADR-029
// version-ancestry (version.SelectVersionAncestry) evaluators select over —
// they compute reachability purely from the parent map, so this carries no diff
// or trailer data (that stays in Range).
//
// Commits are emitted in preorder from TO (a commit precedes its parents),
// which is deterministic for a given graph; the evaluators re-derive
// reachability and do not depend on the order beyond determinism.
func CommitGraph(path, to string) ([]CommitNode, error) {
	apath, err := rootPath(path)
	if err != nil {
		return nil, err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}
	toCommit, err := resolveCommit(r, to)
	if err != nil {
		return nil, fmt.Errorf("commit graph: resolving TO %q: %w", to, err)
	}

	var nodes []CommitNode
	iter := object.NewCommitPreorderIter(toCommit, nil, nil)
	err = iter.ForEach(func(c *object.Commit) error {
		parents := make([]string, 0, c.NumParents())
		for _, p := range c.ParentHashes {
			parents = append(parents, p.String())
		}
		nodes = append(nodes, CommitNode{ID: c.Hash.String(), Parents: parents})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return nodes, nil
}
