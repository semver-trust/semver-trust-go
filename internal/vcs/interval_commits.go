// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// IntervalCommits builds the RangeCommits for an explicit, ordered set of commit
// IDs — the output of SelectInterval (§5.2/ADR-027) — against the repository at
// path. Each ID must be a full commit SHA present in the repository; the result
// preserves the input order and carries the same per-commit facts vcs.Range
// produces (the §4.1 trailer block, the §5.1 diff paths, and §4.3.4 merge
// novel-path handling), so it drops straight into the classification loop in
// place of a Range walk.
//
// It is the production adapter that turns SelectInterval's abstract commit-ID
// interval back into the concrete commits verification classifies. Unlike Range,
// it does not walk FROM..TO — the interval has already been selected — so it
// applies no ancestry or exclusion logic of its own.
func IntervalCommits(path string, ids []string) ([]RangeCommit, error) {
	apath, err := rootPath(path)
	if err != nil {
		return nil, err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}

	commits := make([]RangeCommit, 0, len(ids))
	for _, id := range ids {
		c, err := r.CommitObject(plumbing.NewHash(id))
		if err != nil {
			return nil, fmt.Errorf("interval commits: resolving %q to a commit: %w", id, err)
		}
		paths, err := changedPaths(c)
		if err != nil {
			return nil, err
		}
		message := c.Message
		commits = append(commits, RangeCommit{
			Hash:     c.Hash.String(),
			Subject:  firstLine(message),
			Message:  message,
			Trailers: ParseTrailers(message),
			Paths:    paths,
			Merge:    c.NumParents() > 1,
		})
	}
	return commits, nil
}
