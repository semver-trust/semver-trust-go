// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"reflect"
	"testing"
)

func strptr(s string) *string { return &s }

// TestSelectIntervalOracleSurface exercises the §5.2/ADR-027 reasons the
// vendored range vectors do not currently cover, so SelectInterval mirrors the
// spec oracle's full decision surface rather than only the shipped vectors.
func TestSelectIntervalOracleSurface(t *testing.T) {
	linear := []CommitNode{{ID: "root"}, {ID: "a", Parents: []string{"root"}}, {ID: "to", Parents: []string{"a"}}}

	cases := []struct {
		name string
		in   IntervalInputs
		want string
	}{
		{"duplicate commit ids", IntervalInputs{
			Mode: IntervalInception, To: "a",
			Commits: []CommitNode{{ID: "a"}, {ID: "a"}},
		}, "invalid_commit_graph"},
		{"dangling parent", IntervalInputs{
			Mode: IntervalInception, To: "a",
			Commits: []CommitNode{{ID: "a", Parents: []string{"ghost"}}},
		}, "invalid_commit_graph"},
		{"TO not in graph", IntervalInputs{
			Mode: IntervalInception, To: "missing", Commits: linear,
		}, "unknown_to"},
		{"caller FROM on an inception interval", IntervalInputs{
			Mode: IntervalInception, To: "to", RequestedFrom: strptr("a"), Commits: linear,
		}, "untrusted_from"},
		{"adoption without a boundary", IntervalInputs{
			Mode: IntervalAdoption, To: "to", Commits: linear,
		}, "boundary_required"},
		{"unrecognized interval mode", IntervalInputs{
			Mode: IntervalMode("cherry-pick"), To: "to", Commits: linear,
		}, "unknown_interval_mode"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			commits, reason := SelectInterval(tt.in)
			if reason != tt.want {
				t.Errorf("reason = %q, want %q", reason, tt.want)
			}
			if len(commits) != 0 {
				t.Errorf("commits = %v, want empty on failure", commits)
			}
		})
	}

	// A clean inception interval returns every reachable commit in input order.
	commits, reason := SelectInterval(IntervalInputs{Mode: IntervalInception, To: "to", Commits: linear})
	if reason != "" || !reflect.DeepEqual(commits, []string{"root", "a", "to"}) {
		t.Errorf("inception = %v/%q, want [root a to]/none", commits, reason)
	}
}
