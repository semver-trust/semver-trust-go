// SPDX-License-Identifier: Apache-2.0

package vcs

// IntervalMode is one of the three §5.2 release-interval modes (ADR-027).
type IntervalMode string

const (
	// IntervalInception — a chain-genesis release with no boundary: the
	// interval is every commit reachable from TO (git rev-list TO).
	IntervalInception IntervalMode = "inception"
	// IntervalAdoption — a chain-genesis release with a bootstrap-pinned
	// boundary B: the interval includes B and excludes only history reachable
	// through B's parents (git rev-list TO --not B^@).
	IntervalAdoption IntervalMode = "adoption"
	// IntervalRecurring — a later release anchored to the accepted predecessor
	// chain head P: the interval is Reach(TO) − Reach(P) (git rev-list P..TO).
	IntervalRecurring IntervalMode = "recurring"
)

// CommitNode is one commit in the abstract history graph: its id and its
// parent ids. It is the ground truth the interval is selected over, mirroring
// git reachability without a working repository.
type CommitNode struct {
	ID      string
	Parents []string
}

// BoundaryDescriptor is the adoption boundary as pinned by the out-of-band
// bootstrap descriptor (ADR-028): the boundary object id, the raw ref target
// it must still resolve to, and whether it is bootstrap-pinned at all.
type BoundaryDescriptor struct {
	OID             string
	RefTarget       string
	BootstrapPinned bool
}

// PredecessorDescriptor is the accepted predecessor release for a recurring
// interval: the accepted chain head whose TO anchors this interval.
type PredecessorDescriptor struct {
	Accepted   bool
	ChainHead  bool
	Repository string
	Component  string
	To         string
	TagTarget  string
}

// IntervalInputs are the authenticated facts an interval is selected from
// (§5.2, ADR-027). The interval mode, TO, boundary/predecessor, and chain-head
// count are all verifier-selected; RequestedFrom is the caller-supplied FROM,
// which may never select protocol state (a non-nil value outside recurring, or
// one that is not the predecessor's TO, aborts).
type IntervalInputs struct {
	Repository         string
	Component          string
	Mode               IntervalMode
	To                 string
	ExistingChainHeads int
	RequestedFrom      *string
	Boundary           *BoundaryDescriptor
	Predecessor        *PredecessorDescriptor
	Commits            []CommitNode
}

// commitReach returns the set containing start and every commit reachable
// through its parents (git reachability). Ported from the conformance oracle's
// _commit_reach.
func commitReach(start string, parents map[string][]string) map[string]bool {
	seen := map[string]bool{}
	frontier := []string{start}
	for len(frontier) > 0 {
		c := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if seen[c] {
			continue
		}
		seen[c] = true
		frontier = append(frontier, parents[c]...)
	}
	return seen
}

// SelectInterval selects the release interval's commit set from the
// authenticated inputs (§5.2, ADR-027), returning the included commits in
// input order. A non-empty reason means the release MUST fail verification and
// the commit list is empty; an empty reason means the interval verified. This
// is a faithful port of the conformance oracle's _release_interval — the
// production verifier feeds it real git reachability and accepted-predecessor
// attestations (tracked in semver-trust-go#76).
func SelectInterval(in IntervalInputs) (commits []string, reason string) {
	ordered := make([]string, len(in.Commits))
	parents := make(map[string][]string, len(in.Commits))
	for i, c := range in.Commits {
		ordered[i] = c.ID
		parents[c.ID] = c.Parents
	}

	// invalid_commit_graph: duplicate ids collapse the map, and every named
	// parent must exist in the graph.
	if len(parents) != len(ordered) {
		return nil, "invalid_commit_graph"
	}
	for _, ps := range parents {
		for _, p := range ps {
			if _, ok := parents[p]; !ok {
				return nil, "invalid_commit_graph"
			}
		}
	}
	if _, ok := parents[in.To]; !ok {
		return nil, "unknown_to"
	}
	reachTo := commitReach(in.To, parents)

	var included map[string]bool
	switch in.Mode {
	case IntervalInception:
		if in.ExistingChainHeads != 0 {
			return nil, "predecessor_required"
		}
		if in.RequestedFrom != nil {
			return nil, "untrusted_from"
		}
		included = reachTo

	case IntervalAdoption:
		if in.ExistingChainHeads != 0 {
			return nil, "predecessor_required"
		}
		if in.RequestedFrom != nil {
			return nil, "untrusted_from"
		}
		b := in.Boundary
		if b == nil {
			return nil, "boundary_required"
		}
		if !b.BootstrapPinned {
			return nil, "boundary_not_bootstrap_pinned"
		}
		if b.RefTarget != b.OID {
			return nil, "boundary_ref_moved"
		}
		if !reachTo[b.OID] {
			return nil, "boundary_not_reachable"
		}
		excluded := map[string]bool{}
		for _, parent := range parents[b.OID] {
			for c := range commitReach(parent, parents) {
				excluded[c] = true
			}
		}
		included = map[string]bool{}
		for c := range reachTo {
			if !excluded[c] {
				included[c] = true
			}
		}

	case IntervalRecurring:
		p := in.Predecessor
		if p == nil {
			return nil, "predecessor_missing"
		}
		if !p.Accepted {
			return nil, "predecessor_not_accepted"
		}
		if !p.ChainHead || in.ExistingChainHeads != 1 {
			return nil, "predecessor_not_unique_head"
		}
		if p.Repository != in.Repository {
			return nil, "predecessor_repository_mismatch"
		}
		if p.Component != in.Component {
			return nil, "predecessor_component_mismatch"
		}
		if !reachTo[p.To] {
			return nil, "predecessor_not_ancestor"
		}
		if p.TagTarget != p.To {
			return nil, "predecessor_ref_moved"
		}
		if in.RequestedFrom == nil || *in.RequestedFrom != p.To {
			return nil, "from_not_predecessor"
		}
		if p.To == in.To {
			return nil, "promotion_required"
		}
		reachPrev := commitReach(p.To, parents)
		included = map[string]bool{}
		for c := range reachTo {
			if !reachPrev[c] {
				included[c] = true
			}
		}

	default:
		return nil, "unknown_interval_mode"
	}

	for _, id := range ordered {
		if included[id] {
			commits = append(commits, id)
		}
	}
	return commits, ""
}
