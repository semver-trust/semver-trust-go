// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"fmt"
	"sort"
)

// Effective is a component's propagated trust (§5.3): the floored level and
// the component whose own trust set the floor — the component itself when
// its own trust attains the minimum, otherwise a dependency (recorded in the
// release attestation as the floor source, §8.1).
type Effective struct {
	Level       Level
	FloorSource string
}

// Propagate computes effective trust over the internal dependency graph
// (§5.3):
//
//	effective(C) = min(own(C), min over internal deps D of C: effective(D))
//
// Edges point consumer → dependency. Dependency cycles collapse to their
// strongly connected component: every member of an SCC shares the SCC's
// minimum own trust. When several components attain a consumer's floor, the
// floor source is the lexicographically smallest — a deterministic,
// documented tie-break; the level is what matters.
//
// Propagation is what makes path scoping safe rather than cosmetic: without
// it, risk launders into shared libraries while consumers' scopes stay
// pristine.
func Propagate(own map[string]Level, edges [][2]string) (map[string]Effective, error) {
	for _, e := range edges {
		for _, node := range e {
			if _, ok := own[node]; !ok {
				return nil, fmt.Errorf("propagate: edge references unknown component %q", node)
			}
		}
	}

	nodes := make([]string, 0, len(own))
	for node := range own {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes) // deterministic traversal, hence deterministic tie-breaks

	adj := map[string][]string{}
	for _, e := range edges {
		adj[e[0]] = append(adj[e[0]], e[1])
	}
	for _, deps := range adj {
		sort.Strings(deps)
	}

	sccOf := tarjan(nodes, adj)

	// Per SCC: the minimum own trust and its lexicographically smallest
	// holder (§5.3: every member shares the SCC's minimum own trust).
	type sccState struct {
		level  Level
		source string
		deps   map[int]bool
	}
	sccs := map[int]*sccState{}
	for _, node := range nodes {
		id := sccOf[node]
		s := sccs[id]
		if s == nil {
			s = &sccState{level: own[node], source: node, deps: map[int]bool{}}
			sccs[id] = s
		} else if own[node] < s.level || (own[node] == s.level && node < s.source) {
			s.level, s.source = own[node], node
		}
	}
	for _, e := range edges {
		if a, b := sccOf[e[0]], sccOf[e[1]]; a != b {
			sccs[a].deps[b] = true
		}
	}

	// Effective per SCC, memoized over the (acyclic) condensation.
	memo := map[int]*sccState{}
	var eff func(id int) *sccState
	eff = func(id int) *sccState {
		if got, ok := memo[id]; ok {
			return got
		}
		best := &sccState{level: sccs[id].level, source: sccs[id].source}
		memo[id] = best // safe: condensation is acyclic, no re-entry on a path
		depIDs := make([]int, 0, len(sccs[id].deps))
		for dep := range sccs[id].deps {
			depIDs = append(depIDs, dep)
		}
		sort.Ints(depIDs)
		for _, dep := range depIDs {
			d := eff(dep)
			if d.level < best.level || (d.level == best.level && best.level < sccs[id].level && d.source < best.source) {
				best.level, best.source = d.level, d.source
			}
		}
		return best
	}

	result := make(map[string]Effective, len(own))
	for _, node := range nodes {
		s := eff(sccOf[node])
		source := s.source
		// A component whose own trust attains its floor is its own floor
		// source, even inside an SCC or when a dependency ties.
		if own[node] == s.level {
			source = node
		}
		result[node] = Effective{Level: s.level, FloorSource: source}
	}
	return result, nil
}

// tarjan assigns each node its strongly-connected-component id (iterative
// Tarjan; edges consumer → dependency).
func tarjan(nodes []string, adj map[string][]string) map[string]int {
	index := map[string]int{}
	low := map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	sccOf := map[string]int{}
	next, nextSCC := 0, 0

	type frame struct {
		node string
		dep  int
	}
	for _, root := range nodes {
		if _, seen := index[root]; seen {
			continue
		}
		frames := []frame{{node: root}}
		for len(frames) > 0 {
			f := &frames[len(frames)-1]
			v := f.node
			if f.dep == 0 {
				index[v], low[v] = next, next
				next++
				stack = append(stack, v)
				onStack[v] = true
			}
			advanced := false
			for f.dep < len(adj[v]) {
				w := adj[v][f.dep]
				f.dep++
				if _, seen := index[w]; !seen {
					frames = append(frames, frame{node: w})
					advanced = true
					break
				}
				if onStack[w] && index[w] < low[v] {
					low[v] = index[w]
				}
			}
			if advanced {
				continue
			}
			if low[v] == index[v] {
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					sccOf[w] = nextSCC
					if w == v {
						break
					}
				}
				nextSCC++
			}
			frames = frames[:len(frames)-1]
			if len(frames) > 0 {
				parent := frames[len(frames)-1].node
				if low[v] < low[parent] {
					low[parent] = low[v]
				}
			}
		}
	}
	return sccOf
}
