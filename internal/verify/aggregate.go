// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/semver-trust/semver-trust-go/graph/gomod"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// scopeReports renders per-scope own trust (§10 step 5, §5.2), sorted by scope
// name for deterministic output.
func scopeReports(partition map[string][]string, floors map[string]trust.Level) []ScopeReport {
	names := make([]string, 0, len(floors))
	for name := range floors {
		names = append(names, name)
	}
	sort.Strings(names)

	reports := make([]ScopeReport, 0, len(names))
	for _, name := range names {
		commits := make([]string, 0, len(partition[name]))
		for _, id := range partition[name] {
			commits = append(commits, shortSHA(id))
		}
		reports = append(reports, ScopeReport{
			Scope:    name,
			OwnFloor: floors[name].String(),
			Commits:  commits,
		})
	}
	return reports
}

// propagate computes effective trust over the workspace graph (§10 step 6,
// §5.3).
//
// With the "gomod" adapter, components are the workspace's nested Go modules,
// resolved lexically from a disposable export of TO's tree (never the working
// tree). Own trust per component is the floor over the range commits touching
// paths under the component's directory — the v1 component↔scope mapping,
// flagged as a judgment call: it maps a component to the directory subtree it
// roots rather than to a named policy scope, and a component untouched in the
// range takes the neutral floor T3 (it cannot lower any consumer's effective
// trust; its real trust comes from its own release, which cross-range
// propagation, §12.4, is deferred to a later milestone).
//
// With any other adapter (including the "none" default), there is no workspace
// graph: each scope's effective trust is its own floor, floor-sourced to
// itself.
func propagate(repo string, opts Options, pol *policy.Policy, tcommits []trust.Commit, floors map[string]trust.Level) (PropagationReport, error) {
	if pol.GraphAdapter != policy.AdapterGomod {
		return propagateNone(pol.GraphAdapter, opts.Component, floors), nil
	}

	dir, cleanup, err := exportToTemp(repo, opts.To, "semver-trust-graph-")
	if err != nil {
		return PropagationReport{}, abort(stepPropagate, fmt.Errorf("exporting tree: %w", err))
	}
	defer cleanup()

	g, err := gomod.Adapter{}.Resolve(dir)
	if err != nil {
		return PropagationReport{}, abort(stepPropagate, fmt.Errorf("resolving gomod graph: %w", err))
	}

	own := make(map[string]trust.Level, len(g.Components))
	for _, comp := range g.Components {
		own[comp.Name] = floorOverDir(tcommits, comp.Dir)
	}
	eff, err := trust.Propagate(own, g.Edges)
	if err != nil {
		return PropagationReport{}, abort(stepPropagate, err)
	}

	names := make([]string, 0, len(g.Components))
	for _, comp := range g.Components {
		names = append(names, comp.Name)
	}
	sort.Strings(names)

	report := PropagationReport{
		Adapter: pol.GraphAdapter,
		Target:  targetComponent(opts.Component, names),
		Note:    "v1 component↔scope mapping: own trust per component is the floor over commits touching its directory subtree; untouched components take the neutral floor T3 (cross-range propagation deferred, §12.4)",
	}
	deps := map[string][]string{}
	for _, e := range g.Edges {
		deps[e[0]] = append(deps[e[0]], e[1])
	}
	for _, ds := range deps {
		sort.Strings(ds)
	}
	for _, name := range names {
		report.Components = append(report.Components, ComponentEffective{
			Name:         name,
			Own:          own[name].String(),
			Effective:    eff[name].Level.String(),
			FloorSource:  eff[name].FloorSource,
			Dependencies: deps[name],
		})
	}
	return report, nil
}

// propagateNone renders the no-graph case: effective trust per scope equals its
// own floor, sourced to itself (§5.3 with an empty graph).
func propagateNone(adapter, target string, floors map[string]trust.Level) PropagationReport {
	names := make([]string, 0, len(floors))
	for name := range floors {
		names = append(names, name)
	}
	sort.Strings(names)

	report := PropagationReport{
		Adapter: adapter,
		Target:  targetComponent(target, names),
		Note:    "no workspace graph: effective trust equals own trust per scope, floor-sourced to itself",
	}
	for _, name := range names {
		report.Components = append(report.Components, ComponentEffective{
			Name:        name,
			Own:         floors[name].String(),
			Effective:   floors[name].String(),
			FloorSource: name,
		})
	}
	return report
}

// floorOverDir returns the trust floor over the commits touching any path
// under dir (slash-form, "." for the workspace root). A component untouched in
// the range takes the neutral floor T3.
func floorOverDir(tcommits []trust.Commit, dir string) trust.Level {
	floor := trust.T3
	touched := false
	for _, c := range tcommits {
		if !commitUnderDir(c.Paths, dir) {
			continue
		}
		touched = true
		if c.Level < floor {
			floor = c.Level
		}
	}
	if !touched {
		return trust.T3
	}
	return floor
}

func commitUnderDir(paths []string, dir string) bool {
	for _, p := range paths {
		if dir == "." || p == dir || strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}

// targetComponent chooses the component to headline: the requested one when
// present, else the root (".") when it exists, else the lexicographically
// first, else empty.
func targetComponent(requested string, names []string) string {
	if requested != "" {
		return requested
	}
	for _, n := range names {
		if n == "." {
			return n
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}
