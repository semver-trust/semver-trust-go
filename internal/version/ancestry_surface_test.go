// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

// A valid bootstrap-genesis advance: inception, null version predecessor →
// synthetic v0.0.0 baseline, minor bump → clean v0.1.0.
func avBootstrapBase() AncestryInputs {
	return AncestryInputs{
		Authority: "bootstrap", Action: "advance", Repository: "repo", Component: "app",
		TagPrefix: "", IntervalMode: "inception", Boundary: nil, To: "to",
		Graph: []AncestryCommit{{ID: "root"}, {ID: "to", Parents: []string{"root"}}},
		Refs:  map[string]RefEntry{},
		Decision: DecisionInputs{EffectiveTrust: "T3", Threshold: "T2", Blast: "moderate",
			Strategy: "demote", DifferAvailable: true, SemanticFloor: "minor", ClaimedBump: "minor"},
		Bootstrap: &VersionBootstrap{Authenticated: true, Repository: "repo", Component: "app",
			IntervalMode: "inception", Boundary: nil, TagPrefix: "", PredecessorPresent: true, PredecessorNull: true},
	}
}

// A valid recurring advance from an accepted prerelease predecessor at T0 →
// patch bump → v0.1.1-t0.1.
func avPredecessorBase() AncestryInputs {
	return AncestryInputs{
		Authority: "predecessor", Action: "advance", Repository: "repo", Component: "app",
		TagPrefix: "", IntervalMode: "recurring", To: "to", FixtureRef: "pred",
		Graph: []AncestryCommit{{ID: "root"}, {ID: "p", Parents: []string{"root"}}, {ID: "to", Parents: []string{"p"}}},
		Refs:  map[string]RefEntry{"v0.1.0-t0.1": {RefOID: "tag-p", CommitOID: "p"}},
		Decision: DecisionInputs{EffectiveTrust: "T0", Threshold: "T0", Blast: "low",
			Strategy: "demote", DifferAvailable: true, SemanticFloor: "patch", ClaimedBump: "patch"},
		Predecessor: &VersionSelected{
			Accepted: true, ChainHead: true, Repository: "repo", Component: "app", TagPrefix: "", To: "p",
			CanonicalTags: []Binding{{Tag: "v0.1.0-t0.1", RefOID: "tag-p", CommitOID: "p"}},
			State: VersionState{Baseline: nil, BaselineCore: "0.0.0", TargetCore: "0.1.0", TargetBump: "minor",
				CleanAccepted: false, TargetIntervals: []string{"i1"}, Iterations: map[string]int{"T0": 1}},
		},
	}
}

// TestSelectVersionAncestryOracleSurface exercises the ADR-029 reasons the
// vendored vectors do not cover (18 of 35), so the port mirrors the oracle's
// full decision surface.
func TestSelectVersionAncestryOracleSurface(t *testing.T) {
	if r := SelectVersionAncestry(avBootstrapBase()); r.Reason != "" || r.Version == nil || *r.Version != "v0.1.0" {
		t.Fatalf("bootstrap base = %+v, want clean v0.1.0", r)
	}
	if r := SelectVersionAncestry(avPredecessorBase()); r.Reason != "" || r.Version == nil || *r.Version != "v0.1.1-t0.1" {
		t.Fatalf("predecessor base = %+v, want v0.1.1-t0.1", r)
	}

	cases := []struct {
		name string
		in   func() AncestryInputs
		want string
	}{
		{"duplicate graph ids", func() AncestryInputs {
			in := avBootstrapBase()
			in.Graph = []AncestryCommit{{ID: "to"}, {ID: "to"}}
			return in
		}, "invalid_version_graph"},
		{"TO not in graph", func() AncestryInputs { in := avBootstrapBase(); in.To = "ghost"; return in }, "unknown_to"},
		{"inflate escalation unresolved", func() AncestryInputs {
			in := avBootstrapBase()
			in.Decision.Strategy = "inflate"
			in.Decision.EffectiveTrust, in.Decision.Threshold, in.Decision.Blast = "T0", "T0", "low"
			return in
		}, "version_escalation_target_unresolved"},
		{"unknown authority", func() AncestryInputs { in := avBootstrapBase(); in.Authority = "sideways"; return in }, "version_authority_unknown"},
		{"bootstrap missing", func() AncestryInputs { in := avBootstrapBase(); in.Bootstrap = nil; return in }, "version_bootstrap_missing"},
		{"bootstrap unauthenticated", func() AncestryInputs { in := avBootstrapBase(); in.Bootstrap.Authenticated = false; return in }, "version_bootstrap_unauthenticated"},
		{"bootstrap subject mismatch", func() AncestryInputs { in := avBootstrapBase(); in.Bootstrap.Component = "other"; return in }, "version_bootstrap_subject_mismatch"},
		{"bootstrap interval mismatch", func() AncestryInputs { in := avBootstrapBase(); in.Bootstrap.IntervalMode = "adoption"; return in }, "version_bootstrap_interval_mismatch"},
		{"bootstrap boundary mismatch", func() AncestryInputs { in := avBootstrapBase(); b := "x"; in.Boundary = &b; return in }, "version_bootstrap_boundary_mismatch"},
		{"bootstrap prefix mismatch", func() AncestryInputs { in := avBootstrapBase(); in.Bootstrap.TagPrefix = "svc"; return in }, "version_bootstrap_prefix_mismatch"},
		{"genesis requires advance", func() AncestryInputs { in := avBootstrapBase(); in.Action = "recut"; return in }, "version_genesis_requires_advance"},
		{"adoption boundary invalid", func() AncestryInputs {
			in := avBootstrapBase()
			in.IntervalMode, in.Bootstrap.IntervalMode = "adoption", "adoption"
			b := "ghost"
			in.Boundary, in.Bootstrap.Boundary = &b, &b
			in.Refs = map[string]RefEntry{"v0.0.1": {RefOID: "r", CommitOID: "root"}}
			in.Bootstrap.PredecessorNull = false
			in.Bootstrap.Predecessor = &Binding{Tag: "v0.0.1", RefOID: "r", CommitOID: "root"}
			return in
		}, "version_bootstrap_boundary_invalid"},
		{"predecessor not accepted", func() AncestryInputs { in := avPredecessorBase(); in.Predecessor.Accepted = false; return in }, "version_predecessor_not_accepted"},
		{"predecessor not chain head", func() AncestryInputs { in := avPredecessorBase(); in.Predecessor.ChainHead = false; return in }, "version_predecessor_not_chain_head"},
		{"predecessor interval mismatch", func() AncestryInputs { in := avPredecessorBase(); in.IntervalMode = "inception"; return in }, "version_predecessor_interval_mismatch"},
		{"predecessor action invalid", func() AncestryInputs { in := avPredecessorBase(); in.Action = "supersede"; return in }, "version_action_invalid"},
		{"recut over an accepted clean target", func() AncestryInputs {
			in := avPredecessorBase()
			in.Action = "recut"
			in.Refs = map[string]RefEntry{"v0.1.0": {RefOID: "tag-p", CommitOID: "p"}}
			in.Predecessor.CanonicalTags = []Binding{{Tag: "v0.1.0", RefOID: "tag-p", CommitOID: "p"}}
			in.Predecessor.State.CleanAccepted = true
			in.Predecessor.State.Iterations = map[string]int{}
			return in
		}, "recut_clean_target_accepted"},
		{"supersession action mismatch", func() AncestryInputs {
			in := avPredecessorBase()
			in.Authority = "superseded"
			in.Superseded = in.Predecessor
			in.Predecessor = nil
			return in
		}, "version_supersession_mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := SelectVersionAncestry(c.in())
			if r.Reason != c.want {
				t.Errorf("reason = %q, want %q", r.Reason, c.want)
			}
		})
	}
}
