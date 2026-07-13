// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"reflect"
	"testing"
)

func TestPropagate(t *testing.T) {
	tests := []struct {
		name  string
		own   map[string]Level
		edges [][2]string
		want  map[string]Effective
	}{
		{
			name: "no edges: effective equals own",
			own:  map[string]Level{"auth": T3, "billing": T2, "common": T0},
			want: map[string]Effective{
				"auth":    {T3, "auth"},
				"billing": {T2, "billing"},
				"common":  {T0, "common"},
			},
		},
		{
			name:  "shared dependency floors every consumer",
			own:   map[string]Level{"auth": T3, "billing": T3, "common": T1},
			edges: [][2]string{{"auth", "common"}, {"billing", "common"}},
			want: map[string]Effective{
				"auth":    {T1, "common"},
				"billing": {T1, "common"},
				"common":  {T1, "common"},
			},
		},
		{
			name:  "transitive: the origin propagates as floor source",
			own:   map[string]Level{"app": T3, "middleware": T3, "leaf": T1},
			edges: [][2]string{{"app", "middleware"}, {"middleware", "leaf"}},
			want: map[string]Effective{
				"app":        {T1, "leaf"},
				"middleware": {T1, "leaf"},
				"leaf":       {T1, "leaf"},
			},
		},
		{
			name: "diamond: minimum across branches; no reverse flow",
			own:  map[string]Level{"app": T3, "lib-a": T3, "lib-b": T2, "base": T3},
			edges: [][2]string{
				{"app", "lib-a"}, {"app", "lib-b"}, {"lib-a", "base"}, {"lib-b", "base"},
			},
			want: map[string]Effective{
				"app":   {T2, "lib-b"},
				"lib-a": {T3, "lib-a"},
				"lib-b": {T2, "lib-b"},
				"base":  {T3, "base"},
			},
		},
		{
			name:  "own floor wins: dependencies cannot raise or lower past it",
			own:   map[string]Level{"app": T0, "lib": T3},
			edges: [][2]string{{"app", "lib"}},
			want: map[string]Effective{
				"app": {T0, "app"},
				"lib": {T3, "lib"},
			},
		},
		{
			name:  "SCC collapse: every member shares the cycle minimum",
			own:   map[string]Level{"x": T3, "y": T2, "z": T0},
			edges: [][2]string{{"x", "y"}, {"y", "z"}, {"z", "x"}},
			want: map[string]Effective{
				"x": {T0, "z"},
				"y": {T0, "z"},
				"z": {T0, "z"},
			},
		},
		{
			name: "SCC floors downstream consumers; upstream deps unaffected",
			own:  map[string]Level{"consumer": T3, "x": T3, "y": T1, "base": T3},
			edges: [][2]string{
				{"consumer", "x"}, {"x", "y"}, {"y", "x"}, {"y", "base"},
			},
			want: map[string]Effective{
				"consumer": {T1, "y"},
				"x":        {T1, "y"},
				"y":        {T1, "y"},
				"base":     {T3, "base"},
			},
		},
		{
			name: "two chained SCCs: floor flows one way",
			own:  map[string]Level{"a": T3, "b": T2, "c": T3, "d": T1},
			edges: [][2]string{
				{"a", "b"}, {"b", "a"}, {"b", "c"}, {"c", "d"}, {"d", "c"},
			},
			want: map[string]Effective{
				"a": {T1, "d"},
				"b": {T1, "d"},
				"c": {T1, "d"},
				"d": {T1, "d"},
			},
		},
		{
			name:  "tie between dependencies breaks lexicographically",
			own:   map[string]Level{"app": T3, "libb": T1, "liba": T1},
			edges: [][2]string{{"app", "libb"}, {"app", "liba"}},
			want: map[string]Effective{
				"app":  {T1, "liba"},
				"liba": {T1, "liba"},
				"libb": {T1, "libb"},
			},
		},
		{
			name:  "own attaining the floor beats a tying dependency",
			own:   map[string]Level{"app": T1, "lib": T1},
			edges: [][2]string{{"app", "lib"}},
			want: map[string]Effective{
				"app": {T1, "app"},
				"lib": {T1, "lib"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Propagate(tt.own, tt.edges)
			if err != nil {
				t.Fatalf("Propagate: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Propagate = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPropagateUnknownNode(t *testing.T) {
	_, err := Propagate(map[string]Level{"a": T3}, [][2]string{{"a", "ghost"}})
	if err == nil {
		t.Error("Propagate accepted an edge to an undeclared component")
	}
}

// TestAppendixAEndToEnd chains the aggregation pipeline over the spec's
// Appendix A worked example: per-scope floors (steps 1-2) feed propagation
// (pre- and post-promotion), and the meta-path rule fails billing's step-5
// range outright.
func TestAppendixAEndToEnd(t *testing.T) {
	scopes := map[string]string{
		"services/auth/**":    "auth",
		"services/billing/**": "billing",
		"pkg/**":              "common",
	}

	// Step 1: three unreviewed CI-agent commits on pkg/common.
	commonRange := []Commit{
		{ID: "c1", Level: T0, Paths: []string{"pkg/common/retry.go"}},
		{ID: "c2", Level: T0, Paths: []string{"pkg/common/retry_test.go"}},
		{ID: "c3", Level: T0, Paths: []string{"pkg/common/backoff.go"}},
	}
	// Step 2: five human-reviewed commits on services/auth, all T3.
	authRange := []Commit{
		{ID: "a1", Level: T3, Paths: []string{"services/auth/api/openapi.yaml"}},
		{ID: "a2", Level: T3, Paths: []string{"services/auth/handler.go"}},
		{ID: "a3", Level: T3, Paths: []string{"services/auth/session.go"}},
		{ID: "a4", Level: T3, Paths: []string{"services/auth/token.go"}},
		{ID: "a5", Level: T3, Paths: []string{"services/auth/token_test.go"}},
	}

	commonFloors, err := ScopeFloors(scopes, commonRange)
	if err != nil {
		t.Fatal(err)
	}
	authFloors, err := ScopeFloors(scopes, authRange)
	if err != nil {
		t.Fatal(err)
	}
	if commonFloors["common"] != T0 {
		t.Errorf("step 1: own(common) = %s, want T0", commonFloors["common"])
	}
	if authFloors["auth"] != T3 {
		t.Errorf("step 2: own(auth) = %s, want T3", authFloors["auth"])
	}

	// Step 2: propagation floors auth through common.
	edges := [][2]string{{"auth", "common"}}
	pre, err := Propagate(map[string]Level{
		"auth":   authFloors["auth"],
		"common": commonFloors["common"],
	}, edges)
	if err != nil {
		t.Fatal(err)
	}
	if pre["auth"] != (Effective{T0, "common"}) {
		t.Errorf("step 2: effective(auth) = %+v, want {T0 common}", pre["auth"])
	}

	// Steps 3-4: post-hoc review lifts own(common) to T2; the cascade gives
	// effective(auth) = min(T3, T2) = T2. Only evidence changed.
	post, err := Propagate(map[string]Level{"auth": T3, "common": T2}, edges)
	if err != nil {
		t.Fatal(err)
	}
	if post["auth"] != (Effective{T2, "common"}) {
		t.Errorf("step 4: effective(auth) = %+v, want {T2 common}", post["auth"])
	}
	if post["common"] != (Effective{T2, "common"}) {
		t.Errorf("step 3: effective(common) = %+v, want {T2 common}", post["common"])
	}

	// Step 5: a billing range with a T2 policy edit under T3 meta-paths
	// fails verification outright — not demote, fail.
	violations, err := MetaPathViolations(
		[]string{".semver-trust/**", ".github/workflows/**", "CODEOWNERS"},
		T3,
		[]Commit{
			{ID: "b1", Level: T3, Paths: []string{"services/billing/invoice.go"}},
			{ID: "b2", Level: T2, Paths: []string{".semver-trust/policy.toml"}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(violations, []string{"b2"}) {
		t.Errorf("step 5: violations = %v, want [b2]", violations)
	}
}
