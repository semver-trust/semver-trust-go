// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"reflect"
	"testing"
)

var testScopes = map[string]string{
	"services/auth/**":    "auth",
	"services/billing/**": "billing",
	"pkg/**":              "common",
	"docs/**":             "docs",
}

func TestPartitionScopes(t *testing.T) {
	tests := []struct {
		name    string
		scopes  map[string]string
		commits []Commit
		want    map[string][]string
	}{
		{
			name:   "single scope",
			scopes: testScopes,
			commits: []Commit{
				{ID: "c1", Level: T3, Paths: []string{"pkg/common/util.go"}},
			},
			want: map[string][]string{"common": {"c1"}},
		},
		{
			name:   "multi-scope commit contributes to both",
			scopes: testScopes,
			commits: []Commit{
				{ID: "c1", Level: T3, Paths: []string{"services/auth/handler.go", "docs/auth.md"}},
			},
			want: map[string][]string{"auth": {"c1"}, "docs": {"c1"}},
		},
		{
			name:   "unmatched paths fall to the implicit default scope",
			scopes: testScopes,
			commits: []Commit{
				{ID: "c1", Level: T2, Paths: []string{"README.md"}},
				{ID: "c2", Level: T2, Paths: []string{"tools/x.sh", "pkg/common/util.go"}},
			},
			want: map[string][]string{"common": {"c2"}, "default": {"c1", "c2"}},
		},
		{
			name:   "glob matching is segment-aware",
			scopes: map[string]string{"services/auth/**": "auth"},
			commits: []Commit{
				{ID: "c1", Level: T2, Paths: []string{"services/authz/policy.go"}},
				{ID: "c2", Level: T2, Paths: []string{"services/auth/policy.go"}},
			},
			want: map[string][]string{"auth": {"c2"}, "default": {"c1"}},
		},
		{
			name:   "single-star stays within a segment",
			scopes: map[string]string{"pkg/*/api.go": "api"},
			commits: []Commit{
				{ID: "c1", Level: T2, Paths: []string{"pkg/common/api.go"}},
				{ID: "c2", Level: T2, Paths: []string{"pkg/common/nested/api.go"}},
			},
			want: map[string][]string{"api": {"c1"}, "default": {"c2"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PartitionScopes(tt.scopes, tt.commits)
			if err != nil {
				t.Fatalf("PartitionScopes: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PartitionScopes = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScopeFloors(t *testing.T) {
	tests := []struct {
		name    string
		scopes  map[string]string
		commits []Commit
		want    map[string]Level
	}{
		{
			name:   "floor is the minimum, never an average",
			scopes: testScopes,
			commits: []Commit{
				{ID: "c1", Level: T3, Paths: []string{"pkg/common/api.go"}},
				{ID: "c2", Level: T1, Paths: []string{"pkg/common/impl.go"}},
				{ID: "c3", Level: T3, Paths: []string{"pkg/common/impl_test.go"}},
			},
			want: map[string]Level{"common": T1},
		},
		{
			name:   "no de-minimis: one T0 commit floors the scope",
			scopes: testScopes,
			commits: []Commit{
				{ID: "c1", Level: T3, Paths: []string{"services/auth/handler.go"}},
				{ID: "c2", Level: T0, Paths: []string{"services/auth/config.go"}},
			},
			want: map[string]Level{"auth": T0},
		},
		{
			// ADR-033: derivation claims are non-authoritative. A generated
			// output commit floors at its own level even when a higher-trust
			// commit touched the generator's inputs — no re-leveling.
			name:   "generated outputs floor at the commit's own level",
			scopes: testScopes,
			commits: []Commit{
				{ID: "c1", Level: T3, Paths: []string{"services/auth/api/openapi.yaml"}},
				{ID: "c2", Level: T0, Paths: []string{"services/auth/internal/gen/server.go"}},
			},
			want: map[string]Level{"auth": T0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ScopeFloors(tt.scopes, tt.commits)
			if err != nil {
				t.Fatalf("ScopeFloors: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ScopeFloors = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetaPathViolations(t *testing.T) {
	meta := []string{".semver-trust/**", ".github/workflows/**", "CODEOWNERS"}

	tests := []struct {
		name    string
		commits []Commit
		want    []string
	}{
		{
			name: "meta-path commit below required level violates",
			commits: []Commit{
				{ID: "c1", Level: T3, Paths: []string{"services/billing/invoice.go"}},
				{ID: "c2", Level: T2, Paths: []string{".semver-trust/policy.toml"}},
			},
			want: []string{"c2"},
		},
		{
			name: "workflow edit at T0 violates even when scopes would merely demote",
			commits: []Commit{
				{ID: "c1", Level: T0, Paths: []string{".github/workflows/release.yml"}},
			},
			want: []string{"c1"},
		},
		{
			name: "meta-path commit at the required level verifies",
			commits: []Commit{
				{ID: "c1", Level: T3, Paths: []string{".semver-trust/policy.toml"}},
				{ID: "c2", Level: T1, Paths: []string{"pkg/common/util.go"}},
			},
			want: nil,
		},
		{
			name: "exact-literal meta path matches",
			commits: []Commit{
				{ID: "c1", Level: T2, Paths: []string{"CODEOWNERS"}},
			},
			want: []string{"c1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MetaPathViolations(meta, T3, tt.commits)
			if err != nil {
				t.Fatalf("MetaPathViolations: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("violations = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompileGlobRejectsEmpty(t *testing.T) {
	if _, err := ScopeFloors(map[string]string{"": "x"}, nil); err == nil {
		t.Error("ScopeFloors accepted an empty glob")
	}
}
