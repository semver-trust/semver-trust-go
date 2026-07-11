// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Consumes the aggregation and propagation conformance vectors when
// reachable, per the GO-020 precedent (the durable vendored harness is
// GO-026): SEMVER_TRUST_AGGREGATION_VECTORS / SEMVER_TRUST_PROPAGATION_VECTORS,
// or testdata/aggregation.json / testdata/propagation.json; absent, skip.

type aggVectorFile struct {
	SpecVersion string      `json:"spec_version"`
	Vectors     []aggVector `json:"vectors"`
}

type aggVector struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Inputs   json.RawMessage `json:"inputs"`
	Expected json.RawMessage `json:"expected"`
}

type aggCommit struct {
	ID         string         `json:"id"`
	Level      string         `json:"level"`
	Paths      []string       `json:"paths"`
	Derivation *aggDerivation `json:"derivation"`
}

type aggDerivation struct {
	Outputs        []string `json:"outputs"`
	Verified       bool     `json:"verified"`
	InheritedLevel string   `json:"inherited_level"`
}

func loadAggVectors(t *testing.T, env, name string) aggVectorFile {
	t.Helper()

	path := os.Getenv(env)
	if path == "" {
		candidate := filepath.Join("testdata", name)
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	if path == "" {
		t.Skipf("conformance vectors absent; set %s or vendor testdata/%s (GO-026)", env, name)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	var vf aggVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return vf
}

func mustLevel(t *testing.T, s string) Level {
	t.Helper()
	l, err := ParseLevel(s)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func toCommits(t *testing.T, in []aggCommit) []Commit {
	t.Helper()
	commits := make([]Commit, len(in))
	for i, c := range in {
		commit := Commit{ID: c.ID, Paths: c.Paths}
		if c.Level != "" {
			commit.Level = mustLevel(t, c.Level)
		}
		if c.Derivation != nil {
			commit.Derivation = &DerivationFacts{
				Outputs:        c.Derivation.Outputs,
				Verified:       c.Derivation.Verified,
				InheritedLevel: mustLevel(t, c.Derivation.InheritedLevel),
			}
		}
		commits[i] = commit
	}
	return commits
}

func TestConformanceScopePartition(t *testing.T) {
	vf := loadAggVectors(t, "SEMVER_TRUST_AGGREGATION_VECTORS", "aggregation.json")

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "scope_partition" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			var inputs struct {
				Scopes  map[string]string `json:"scopes"`
				Commits []aggCommit       `json:"commits"`
			}
			var expected struct {
				Scopes map[string][]string `json:"scopes"`
			}
			decode(t, vec.Inputs, &inputs)
			decode(t, vec.Expected, &expected)

			got, err := PartitionScopes(inputs.Scopes, toCommits(t, inputs.Commits))
			if err != nil {
				t.Fatalf("PartitionScopes: %v", err)
			}
			if !reflect.DeepEqual(got, expected.Scopes) {
				t.Errorf("partition = %v, want %v", got, expected.Scopes)
			}
		})
	}
	if seen == 0 {
		t.Error("no scope_partition vectors found")
	}
}

func TestConformanceScopeFloor(t *testing.T) {
	vf := loadAggVectors(t, "SEMVER_TRUST_AGGREGATION_VECTORS", "aggregation.json")

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "scope_floor" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			var inputs struct {
				Scopes  map[string]string `json:"scopes"`
				Commits []aggCommit       `json:"commits"`
			}
			var expected struct {
				OwnTrust map[string]string `json:"own_trust"`
			}
			decode(t, vec.Inputs, &inputs)
			decode(t, vec.Expected, &expected)

			floors, err := ScopeFloors(inputs.Scopes, toCommits(t, inputs.Commits))
			if err != nil {
				t.Fatalf("ScopeFloors: %v", err)
			}
			got := map[string]string{}
			for scope, level := range floors {
				got[scope] = level.String()
			}
			if !reflect.DeepEqual(got, expected.OwnTrust) {
				t.Errorf("own_trust = %v, want %v", got, expected.OwnTrust)
			}
		})
	}
	if seen == 0 {
		t.Error("no scope_floor vectors found")
	}
}

func TestConformanceMetaPath(t *testing.T) {
	vf := loadAggVectors(t, "SEMVER_TRUST_AGGREGATION_VECTORS", "aggregation.json")

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "meta_path" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			var inputs struct {
				Meta struct {
					Paths         []string `json:"paths"`
					RequiredLevel string   `json:"required_level"`
				} `json:"meta"`
				Commits []aggCommit `json:"commits"`
			}
			var expected struct {
				Outcome    string   `json:"outcome"`
				Violations []string `json:"violations"`
			}
			decode(t, vec.Inputs, &inputs)
			decode(t, vec.Expected, &expected)

			violations, err := MetaPathViolations(
				inputs.Meta.Paths,
				mustLevel(t, inputs.Meta.RequiredLevel),
				toCommits(t, inputs.Commits),
			)
			if err != nil {
				t.Fatalf("MetaPathViolations: %v", err)
			}
			outcome := "verified"
			if len(violations) > 0 {
				outcome = "verification_failed"
			}
			if outcome != expected.Outcome {
				t.Errorf("outcome = %s, want %s", outcome, expected.Outcome)
			}
			if len(violations) == 0 {
				violations = []string{}
			}
			if !reflect.DeepEqual(violations, expected.Violations) {
				t.Errorf("violations = %v, want %v", violations, expected.Violations)
			}
		})
	}
	if seen == 0 {
		t.Error("no meta_path vectors found")
	}
}

func TestConformancePropagation(t *testing.T) {
	vf := loadAggVectors(t, "SEMVER_TRUST_PROPAGATION_VECTORS", "propagation.json")

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "propagation" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			var inputs struct {
				Nodes map[string]string `json:"nodes"`
				Edges [][2]string       `json:"edges"`
			}
			var expected struct {
				Effective   map[string]string `json:"effective"`
				FloorSource map[string]string `json:"floor_source"`
			}
			decode(t, vec.Inputs, &inputs)
			decode(t, vec.Expected, &expected)

			own := map[string]Level{}
			for node, level := range inputs.Nodes {
				own[node] = mustLevel(t, level)
			}
			got, err := Propagate(own, inputs.Edges)
			if err != nil {
				t.Fatalf("Propagate: %v", err)
			}

			effective := map[string]string{}
			for node, e := range got {
				effective[node] = e.Level.String()
			}
			if !reflect.DeepEqual(effective, expected.Effective) {
				t.Errorf("effective = %v, want %v", effective, expected.Effective)
			}
			for node, source := range expected.FloorSource {
				if got[node].FloorSource != source {
					t.Errorf("floor_source[%s] = %s, want %s", node, got[node].FloorSource, source)
				}
			}
		})
	}
	if seen == 0 {
		t.Error("no propagation vectors found")
	}
}

func decode(t *testing.T, raw json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
}
