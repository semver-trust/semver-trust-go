// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestConformanceRange drives the spec's release-interval vectors (§5.2,
// ADR-027) through SelectInterval: inception covers Reach(TO), adoption
// includes the bootstrap-pinned boundary and excludes only its parent history,
// recurring anchors to the accepted predecessor chain head, and every
// caller-selected / skipped / moved / mismatched predecessor or boundary aborts
// with a stable reason.
func TestConformanceRange(t *testing.T) {
	vf := loadRangeVectors(t)
	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "release_range" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			in := IntervalInputs{
				Repository:         vec.Inputs.Repository,
				Component:          vec.Inputs.Component,
				Mode:               IntervalMode(vec.Inputs.Mode),
				To:                 vec.Inputs.To,
				ExistingChainHeads: vec.Inputs.ExistingChainHeads,
				RequestedFrom:      vec.Inputs.RequestedFrom,
			}
			if b := vec.Inputs.Boundary; b != nil {
				in.Boundary = &BoundaryDescriptor{OID: b.OID, RefTarget: b.RefTarget, BootstrapPinned: b.BootstrapPinned}
			}
			if p := vec.Inputs.Predecessor; p != nil {
				in.Predecessor = &PredecessorDescriptor{
					Accepted: p.Accepted, ChainHead: p.ChainHead,
					Repository: p.Repository, Component: p.Component,
					To: p.To, TagTarget: p.TagTarget,
				}
			}
			for _, c := range vec.Inputs.Commits {
				in.Commits = append(in.Commits, CommitNode{ID: c.ID, Parents: c.Parents})
			}

			commits, reason := SelectInterval(in)
			outcome := "verified"
			if reason != "" {
				outcome = "verification_failed"
			}
			if outcome != vec.Expected.Outcome {
				t.Errorf("outcome = %s (reason %q), want %s (reason %q)", outcome, reason, vec.Expected.Outcome, vec.Expected.Reason)
			}
			if reason != vec.Expected.Reason {
				t.Errorf("reason = %q, want %q", reason, vec.Expected.Reason)
			}
			want := vec.Expected.Commits
			if len(commits) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(commits, want) {
				t.Errorf("commits = %v, want %v", commits, want)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no release_range vectors ran")
	}
}

type rangeVectorFile struct {
	SpecVersion string        `json:"spec_version"`
	Vectors     []rangeVector `json:"vectors"`
}

type rangeVector struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Inputs struct {
		Repository         string  `json:"repository"`
		Component          string  `json:"component"`
		Mode               string  `json:"mode"`
		To                 string  `json:"to"`
		ExistingChainHeads int     `json:"existing_chain_heads"`
		RequestedFrom      *string `json:"requested_from"`
		Boundary           *struct {
			OID             string `json:"oid"`
			RefTarget       string `json:"ref_target"`
			BootstrapPinned bool   `json:"bootstrap_pinned"`
		} `json:"boundary"`
		Predecessor *struct {
			Accepted   bool   `json:"accepted"`
			ChainHead  bool   `json:"chain_head"`
			Repository string `json:"repository"`
			Component  string `json:"component"`
			To         string `json:"to"`
			TagTarget  string `json:"tag_target"`
		} `json:"predecessor"`
		Commits []struct {
			ID      string   `json:"id"`
			Parents []string `json:"parents"`
		} `json:"commits"`
	} `json:"inputs"`
	Expected struct {
		Outcome string   `json:"outcome"`
		Commits []string `json:"commits"`
		Reason  string   `json:"reason"`
	} `json:"expected"`
}

func loadRangeVectors(t *testing.T) rangeVectorFile {
	t.Helper()
	const name = "range.json"
	path := os.Getenv("SEMVER_TRUST_RANGE_VECTORS")
	if path == "" {
		for _, candidate := range []string{
			filepath.Join("testdata", name),
			filepath.Join("..", "..", "conformance", "vendor", name),
		} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		t.Fatalf("conformance vectors absent: conformance/vendor/%s missing (refresh via scripts/sync-conformance.py)", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	var vf rangeVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return vf
}
