// SPDX-License-Identifier: Apache-2.0

package source

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConformanceSourceEvidence drives the spec's source-evidence vectors
// (§8.3, ADR-035) through SelectSourceEvidence: a profile binds repository
// identity, subject revision, digest algorithms, issuer authorization, and
// verification mode, and rejects unauthorized issuers, resource/subject
// mismatches, disallowed algorithms, unreplayed or stale evidence, hidden
// demotions, and issuer equivocation with a stable reason.
func TestConformanceSourceEvidence(t *testing.T) {
	doc := loadSourceEvidenceVectors(t)
	seen := 0
	for _, vec := range doc.Vectors {
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			accepted, reason := SelectSourceEvidence(vec.Inputs.build())
			if accepted != vec.Expected.Accepted {
				t.Errorf("accepted = %v (reason %q), want %v (reason %q)", accepted, reason, vec.Expected.Accepted, ptrStr(vec.Expected.Reason))
			}
			if reason != ptrStr(vec.Expected.Reason) {
				t.Errorf("reason = %q, want %q", reason, ptrStr(vec.Expected.Reason))
			}
		})
	}
	if seen == 0 {
		t.Fatal("no source-evidence vectors ran")
	}
}

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

type seStatement struct {
	Issuer         string            `json:"issuer"`
	ResourceURI    string            `json:"resourceUri"`
	Subject        map[string]string `json:"subject"`
	VerifiedLevels []string          `json:"verifiedLevels"`
	SourceRefs     []string          `json:"sourceRefs"`
	Fresh          bool              `json:"fresh"`
	Replayed       bool              `json:"replayed"`
}

type seInputs struct {
	Mode                    string            `json:"mode"`
	Repository              string            `json:"repository"`
	ReleaseTo               map[string]string `json:"release_to"`
	AllowedDigestAlgorithms []string          `json:"allowed_digest_algorithms"`
	TrustedIssuers          []string          `json:"trusted_issuers"`
	Evidence                []seStatement     `json:"evidence"`
	CurrentState            struct {
		HiddenDemotions []string `json:"hidden_demotions"`
	} `json:"current_state"`
}

func (in seInputs) build() EvidenceInputs {
	stmts := make([]Statement, len(in.Evidence))
	for i, s := range in.Evidence {
		stmts[i] = Statement{
			Issuer: s.Issuer, ResourceURI: s.ResourceURI, Subject: s.Subject,
			VerifiedLevels: s.VerifiedLevels, Fresh: s.Fresh, Replayed: s.Replayed,
		}
	}
	return EvidenceInputs{
		Mode: in.Mode, Repository: in.Repository, ReleaseTo: in.ReleaseTo,
		AllowedDigestAlgorithms: in.AllowedDigestAlgorithms, TrustedIssuers: in.TrustedIssuers,
		Evidence: stmts, HiddenDemotions: in.CurrentState.HiddenDemotions,
	}
}

type seVector struct {
	ID       string   `json:"id"`
	Inputs   seInputs `json:"inputs"`
	Expected struct {
		Accepted bool    `json:"accepted"`
		Reason   *string `json:"reason"`
	} `json:"expected"`
}

type seDoc struct {
	SpecVersion string     `json:"spec_version"`
	Vectors     []seVector `json:"vectors"`
}

func loadSourceEvidenceVectors(t *testing.T) seDoc {
	t.Helper()
	const name = "source-evidence.json"
	path := os.Getenv("SEMVER_TRUST_SOURCE_EVIDENCE_VECTORS")
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
	var doc seDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return doc
}
