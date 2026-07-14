// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConformancePredicateV02 drives the spec's predicate-v0.2 vectors (§8.1,
// ADR-030) through the schema-only ValidatePayload entrypoint: each release/v0.2
// or review/v0.2 payload must validate (or fail to validate) against its
// vendored schema exactly as the vector expects, and payloads flagged with a
// source-evidence extension must additionally carry a structurally bound one
// (§8.3, ADR-035).
func TestConformancePredicateV02(t *testing.T) {
	attDir := filepath.Join(vendorDir(t), "crypto", "attestations")
	verifier := newConformanceVerifier(t, attDir)

	index := filepath.Join(vendorDir(t), "predicate-v0.2.json")
	data, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("predicate-v0.2 vectors missing (refresh via scripts/sync-conformance.py): %v", err)
	}
	var doc struct {
		Vectors []struct {
			ID     string `json:"id"`
			Kind   string `json:"kind"`
			Inputs struct {
				Payload string `json:"payload"`
			} `json:"inputs"`
			Expected struct {
				SchemaValid             bool `json:"schema_valid"`
				SourceEvidenceExtension bool `json:"source_evidence_extension"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing predicate-v0.2 index: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no predicate-v0.2 vectors ran")
	}

	for _, vec := range doc.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(vendorDir(t), vec.Inputs.Payload))
			if err != nil {
				t.Fatalf("payload %q missing: %v", vec.Inputs.Payload, err)
			}
			gotValid := verifier.ValidatePayload(payload) == nil
			if gotValid != vec.Expected.SchemaValid {
				t.Errorf("schema_valid = %v, want %v", gotValid, vec.Expected.SchemaValid)
			}
			if vec.Expected.SourceEvidenceExtension && !SourceEvidenceExtensionBound(payload) {
				t.Errorf("expected a structurally bound source-evidence extension, got none")
			}
		})
	}
}
