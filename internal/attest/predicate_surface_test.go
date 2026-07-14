// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestValidatePayloadSurface pins the ValidatePayload outcomes the vectors do
// not exercise: an unrecognized predicateType and a malformed payload both fail
// (schema_valid=false), the first as ErrUnsupportedPredicate.
func TestValidatePayloadSurface(t *testing.T) {
	v, err := NewVerifier(nil, map[string][]byte{PredicateReleaseV02: []byte(`{"type":"object"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ValidatePayload([]byte(`{"predicateType":"https://example.test/unknown"}`)); !errors.Is(err, ErrUnsupportedPredicate) {
		t.Errorf("unknown predicateType: err = %v, want ErrUnsupportedPredicate", err)
	}
	if err := v.ValidatePayload([]byte("not json")); !errors.Is(err, ErrSchemaInvalid) {
		t.Errorf("malformed payload: err = %v, want ErrSchemaInvalid", err)
	}
}

// seExtBase is a minimal release/v0.2 statement carrying a structurally bound
// source-evidence extension.
func seExtBase() map[string]any {
	return map[string]any{
		"predicateType": PredicateReleaseV02,
		"predicate": map[string]any{
			"interval":   map[string]any{"source_identity": map[string]any{"gitCommit": "cccc"}},
			"repository": map[string]any{"id": "repo:test/auth"},
			"extensions": map[string]any{
				sourceEvidenceExtensionURI: map[string]any{
					"source_revision":         map[string]any{"gitCommit": "cccc"},
					"repository_resource_uri": "repo:test/auth",
					"mode":                    "trusted_issuer",
					"profile":                 map[string]any{"name": "p", "version": "0.1", "digest": map[string]any{"sha256": "22"}},
					"issuer_roots":            []any{map[string]any{"uri": "scs:root"}},
					"evidence":                []any{map[string]any{"x": float64(1)}},
					"freshness": map[string]any{
						"verification_instant": "2026-07-12T20:00:00Z",
						"current_state":        map[string]any{"digest": map[string]any{"sha256": "55"}},
					},
				},
			},
		},
	}
}

func seExtOf(m map[string]any) map[string]any {
	return m["predicate"].(map[string]any)["extensions"].(map[string]any)[sourceEvidenceExtensionURI].(map[string]any)
}

func mustJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSourceEvidenceExtensionBoundSurface pins the extension-bound rejection
// branches — none of which the single positive vector exercises — so the port
// mirrors the oracle's full decision surface.
func TestSourceEvidenceExtensionBoundSurface(t *testing.T) {
	if !SourceEvidenceExtensionBound(mustJSON(t, seExtBase())) {
		t.Fatal("base extension should be bound")
	}

	cases := []struct {
		name string
		mut  func(m map[string]any)
	}{
		{"wrong predicate type", func(m map[string]any) { m["predicateType"] = PredicateReviewV02 }},
		{"extension absent", func(m map[string]any) {
			delete(m["predicate"].(map[string]any)["extensions"].(map[string]any), sourceEvidenceExtensionURI)
		}},
		{"source revision not bound to interval", func(m map[string]any) {
			seExtOf(m)["source_revision"] = map[string]any{"gitCommit": "dddd"}
		}},
		{"repository resource uri not bound", func(m map[string]any) {
			seExtOf(m)["repository_resource_uri"] = "repo:other/thing"
		}},
		{"empty mode", func(m map[string]any) { seExtOf(m)["mode"] = "" }},
		{"empty profile digest", func(m map[string]any) {
			seExtOf(m)["profile"].(map[string]any)["digest"] = map[string]any{}
		}},
		{"missing current-state digest", func(m map[string]any) {
			seExtOf(m)["freshness"].(map[string]any)["current_state"] = map[string]any{}
		}},
		{"empty evidence", func(m map[string]any) { seExtOf(m)["evidence"] = []any{} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := seExtBase()
			c.mut(m)
			if SourceEvidenceExtensionBound(mustJSON(t, m)) {
				t.Error("expected unbound, got bound")
			}
		})
	}
}
