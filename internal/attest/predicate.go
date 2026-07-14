// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// sourceEvidenceExtensionURI is the §8.3/ADR-035 source-evidence extension key
// carried inside a release/v0.2 predicate's extensions map.
const sourceEvidenceExtensionURI = "https://semver-trust.dev/extensions/source-evidence/v0.1"

// ValidatePayload validates a raw in-toto statement payload against the
// compiled schema for its predicateType, performing no envelope or signature
// checks. It is the schema half of Verify, exposed for predicate-payload
// conformance (§8.1, ADR-030): a well-formed but schema-invalid payload is the
// interesting negative case, and it need not be re-signed to be exercised.
//
// It returns nil when the payload validates, ErrUnsupportedPredicate for an
// unrecognized predicateType, and ErrSchemaInvalid when the payload does not
// validate against its schema.
func (v *Verifier) ValidatePayload(payload []byte) error {
	var stmt struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return fmt.Errorf("attest: %w: statement: %v", ErrSchemaInvalid, err)
	}
	schema, ok := v.schemas[stmt.PredicateType]
	if !ok {
		return fmt.Errorf("attest: %q: %w", stmt.PredicateType, ErrUnsupportedPredicate)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("attest: %w: %v", ErrSchemaInvalid, err)
	}
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("attest: %w: %v", ErrSchemaInvalid, err)
	}
	return nil
}

// SourceEvidenceExtensionBound reports whether a release/v0.2 payload carries a
// structurally bound source-evidence extension (§8.3, ADR-035): the extension
// must be present as an object, its source_revision must equal the interval's
// source_identity and its repository_resource_uri the repository id, and its
// mode, profile (name/version/digest), issuer roots, evidence, freshness
// instant, and current-state digest must all be populated — so the summarized
// source facts are pinned to the release's own subject rather than free-floating.
// A faithful port of the conformance oracle's _source_evidence_extension_bound.
func SourceEvidenceExtensionBound(payload []byte) bool {
	var stmt map[string]any
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return false
	}
	if s, _ := stmt["predicateType"].(string); s != PredicateReleaseV02 {
		return false
	}
	predicate, _ := stmt["predicate"].(map[string]any)
	extensions, _ := predicate["extensions"].(map[string]any)
	ext, ok := extensions[sourceEvidenceExtensionURI].(map[string]any)
	if !ok {
		return false
	}

	interval, _ := predicate["interval"].(map[string]any)
	var intervalSource any = map[string]any{}
	if s, present := interval["source_identity"]; present {
		intervalSource = s
	}
	if !reflect.DeepEqual(ext["source_revision"], intervalSource) {
		return false
	}
	repository, _ := predicate["repository"].(map[string]any)
	if !reflect.DeepEqual(ext["repository_resource_uri"], repository["id"]) {
		return false
	}

	profile, _ := ext["profile"].(map[string]any)
	freshness, _ := ext["freshness"].(map[string]any)
	currentState, _ := freshness["current_state"].(map[string]any)
	for _, value := range []any{
		ext["mode"], profile["name"], profile["version"], profile["digest"],
		ext["issuer_roots"], ext["evidence"],
		freshness["verification_instant"], currentState["digest"],
	} {
		if !truthy(value) {
			return false
		}
	}
	return true
}

// truthy mirrors Python's bool() for parsed-JSON values: nil, false, an empty
// string, zero, or an empty array/object is falsy; anything else is truthy.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}
