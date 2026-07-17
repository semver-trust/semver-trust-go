// SPDX-License-Identifier: Apache-2.0

package version

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// This file implements the ADR-036 semver-trust-version-state-json v0.2 profile:
// the carried-forward version state (§7.5/ADR-029) serialized with RFC 8785
// (JSON Canonicalization Scheme) and hashed with SHA-256. The digest is bound as
// a release/v0.2 stateIdentity and re-derived by a verifier to authenticate the
// version-decision chain (§8.1). ADR-036 defines the field set; these functions
// only serialize and digest whatever canonical object the caller supplies.

// CanonicalizeState returns the RFC 8785 (JCS) serialization of a version-state
// object. The object MUST be composed of maps, slices, strings, integers,
// bools, and nil — NOT Go structs — because JCS orders object members
// lexicographically and encoding/json sorts map keys but preserves struct-field
// declaration order. For this object domain (ASCII keys/strings, integers,
// bool, null, arrays, nested objects — no floats), a sorted-key, minimally
// separated, non-HTML-escaping JSON encoding is byte-identical to JCS, which is
// exactly what encoding/json produces with SetEscapeHTML(false); no JCS
// dependency is required. The spec oracle (check-conformance.py) computes the
// same bytes, and the vendored conformance vectors pin the resulting digests.
func CanonicalizeState(state any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(state); err != nil {
		return nil, fmt.Errorf("version: canonicalize state: %w", err)
	}
	// Encoder.Encode appends a trailing newline; JCS output carries none.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// StateDigest is the lowercase-hex SHA-256 of the canonicalized version state —
// the bare-hex value bound as a release/v0.2 stateIdentity digest
// (`{"sha256": <StateDigest>}`) and reproduced by a verifier to authenticate the
// version-decision chain (ADR-036, §8.1).
func StateDigest(state any) (string, error) {
	canon, err := CanonicalizeState(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}
