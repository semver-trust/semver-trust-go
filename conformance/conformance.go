// SPDX-License-Identifier: Apache-2.0

// Package conformance carries the vendored SemVer-Trust conformance
// artifacts and their pin (ADR-021): the spec repository's vectors are
// vendored under vendor/ as digest-pinned copies, and manifest.json records
// the source commit, a SHA-256 per file, and the spec draft version — the
// single place this implementation pins the spec version it claims
// conformance against (surfaced by --version).
//
// scripts/sync-conformance.py is the only sanctioned way to refresh the
// vendored copies; the tests in this package fail on any byte drift between
// vendor/ and the manifest, making suite updates deliberate, reviewable
// diffs against a stated spec version rather than silent drift.
package conformance

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed manifest.json vendor
var fs embed.FS

// Manifest is the ADR-021 pin record.
type Manifest struct {
	// SpecVersion is the spec draft the vendored vectors encode ("0.2").
	SpecVersion string `json:"spec_version"`
	// Source identifies the exact spec-repository commit vendored.
	Source struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
	} `json:"source"`
	// Files maps each vendored file to its "sha256:<hex>" digest.
	Files map[string]string `json:"files"`
}

// Load returns the embedded manifest.
func Load() (Manifest, error) {
	data, err := fs.ReadFile("manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("conformance: parsing manifest: %w", err)
	}
	return m, nil
}

// SpecVersion returns the pinned spec draft version, or "unknown" if the
// manifest cannot be read (which the tests in this package fail on).
func SpecVersion() string {
	m, err := Load()
	if err != nil {
		return "unknown"
	}
	return m.SpecVersion
}

// SourceCommit returns the pinned spec-repository commit, or "unknown".
func SourceCommit() string {
	m, err := Load()
	if err != nil {
		return "unknown"
	}
	return m.Source.Commit
}

// Vector returns the raw bytes of a vendored vector file (e.g.
// "levels.json").
func Vector(name string) ([]byte, error) {
	return fs.ReadFile("vendor/" + name)
}
