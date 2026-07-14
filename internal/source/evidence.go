// SPDX-License-Identifier: Apache-2.0

// Package source evaluates SLSA source-evidence profiles (§8.3, ADR-035):
// profile-bound consumption of source-control provenance and Verification
// Summary Attestations. A profile binds repository identity, subject-revision
// matching, allowed digest algorithms, issuer authorization, and a verification
// mode (replay or trusted_issuer), and detects hidden demotions and issuer
// equivocation before the summarized source facts may be trusted.
package source

import (
	"sort"
	"strings"
)

// Statement is one source-evidence record as a profile sees it — a VSA or
// source-provenance statement: its issuer, the resource (repository) it binds,
// the subject revision (digest algorithm → value), the SLSA levels it asserts,
// and its replay/freshness flags.
type Statement struct {
	Issuer         string
	ResourceURI    string
	Subject        map[string]string
	VerifiedLevels []string
	Fresh          bool
	Replayed       bool
}

// EvidenceInputs are the release-time facts a source-evidence profile is
// evaluated against (§8.3, ADR-035). HiddenDemotions carries the current-state
// demotion set; a non-empty set aborts the profile.
type EvidenceInputs struct {
	Mode                    string // replay | trusted_issuer
	Repository              string
	ReleaseTo               map[string]string
	AllowedDigestAlgorithms []string
	TrustedIssuers          []string
	Evidence                []Statement
	HiddenDemotions         []string
}

// SelectSourceEvidence evaluates a source-evidence profile (§8.3, ADR-035): a
// signed VSA is a summary from an issuer, so the profile either replays the
// underlying source provenance or explicitly trusts the issuer, and always
// binds repository/resource and subject identity so a valid attestation for one
// repository or revision can never be replayed into another release chain.
//
// It returns whether the evidence is accepted and, on rejection, a stable
// reason (empty when accepted). A faithful port of the conformance oracle's
// _source_evidence_result; the production verifier feeds it real VSA / source
// provenance facts (tracked in semver-trust-go#76).
func SelectSourceEvidence(in EvidenceInputs) (accepted bool, reason string) {
	if len(in.Evidence) == 0 {
		return false, "missing_evidence"
	}

	allowed := make(map[string]bool, len(in.AllowedDigestAlgorithms))
	for _, a := range in.AllowedDigestAlgorithms {
		allowed[a] = true
	}
	trusted := make(map[string]bool, len(in.TrustedIssuers))
	for _, i := range in.TrustedIssuers {
		trusted[i] = true
	}

	type norm struct {
		key    string
		levels []string
	}
	normalized := make([]norm, 0, len(in.Evidence))

	for _, s := range in.Evidence {
		if !trusted[s.Issuer] {
			return false, "unauthorized_issuer"
		}
		if s.ResourceURI != in.Repository {
			return false, "resource_mismatch"
		}
		for alg := range s.Subject {
			if !allowed[alg] {
				return false, "digest_algorithm_disallowed"
			}
		}
		if !equalStringMap(s.Subject, in.ReleaseTo) {
			return false, "subject_mismatch"
		}
		if in.Mode == "replay" && !s.Replayed {
			return false, "replay_required"
		}
		if !s.Fresh {
			return false, "stale_evidence"
		}
		normalized = append(normalized, norm{
			key:    s.Issuer + "\x00" + s.ResourceURI + "\x00" + subjectKey(s.Subject),
			levels: s.VerifiedLevels,
		})
	}

	if len(in.HiddenDemotions) > 0 {
		return false, "hidden_demotion"
	}

	byIdentity := make(map[string][]string, len(normalized))
	for _, n := range normalized {
		prior, ok := byIdentity[n.key]
		if !ok {
			byIdentity[n.key] = n.levels
			continue
		}
		if !equalStrings(prior, n.levels) {
			return false, "equivocation"
		}
	}

	return true, ""
}

// subjectKey renders a subject (digest algorithm → value) as a stable string,
// mirroring the oracle's tuple(sorted(subject.items())) identity component.
func subjectKey(subject map[string]string) string {
	algs := make([]string, 0, len(subject))
	for a := range subject {
		algs = append(algs, a)
	}
	sort.Strings(algs)
	var sb strings.Builder
	for _, a := range algs {
		sb.WriteString(a)
		sb.WriteByte('=')
		sb.WriteString(subject[a])
		sb.WriteByte('\x00')
	}
	return sb.String()
}

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
