// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"github.com/semver-trust/semver-trust-go/internal/policy"
)

// reportDerivations records each policy-declared derivation rule as
// non-authoritative metadata and nothing more. The verifier MUST NOT execute
// repository-, policy-, or producer-supplied commands (spec repository
// ADR-033): re-running a command and observing byte-identical outputs is
// fixed-point evidence, not derivation evidence, and executing the target
// repository's commands hands it the verifier host. A declared rule therefore
// supplies no trust elevation — commits covering a rule's outputs keep the
// levels their own provenance earned — and an unevaluable claim is neither an
// abort nor a waiver: it is simply ignored for re-leveling, with ordinary
// weakest-link flooring applying throughout.
func reportDerivations(rules []policy.Derivation) []DerivationReport {
	reports := make([]DerivationReport, 0, len(rules))
	for _, rule := range rules {
		reports = append(reports, DerivationReport{
			Rule: rule.Name,
			Note: "not executed: derivation claims are non-authoritative and supply no elevation (ADR-033)",
		})
	}
	return reports
}
