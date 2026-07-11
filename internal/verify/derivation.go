// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"

	"github.com/semver-trust/semver-trust-go/internal/derive"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// runDerivations applies each policy derivation rule against a disposable
// export of TO's tree (§10 step 4, §4.4) and, on a verified proof, re-levels
// the outputs to the inputs' floor by attaching trust.DerivationFacts to the
// commits whose diff paths touch the rule's outputs. It mutates tcommits.
//
// Two abort/non-abort distinctions are load-bearing (§4.4):
//   - A rule whose command fails proves nothing → abort (§10 step 4).
//   - A void proof (outputs regenerate differently) does NOT abort: the
//     outputs classify by their commits' own provenance and the differing
//     paths are reported, never silently absorbed.
//
// Judgment call: derive.Run also errors when a rule's declared outputs match
// no committed file in TO's tree — an unevaluable proof. This is treated as an
// abort (fail-closed): a declared derivation whose outputs are absent from the
// tree cannot be shown to hold, and §4.4's exception to weakest-link flooring
// is only earned by a proof that actually ran.
func runDerivations(repo, rev string, rules []policy.Derivation, tcommits []trust.Commit) ([]DerivationReport, error) {
	reports := make([]DerivationReport, 0, len(rules))
	for _, rule := range rules {
		dir, cleanup, err := exportToTemp(repo, rev, "semver-trust-derive-")
		if err != nil {
			return nil, abort(stepDerivation, fmt.Errorf("rule %q: exporting tree: %w", rule.Name, err))
		}
		verdict, err := derive.Run(dir, rule)
		cleanup()
		if err != nil {
			return nil, abort(stepDerivation, fmt.Errorf("rule %q: %w", rule.Name, err))
		}

		report := DerivationReport{Rule: rule.Name, Verified: verdict.Verified, Diffs: verdict.Diffs}
		if !verdict.Verified {
			// Void proof: outputs keep their own provenance; report the diffs.
			reports = append(reports, report)
			continue
		}

		floor, err := derive.InputsFloor(tcommits, rule)
		if err != nil {
			// No range commit touches the rule's inputs, so its outputs were
			// not touched in this range either: there is nothing to re-level.
			report.Note = "no range commit touches the rule inputs; re-leveling not applicable to this range"
			reports = append(reports, report)
			continue
		}
		report.InheritedLevel = floor.String()

		facts := derive.Facts(rule, verdict, floor)
		for i := range tcommits {
			if touchesGlobs(tcommits[i].Paths, rule.Outputs) {
				tcommits[i].Derivation = facts
			}
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// derivationRuleFor returns the policy rule whose outputs equal a set of
// derivation-facts outputs — used only to label a commit report row with the
// rule that re-leveled it.
func derivationRuleFor(rules []policy.Derivation, outputs []string) string {
	for _, rule := range rules {
		if equalStrings(rule.Outputs, outputs) {
			return rule.Name
		}
	}
	return ""
}

// touchesGlobs reports whether any path matches any glob (§5.1 segment-aware
// matching, via trust.MatchGlob).
func touchesGlobs(paths, globs []string) bool {
	for _, path := range paths {
		for _, glob := range globs {
			if ok, err := trust.MatchGlob(glob, path); err == nil && ok {
				return true
			}
		}
	}
	return false
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
