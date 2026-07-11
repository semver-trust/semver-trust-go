// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"strings"

	"github.com/semver-trust/semver-trust-go/evidence"
	"github.com/semver-trust/semver-trust-go/evidence/apidiff"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// collectEvidence gathers the §10 step 7 evidence honestly (§6, §1.1). Blast
// inputs that are universal from git — the count of changed files — are
// reported; those that need evidence providers not wired in v1 (changed LOC,
// import-graph fan-in, coverage) are reported unavailable, never fabricated,
// so the blast score stays "unavailable" rather than a made-up qualitative
// grade.
//
// The semantic floor (§6.1) comes from a configured compatibility differ when
// one applies — policy configures apidiff for the ecosystem and FROM names a
// tree that can be exported — else from declared intent (Conventional Commits,
// §6.1(2)). The decision that consumes this floor is §10 step 8 (the release
// command, GO-042); step 7 only collects.
func collectEvidence(repo string, opts Options, pol *policy.Policy, commits []vcs.RangeCommit) (EvidenceReport, error) {
	changed := map[string]bool{}
	for _, c := range commits {
		for _, p := range c.Paths {
			changed[p] = true
		}
	}

	report := EvidenceReport{
		ChangedFiles: len(changed),
		LOCAvailable: false,
		BlastScore:   "unavailable",
		Note:         "blast inputs beyond changed-file count (LOC, import-graph fan-in, coverage) require evidence providers not wired in v1; reported unavailable rather than fabricated (§1.1)",
	}

	floor, source, provider, err := semanticFloor(repo, opts, pol, commits)
	if err != nil {
		return EvidenceReport{}, err
	}
	report.SemanticFloor = floor.String()
	report.SemanticFloorSource = source
	report.DifferAvailable = provider != ""
	report.DifferProvider = provider
	return report, nil
}

// semanticFloor returns the §6.1 semantic floor and how it was derived: from
// a compatibility differ (preferred) or from declared intent. apidiff is run
// only when the policy configures it for the "go" ecosystem and FROM names an
// exportable tree; a differ error falls back to declared intent honestly
// rather than aborting (the floor is advisory input to a later decision).
func semanticFloor(repo string, opts Options, pol *policy.Policy, commits []vcs.RangeCommit) (evidence.Bump, string, string, error) {
	if goEv, ok := pol.Evidence["go"]; ok && goEv.Compat == "apidiff" && opts.From != "" {
		bump, ok := runAPIDiff(repo, opts.From, opts.To)
		if ok {
			return bump, "differ", "apidiff", nil
		}
	}
	return declaredIntent(commits), "declared_intent", "", nil
}

// runAPIDiff exports the FROM and TO trees and runs the apidiff differ over
// them (§6.1(1)). A failure (e.g. a non-Go tree, or trees the differ cannot
// load) returns ok=false so the caller falls back to declared intent.
func runAPIDiff(repo, from, to string) (evidence.Bump, bool) {
	oldDir, cleanOld, err := exportToTemp(repo, from, "semver-trust-apidiff-old-")
	if err != nil {
		return 0, false
	}
	defer cleanOld()
	newDir, cleanNew, err := exportToTemp(repo, to, "semver-trust-apidiff-new-")
	if err != nil {
		return 0, false
	}
	defer cleanNew()
	bump, err := apidiff.Differ{}.Floor(oldDir, newDir)
	if err != nil {
		return 0, false
	}
	return bump, true
}

// declaredIntent computes the §6.1(2) semantic floor from Conventional Commit
// subjects: the maximum bump over the range, where feat → MINOR, a `!` marker
// or a BREAKING CHANGE footer → MAJOR, and everything else → PATCH. Declared
// intent is weak evidence (§6.1); it is the honest floor when no differ exists.
func declaredIntent(commits []vcs.RangeCommit) evidence.Bump {
	floor := evidence.BumpPatch
	for _, c := range commits {
		if b := conventionalBump(c.Subject, c.Message); b > floor {
			floor = b
		}
	}
	return floor
}

func conventionalBump(subject, message string) evidence.Bump {
	if strings.Contains(message, "BREAKING CHANGE") {
		return evidence.BumpMajor
	}
	idx := strings.Index(subject, ":")
	if idx < 0 {
		return evidence.BumpPatch
	}
	head := subject[:idx]
	if strings.HasSuffix(head, "!") {
		return evidence.BumpMajor
	}
	if scope := strings.IndexByte(head, '('); scope >= 0 {
		head = head[:scope]
	}
	if strings.TrimSpace(head) == "feat" {
		return evidence.BumpMinor
	}
	return evidence.BumpPatch
}

// readFile reads a filesystem path — the injected trust material (allowed
// signers) the CLI resolves outside any git tree.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
