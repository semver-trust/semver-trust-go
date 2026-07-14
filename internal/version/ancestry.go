// SPDX-License-Identifier: Apache-2.0

package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This file ports the §7.5/ADR-029 authenticated-version-ancestry oracle
// (_version_ancestry): interval selection never supplies version ancestry;
// bootstrap or accepted-predecessor state selects the baseline, the signed
// action and bump are candidate facts, and the exact target core, iteration,
// and tag are derived. The production release path still derives versions from
// FROM (the pre-ADR-029 model); feeding this real chain state is tracked in
// semver-trust-go#76.

var bumpRank = map[string]int{"patch": 0, "minor": 1, "major": 2}
var levelRank = map[string]int{"T0": 0, "T1": 1, "T2": 2, "T3": 3}

var trustTagRe = regexp.MustCompile(
	`^(?:(?P<path>[0-9A-Za-z._-]+(?:/[0-9A-Za-z._-]+)*)/)?` +
		`v(?P<core>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))` +
		`(?:-t(?P<level>[0-3])\.(?P<iter>[1-9][0-9]*))?$`)

var semverRe = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)

// AncestryCommit is a commit in the version graph (id + parents).
type AncestryCommit struct {
	ID      string
	Parents []string
}

// RefEntry is a ref-set observation: the raw ref target and peeled commit.
type RefEntry struct {
	RefOID    string
	CommitOID string
}

// Binding pins a tag to its raw/peeled object ids (§7.5 version predecessor).
type Binding struct {
	Tag       string
	RefOID    string
	CommitOID string
}

// VersionState is the accepted per-component version state carried forward.
type VersionState struct {
	Baseline        *Binding
	BaselineCore    string
	TargetCore      string
	TargetBump      string
	CleanAccepted   bool
	TargetIntervals []string
	Iterations      map[string]int
	CorrectiveFloor *string
}

// VersionBootstrap is the chain-genesis version authority. VersionPredecessor
// is present/absent (PredecessorPresent), null (a new v0 line), a binding, or a
// list (ambiguous, PredecessorAmbiguous).
type VersionBootstrap struct {
	Authenticated        bool
	Repository           string
	Component            string
	IntervalMode         string
	Boundary             *string
	TagPrefix            string
	PredecessorPresent   bool
	PredecessorNull      bool
	PredecessorAmbiguous bool
	Predecessor          *Binding
}

// VersionSelected is an accepted predecessor or superseded release.
type VersionSelected struct {
	Accepted              bool
	ChainHead             bool
	SourceSuccessorExists bool
	Repository            string
	Component             string
	TagPrefix             string
	To                    string
	CanonicalTags         []Binding
	State                 VersionState
}

// DecisionInputs are the §6 decision facts a version cut consumes.
type DecisionInputs struct {
	EffectiveTrust  string
	Threshold       string
	Blast           string
	Strategy        string
	DifferAvailable bool
	SemanticFloor   string
	ClaimedBump     string
}

// TargetReevaluation authenticates a raised target-trust re-evaluation.
type TargetReevaluation struct {
	Authenticated   bool
	Predecessor     string
	TargetCore      string
	SourceIntervals []string
	EffectiveTrust  string
}

// AncestryInputs are the release-time facts a version-ancestry decision is
// evaluated against.
type AncestryInputs struct {
	Authority          string // bootstrap | predecessor | superseded
	Action             string // advance | recut | supersede
	Repository         string
	Component          string
	TagPrefix          string
	IntervalMode       string
	Boundary           *string
	To                 string
	Graph              []AncestryCommit
	Refs               map[string]RefEntry
	Decision           DecisionInputs
	FixtureRef         string // the selected predecessor/superseded key (for reeval binding)
	Bootstrap          *VersionBootstrap
	Predecessor        *VersionSelected
	Superseded         *VersionSelected
	TargetReevaluation *TargetReevaluation

	RequestedVersionPredecessor *string
	RequestedIteration          *int
}

// AncestryResult is the derived version state or the failure reason.
type AncestryResult struct {
	Outcome             string
	VersionPredecessor  *string
	TargetCore          *string
	Iteration           *int
	Version             *string
	AdvancesVersionHead bool
	CorrectiveFloor     *string
	Reason              string
}

func ancestryFail(reason string) AncestryResult {
	return AncestryResult{Outcome: "verification_failed", Reason: reason}
}

func bumpCore(core, bump string) string {
	parts := strings.SplitN(core, ".", 3)
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patch, _ := strconv.Atoi(parts[2])
	switch bump {
	case "major":
		return fmt.Sprintf("%d.0.0", major+1)
	case "minor":
		return fmt.Sprintf("%d.%d.0", major, minor+1)
	default:
		return fmt.Sprintf("%d.%d.%d", major, minor, patch+1)
	}
}

var decisionTable = map[[2]string]string{
	{"T3", "low"}: "clean", {"T3", "moderate"}: "clean", {"T3", "high"}: "differ_patch",
	{"T2", "low"}: "clean", {"T2", "moderate"}: "differ_patch", {"T2", "high"}: "prerelease",
	{"T1", "low"}: "prerelease", {"T1", "moderate"}: "prerelease", {"T1", "high"}: "prerelease",
	{"T0", "low"}: "prerelease", {"T0", "moderate"}: "prerelease", {"T0", "high"}: "prerelease",
}

// decisionOutcome ports _decision_outcome: the channel and the effective bump
// (nil bump signals an inflate escalation with no fixed target).
func decisionOutcome(in DecisionInputs) (channel string, bump *string) {
	cell := decisionTable[[2]string{in.EffectiveTrust, in.Blast}]
	b := in.ClaimedBump
	if bumpRank[in.SemanticFloor] > bumpRank[b] {
		b = in.SemanticFloor
	}
	belowThreshold := levelRank[in.EffectiveTrust] < levelRank[in.Threshold]
	differNeeded := cell == "differ_any" || (cell == "differ_patch" && b == "patch")
	demoted := belowThreshold || cell == "prerelease" || (differNeeded && !in.DifferAvailable)

	if in.Strategy == "inflate" {
		if demoted {
			return "clean", nil
		}
		return "clean", &b
	}
	if demoted {
		return "prerelease", &b
	}
	return "clean", &b
}

type tagMatch struct {
	path  string
	core  string
	level *int
	iter  *int
}

func matchTrustTag(tag string) *tagMatch {
	m := trustTagRe.FindStringSubmatch(tag)
	if m == nil {
		return nil
	}
	out := &tagMatch{path: m[1], core: m[2]}
	if m[3] != "" {
		lv, _ := strconv.Atoi(m[3])
		it, _ := strconv.Atoi(m[4])
		out.level = &lv
		out.iter = &it
	}
	return out
}

func ancestryReach(start string, parents map[string][]string) map[string]bool {
	seen := map[string]bool{}
	frontier := []string{start}
	for len(frontier) > 0 {
		c := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if seen[c] {
			continue
		}
		seen[c] = true
		frontier = append(frontier, parents[c]...)
	}
	return seen
}

func bindingParts(b *Binding, requireClean bool, tagPrefix string, refs map[string]RefEntry) (*tagMatch, string) {
	if b == nil || b.Tag == "" {
		return nil, "version_predecessor_malformed"
	}
	m := matchTrustTag(b.Tag)
	if m == nil || (requireClean && m.level != nil) {
		return nil, "version_predecessor_malformed"
	}
	if m.path != tagPrefix {
		return nil, "version_predecessor_component_mismatch"
	}
	observed, ok := refs[b.Tag]
	if !ok {
		return nil, "version_predecessor_missing"
	}
	if observed.RefOID != b.RefOID {
		return nil, "version_predecessor_ref_moved"
	}
	if observed.CommitOID != b.CommitOID {
		return nil, "version_predecessor_commit_moved"
	}
	return m, ""
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }

// SelectVersionAncestry ports _version_ancestry (§7.5, ADR-029): it derives the
// target core, iteration, exact tag, and whether the release advances the
// version head — or fails with a stable reason.
func SelectVersionAncestry(in AncestryInputs) AncestryResult {
	ordered := make([]string, len(in.Graph))
	parents := make(map[string][]string, len(in.Graph))
	for i, c := range in.Graph {
		ordered[i] = c.ID
		parents[c.ID] = c.Parents
	}
	if len(ordered) != len(parents) {
		return ancestryFail("invalid_version_graph")
	}
	for _, ps := range parents {
		for _, p := range ps {
			if _, ok := parents[p]; !ok {
				return ancestryFail("invalid_version_graph")
			}
		}
	}
	if _, ok := parents[in.To]; !ok {
		return ancestryFail("unknown_to")
	}
	reachableTo := ancestryReach(in.To, parents)

	channel0, bump0 := decisionOutcome(in.Decision)
	bump := bump0
	if bump == nil {
		return ancestryFail("version_escalation_target_unresolved")
	}
	decisionInputs := in.Decision

	var state *VersionState
	var versionPredecessor *string
	sourceSuccessorExists := false
	targetReevaluationConsumed := false
	var targetCore string
	iterations := map[string]int{}
	cleanAccepted := false

	switch in.Authority {
	case "bootstrap":
		b := in.Bootstrap
		if b == nil {
			return ancestryFail("version_bootstrap_missing")
		}
		if !b.Authenticated {
			return ancestryFail("version_bootstrap_unauthenticated")
		}
		if b.Repository != in.Repository || b.Component != in.Component {
			return ancestryFail("version_bootstrap_subject_mismatch")
		}
		if b.IntervalMode != in.IntervalMode {
			return ancestryFail("version_bootstrap_interval_mismatch")
		}
		if !strEqPtr(b.Boundary, in.Boundary) {
			return ancestryFail("version_bootstrap_boundary_mismatch")
		}
		if b.TagPrefix != in.TagPrefix {
			return ancestryFail("version_bootstrap_prefix_mismatch")
		}
		if in.Action != "advance" {
			return ancestryFail("version_genesis_requires_advance")
		}
		if !b.PredecessorPresent {
			return ancestryFail("version_predecessor_selection_missing")
		}
		if b.PredecessorAmbiguous {
			return ancestryFail("version_predecessor_ambiguous")
		}
		baseCore := "0.0.0"
		if !b.PredecessorNull {
			m, reason := bindingParts(b.Predecessor, true, in.TagPrefix, in.Refs)
			if reason != "" {
				return ancestryFail(reason)
			}
			predCommit := b.Predecessor.CommitOID
			if _, ok := parents[predCommit]; !ok {
				return ancestryFail("version_predecessor_not_ancestor")
			}
			var ancestorTarget map[string]bool
			switch in.IntervalMode {
			case "inception":
				ancestorTarget = reachableTo
			case "adoption":
				boundary := ""
				if in.Boundary != nil {
					boundary = *in.Boundary
				}
				if _, ok := parents[boundary]; !ok || !reachableTo[boundary] {
					return ancestryFail("version_bootstrap_boundary_invalid")
				}
				ancestorTarget = ancestryReach(boundary, parents)
			default:
				return ancestryFail("version_bootstrap_interval_mismatch")
			}
			if !ancestorTarget[predCommit] {
				return ancestryFail("version_predecessor_not_ancestor")
			}
			baseCore = m.core
			versionPredecessor = strPtr(b.Predecessor.Tag)
		}
		targetCore = bumpCore(baseCore, *bump)

	case "predecessor", "superseded":
		var selected *VersionSelected
		if in.Authority == "predecessor" {
			selected = in.Predecessor
		} else {
			selected = in.Superseded
		}
		if selected == nil {
			return ancestryFail("version_predecessor_missing")
		}
		if !selected.Accepted {
			return ancestryFail("version_predecessor_not_accepted")
		}
		if in.Authority == "predecessor" && !selected.ChainHead {
			return ancestryFail("version_predecessor_not_chain_head")
		}
		if selected.Repository != in.Repository || selected.Component != in.Component {
			return ancestryFail("version_predecessor_subject_mismatch")
		}
		if selected.TagPrefix != in.TagPrefix {
			return ancestryFail("version_predecessor_component_mismatch")
		}
		if in.IntervalMode != "recurring" {
			return ancestryFail("version_predecessor_interval_mismatch")
		}
		if len(selected.CanonicalTags) != 1 {
			return ancestryFail("version_predecessor_ambiguous")
		}
		canonical := selected.CanonicalTags[0]
		m, reason := bindingParts(&canonical, false, in.TagPrefix, in.Refs)
		if reason != "" {
			return ancestryFail(reason)
		}
		if canonical.CommitOID != selected.To {
			return ancestryFail("version_predecessor_state_mismatch")
		}
		if in.Authority == "predecessor" {
			if !reachableTo[selected.To] || selected.To == in.To {
				return ancestryFail("version_predecessor_not_ancestor")
			}
			if in.Action != "advance" && in.Action != "recut" {
				return ancestryFail("version_action_invalid")
			}
		} else {
			if selected.To != in.To || in.Action != "supersede" {
				return ancestryFail("version_supersession_mismatch")
			}
			sourceSuccessorExists = selected.SourceSuccessorExists
		}

		st := selected.State
		state = &st
		if !semverRe.MatchString(st.TargetCore) {
			return ancestryFail("version_predecessor_state_mismatch")
		}
		if _, ok := bumpRank[st.TargetBump]; !ok {
			return ancestryFail("version_predecessor_state_mismatch")
		}
		if st.CorrectiveFloor != nil {
			if _, ok := bumpRank[*st.CorrectiveFloor]; !ok {
				return ancestryFail("version_predecessor_state_mismatch")
			}
			if bumpRank[*st.CorrectiveFloor] <= bumpRank[st.TargetBump] {
				return ancestryFail("version_predecessor_state_mismatch")
			}
		}
		if len(st.TargetIntervals) == 0 || !distinctNonEmpty(st.TargetIntervals) {
			return ancestryFail("version_predecessor_state_mismatch")
		}
		if st.TargetCore != m.core {
			return ancestryFail("version_predecessor_state_mismatch")
		}
		iterations = map[string]int{}
		for k, v := range st.Iterations {
			iterations[k] = v
		}
		for level, value := range iterations {
			if _, ok := levelRank[level]; !ok || value < 1 {
				return ancestryFail("version_predecessor_state_mismatch")
			}
		}
		if m.level == nil {
			if !st.CleanAccepted {
				return ancestryFail("version_predecessor_state_mismatch")
			}
		} else {
			level := fmt.Sprintf("T%d", *m.level)
			if st.CleanAccepted || iterations[level] != *m.iter {
				return ancestryFail("version_predecessor_state_mismatch")
			}
		}
		if st.Baseline == nil {
			if st.BaselineCore != "0.0.0" {
				return ancestryFail("version_predecessor_state_mismatch")
			}
		} else {
			bm, reason := bindingParts(st.Baseline, false, in.TagPrefix, in.Refs)
			if reason != "" || bm.core != st.BaselineCore {
				if reason == "" {
					reason = "version_predecessor_state_mismatch"
				}
				return ancestryFail(reason)
			}
			if !ancestryReach(selected.To, parents)[st.Baseline.CommitOID] {
				return ancestryFail("version_predecessor_state_mismatch")
			}
		}
		if bumpCore(st.BaselineCore, st.TargetBump) != st.TargetCore {
			return ancestryFail("version_predecessor_state_mismatch")
		}

		versionPredecessor = strPtr(canonical.Tag)
		if in.Action == "recut" {
			if st.CorrectiveFloor != nil {
				return ancestryFail("version_corrective_advance_required")
			}
			if st.CleanAccepted {
				return ancestryFail("recut_clean_target_accepted")
			}
			if bumpRank[*bump] > bumpRank[st.TargetBump] {
				return ancestryFail("recut_target_bump_exceeded")
			}
		}

		carriesTargetLineage := in.Action == "recut" || (in.Action == "advance" && !st.CleanAccepted)
		if carriesTargetLineage {
			priorTargetTrust := fmt.Sprintf("T%d", *m.level)
			if in.TargetReevaluation != nil {
				r := in.TargetReevaluation
				wantIntervals := append(append([]string{}, st.TargetIntervals...), fmt.Sprintf("%s..%s", selected.To, in.To))
				if !r.Authenticated || r.Predecessor != in.FixtureRef ||
					r.TargetCore != st.TargetCore ||
					!equalStrs(r.SourceIntervals, wantIntervals) ||
					r.EffectiveTrust != decisionInputs.EffectiveTrust {
					return ancestryFail("version_target_trust_reevaluation_invalid")
				}
				targetReevaluationConsumed = true
			} else if levelRank[decisionInputs.EffectiveTrust] > levelRank[priorTargetTrust] {
				return ancestryFail("version_target_trust_reevaluation_required")
			}
		}

		switch in.Action {
		case "advance":
			if st.CorrectiveFloor != nil {
				floor := decisionInputs.SemanticFloor
				if bumpRank[*st.CorrectiveFloor] > bumpRank[floor] {
					floor = *st.CorrectiveFloor
				}
				decisionInputs.SemanticFloor = floor
				_, b2 := decisionOutcome(decisionInputs)
				if b2 == nil {
					return ancestryFail("version_escalation_target_unresolved")
				}
				bump = b2
				channel0, _ = decisionOutcome(decisionInputs)
			}
			advanceBump := *bump
			if st.CorrectiveFloor != nil && bumpRank[*st.CorrectiveFloor] > bumpRank[advanceBump] {
				advanceBump = *st.CorrectiveFloor
			}
			targetCore = bumpCore(st.TargetCore, advanceBump)
			iterations = map[string]int{}
			cleanAccepted = false
		case "recut":
			targetCore = st.TargetCore
			cleanAccepted = false
		default: // supersede
			targetCore = st.TargetCore
			cleanAccepted = st.CleanAccepted
		}

	default:
		return ancestryFail("version_authority_unknown")
	}

	if in.TargetReevaluation != nil && !targetReevaluationConsumed {
		return ancestryFail("version_target_trust_reevaluation_invalid")
	}
	if in.RequestedVersionPredecessor != nil && !strEqPtr(in.RequestedVersionPredecessor, versionPredecessor) {
		return ancestryFail("version_predecessor_override")
	}

	channel := channel0
	advancesVersionHead := in.Authority != "superseded" || !sourceSuccessorExists

	if in.Authority == "superseded" && sourceSuccessorExists {
		if in.RequestedIteration != nil {
			return ancestryFail("version_iteration_override")
		}
		return AncestryResult{Outcome: "verified", VersionPredecessor: versionPredecessor, TargetCore: strPtr(targetCore), AdvancesVersionHead: false}
	}
	if in.Authority == "superseded" && bumpRank[*bump] > bumpRank[state.TargetBump] {
		if in.RequestedIteration != nil {
			return ancestryFail("version_iteration_override")
		}
		cf := *bump
		if state.CorrectiveFloor != nil && bumpRank[*state.CorrectiveFloor] > bumpRank[cf] {
			cf = *state.CorrectiveFloor
		}
		return AncestryResult{Outcome: "verified", VersionPredecessor: versionPredecessor, TargetCore: strPtr(targetCore), AdvancesVersionHead: advancesVersionHead, CorrectiveFloor: strPtr(cf)}
	}
	if in.Authority == "superseded" && cleanAccepted && channel == "prerelease" {
		if in.RequestedIteration != nil {
			return ancestryFail("version_iteration_override")
		}
		return AncestryResult{Outcome: "verified", VersionPredecessor: versionPredecessor, TargetCore: strPtr(targetCore), AdvancesVersionHead: advancesVersionHead}
	}

	prefix := ""
	if in.TagPrefix != "" {
		prefix = in.TagPrefix + "/"
	}
	var version *string
	var iteration *int
	if channel == "clean" {
		if !cleanAccepted {
			version = strPtr(fmt.Sprintf("%sv%s", prefix, targetCore))
		}
	} else {
		level := decisionInputs.EffectiveTrust
		it := iterations[level] + 1
		iteration = intPtr(it)
		version = strPtr(fmt.Sprintf("%sv%s-t%d.%d", prefix, targetCore, levelRank[level], it))
	}

	if in.RequestedIteration != nil && (iteration == nil || *in.RequestedIteration != *iteration) {
		return ancestryFail("version_iteration_override")
	}
	if version != nil {
		if _, ok := in.Refs[*version]; ok {
			return ancestryFail("version_output_tag_exists")
		}
	}
	return AncestryResult{
		Outcome: "verified", VersionPredecessor: versionPredecessor,
		TargetCore: strPtr(targetCore), Iteration: iteration, Version: version,
		AdvancesVersionHead: advancesVersionHead,
	}
}

func strEqPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func distinctNonEmpty(xs []string) bool {
	seen := map[string]bool{}
	for _, x := range xs {
		if x == "" || seen[x] {
			return false
		}
		seen[x] = true
	}
	return true
}

func equalStrs(a, b []string) bool {
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
