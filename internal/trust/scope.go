// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DefaultScope is the implicit scope for paths matching no scope glob (§5.1).
const DefaultScope = "default"

// Commit is the aggregation-facing view of a verified commit: its assigned
// level (§3.2, via Classify), its diff paths, and any verified derivation
// re-leveling (§4.4). A commit that could not be verified end-to-end never
// becomes a Commit — verification aborts instead (unverifiable ≠ T0, §5.2).
type Commit struct {
	ID    string
	Level Level
	Paths []string

	// Derivation carries the §4.4 re-leveling facts, or nil when the commit
	// is not covered by a derivation rule.
	Derivation *DerivationFacts
}

// DerivationFacts records the outcome of running a §4.4 derivation rule
// against the tree: whether the regenerated outputs were byte-identical, and
// the inputs' floor the output paths inherit when they were. The proof is
// reproducibility, not identity — who ran the generator is irrelevant.
type DerivationFacts struct {
	// Outputs are the rule's declared output globs.
	Outputs []string
	// Verified reports byte-identical regeneration; a failed proof is void
	// and the commit's own level applies everywhere.
	Verified bool
	// InheritedLevel is the minimum trust level of the rule's input paths as
	// of the same tree (§4.4), computed by the derivation runner.
	InheritedLevel Level
}

// pathLevel is the level a single path contributes (§5.2): the inherited
// level for a verified derivation's declared outputs, the commit's own level
// for everything else — including every path of a commit whose proof failed,
// and any path smuggled alongside the declared outputs.
func (c Commit) pathLevel(path string, globs map[string]*regexp.Regexp) Level {
	d := c.Derivation
	if d == nil || !d.Verified {
		return c.Level
	}
	for _, out := range d.Outputs {
		if globs[out].MatchString(path) {
			return d.InheritedLevel
		}
	}
	return c.Level
}

// compileGlobs compiles gitignore-style scope globs (§5.1, conformance
// README): '*' matches within a path segment, '**' across segments, '?' a
// single non-separator character. Matching is segment-aware on purpose —
// services/auth/** must not match services/authz/….
func compileGlobs(patterns []string) (map[string]*regexp.Regexp, error) {
	compiled := make(map[string]*regexp.Regexp, len(patterns))
	for _, p := range patterns {
		if _, ok := compiled[p]; ok {
			continue
		}
		rx, err := compileGlob(p)
		if err != nil {
			return nil, err
		}
		compiled[p] = rx
	}
	return compiled, nil
}

// MatchGlob reports whether a §5.1-style glob matches a slash-separated
// path — the same segment-aware semantics scope partitioning uses, exported
// for the derivation runner's input/output path matching (§4.4).
func MatchGlob(pattern, path string) (bool, error) {
	rx, err := compileGlob(pattern)
	if err != nil {
		return false, err
	}
	return rx.MatchString(path), nil
}

func compileGlob(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty path glob")
	}
	var sb strings.Builder
	sb.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**"):
			sb.WriteString(".*")
			i++
		case pattern[i] == '*':
			sb.WriteString("[^/]*")
		case pattern[i] == '?':
			sb.WriteString("[^/]")
		default:
			sb.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	sb.WriteByte('$')
	return regexp.Compile(sb.String())
}

// scopeGlobs returns the compiled glob set for a scope map plus any
// derivation output globs carried by the commits.
func scopeGlobs(scopes map[string]string, commits []Commit) (map[string]*regexp.Regexp, error) {
	patterns := make([]string, 0, len(scopes))
	for glob := range scopes {
		patterns = append(patterns, glob)
	}
	for _, c := range commits {
		if c.Derivation != nil {
			patterns = append(patterns, c.Derivation.Outputs...)
		}
	}
	return compileGlobs(patterns)
}

// scopesOf returns the scopes a path falls into: every scope whose glob
// matches, or DefaultScope when none do (§5.1).
func scopesOf(path string, scopes map[string]string, globs map[string]*regexp.Regexp) []string {
	var touched []string
	for glob, name := range scopes {
		if globs[glob].MatchString(path) {
			touched = append(touched, name)
		}
	}
	if touched == nil {
		return []string{DefaultScope}
	}
	return touched
}

// PartitionScopes partitions commits by scope (§5.1): a commit touches a
// scope if any path in its diff matches the scope's globs, and a commit
// touching several scopes appears under each. The returned lists preserve
// commit order. Scoping keys off diff paths — objective ground truth from
// git — never off declared intent.
func PartitionScopes(scopes map[string]string, commits []Commit) (map[string][]string, error) {
	globs, err := scopeGlobs(scopes, nil)
	if err != nil {
		return nil, err
	}
	partition := map[string][]string{}
	for _, c := range commits {
		touched := map[string]bool{}
		for _, path := range c.Paths {
			for _, scope := range scopesOf(path, scopes, globs) {
				touched[scope] = true
			}
		}
		names := make([]string, 0, len(touched))
		for scope := range touched {
			names = append(names, scope)
		}
		sort.Strings(names)
		for _, scope := range names {
			partition[scope] = append(partition[scope], c.ID)
		}
	}
	return partition, nil
}

// ScopeFloors computes own trust per touched scope (§5.2): the minimum over
// the levels contributed by every path of every commit touching the scope,
// after §4.4 derivation re-leveling. There is no de-minimis exception — a
// one-line T0 commit floors its scope exactly like a thousand-line one; the
// only sanctioned exception is a verified derivation proof.
func ScopeFloors(scopes map[string]string, commits []Commit) (map[string]Level, error) {
	globs, err := scopeGlobs(scopes, commits)
	if err != nil {
		return nil, err
	}
	floors := map[string]Level{}
	for _, c := range commits {
		for _, path := range c.Paths {
			level := c.pathLevel(path, globs)
			for _, scope := range scopesOf(path, scopes, globs) {
				if current, ok := floors[scope]; !ok || level < current {
					floors[scope] = level
				}
			}
		}
	}
	return floors, nil
}

// MetaPathViolations returns, in commit order, the commits touching a
// declared meta-path below the required level (§5.4). Any violation means
// the release range MUST fail verification outright — not demote, fail; the
// abort belongs to the verification pipeline (§10 step 1), which treats a
// non-empty result as fatal.
func MetaPathViolations(metaPaths []string, required Level, commits []Commit) ([]string, error) {
	globs, err := compileGlobs(metaPaths)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, c := range commits {
		if c.Level >= required {
			continue
		}
		for _, path := range c.Paths {
			if matchesAny(path, metaPaths, globs) {
				violations = append(violations, c.ID)
				break
			}
		}
	}
	return violations, nil
}

func matchesAny(path string, patterns []string, globs map[string]*regexp.Regexp) bool {
	for _, p := range patterns {
		if globs[p].MatchString(path) {
			return true
		}
	}
	return false
}
