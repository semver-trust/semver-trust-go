// SPDX-License-Identifier: Apache-2.0

package version

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ReleaseType is an increment level for Increment. Obtain one with
// ToReleaseType; the internal "pre" level is not externally requestable.
type ReleaseType int

const (
	major ReleaseType = iota
	minor
	patch
	preMajor
	preMinor
	prePatch
	preRelease
	pre // internal only: raw pre-release identifier bump
)

var (
	// ErrInternalOnlyReleaseType is returned when the internal "pre" release
	// type is requested through the public surface.
	ErrInternalOnlyReleaseType = errors.New("release type is for internal use only")
	// ErrUnknownReleaseType is returned for an unrecognized release type.
	ErrUnknownReleaseType = errors.New("unknown release type")
)

// String returns the level name ("major", "minor", …).
func (t ReleaseType) String() string {
	names := [...]string{"major", "minor", "patch", "premajor", "preminor", "prepatch", "prerelease", "pre"}
	if t < 0 || int(t) >= len(names) {
		return "unknown"
	}
	return names[t]
}

// ToReleaseType parses a level name into a ReleaseType. The internal "pre" level
// returns ErrInternalOnlyReleaseType; any other unrecognized name returns
// ErrUnknownReleaseType.
func ToReleaseType(s string) (ReleaseType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "major":
		return major, nil
	case "minor":
		return minor, nil
	case "patch":
		return patch, nil
	case "premajor":
		return preMajor, nil
	case "preminor":
		return preMinor, nil
	case "prepatch":
		return prePatch, nil
	case "prerelease":
		return preRelease, nil
	case "pre":
		return pre, ErrInternalOnlyReleaseType
	default:
		return major, ErrUnknownReleaseType
	}
}

// Increment returns v advanced by rt, mimicking npm/node-semver's increment
// semantics. preid seeds the pre-release identifier for the pre* levels (an
// empty preid uses the bare numeric counter).
//
// v must be a plain SemVer version: Increment rejects a trust suffix, since a
// trust re-cut is NextIteration/WithLevel (§7.2), not a node-semver bump. The
// component path is carried through unchanged.
//
// Ported from go-semver's semver.Increment, with two swallowed-error paths from
// the original fixed: the prepatch clear-pre-release path and the switch default
// now return real errors instead of an empty success.
func Increment(v Version, rt ReleaseType, preid string) (Version, error) {
	if v.Trust != nil {
		return Version{}, fmt.Errorf("cannot node-semver-increment trust version %s; use NextIteration or WithLevel", v)
	}

	switch rt {
	case major:
		return settleMajor(v), nil
	case minor:
		return settleMinor(v), nil
	case patch:
		return settlePatch(v), nil
	case preMajor:
		return bumpPre(bumpMajor(v), preid), nil
	case preMinor:
		return bumpPre(bumpMinor(v), preid), nil
	case prePatch:
		// Clear any pre-release, bump patch, then start the pre-release counter.
		base := Version{Component: v.Component, Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1}
		return bumpPre(base, preid), nil
	case preRelease:
		base := v
		if len(v.Pre) == 0 {
			// On a release, prerelease behaves as prepatch: bump patch first.
			base = settlePatch(v)
		}
		return bumpPre(base, preid), nil
	case pre:
		return Version{}, ErrInternalOnlyReleaseType
	default:
		return Version{}, ErrUnknownReleaseType
	}
}

// bumpMajor is node-semver's IncMajor: increment major, zero the rest, drop the
// pre-release.
func bumpMajor(v Version) Version {
	return Version{Component: v.Component, Major: v.Major + 1}
}

// bumpMinor is node-semver's IncMinor: increment minor, zero patch, drop the
// pre-release.
func bumpMinor(v Version) Version {
	return Version{Component: v.Component, Major: v.Major, Minor: v.Minor + 1}
}

// settleMajor increments major, except that a pre-release whose lower fields are
// already zero "settles" onto its release (1.0.0-1 major → 1.0.0).
func settleMajor(v Version) Version {
	if v.Minor != 0 || v.Patch != 0 || len(v.Pre) == 0 {
		return bumpMajor(v)
	}
	return Version{Component: v.Component, Major: v.Major}
}

// settleMinor increments minor, except that a pre-release whose patch is already
// zero settles onto its release (1.2.0-5 minor → 1.2.0).
func settleMinor(v Version) Version {
	if v.Patch != 0 || len(v.Pre) == 0 {
		return bumpMinor(v)
	}
	return Version{Component: v.Component, Major: v.Major, Minor: v.Minor}
}

// settlePatch is node-semver's IncPatch: a pre-release settles onto its release
// without bumping (1.2.3-4 patch → 1.2.3); a release bumps patch.
func settlePatch(v Version) Version {
	if len(v.Pre) > 0 {
		return Version{Component: v.Component, Major: v.Major, Minor: v.Minor, Patch: v.Patch}
	}
	return Version{Component: v.Component, Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1}
}

// bumpPre applies the internal "pre" level: increment the last numeric
// identifier (appending "0" when none is numeric), then apply preid — a changed
// preid resets the counter to <preid>.0, a matching one keeps the incremented
// counter.
func bumpPre(v Version, preid string) Version {
	prerelease := append([]string(nil), v.Pre...)

	if len(prerelease) == 0 {
		prerelease = []string{"0"}
	} else {
		bumped := false
		for i := len(prerelease) - 1; i >= 0; i-- {
			if n, err := strconv.Atoi(prerelease[i]); err == nil {
				prerelease[i] = strconv.Itoa(n + 1)
				bumped = true
				break
			}
		}
		if !bumped {
			prerelease = append(prerelease, "0")
		}
	}

	if preid != "" {
		if len(prerelease) >= 2 && preid == prerelease[0] {
			// Same preid: keep the counter unless the second field is
			// non-numeric, in which case restart it.
			if _, err := strconv.Atoi(prerelease[1]); err != nil {
				prerelease = []string{preid, "0"}
			}
		} else {
			prerelease = []string{preid, "0"}
		}
	}

	return Version{
		Component: v.Component,
		Major:     v.Major,
		Minor:     v.Minor,
		Patch:     v.Patch,
		Pre:       prerelease,
	}
}
