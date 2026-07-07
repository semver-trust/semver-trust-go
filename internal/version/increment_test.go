// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

// TestReleaseTypeString is the go-semver TestReleaseTypes suite, re-expressed
// for the ported ReleaseType.
func TestReleaseTypeString(t *testing.T) {
	tests := []struct {
		rt   ReleaseType
		want string
	}{
		{major, "major"},
		{minor, "minor"},
		{patch, "patch"},
		{preMajor, "premajor"},
		{preMinor, "preminor"},
		{prePatch, "prepatch"},
		{preRelease, "prerelease"},
		{pre, "pre"},
		{ReleaseType(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.rt.String(); got != tc.want {
			t.Errorf("ReleaseType(%d).String() = %q, want %q", int(tc.rt), got, tc.want)
		}
	}
}

func TestToReleaseType(t *testing.T) {
	tests := []struct {
		in      string
		want    ReleaseType
		wantErr error
	}{
		{"major", major, nil},
		{"  Minor ", minor, nil},
		{"PATCH", patch, nil},
		{"premajor", preMajor, nil},
		{"preminor", preMinor, nil},
		{"prepatch", prePatch, nil},
		{"prerelease", preRelease, nil},
		{"pre", pre, ErrInternalOnlyReleaseType},
		{"nonsense", major, ErrUnknownReleaseType},
	}
	for _, tc := range tests {
		got, err := ToReleaseType(tc.in)
		if err != tc.wantErr {
			t.Errorf("ToReleaseType(%q) err = %v, want %v", tc.in, err, tc.wantErr)
		}
		if tc.wantErr == nil && got != tc.want {
			t.Errorf("ToReleaseType(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestIncrement is the go-semver TestIncrement table, re-expressed against the
// new API. Two faithful adaptations from the original:
//
//   - The original parsed inside Increment and asserted Masterminds'
//     ErrInvalidSemVer for unparseable input. Here parsing is a separate strict
//     step (parseSemver), so those rows assert that parsing rejects the input
//     (wantErr); there is no Masterminds error type to compare.
//   - want strings are bare SemVer (as in the original); the new Version.String
//     renders the canonical tag, so a component-less result is compared against
//     "v"+want.
//
// Every behavioral row from the original — the node-semver settle rules, the
// last-numeric prerelease walk, and the preid counter reset — is preserved.
func TestIncrement(t *testing.T) {
	tests := []struct {
		in      string
		rt      ReleaseType
		preid   string
		want    string
		wantErr bool
	}{
		// --- original block 1: no preid ---
		{"1.2.3", major, "", "2.0.0", false},
		{"1.2.3", minor, "", "1.3.0", false},
		{"1.2.3", patch, "", "1.2.4", false},
		{"1.2.3tag", major, "", "", true},
		{"1.2.3-tag", major, "", "2.0.0", false},
		{"1.2.0-0", patch, "", "1.2.0", false},
		{"1.2.3-4", major, "", "2.0.0", false},
		{"1.2.3-4", minor, "", "1.3.0", false},
		{"1.2.3-4", patch, "", "1.2.3", false},
		{"1.2.3-alpha.0.beta", major, "", "2.0.0", false},
		{"1.2.3-alpha.0.beta", minor, "", "1.3.0", false},
		{"1.2.3-alpha.0.beta", patch, "", "1.2.3", false},
		{"1.2.4", preRelease, "", "1.2.5-0", false},
		{"1.2.3-0", preRelease, "", "1.2.3-1", false},
		{"1.2.3-alpha.0", preRelease, "", "1.2.3-alpha.1", false},
		{"1.2.3-alpha.1", preRelease, "", "1.2.3-alpha.2", false},
		{"1.2.3-alpha.2", preRelease, "", "1.2.3-alpha.3", false},
		{"1.2.3-alpha.0.beta", preRelease, "", "1.2.3-alpha.1.beta", false},
		{"1.2.3-alpha.1.beta", preRelease, "", "1.2.3-alpha.2.beta", false},
		{"1.2.3-alpha.2.beta", preRelease, "", "1.2.3-alpha.3.beta", false},
		{"1.2.3-alpha.10.0.beta", preRelease, "", "1.2.3-alpha.10.1.beta", false},
		{"1.2.3-alpha.10.1.beta", preRelease, "", "1.2.3-alpha.10.2.beta", false},
		{"1.2.3-alpha.10.2.beta", preRelease, "", "1.2.3-alpha.10.3.beta", false},
		{"1.2.3-alpha.10.beta.0", preRelease, "", "1.2.3-alpha.10.beta.1", false},
		{"1.2.3-alpha.10.beta.1", preRelease, "", "1.2.3-alpha.10.beta.2", false},
		{"1.2.3-alpha.10.beta.2", preRelease, "", "1.2.3-alpha.10.beta.3", false},
		{"1.2.3-alpha.9.beta", preRelease, "", "1.2.3-alpha.10.beta", false},
		{"1.2.3-alpha.10.beta", preRelease, "", "1.2.3-alpha.11.beta", false},
		{"1.2.3-alpha.11.beta", preRelease, "", "1.2.3-alpha.12.beta", false},
		{"1.2.0", prePatch, "", "1.2.1-0", false},
		{"1.2.0-1", prePatch, "", "1.2.1-0", false},
		{"1.2.0", preMinor, "", "1.3.0-0", false},
		{"1.2.3-1", preMinor, "", "1.3.0-0", false},
		{"1.2.0", preMajor, "", "2.0.0-0", false},
		{"1.2.3-1", preMajor, "", "2.0.0-0", false},
		{"1.2.0-1", minor, "", "1.2.0", false},
		{"1.0.0-1", major, "", "1.0.0", false},

		// --- original block 2: preid variants and a second unparseable case ---
		{"1.2.3", major, "", "2.0.0", false},
		{"1.2.3", minor, "", "1.3.0", false},
		{"1.2.3", patch, "", "1.2.4", false},
		{"1.2.3tag", major, "", "", true},
		{"1.2.3-tag", major, "", "2.0.0", false},
		{"1.2.0-0", patch, "", "1.2.0", false},
		{"fake", major, "", "", true},
		{"1.2.3-4", major, "", "2.0.0", false},
		{"1.2.3-4", minor, "", "1.3.0", false},
		{"1.2.3-4", patch, "", "1.2.3", false},
		{"1.2.3-alpha.0.beta", major, "", "2.0.0", false},
		{"1.2.3-alpha.0.beta", minor, "", "1.3.0", false},
		{"1.2.3-alpha.0.beta", patch, "", "1.2.3", false},
		{"1.2.4", preRelease, "dev", "1.2.5-dev.0", false},
		{"1.2.3-0", preRelease, "dev", "1.2.3-dev.0", false},
		{"1.2.3-alpha.0", preRelease, "dev", "1.2.3-dev.0", false},
		{"1.2.3-alpha.0", preRelease, "", "1.2.3-alpha.1", false},
		{"1.2.3-alpha.0.beta", preRelease, "dev", "1.2.3-dev.0", false},
		{"1.2.3-alpha.0.beta", preRelease, "", "1.2.3-alpha.1.beta", false},
		{"1.2.3-alpha.10.0.beta", preRelease, "dev", "1.2.3-dev.0", false},
		{"1.2.3-alpha.10.0.beta", preRelease, "", "1.2.3-alpha.10.1.beta", false},
		{"1.2.3-alpha.10.1.beta", preRelease, "", "1.2.3-alpha.10.2.beta", false},
		{"1.2.3-alpha.10.2.beta", preRelease, "", "1.2.3-alpha.10.3.beta", false},
		{"1.2.3-alpha.10.beta.0", preRelease, "dev", "1.2.3-dev.0", false},
		{"1.2.3-alpha.10.beta.0", preRelease, "", "1.2.3-alpha.10.beta.1", false},
		{"1.2.3-alpha.10.beta.1", preRelease, "", "1.2.3-alpha.10.beta.2", false},
		{"1.2.3-alpha.10.beta.2", preRelease, "", "1.2.3-alpha.10.beta.3", false},
		{"1.2.3-alpha.9.beta", preRelease, "dev", "1.2.3-dev.0", false},
		{"1.2.3-alpha.9.beta", preRelease, "", "1.2.3-alpha.10.beta", false},
		{"1.2.3-alpha.10.beta", preRelease, "", "1.2.3-alpha.11.beta", false},
		{"1.2.3-alpha.11.beta", preRelease, "", "1.2.3-alpha.12.beta", false},
		{"1.2.0", prePatch, "dev", "1.2.1-dev.0", false},
		{"1.2.0-1", prePatch, "dev", "1.2.1-dev.0", false},
		{"1.2.0", preMinor, "dev", "1.3.0-dev.0", false},
		{"1.2.3-1", preMinor, "dev", "1.3.0-dev.0", false},
		{"1.2.0", preMajor, "dev", "2.0.0-dev.0", false},
		{"1.2.3-1", preMajor, "dev", "2.0.0-dev.0", false},
		{"1.2.0-1", minor, "dev", "1.2.0", false},
		{"1.0.0-1", major, "dev", "1.0.0", false},
		{"1.2.3-dev.bar", preRelease, "dev", "1.2.3-dev.0", false},
	}

	for _, tc := range tests {
		v, err := parseSemver(tc.in)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("parseSemver(%q): unexpected error: %v", tc.in, err)
			}
			continue
		}

		got, err := Increment(v, tc.rt, tc.preid)
		switch {
		case err != nil && !tc.wantErr:
			t.Errorf("Increment(%q, %s, %q): unexpected error: %v", tc.in, tc.rt, tc.preid, err)
		case err == nil && tc.wantErr:
			t.Errorf("Increment(%q, %s, %q): want error, got %q", tc.in, tc.rt, tc.preid, got)
		case err == nil:
			if gotStr := got.String(); gotStr != "v"+tc.want {
				t.Errorf("Increment(%q, %s, %q) = %q, want %q", tc.in, tc.rt, tc.preid, gotStr, "v"+tc.want)
			}
		}
	}
}

// TestIncrementRejectsTrustVersion verifies the port's guard: node-semver
// increments do not apply to trust versions (§7.2 re-cuts are NextIteration /
// WithLevel).
func TestIncrementRejectsTrustVersion(t *testing.T) {
	v, err := Parse("v1.2.3-t1.1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := Increment(v, patch, ""); err == nil {
		t.Fatal("Increment on a trust version: want error, got nil")
	}
}
