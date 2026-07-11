// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// plainFixtures builds the internal/vcs fixture repositories (the donor tag
// set, including the deliberately invalid 0.1.0-alpha.01) into a temp dir and
// returns the two repo paths. Neither repository has a policy.toml — every
// test here is therefore also the zero-configuration acceptance: plain-mode
// commands must work in a repo with no policy.
func plainFixtures(t *testing.T) (noTags, tagged string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	script := filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", "build-fixtures.sh")
	dest := t.TempDir()
	if out, err := exec.Command("bash", script, dest).CombinedOutput(); err != nil {
		t.Fatalf("build-fixtures.sh failed: %v\n%s", err, out)
	}
	return filepath.Join(dest, "no-tags"), filepath.Join(dest, "tagged")
}

// list shows every tag: coerced forms in donor precedence order, and the
// invalid 0.1.0-alpha.01 flagged with its reason instead of silently dropped.
func TestListLenient(t *testing.T) {
	_, tagged := plainFixtures(t)
	stdout, _, err := runRoot(t, "list", "--repo", tagged)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("list printed %d lines, want 6:\n%s", len(lines), stdout)
	}
	// Valid entries ascending by precedence, invalid last.
	wantOrder := []string{
		"0.0.1", "0.0.2", "0.1.0-alpha.0.beta", "0.1.0", "0.1.1-beta.0", "-",
	}
	for i, want := range wantOrder {
		if got := strings.Fields(lines[i])[0]; got != want {
			t.Errorf("line %d starts with %q, want %q\n%s", i, got, want, stdout)
		}
	}
	// Coercion is flagged; §7.1-valid tags are not. Compare with runs of
	// tabwriter padding collapsed.
	squeezed := strings.Join(strings.Fields(stdout), " ")
	for _, want := range []string{
		"0.0.2 0.0.2 coerced",
		"invalid:",
		"0.1.0-alpha.01",
	} {
		if !strings.Contains(squeezed, want) {
			t.Errorf("list output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(lines[0], "coerced") {
		t.Errorf("v0.0.1 is §7.1-valid and must not be flagged coerced: %q", lines[0])
	}
}

// --strict keeps only §7.1-valid tags, in canonical tag form with their
// grammar outcome, and surfaces the rejected count on stderr.
func TestListStrict(t *testing.T) {
	_, tagged := plainFixtures(t)
	stdout, stderr, err := runRoot(t, "list", "--repo", tagged, "--strict")
	if err != nil {
		t.Fatalf("list --strict: %v", err)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("strict list printed %d lines, want 2:\n%s", len(lines), stdout)
	}
	if !strings.HasPrefix(lines[0], "v0.0.1") || !strings.HasPrefix(lines[1], "v0.1.0") {
		t.Errorf("strict list = %q, want v0.0.1 then v0.1.0", lines)
	}
	if !strings.Contains(stdout, "trust_version") {
		t.Errorf("strict list should name the grammar outcome:\n%s", stdout)
	}
	if !strings.Contains(stderr, "4 invalid tag(s) ignored") {
		t.Errorf("stderr = %q, want the rejected count (audit §5.2)", stderr)
	}
}

// latest is the lenient-valid precedence maximum, with the invalid tag
// counted on stderr — never silently.
func TestLatestCommand(t *testing.T) {
	_, tagged := plainFixtures(t)
	stdout, stderr, err := runRoot(t, "latest", "--repo", tagged)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "0.1.1-beta.0" {
		t.Errorf("latest = %q, want %q", got, "0.1.1-beta.0")
	}
	if !strings.Contains(stderr, "1 invalid tag(s) ignored") {
		t.Errorf("stderr = %q, want the rejected count", stderr)
	}
}

func TestLatestNoVersionsErrors(t *testing.T) {
	noTags, _ := plainFixtures(t)
	if _, _, err := runRoot(t, "latest", "--repo", noTags); err == nil {
		t.Error("latest on a tagless repo succeeded, want an error")
	}
}

// next: donor increment semantics over the fixture set, plus the donor
// anchors for the bootstrap (`-i -d` on a tagless repo -> 0.0.1).
func TestNextCommand(t *testing.T) {
	noTags, tagged := plainFixtures(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default patch settles the beta", []string{"next", "--repo", tagged}, "0.1.1"},
		{"prerelease walks the counter", []string{"next", "--repo", tagged, "-i=prerelease", "--preid=beta"}, "0.1.1-beta.1"},
		{"donor anchor: tagless -i -d", []string{"next", "--repo", noTags, "-i", "-d"}, "0.0.1"},
		{"tagless bootstraps without -d", []string{"next", "--repo", noTags}, "0.0.1"},
		{"-d seeds a candidate that wins", []string{"next", "--repo", noTags, "-d=1.2", "-i=preminor", "--preid=rc"}, "1.3.0-rc.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runRoot(t, tc.args...)
			if err != nil {
				t.Fatalf("%v: %v", tc.args, err)
			}
			if got := strings.TrimSpace(stdout); got != tc.want {
				t.Errorf("%v = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// tag without a name computes next (bootstrap here) and writes the §7.1
// canonical v-prefixed form; the created tag round-trips through list.
func TestTagComputedNext(t *testing.T) {
	noTags, _ := plainFixtures(t)
	stdout, _, err := runRoot(t, "tag", "--repo", noTags,
		"--tagger-name", "Fixture Tagger", "--tagger-email", "tagger@semver-trust.test")
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "v0.0.1" {
		t.Errorf("tag printed %q, want %q", got, "v0.0.1")
	}

	stdout, _, err = runRoot(t, "list", "--repo", noTags, "--strict")
	if err != nil {
		t.Fatalf("list after tag: %v", err)
	}
	if !strings.Contains(stdout, "v0.0.1") {
		t.Errorf("created tag missing from strict list:\n%s", stdout)
	}
}

// tag with an explicit name accepts §7.1-valid and donor-lenient names
// verbatim, and refuses malformed trust shapes and garbage (§7.1 fail-closed).
func TestTagExplicitName(t *testing.T) {
	tagger := []string{"--tagger-name", "Fixture Tagger", "--tagger-email", "tagger@semver-trust.test"}

	t.Run("lenient name is created verbatim", func(t *testing.T) {
		noTags, _ := plainFixtures(t)
		args := append([]string{"tag", "2.1", "--repo", noTags}, tagger...)
		stdout, _, err := runRoot(t, args...)
		if err != nil {
			t.Fatalf("tag 2.1: %v", err)
		}
		if got := strings.TrimSpace(stdout); got != "2.1" {
			t.Errorf("tag printed %q, want the verbatim name %q", got, "2.1")
		}
	})

	t.Run("trust-suffixed strict name is allowed", func(t *testing.T) {
		noTags, _ := plainFixtures(t)
		args := append([]string{"tag", "v1.0.0-t2.1", "--repo", noTags}, tagger...)
		if _, _, err := runRoot(t, args...); err != nil {
			t.Fatalf("tag v1.0.0-t2.1: %v", err)
		}
	})

	for _, bad := range []string{"v1.0.0-t10.1", "v1.0.0-t1.0", "4.x", "1.0-t2.1"} {
		t.Run("refuses "+bad, func(t *testing.T) {
			noTags, _ := plainFixtures(t)
			args := append([]string{"tag", bad, "--repo", noTags}, tagger...)
			if _, _, err := runRoot(t, args...); err == nil {
				t.Errorf("tag %q succeeded, want refusal", bad)
			}
		})
	}
}

// next fails closed when the newest tag is trust-suffixed: the error points
// at the release operations instead of skipping or bumping the trust tag.
func TestNextRefusesTrustLatestE2E(t *testing.T) {
	_, tagged := plainFixtures(t)
	args := []string{"tag", "v1.0.0-t2.1", "--repo", tagged,
		"--tagger-name", "Fixture Tagger", "--tagger-email", "tagger@semver-trust.test"}
	if _, _, err := runRoot(t, args...); err != nil {
		t.Fatalf("creating trust tag: %v", err)
	}

	// The trust tag participates in latest selection...
	stdout, _, err := runRoot(t, "latest", "--repo", tagged)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "1.0.0-t2.1" {
		t.Errorf("latest = %q, want the trust tag 1.0.0-t2.1", got)
	}

	// ...but next refuses to node-semver-bump it.
	_, _, err = runRoot(t, "next", "--repo", tagged)
	if err == nil {
		t.Fatal("next on a trust-suffixed latest succeeded, want refusal")
	}
	if !strings.Contains(err.Error(), "trust suffix") {
		t.Errorf("error = %q, want it to name the trust suffix", err)
	}
}
