// SPDX-License-Identifier: Apache-2.0

package pathfence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".semver-trust"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".semver-trust", "allowed_signers"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink whose target escapes the repo, and a symlinked directory.
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "evil")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link-dir")); err != nil {
		t.Fatal(err)
	}

	t.Run("ok", func(t *testing.T) {
		// An existing in-repo file and a not-yet-created in-repo path both resolve.
		for _, p := range []string{".semver-trust/allowed_signers", ".semver-trust/gpg-keyring.asc"} {
			got, err := Resolve(root, p)
			if err != nil {
				t.Errorf("Resolve(%q) = %v, want ok", p, err)
			}
			if want := filepath.Join(root, p); got != want {
				t.Errorf("Resolve(%q) = %q, want %q", p, got, want)
			}
		}
	})

	t.Run("refused", func(t *testing.T) {
		for _, p := range []string{
			"/etc/passwd",                       // absolute
			"../../.ssh/authorized_keys",        // .. escape
			".semver-trust/../../../etc/passwd", // .. escape mid-path
			"evil",                              // symlink leaf
			"link-dir/registry",                 // symlink in the middle
			"",                                  // empty
		} {
			if _, err := Resolve(root, p); err == nil {
				t.Errorf("Resolve(%q) = ok, want refusal", p)
			}
		}
	})
}
