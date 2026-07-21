// SPDX-License-Identifier: Apache-2.0

// Package pathfence validates policy-named paths (registries, the policy file,
// the keyring) before a bootstrap-family command reads or writes them on the
// filesystem. It is reject-don't-sanitize, mirroring attest.validSubject: an
// absolute path, a ".." component, or a symlink anywhere along the path is
// refused, never clamped (ADR-039). This fences the traversal surface that opens
// the moment a command touches a policy-named path in the working tree instead of
// reading it from a git tree — a hostile repo declaring
// allowed_signers = "../../.ssh/authorized_keys" (or an in-repo symlink escaping
// the tree) must be refused, not followed. filepath-securejoin is deliberately
// NOT used: it clamps symlinks into root rather than refusing them.
package pathfence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolve validates that relPath stays inside repoRoot and returns its absolute
// path. relPath must be repo-relative (not absolute), must contain no ".."
// component, and must not traverse a symlink at any existing level.
func Resolve(repoRoot, relPath string) (string, error) {
	if relPath == "" {
		return "", errors.New("pathfence: empty path")
	}
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("pathfence: %q is absolute; policy-named paths are repo-relative", relPath)
	}
	clean := filepath.Clean(relPath)
	sep := string(filepath.Separator)
	for _, part := range strings.Split(clean, sep) {
		if part == ".." {
			return "", fmt.Errorf("pathfence: %q escapes the repository (\"..\" component)", relPath)
		}
	}
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", err
	}
	// Walk each component from the root, refusing a symlink at any level (a
	// symlink can redirect the final read/write outside the repo) and refusing
	// any lexical escape.
	cur := root
	for _, part := range strings.Split(clean, sep) {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		if !within(root, cur) {
			return "", fmt.Errorf("pathfence: %q escapes the repository", relPath)
		}
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				continue // a not-yet-created component has nothing to traverse
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("pathfence: %q traverses a symlink at %q; refusing", relPath, cur)
		}
	}
	return filepath.Join(root, clean), nil
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
