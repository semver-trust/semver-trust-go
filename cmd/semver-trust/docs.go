// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// newDocsCmd builds the hidden `docs` command: it regenerates the Markdown CLI
// reference under docs/cli from the live command tree, so the committed
// reference cannot drift from the flags and help text it documents. It is
// Hidden because it is a maintenance tool for contributors (invoked via the
// `docs:cli` Taskfile target), not part of the user-facing surface — hidden
// commands are also skipped by GenMarkdownTree, so `docs` documents no page of
// its own. Regeneration is manual and CONTRIBUTING notes the step; there is no
// CI drift gate on it.
func newDocsCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:    "docs",
		Short:  "Regenerate the Markdown CLI reference under docs/cli",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root := cmd.Root()
			// Suppress cobra's "Auto generated … on <date>" footer so the
			// committed pages are byte-stable across regenerations.
			root.DisableAutoGenTag = true
			if err := doc.GenMarkdownTree(root, dir); err != nil {
				return err
			}
			// cobra emits each page with a trailing blank line ("…\n\n");
			// normalize every generated page to a single trailing newline so the
			// committed reference carries no whitespace debt (git diff --check).
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
					continue
				}
				p := filepath.Join(dir, e.Name())
				data, rerr := os.ReadFile(p)
				if rerr != nil {
					return rerr
				}
				if trimmed := append(bytes.TrimRight(data, "\n"), '\n'); !bytes.Equal(trimmed, data) {
					if werr := os.WriteFile(p, trimmed, 0o644); werr != nil {
						return werr
					}
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote CLI reference to %s\n", dir)
			return err
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "docs/cli", "output directory for the generated reference")
	return cmd
}
