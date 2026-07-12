// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

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
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "wrote CLI reference to %s\n", dir)
			return err
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "docs/cli", "output directory for the generated reference")
	return cmd
}
