// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/gitconfig"
	"github.com/semver-trust/semver-trust-go/internal/pathfence"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/setup"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// newSetupCmd is the `setup` subcommand: it configures THIS clone's git for
// semver-trust and nothing else — repo-local .git/config keys through the git binary
// (ADR-042), never --global, never the working tree, never a hook (the committed
// .githooks/commit-msg + a printed core.hooksPath line do that). It obeys the ADR-039
// writer contract: all-or-nothing conflicts, --dry-run mutates nothing and prints the
// exact git config commands, and every run ends with a reversal receipt.
func newSetupCmd() *cobra.Command {
	var (
		repoPath   string
		remote     string
		signingKey string
		gpgKey     string
		policyPath string
		force      bool
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Configure this clone's git for semver-trust (repo-local config only)",
		Long: `setup writes only this clone's repo-local git configuration — gpg.format,
user.signingkey, commit.gpgsign, commit.template (if .gitmessage exists),
gpg.ssh.allowedSignersFile (SSH mode), and an attestation fetch refspec — through the
git binary (ADR-042). It never writes --global, the working tree, a push refspec, or
a hook: the committed .githooks/commit-msg plus a one-time 'git config core.hooksPath
.githooks' do the hook job without the trust tool writing executable code.

It is all-or-nothing (ADR-039): any key already set to a different value fails the run
listing every conflict, writing nothing. --force overwrites, except user.signingkey,
which is never overwritten by a flag. --dry-run changes nothing and prints the exact
git config commands. Every run ends by printing the commands that reverse it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if remote == "" {
				remote = "origin"
			}
			cfg, err := gitconfig.Load(repoPath)
			if err != nil {
				return err
			}
			git := gitconfig.Git{Path: cfg.GitPath, Repo: repoPath}

			// Gather the injected facts the pure planner runs against.
			currents, err := setup.ReadCurrents(git)
			if err != nil {
				return fmt.Errorf("setup: reading current config: %w", err)
			}
			remoteURL, err := git.RemoteURL(remote)
			if err != nil {
				return fmt.Errorf("setup: reading remote %q: %w", remote, err)
			}
			fetchRefspecs, err := git.FetchRefspecs(remote)
			if err != nil {
				return fmt.Errorf("setup: reading remote %q fetch: %w", remote, err)
			}
			pol := loadSetupPolicy(repoPath, policyPath) // optional; nil if absent/unparseable

			env := setup.Env{
				Config:              cfg,
				Policy:              pol,
				Current:             currents,
				SigningKey:          signingKey,
				GPGSigningKey:       gpgKey,
				Remote:              remote,
				RemoteURL:           remoteURL,
				RemoteFetchRefspecs: fetchRefspecs,
				GitmessageExists:    fileExists(repoPath, ".gitmessage"),
				Force:               force,
				Euid:                os.Geteuid(),
				GitDirEnv:           os.Getenv("GIT_DIR") != "",
				GitConfigEnv:        gitConfigEnvSet(),
			}

			// SSH mode: fingerprint the offered key (for the ADR-022 cross-check) and
			// resolve the allowed-signers registry to wire.
			if signingKey != "" {
				pub, perr := readPubKey(expandTilde(signingKey))
				if perr != nil {
					return fmt.Errorf("--signing-key %q: %w", signingKey, perr)
				}
				env.SigningKeyFingerprint = ssh.FingerprintSHA256(pub)
				env.AllowedSignersPath, env.AllowedSignersExists = resolveAllowedSigners(repoPath, pol)
			}
			env.AttestationSignersDeclared, env.AttestationFingerprints, env.AttestationReadErr = attestationFacts(repoPath, pol)

			plan, err := setup.Compute(env)
			if err != nil {
				return err // a refusal — cobra prints it, main exits 1
			}

			return renderSetup(cmd, env, plan, dryRun, git)
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository to configure")
	f.StringVar(&remote, "remote", "origin", "remote to configure the attestation fetch refspec on")
	f.StringVar(&signingKey, "signing-key", "", "path to an SSH public key to sign commits with")
	f.StringVar(&gpgKey, "gpg-signing-key", "", "a GPG key id to sign commits with")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within the repository")
	f.BoolVar(&force, "force", false, "overwrite conflicting config (never user.signingkey)")
	f.BoolVar(&dryRun, "dry-run", false, "print the git config commands; change nothing")
	return cmd
}

// renderSetup writes the environment echo, the plan, and either the dry-run commands
// or the applied receipt.
func renderSetup(cmd *cobra.Command, env setup.Env, plan *setup.Plan, dryRun bool, git gitconfig.Git) error {
	w := &errWriter{w: cmd.OutOrStdout()}

	// The environment echo is the FIRST line of every run (dry-run included) — the
	// audit trail: which repo, which gitdir, which git binary (PATH-hijack surface),
	// and which remote/URL (SU-8).
	url := env.RemoteURL
	if url == "" {
		url = "(no url)"
	}
	w.printf("setup: repo %s  gitdir %s  git %s  remote %s (%s)\n",
		orDot(env.Config.TopLevel), orDot(env.Config.GitDir), env.Config.GitPath, env.Remote, url)

	if isLinkedWorktree(env.Config) {
		w.printf("note: linked worktree — repo-local config is shared across all worktrees of this repository\n")
	}
	for _, warn := range plan.Warnings {
		w.printf("warn: %s\n", warn)
	}

	w.printf("\n")
	for _, c := range plan.Changes {
		switch c.Action {
		case setup.ActionForced:
			w.printf("  %-8s %s = %s  (was %s)\n", "force", c.Key, c.Desired, c.Current)
		default:
			w.printf("  %-8s %s = %s\n", c.Action, c.Key, c.Desired)
		}
	}
	if plan.Fetch != nil {
		if plan.Fetch.Already {
			w.printf("  %-8s remote.%s.fetch %s\n", setup.ActionOK, plan.Fetch.Remote, plan.Fetch.Refspec)
		} else {
			w.printf("  %-8s remote.%s.fetch += %s\n", "add", plan.Fetch.Remote, plan.Fetch.Refspec)
		}
	}

	if dryRun {
		w.printf("\n--dry-run: nothing was changed. these are the exact commands to run:\n")
		for _, line := range plan.GitCommands() {
			w.printf("  %s\n", line)
		}
		if len(plan.GitCommands()) == 0 {
			w.printf("  (already fully configured — nothing to do)\n")
		}
		return w.err
	}

	if err := plan.Apply(git); err != nil {
		return err
	}
	rev := plan.ReverseCommands()
	if len(rev) == 0 {
		w.printf("\nalready fully configured — nothing to change.\n")
		return w.err
	}
	w.printf("\napplied. to reverse this setup:\n")
	for _, line := range rev {
		w.printf("  %s\n", line)
	}
	return w.err
}

// loadSetupPolicy fences + parses the working-tree policy; setup does not require one
// (it configures git, not trust material), so any failure yields nil — the policy
// only informs the allowed-signers path and the ADR-022 cross-check.
func loadSetupPolicy(repo, policyPath string) *policy.Policy {
	abs, err := pathfence.Resolve(repo, policyPath)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil
	}
	pol, err := policy.Parse(data)
	if err != nil {
		return nil
	}
	return pol
}

// resolveAllowedSigners returns the allowed-signers registry path to wire into
// gpg.ssh.allowedSignersFile (from the policy, else the convention) and whether that
// file exists — it is set only when present (SSH mode).
func resolveAllowedSigners(repo string, pol *policy.Policy) (path string, exists bool) {
	path = ".semver-trust/allowed_signers"
	if pol != nil && pol.Identity.Human.AllowedSigners != "" {
		path = pol.Identity.Human.AllowedSigners
	}
	return path, fileExists(repo, path)
}

// attestationFacts reports whether the policy declares attestation_signers, the
// SHA256 fingerprints enrolled there, and any read error (a declared-but-unreadable
// registry fails closed in the planner's ADR-022 cross-check).
func attestationFacts(repo string, pol *policy.Policy) (declared bool, fps []string, readErr error) {
	if pol == nil || pol.Identity.AttestationSigners == "" {
		return false, nil, nil
	}
	abs, err := pathfence.Resolve(repo, pol.Identity.AttestationSigners)
	if err != nil {
		return true, nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return true, nil, err
	}
	signers, err := sshsig.ParseAllowedSigners(data)
	if err != nil {
		return true, nil, err
	}
	for _, s := range signers {
		if s.Key != nil {
			fps = append(fps, ssh.FingerprintSHA256(s.Key))
		}
	}
	return true, fps, nil
}

// gitConfigEnvSet reports whether any GIT_CONFIG* variable is set — these redirect
// git config to an ambiguous target, so setup refuses to write under them (SU-7).
func gitConfigEnvSet() bool {
	for _, k := range []string{"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// isLinkedWorktree reports whether the clone is a linked worktree, where a repo-local
// config write is shared across all worktrees — worth disclosing. A linked worktree's
// git-dir lives under the main repository's .git/worktrees/.
func isLinkedWorktree(cfg *gitconfig.Config) bool {
	return strings.Contains(filepath.ToSlash(cfg.GitDir), "/worktrees/")
}

func fileExists(repo, rel string) bool {
	info, err := os.Stat(filepath.Join(repo, rel))
	return err == nil && !info.IsDir()
}

// expandTilde expands a leading ~ in a user-supplied key path (the shell usually does
// this, but a quoted path reaches us literally).
func expandTilde(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
		}
	}
	return path
}

func orDot(s string) string {
	if s == "" {
		return "."
	}
	return s
}
