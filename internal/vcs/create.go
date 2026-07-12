// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"fmt"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// CreateTag writes an annotated tag named name at the object target in the
// repository at path, tagged by taggerName/taggerEmail with the given message.
//
// The tagger timestamp is the injected when, never time.Now: verification-shaped
// packages take an injected clock so tagging is deterministic and testable
// (ADR-018, plan §6). The tagger identity is passed in rather than read from
// git config, so the operation needs no ambient environment. path is resolved
// the same way as Tags (see rootPath). For the signed release tag §10 step 9
// requires, see CreateSignedTag (sign.go).
func CreateTag(path, name string, target plumbing.Hash, taggerName, taggerEmail, message string, when time.Time) error {
	apath, err := rootPath(path)
	if err != nil {
		return err
	}

	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return err
	}

	_, err = r.CreateTag(name, target, &git.CreateTagOptions{
		Tagger: &object.Signature{
			Name:  taggerName,
			Email: taggerEmail,
			When:  when,
		},
		Message: message,
	})
	return err
}

// CreateTagAtHead is CreateTag with the repository's current HEAD commit as
// the target — the plain-mode `tag` command's shape, where the tag marks
// whatever the working tree's branch points at. The clock stays injected.
func CreateTagAtHead(path, name, taggerName, taggerEmail, message string, when time.Time) error {
	apath, err := rootPath(path)
	if err != nil {
		return err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return err
	}
	head, err := r.Head()
	if err != nil {
		return err
	}
	return CreateTag(path, name, head.Hash(), taggerName, taggerEmail, message, when)
}

// Tagger resolves the tagger identity from git config (local merged with
// global and system — the same resolution `git tag` uses). It errors when
// user.name or user.email is unset, so a caller can prompt for explicit
// flags instead of writing an anonymous tag. CreateTag itself keeps taking
// the identity injected; this helper is the CLI boundary's resolver.
func Tagger(path string) (name, email string, err error) {
	apath, err := rootPath(path)
	if err != nil {
		return "", "", err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", "", err
	}
	cfg, err := r.ConfigScoped(config.SystemScope)
	if err != nil {
		return "", "", err
	}
	if cfg.User.Name == "" || cfg.User.Email == "" {
		return "", "", fmt.Errorf("git config user.name/user.email not set; set them or pass an explicit tagger")
	}
	return cfg.User.Name, cfg.User.Email, nil
}
