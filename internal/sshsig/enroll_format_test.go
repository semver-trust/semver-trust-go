// SPDX-License-Identifier: Apache-2.0

package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestFormatEnrollmentLine pins the byte-exact registry line the formatter emits
// and confirms it round-trips through the verifier's own strict parser — the
// fail-closed-writer property (ADR-039): the tool never prints a line it would
// itself reject.
func TestFormatEnrollmentLine(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	marshaled := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	for _, ns := range []string{"git", "attestation@semver-trust.dev"} {
		t.Run(ns, func(t *testing.T) {
			line, err := FormatEnrollmentLine("alex@example.com", ns, pub)
			if err != nil {
				t.Fatalf("FormatEnrollmentLine: %v", err)
			}
			want := `alex@example.com namespaces="` + ns + `" ` + marshaled
			if line != want {
				t.Errorf("line =\n  %q\nwant\n  %q", line, want)
			}
			signers, err := ParseAllowedSigners([]byte(line + "\n"))
			if err != nil {
				t.Fatalf("ParseAllowedSigners(formatted): %v", err)
			}
			if len(signers) != 1 {
				t.Fatalf("parsed %d signers, want 1", len(signers))
			}
			if got := signers[0].Principals; len(got) != 1 || got[0] != "alex@example.com" {
				t.Errorf("principals = %v, want [alex@example.com]", got)
			}
		})
	}

	if _, err := FormatEnrollmentLine("", "git", pub); err == nil {
		t.Error("empty principal: want error")
	}
	if _, err := FormatEnrollmentLine("alex@example.com", "", pub); err == nil {
		t.Error("empty namespace: want error")
	}
	if _, err := FormatEnrollmentLine("alex@example.com", "git", nil); err == nil {
		t.Error("nil key: want error")
	}
}
