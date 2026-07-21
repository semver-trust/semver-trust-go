// SPDX-License-Identifier: Apache-2.0

package sshsig

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// FormatEnrollmentLine formats the byte-exact allowed-signers registry line that
// enrolls pub for principal under the given signature namespace — "git" for
// commit signing (vcs.GitSSHNamespace), "attestation@semver-trust.dev" for
// attestations (attest.Namespace). It is the writer counterpart to
// parseAllowedSignerLine: the produced line parses back through
// ParseAllowedSigners unchanged.
//
// It is consumed by the bootstrap-family tooling (enroll/doctor): the tool prints
// this line and the human commits it — the enrollment is the accountability act,
// never performed by the tool (ADR-038).
func FormatEnrollmentLine(principal, namespace string, pub ssh.PublicKey) (string, error) {
	switch {
	case principal == "":
		return "", fmt.Errorf("sshsig: enrollment line needs a principal")
	case namespace == "":
		return "", fmt.Errorf("sshsig: enrollment line needs a namespace")
	case pub == nil:
		return "", fmt.Errorf("sshsig: enrollment line needs a public key")
	}
	// ssh.MarshalAuthorizedKey emits "<type> <base64>\n"; the enrollment line
	// prepends the principal and the purpose-binding namespaces= option.
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	return fmt.Sprintf("%s namespaces=%q %s", principal, namespace, key), nil
}
