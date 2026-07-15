// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/policy"
)

func wantSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// TestMetaPolicyFromTree builds a MetaPolicy from a policy that declares all
// three in-tree registries and checks the digest-pinned trust material, the
// role convention + roles↔material bijection, the sha256:-prefixed policy digest,
// and the authorized signers.
func TestMetaPolicyFromTree(t *testing.T) {
	allowedSigners, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	const gpgKeyring = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nplaceholder-hashed-only\n-----END PGP PUBLIC KEY BLOCK-----\n"
	const attSigners = "attester@semver-trust.test ssh-ed25519 AAAAplaceholderhashedonly\n"

	policyTOML := `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
gpg_keyring     = ".semver-trust/gpg-keyring.asc"
`
	repo, rev := repoWithTreeFiles(t, map[string]string{
		".semver-trust/policy.toml":         policyTOML,
		".semver-trust/allowed_signers":     string(allowedSigners),
		".semver-trust/gpg-keyring.asc":     gpgKeyring,
		".semver-trust/attestation_signers": attSigners,
	})
	pol, err := policy.Parse([]byte(policyTOML))
	if err != nil {
		t.Fatal(err)
	}
	mp, err := MetaPolicyFromTree(pol, ".semver-trust/policy.toml", repo, rev)
	if err != nil {
		t.Fatalf("MetaPolicyFromTree: %v", err)
	}

	if mp.Path != ".semver-trust/policy.toml" {
		t.Errorf("path = %q", mp.Path)
	}
	if mp.Digest != "sha256:"+pol.Digest {
		t.Errorf("digest = %q, want sha256:%s (bare-hex Policy.Digest re-prefixed)", mp.Digest, pol.Digest)
	}
	if mp.RequiredLevel != "T2" || len(mp.MetaPaths) != 1 || mp.MetaPaths[0] != ".semver-trust/**" {
		t.Errorf("required level / meta paths = %q / %v", mp.RequiredLevel, mp.MetaPaths)
	}

	wantMaterial := map[string]string{
		".semver-trust/allowed_signers":     wantSHA256(allowedSigners),
		".semver-trust/gpg-keyring.asc":     wantSHA256([]byte(gpgKeyring)),
		".semver-trust/attestation_signers": wantSHA256([]byte(attSigners)),
	}
	if !reflect.DeepEqual(mp.TrustMaterial, wantMaterial) {
		t.Errorf("trust material = %v, want %v", mp.TrustMaterial, wantMaterial)
	}
	wantRoles := map[string]string{
		RoleHumanSigners: ".semver-trust/allowed_signers",
		RoleHumanGPG:     ".semver-trust/gpg-keyring.asc",
		RoleAttesters:    ".semver-trust/attestation_signers",
	}
	if !reflect.DeepEqual(mp.TrustRoles, wantRoles) {
		t.Errorf("trust roles = %v, want %v", mp.TrustRoles, wantRoles)
	}

	// The roles↔material bijection SelectPolicyTransition's trustRolesValid
	// checks: the set of role target paths equals the set of material keys.
	roleVals := map[string]bool{}
	for _, v := range mp.TrustRoles {
		roleVals[v] = true
	}
	matKeys := map[string]bool{}
	for k := range mp.TrustMaterial {
		matKeys[k] = true
	}
	if !reflect.DeepEqual(roleVals, matKeys) {
		t.Errorf("roles↔material is not a bijection: role values %v vs material keys %v", roleVals, matKeys)
	}

	if len(mp.AuthorizedSigners) == 0 {
		t.Error("no authorized signers extracted from the allowed-signers registry")
	}
}

// TestMetaPolicyFromTreeMinimal covers a policy declaring only allowed-signers
// (no gpg/attestation) — a single-registry trust map — and the boundary pointer.
func TestMetaPolicyFromTreeMinimal(t *testing.T) {
	allowedSigners, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	policyTOML := `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
adoption_boundary = "v0-import"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
`
	repo, rev := repoWithTreeFiles(t, map[string]string{
		".semver-trust/policy.toml":     policyTOML,
		".semver-trust/allowed_signers": string(allowedSigners),
	})
	pol, err := policy.Parse([]byte(policyTOML))
	if err != nil {
		t.Fatal(err)
	}
	mp, err := MetaPolicyFromTree(pol, ".semver-trust/policy.toml", repo, rev)
	if err != nil {
		t.Fatalf("MetaPolicyFromTree: %v", err)
	}
	if len(mp.TrustMaterial) != 1 || len(mp.TrustRoles) != 1 {
		t.Errorf("single-registry policy should yield one material/role entry: %v / %v", mp.TrustMaterial, mp.TrustRoles)
	}
	if mp.AdoptionBoundary == nil || *mp.AdoptionBoundary != "v0-import" {
		t.Errorf("adoption boundary = %v, want v0-import", mp.AdoptionBoundary)
	}
}

// TestMetaPolicyFromTreeMissingRegistry fails closed when a policy declares a
// trust-material path absent from the tree.
func TestMetaPolicyFromTreeMissingRegistry(t *testing.T) {
	policyTOML := `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
`
	repo, rev := repoWithTreeFiles(t, map[string]string{
		".semver-trust/policy.toml": policyTOML, // allowed_signers NOT committed
	})
	pol, err := policy.Parse([]byte(policyTOML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MetaPolicyFromTree(pol, ".semver-trust/policy.toml", repo, rev); err == nil {
		t.Error("expected an error for a declared trust-material path missing from the tree")
	}
}
