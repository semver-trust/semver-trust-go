// SPDX-License-Identifier: Apache-2.0

package source

import "testing"

const seCommitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// seBase is a valid trusted-issuer profile: one fresh statement whose issuer,
// resource, subject, and digest algorithm all match.
func seBase() EvidenceInputs {
	return EvidenceInputs{
		Mode:                    "trusted_issuer",
		Repository:              "git+https://github.com/acme/auth",
		ReleaseTo:               map[string]string{"gitCommit": seCommitA},
		AllowedDigestAlgorithms: []string{"gitCommit"},
		TrustedIssuers:          []string{"scs:github:acme"},
		Evidence: []Statement{{
			Issuer: "scs:github:acme", ResourceURI: "git+https://github.com/acme/auth",
			Subject: map[string]string{"gitCommit": seCommitA},
			VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"}, Fresh: true, Replayed: true,
		}},
	}
}

// TestSelectSourceEvidenceOracleSurface pins every ADR-035 reject reason,
// including missing_evidence (which the vendored vectors do not exercise) and
// the digest-before-subject gate order, so the port mirrors the oracle's full
// decision surface.
func TestSelectSourceEvidenceOracleSurface(t *testing.T) {
	if ok, r := SelectSourceEvidence(seBase()); !ok || r != "" {
		t.Fatalf("base = (%v,%q), want accepted", ok, r)
	}

	cases := []struct {
		name string
		in   func() EvidenceInputs
		want string
	}{
		{"no evidence", func() EvidenceInputs { in := seBase(); in.Evidence = nil; return in }, "missing_evidence"},
		{"untrusted issuer", func() EvidenceInputs { in := seBase(); in.Evidence[0].Issuer = "scs:github:evil"; return in }, "unauthorized_issuer"},
		{"resource mismatch", func() EvidenceInputs {
			in := seBase()
			in.Evidence[0].ResourceURI = "git+https://github.com/acme/other"
			return in
		}, "resource_mismatch"},
		{"disallowed digest wins over subject mismatch", func() EvidenceInputs {
			in := seBase()
			// sha256 is not in allowed_digest_algorithms and also differs from
			// release_to; the oracle reports the algorithm gate first.
			in.Evidence[0].Subject = map[string]string{"sha256": "deadbeef"}
			return in
		}, "digest_algorithm_disallowed"},
		{"subject mismatch", func() EvidenceInputs {
			in := seBase()
			in.Evidence[0].Subject = map[string]string{"gitCommit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
			return in
		}, "subject_mismatch"},
		{"replay mode requires replayed", func() EvidenceInputs {
			in := seBase()
			in.Mode = "replay"
			in.Evidence[0].Replayed = false
			return in
		}, "replay_required"},
		{"stale evidence", func() EvidenceInputs { in := seBase(); in.Evidence[0].Fresh = false; return in }, "stale_evidence"},
		{"hidden demotion", func() EvidenceInputs {
			in := seBase()
			in.HiddenDemotions = []string{"v1.2.3-t2.1"}
			return in
		}, "hidden_demotion"},
		{"issuer equivocation", func() EvidenceInputs {
			in := seBase()
			dup := in.Evidence[0]
			dup.VerifiedLevels = []string{"SLSA_SOURCE_LEVEL_2"}
			in.Evidence = []Statement{in.Evidence[0], dup}
			return in
		}, "equivocation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, r := SelectSourceEvidence(c.in())
			if ok {
				t.Fatalf("accepted, want reject %q", c.want)
			}
			if r != c.want {
				t.Errorf("reason = %q, want %q", r, c.want)
			}
		})
	}
}
