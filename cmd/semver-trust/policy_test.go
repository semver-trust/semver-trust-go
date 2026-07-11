// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// specPolicyPath is the §9 reference policy vendored as internal/policy
// testdata — the same file the parser's own tests pin.
func specPolicyPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..",
		"internal", "policy", "testdata", "spec-section-9.toml")
}

func runRoot(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errBuf.String(), err
}

func TestPolicyValidate(t *testing.T) {
	stdout, _, err := runRoot(t, "policy", "validate", "--policy", specPolicyPath(t))
	if err != nil {
		t.Fatalf("policy validate: %v", err)
	}
	for _, want := range []string{
		"is valid (schema 0.1)",
		"digest:      sha256:",
		"threshold:   T2",
		"strategy:    demote",
		"meta-paths:  3 at required level T3",
		"derivations: 2",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("validate output missing %q:\n%s", want, stdout)
		}
	}
}

// A missing policy file is a clear error, not an invented default: validate
// needs a file (zero-configuration honesty is the plain commands' property).
func TestPolicyValidateMissingFile(t *testing.T) {
	_, _, err := runRoot(t, "policy", "validate", "--repo", t.TempDir())
	if err == nil {
		t.Fatal("policy validate with no file succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no policy file at") {
		t.Errorf("error = %q, want a clear missing-file message", err)
	}
}

// A parse error surfaces verbatim and exits non-zero.
func TestPolicyValidateParseError(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(bad, []byte("[policy]\nversion = \"9.9\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runRoot(t, "policy", "validate", "--policy", bad)
	if err == nil {
		t.Fatal("policy validate on a bad file succeeded, want error")
	}
	if !strings.Contains(err.Error(), `unsupported policy version "9.9"`) {
		t.Errorf("error = %q, want the parser's verbatim reason", err)
	}
}

// The GO-041 acceptance: `policy explain` prints the decision table in
// effect — every §6.4 row, the threshold, and the configured strategy.
func TestPolicyExplainPrintsDecisionTable(t *testing.T) {
	stdout, _, err := runRoot(t, "policy", "explain", "--policy", specPolicyPath(t))
	if err != nil {
		t.Fatalf("policy explain: %v", err)
	}
	for _, want := range []string{
		"decision table in effect (§6.4 default)",
		"threshold: T2",
		"strategy:  demote",
		"trust",
		"blast low",
		"blast moderate",
		"blast high",
		"clean",
		"differ proof (patch)",
		"differ proof (any)",
		"pre-release",
		"meta-paths:",
		"derivations: openapi-server, gofmt",
		"weights:     auth=critical, billing=high, common=critical, docs=low",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("explain output missing %q:\n%s", want, stdout)
		}
	}
	// Every level row renders.
	for _, row := range []string{"T0", "T1", "T2", "T3"} {
		if !strings.Contains(stdout, "\n"+row+" ") {
			t.Errorf("explain output missing row %s:\n%s", row, stdout)
		}
	}
}
