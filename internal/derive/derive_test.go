// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// writeTree lays out a disposable checkout. Hermetic: plain files, POSIX
// commands, no git, no network.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// generatorRule mimics an oapi-codegen-style derivation: gen/output.txt is
// deterministically produced from api/source.txt by a pinned command.
var generatorRule = policy.Derivation{
	Name:    "oapi-style-generator",
	Inputs:  []string{"api/source.txt"},
	Command: "tr 'a-z' 'A-Z' < api/source.txt > gen/output.txt",
	Outputs: []string{"gen/**"},
}

func TestRunVerifiedGenerator(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"api/source.txt": "hello derivation\n",
		"gen/output.txt": "HELLO DERIVATION\n", // exactly what the command regenerates
	})
	verdict, err := Run(dir, generatorRule)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !verdict.Verified || len(verdict.Diffs) != 0 {
		t.Errorf("verdict = %+v, want verified with no diffs", verdict)
	}
}

func TestRunTamperedOutputVoidsAndReports(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"api/source.txt": "hello derivation\n",
		"gen/output.txt": "HELLO DERIVATION\n// smuggled payload\n",
	})
	verdict, err := Run(dir, generatorRule)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if verdict.Verified {
		t.Fatal("tampered output verified")
	}
	if !reflect.DeepEqual(verdict.Diffs, []string{"gen/output.txt"}) {
		t.Errorf("Diffs = %v, want the tampered path reported", verdict.Diffs)
	}
}

// The §4.4 degenerate case: inputs = outputs, command = formatter. An
// already-formatted tree reproduces itself; an unformatted one does not.
func TestRunFormattingDegenerateCase(t *testing.T) {
	formatter := policy.Derivation{
		Name:    "crlf-formatter",
		Inputs:  []string{"src/**"},
		Command: "tr -d '\\r' < src/main.txt > src/.fmt && mv src/.fmt src/main.txt",
		Outputs: []string{"src/**"},
	}

	t.Run("already formatted: proof verifies", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"src/main.txt": "clean\nlines\n"})
		verdict, err := Run(dir, formatter)
		if err != nil {
			t.Fatal(err)
		}
		if !verdict.Verified {
			t.Errorf("verdict = %+v, want verified (formatting is idempotent here)", verdict)
		}
	})

	t.Run("unformatted content: proof is void", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"src/main.txt": "dirty\r\nlines\r\n"})
		verdict, err := Run(dir, formatter)
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Verified || len(verdict.Diffs) != 1 {
			t.Errorf("verdict = %+v, want void with the reformatted path", verdict)
		}
	})
}

func TestRunErrors(t *testing.T) {
	t.Run("failing command", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"gen/output.txt": "x\n"})
		_, err := Run(dir, policy.Derivation{
			Name: "broken", Inputs: []string{"a"}, Command: "exit 3", Outputs: []string{"gen/**"},
		})
		if err == nil || !strings.Contains(err.Error(), "command failed") {
			t.Errorf("err = %v, want command failure", err)
		}
	})
	t.Run("outputs match nothing", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"api/source.txt": "x\n"})
		_, err := Run(dir, generatorRule)
		if err == nil || !strings.Contains(err.Error(), "no committed files match") {
			t.Errorf("err = %v, want no-matching-outputs error", err)
		}
	})
	t.Run("appearing output is a diff", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"api/source.txt": "x\n",
			"gen/output.txt": "X\n",
		})
		rule := generatorRule
		rule.Command = rule.Command + " && echo extra > gen/new.txt"
		verdict, err := Run(dir, rule)
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Verified || !reflect.DeepEqual(verdict.Diffs, []string{"gen/new.txt"}) {
			t.Errorf("verdict = %+v, want void with the appearing path", verdict)
		}
	})
}

func TestInputsFloor(t *testing.T) {
	commits := []trust.Commit{
		{ID: "c1", Level: trust.T3, Paths: []string{"api/source.txt"}},
		{ID: "c2", Level: trust.T2, Paths: []string{"api/source.txt"}},
		{ID: "c3", Level: trust.T0, Paths: []string{"unrelated.txt"}},
	}
	floor, err := InputsFloor(commits, generatorRule)
	if err != nil {
		t.Fatal(err)
	}
	if floor != trust.T2 {
		t.Errorf("InputsFloor = %s, want T2 (min over input-touching commits; the T0 commit is unrelated)", floor)
	}

	if _, err := InputsFloor(commits[2:], generatorRule); err == nil {
		t.Error("InputsFloor accepted a range where nothing touches the inputs")
	}
}

// TestAcceptanceEndToEnd is the GO-034 acceptance: a verified
// oapi-codegen-style derivation makes the generated paths inherit the
// reviewed inputs' trust through the §5.2 floor, and a tampered output voids
// the proof — the regeneration commit's own T0 floors the scope instead, and
// the discrepancy is reported.
func TestAcceptanceEndToEnd(t *testing.T) {
	scopes := map[string]string{"api/**": "svc", "gen/**": "svc"}
	commits := []trust.Commit{
		// Reviewed spec change: two accountable humans.
		{ID: "spec", Level: trust.T3, Paths: []string{"api/source.txt"}},
	}
	regen := trust.Commit{ID: "regen", Level: trust.T0, Paths: []string{"gen/output.txt"}}

	t.Run("verified derivation inherits input trust", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"api/source.txt": "hello derivation\n",
			"gen/output.txt": "HELLO DERIVATION\n",
		})
		verdict, err := Run(dir, generatorRule)
		if err != nil || !verdict.Verified {
			t.Fatalf("Run = %+v, %v", verdict, err)
		}
		floor, err := InputsFloor(commits, generatorRule)
		if err != nil {
			t.Fatal(err)
		}
		commit := regen
		commit.Derivation = Facts(generatorRule, verdict, floor)

		floors, err := trust.ScopeFloors(scopes, append(commits, commit))
		if err != nil {
			t.Fatal(err)
		}
		if floors["svc"] != trust.T3 {
			t.Errorf("own(svc) = %s, want T3 — generated paths inherit the reviewed inputs' trust", floors["svc"])
		}
	})

	t.Run("tampered output voids the proof and floors", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"api/source.txt": "hello derivation\n",
			"gen/output.txt": "HELLO DERIVATION\n// smuggled\n",
		})
		verdict, err := Run(dir, generatorRule)
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Verified || len(verdict.Diffs) == 0 {
			t.Fatalf("verdict = %+v, want void with reported diffs", verdict)
		}
		floor, err := InputsFloor(commits, generatorRule)
		if err != nil {
			t.Fatal(err)
		}
		commit := regen
		commit.Derivation = Facts(generatorRule, verdict, floor)

		floors, err := trust.ScopeFloors(scopes, append(commits, commit))
		if err != nil {
			t.Fatal(err)
		}
		if floors["svc"] != trust.T0 {
			t.Errorf("own(svc) = %s, want T0 — a void proof gives no exception", floors["svc"])
		}
	})
}
