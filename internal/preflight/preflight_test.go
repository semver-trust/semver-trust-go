// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"strings"
	"testing"
)

func TestVerifyInvocationShellSafe(t *testing.T) {
	if got := verifyInvocation(&Env{Repo: "/tmp/my repo"}); !strings.Contains(got, `--repo '/tmp/my repo'`) {
		t.Errorf("a repo path with a space must be shell-quoted: %q", got)
	}
	if got := verifyInvocation(&Env{Repo: "."}); !strings.Contains(got, "--repo . ") {
		t.Errorf("a plain path must not be gratuitously quoted: %q", got)
	}
	if got := verifyInvocation(&Env{Repo: "a'b"}); !strings.Contains(got, `'a'\''b'`) {
		t.Errorf("an embedded single quote must be escaped: %q", got)
	}
}

func TestSeverityExit(t *testing.T) {
	mk := func(p Persona, r Result) Check {
		return Check{ID: "x", Personas: []Persona{p}, Run: func(*Env) Result { return r }}
	}

	// No FAIL among PASS/SKIP → HasFail false.
	rep := Run(&Env{Persona: Maintainer}, []Check{
		mk(Maintainer, pass("ok")),
		{ID: "y", Personas: []Persona{Maintainer}, Run: func(*Env) Result { return skip("n/a") }},
	})
	if rep.HasFail() {
		t.Error("no FAIL: HasFail should be false")
	}

	// A FAIL → HasFail true.
	if !Run(&Env{Persona: Maintainer}, []Check{mk(Maintainer, fail("bad", "§10 step 3", "fix"))}).HasFail() {
		t.Error("a FAIL: HasFail should be true")
	}

	// A FAIL that does not apply to the persona is not run and must not count.
	rep3 := Run(&Env{Persona: Agent}, []Check{mk(Maintainer, fail("x", "y", "z"))})
	if len(rep3.Checks) != 0 || rep3.HasFail() {
		t.Errorf("maintainer-only check ran under agent persona: %+v", rep3.Checks)
	}
}

func TestRenderContract(t *testing.T) {
	rep := Run(&Env{Repo: "/tmp/x", Persona: Maintainer}, []Check{
		{ID: "keys/attestation-distinct", Personas: []Persona{Maintainer}, Run: func(*Env) Result {
			return fail("commit and attestation keys are the same", "§5.4 (config)", "semver-trust enroll --attest-key …")
		}},
		{ID: "config/identity", Personas: []Persona{Maintainer}, Run: func(*Env) Result { return pass("user.email set") }},
	})

	var b strings.Builder
	if err := rep.Render(&b, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	for _, banned := range []string{"all checks passed", "all passed", "healthy", "everything looks good"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("render must not print a health verdict; found %q\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "would abort at verify: §5.4") {
		t.Error("FAIL must name the preempted abort")
	}
	if !strings.Contains(out, "fix: semver-trust enroll") {
		t.Error("FAIL must carry a fix line")
	}
	if !strings.Contains(out, "cannot check") {
		t.Error("must print the cannot-check footer")
	}
	if !strings.Contains(out, "semver-trust verify --repo /tmp/x --to HEAD") {
		t.Error("must end by printing the verify invocation")
	}

	var jb strings.Builder
	if err := rep.WriteJSON(&jb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jb.String(), `"severity": "FAIL"`) {
		t.Errorf("json severity should render as a string:\n%s", jb.String())
	}

	// --strict promotes WARN to FAIL in the rendered severity.
	warnRep := Run(&Env{Repo: ".", Persona: Maintainer}, []Check{
		{ID: "registry/parse", Personas: []Persona{Maintainer}, Run: func(*Env) Result { return warn("drift", "commit the registry") }},
	})
	var sb strings.Builder
	if err := warnRep.Render(&sb, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "FAIL  registry/parse") {
		t.Errorf("--strict should render WARN as FAIL:\n%s", sb.String())
	}
}
