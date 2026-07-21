// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"encoding/json"
	"fmt"
	"io"
)

// MarshalText renders severities and personas as their names in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }
func (p Persona) MarshalText() ([]byte, error)  { return []byte(p.String()), nil }

// errWriter threads the first write error (house pattern, cf. internal/verify/render.go).
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

// WriteJSON emits the structured report.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Render writes the human report under the §4.1 output contract: never a health
// verdict; every FAIL names the verify abort it preempts and the exact fix; a
// structural cannot-check footer names what no tool can verify; and the run ends
// by printing the real verify invocation. --strict promotes WARN to FAIL.
func (r *Report) Render(w io.Writer, strict bool) error {
	e := &errWriter{w: w}
	e.printf("semver-trust doctor — persona: %s\n\n", r.Persona)
	for _, n := range r.Checks {
		sev := n.Result.Severity
		if strict && sev == WARN {
			sev = FAIL
		}
		e.printf("  %-4s  %-30s  %s\n", sev, n.ID, n.Result.Message)
		if sev == FAIL && n.Result.Preempts != "" {
			e.printf("        would abort at verify: %s\n", n.Result.Preempts)
		}
		if n.Result.Fix != "" {
			e.printf("        fix: %s\n", n.Result.Fix)
		}
	}
	// The cannot-check footer is structural and always printed: doctor never
	// claims a clean bill of health, only that its mechanical checks passed.
	e.printf("\ncannot check (no tool can): that your signing key is held only by you;\n")
	e.printf("that a reviewer is a distinct natural person; that the platform enforces its\n")
	e.printf("rulesets live.\n")
	e.printf("\nnext, run the gate doctor preempts:\n  %s\n", r.VerifyCmd)
	return e.err
}
