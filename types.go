// Package pkgguard guards what AI agents install.
//
// It is a Bifrost gateway plugin: it reads the tool calls an LLM asks an agent
// to run (and the tool executions that pass through Bifrost's MCP gateway),
// extracts package installs from them (npm, pnpm, yarn, bun, pip, uv, pipx,
// poetry, cargo, go, gem, curl|sh), and decides allow / warn / block before the
// command ever runs. Nothing from a package is executed; the checks only read
// registry metadata and, for npm, the install-hook files inside the tarball.
package pkgguard

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks a finding.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(sevNames) {
		return "unknown"
	}
	return sevNames[s]
}

// ParseSeverity parses a severity name ("high", "critical", ...).
func ParseSeverity(v string) (Severity, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	for i, n := range sevNames {
		if n == v {
			return Severity(i), true
		}
	}
	return SevInfo, false
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, ok := ParseSeverity(str)
	if !ok {
		return fmt.Errorf("unknown severity %q", str)
	}
	*s = v
	return nil
}

// Finding is one reason a package or command looks risky (or notable).
type Finding struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Package  string   `json:"package,omitempty"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
	Hint     string   `json:"hint,omitempty"`
}

// Action is the outcome for a command.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// Decision is the result of analysing one command string.
type Decision struct {
	Action   Action    `json:"action"`
	Command  string    `json:"command"`
	Intents  []Intent  `json:"intents,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

// Message renders the decision as text an agent (and its user) can act on.
func (d Decision) Message() string {
	var b strings.Builder
	switch d.Action {
	case ActionBlock:
		b.WriteString("[pkgguard] BLOCKED: this command was not run because it installs software that looks unsafe.\n")
	case ActionWarn:
		b.WriteString("[pkgguard] WARNING: this command installs software with some risk signals.\n")
	default:
		return ""
	}
	for _, f := range d.Findings {
		if f.Severity < SevMedium {
			continue
		}
		pkg := ""
		if f.Package != "" {
			pkg = f.Package + ": "
		}
		fmt.Fprintf(&b, "- (%s) %s%s\n", f.Severity, pkg, f.Message)
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "    > %s\n", e)
		}
		if f.Hint != "" {
			fmt.Fprintf(&b, "    hint: %s\n", f.Hint)
		}
	}
	if d.Action == ActionBlock {
		b.WriteString("Do not retry the same install. Check the package name with the user, pick a verified package, or ask the user to approve it explicitly.")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (d Decision) maxSeverity() Severity {
	m := SevInfo
	for _, f := range d.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}
