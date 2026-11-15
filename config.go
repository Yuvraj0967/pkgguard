package pkgguard

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config is the plugin configuration. Every field is optional; WithDefaults
// fills the rest. It is read from the "config" object of the plugin entry in
// Bifrost's config.json (see examples/config.json).
type Config struct {
	// Mode is "enforce" (default: block bad commands) or "monitor" (log only).
	Mode string `json:"mode"`
	// BlockAt / WarnAt are severity names. Defaults: block at "high", warn at "medium".
	BlockAt string `json:"block_at"`
	WarnAt  string `json:"warn_at"`
	// MinAgeHours holds versions published more recently than this. Default 24; 0 turns it off.
	MinAgeHours *int `json:"min_age_hours"`
	// Allow lists package names that skip every check. Deny lists names that are always blocked.
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
	// AllowedRegistries are hosts a command may point --registry / --index-url at.
	AllowedRegistries []string `json:"allowed_registries"`
	// Offline never contacts a registry, OSV or Claude (only local rules run).
	Offline bool `json:"offline"`
	// DisableOSV skips the OSV malware lookup (it sends only package name and version).
	DisableOSV bool `json:"disable_osv"`
	// FailClosed raises a failed lookup to "high" so the command is blocked.
	FailClosed bool `json:"fail_closed"`
	// CheckDependencies also checks the direct dependencies of an npm package. Default true.
	CheckDependencies *bool `json:"check_dependencies"`
	// IgnoreTools are tool-name substrings whose arguments are never scanned
	// (file writers and readers, where an install command is just text).
	IgnoreTools []string `json:"ignore_tools"`
	// AnthropicAPIKey enables the Claude reviewer for flagged packages (falls back to $ANTHROPIC_API_KEY).
	AnthropicAPIKey string `json:"anthropic_api_key"`
	ReviewerModel   string `json:"reviewer_model"`
	// AuditLog is an optional JSONL file every decision is appended to.
	AuditLog string `json:"audit_log"`
	// DashboardAddr (e.g. "127.0.0.1:8099") starts the dashboard: live events, stats and an
	// Approve button. Empty disables it. A non-loopback address requires dashboard_token.
	DashboardAddr string `json:"dashboard_addr"`
	// DashboardToken protects the dashboard API. Empty: a random token is generated and logged at start.
	DashboardToken string `json:"dashboard_token"`
	// ApprovalsFile persists human approvals across restarts (JSON). Empty keeps them in memory.
	ApprovalsFile string `json:"approvals_file"`
}

func intp(v int) *int    { return &v }
func boolp(v bool) *bool { return &v }

// WithDefaults returns a copy with defaults applied.
func (c Config) WithDefaults() Config {
	if c.Mode == "" {
		c.Mode = "enforce"
	}
	if c.BlockAt == "" {
		c.BlockAt = "high"
	}
	if c.WarnAt == "" {
		c.WarnAt = "medium"
	}
	if c.MinAgeHours == nil {
		c.MinAgeHours = intp(24)
	}
	if c.CheckDependencies == nil {
		c.CheckDependencies = boolp(true)
	}
	if len(c.AllowedRegistries) == 0 {
		c.AllowedRegistries = []string{"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org", "crates.io", "index.crates.io", "proxy.golang.org", "rubygems.org"}
	}
	if len(c.IgnoreTools) == 0 {
		c.IgnoreTools = []string{"write", "edit", "patch", "read", "create_file", "str_replace", "view", "grep", "search"}
	}
	if c.AnthropicAPIKey == "" && !c.Offline {
		c.AnthropicAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if c.ReviewerModel == "" {
		c.ReviewerModel = "claude-sonnet-5-5"
	}
	return c
}

// Validate reports configuration mistakes.
func (c Config) Validate() error {
	if c.Mode != "enforce" && c.Mode != "monitor" {
		return fmt.Errorf("pkgguard: mode must be \"enforce\" or \"monitor\", got %q", c.Mode)
	}
	for _, s := range []string{c.BlockAt, c.WarnAt} {
		if _, ok := ParseSeverity(s); !ok {
			return fmt.Errorf("pkgguard: unknown severity %q", s)
		}
	}
	return nil
}

// ConfigFromAny builds a Config from the loosely typed value Bifrost passes to Init.
func ConfigFromAny(v any) (Config, error) {
	var c Config
	switch t := v.(type) {
	case nil:
	case Config:
		c = t
	case *Config:
		if t != nil {
			c = *t
		}
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return c, err
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return c, fmt.Errorf("pkgguard: bad config: %w", err)
		}
	}
	c = c.WithDefaults()
	return c, c.Validate()
}

func (c Config) minAge() int { return *c.MinAgeHours }

func (c Config) ignoresTool(name string) bool {
	n := strings.ToLower(name)
	for _, s := range c.IgnoreTools {
		if s != "" && strings.Contains(n, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func (c Config) registryAllowed(host string) bool {
	host = strings.ToLower(host)
	for _, a := range c.AllowedRegistries {
		a = strings.ToLower(a)
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func nameIn(list []string, eco, name string) bool {
	n := normalizeName(eco, name)
	for _, x := range list {
		if normalizeName(eco, x) == n {
			return true
		}
	}
	return false
}
