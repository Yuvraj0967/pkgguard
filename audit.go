package pkgguard

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ---- parsing manifests and lockfiles -------------------------------------------------

// ParseRequirements reads a pip requirements file. Only lines naming a
// package are returned; options and includes are noted as findings.
func ParseRequirements(text string) ([]Intent, []Finding) {
	var out []Intent
	var notes []Finding
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "\\"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement"):
			notes = append(notes, Finding{ID: "requirements-include", Severity: SevInfo, Message: "includes another requirements file (" + strings.TrimSpace(line) + "); audit it too"})
			continue
		case strings.HasPrefix(line, "--extra-index-url") || strings.HasPrefix(line, "--index-url") || strings.HasPrefix(line, "-i "):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				in := Intent{Manager: "pip", Ecosystem: "pypi", Name: "(project dependencies)", Source: SourcePath, Registries: []string{fields[len(fields)-1]}, ExtraIndex: strings.Contains(line, "extra"), Raw: line}
				out = append(out, in)
			}
			continue
		case strings.HasPrefix(line, "-"):
			continue
		}
		if i := strings.Index(line, ";"); i >= 0 { // environment marker
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, " --hash"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		name, spec, src := parsePySpec(line)
		if name == "" {
			continue
		}
		out = append(out, Intent{Manager: "pip", Ecosystem: "pypi", Name: name, Spec: spec, Source: src, Raw: line})
	}
	return out, notes
}

type lockV2Entry struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Link      bool   `json:"link"`
	Dev       bool   `json:"dev"`
}

type lockV1Dep struct {
	Version      string               `json:"version"`
	Resolved     string               `json:"resolved"`
	Integrity    string               `json:"integrity"`
	Dependencies map[string]lockV1Dep `json:"dependencies"`
}

// ParsePackageLock reads an npm package-lock.json (lockfile v1, v2 or v3).
func ParsePackageLock(data []byte) ([]Intent, error) {
	var doc struct {
		Packages     map[string]lockV2Entry `json:"packages"`
		Dependencies map[string]lockV1Dep   `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	var out []Intent
	add := func(name, version, resolved string, link bool) {
		if name == "" || link {
			return
		}
		in := Intent{Manager: "npm", Ecosystem: "npm", Name: name, Spec: version, Source: SourceRegistry, Resolved: resolved}
		low := strings.ToLower(resolved)
		switch {
		case strings.HasPrefix(low, "git+"), strings.HasPrefix(low, "git://"), strings.Contains(low, "github.com") && strings.Contains(low, "codeload"):
			in.Source = SourceGit
		case resolved != "" && !strings.HasPrefix(low, "https://registry.npmjs.org/") && !strings.HasPrefix(low, "https://registry.yarnpkg.com/") && strings.HasPrefix(low, "http"):
			in.Source = SourceURL
		}
		out = append(out, in)
	}
	for path, e := range doc.Packages {
		if path == "" {
			continue
		}
		i := strings.LastIndex(path, "node_modules/")
		if i < 0 {
			continue
		}
		add(path[i+len("node_modules/"):], e.Version, e.Resolved, e.Link)
	}
	var walk func(map[string]lockV1Dep)
	walk = func(m map[string]lockV1Dep) {
		for n, d := range m {
			add(n, d.Version, d.Resolved, false)
			walk(d.Dependencies)
		}
	}
	if len(doc.Packages) == 0 {
		walk(doc.Dependencies)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].Spec < out[j].Name+out[j].Spec })
	return out, nil
}

// ParsePackageJSON reads dependency names and ranges from a package.json.
func ParsePackageJSON(data []byte) ([]Intent, error) {
	var doc struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	var out []Intent
	for _, m := range []map[string]string{doc.Dependencies, doc.DevDependencies, doc.OptionalDependencies} {
		for n, spec := range m {
			_, _, src := parseNpmSpec(spec)
			in := Intent{Manager: "npm", Ecosystem: "npm", Name: n, Spec: spec, Source: SourceRegistry}
			if src != SourceRegistry || strings.Contains(spec, "/") && !strings.HasPrefix(spec, "npm:") {
				in.Source = src
				if in.Source == SourceRegistry {
					in.Source = SourceGit
				}
			}
			out = append(out, in)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ---- auditing -------------------------------------------------------------------------

// AuditReport is the result of auditing a set of dependencies.
type AuditReport struct {
	Scanned   int       `json:"scanned"`
	Deep      int       `json:"deep_checked"`
	Truncated bool      `json:"truncated,omitempty"` // more packages than DeepLimit; the rest got the fast checks only
	Findings  []Finding `json:"findings"`
}

// Worst returns the highest severity in the report.
func (r AuditReport) Worst() Severity {
	m := SevInfo
	for _, f := range r.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// BatchMalwareIndex is an optional MalwareIndex capability: many lookups in one request.
type BatchMalwareIndex interface {
	MalwareBatch(ctx context.Context, qs []BatchQuery) ([][]string, error)
}

// BatchQuery is one package version to look up.
type BatchQuery struct{ Eco, Name, Version string }

// AuditOptions tunes Audit.
type AuditOptions struct {
	// Deep also runs the full per-package checks (registry existence, age, install scripts,
	// dependencies, Claude) on up to DeepLimit packages. Default fast mode does lockfile
	// integrity checks and one batched OSV lookup for every pinned version.
	Deep      bool
	DeepLimit int
}

// Audit checks a set of dependencies. Pinned versions (lockfiles) are looked up in OSV
// in one batch; entries whose "resolved" URL is outside the registry are flagged as a
// poisoned lockfile (the way a malicious pull request swaps a package's source).
func (e *Engine) Audit(ctx context.Context, intents []Intent, opts AuditOptions) AuditReport {
	if opts.DeepLimit <= 0 {
		opts.DeepLimit = 100
	}
	rep := AuditReport{}
	seen := map[string]bool{}
	var uniq []Intent
	for _, in := range intents {
		if in.Name == "" || seen[in.key()+in.Resolved] {
			continue
		}
		seen[in.key()+in.Resolved] = true
		uniq = append(uniq, in)
	}
	rep.Scanned = len(uniq)

	// 1. local checks: deny list, foreign sources, registries
	for _, in := range uniq {
		if nameIn(e.Cfg.Allow, in.Ecosystem, in.Name) {
			continue
		}
		add := func(id string, sev Severity, msg, hint string, ev ...string) {
			rep.Findings = append(rep.Findings, Finding{ID: id, Severity: sev, Package: in.Name + versionSuffix(in), Message: msg, Hint: hint, Evidence: ev})
		}
		if nameIn(e.Cfg.Deny, in.Ecosystem, in.Name) {
			add("denylist", SevCritical, "package is on this gateway's deny list", "")
		}
		e.checkRegistries(in, add)
		switch in.Source {
		case SourceGit:
			add("source-git", SevHigh, "resolved from a git repository, not the registry; a changed lockfile entry like this is how a poisoned pull request swaps code in", "check who changed this line", in.Resolved)
		case SourceURL:
			add("source-url", SevHigh, "resolved from outside the public registry", "check who changed this line", in.Resolved)
		}
	}

	// 2. OSV, pinned versions in one batch
	if e.Malware != nil {
		var qs []BatchQuery
		var idx []int
		for i, in := range uniq {
			if in.Source == SourceRegistry && in.Name != "(project dependencies)" && !nameIn(e.Cfg.Allow, in.Ecosystem, in.Name) {
				qs = append(qs, BatchQuery{in.Ecosystem, in.Name, strings.TrimPrefix(in.Spec, "==")})
				idx = append(idx, i)
			}
		}
		var res [][]string
		var err error
		if b, ok := e.Malware.(BatchMalwareIndex); ok {
			res, err = b.MalwareBatch(ctx, qs)
		} else {
			res = make([][]string, len(qs))
			var wg sync.WaitGroup
			sem := make(chan struct{}, 8)
			for i, q := range qs {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					res[i], _ = e.Malware.Malware(ctx, q.Eco, q.Name, q.Version)
				}()
			}
			wg.Wait()
		}
		if err != nil {
			rep.Findings = append(rep.Findings, Finding{ID: "lookup-failed", Severity: SevMedium, Message: "OSV batch lookup failed: " + trim(err.Error(), 120)})
		}
		for k, ids := range res {
			if len(ids) == 0 {
				continue
			}
			in := uniq[idx[k]]
			sev, id, msg := SevCritical, "known-malware", "this pinned version is listed as malware in OSV"
			if !looseVersion.MatchString(strings.TrimPrefix(in.Spec, "==")) {
				sev, id, msg = SevMedium, "malware-advisory", "OSV lists malware for some version of this package; the version here is a range, so pin it and re-audit"
			}
			rep.Findings = append(rep.Findings, Finding{ID: id, Severity: sev, Package: in.Name + versionSuffix(in), Message: msg, Evidence: ids})
		}
	}

	// 3. deep checks (registry, age, scripts, Claude) on a bounded number of packages
	if opts.Deep && e.Registry != nil {
		var deep []Intent
		for _, in := range uniq {
			if in.Source == SourceRegistry && hasRegistryClient(in.Ecosystem) && in.Name != "(project dependencies)" {
				deep = append(deep, in)
			}
		}
		if len(deep) > opts.DeepLimit {
			deep = deep[:opts.DeepLimit]
			rep.Truncated = true
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 6)
		for _, in := range deep {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				in.Spec = strings.TrimPrefix(in.Spec, "==")
				fs := e.checkIntent(ctx, in)
				// known-malware was already reported by the batch
				var keep []Finding
				for _, f := range fs {
					if f.ID != "known-malware" && f.ID != "malware-advisory" {
						keep = append(keep, f)
					}
				}
				mu.Lock()
				rep.Findings = append(rep.Findings, keep...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		rep.Deep = len(deep)
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Severity > rep.Findings[j].Severity })
	return rep
}

var pinned = regexp.MustCompile(`^[0-9]`)

func versionSuffix(in Intent) string {
	v := strings.TrimPrefix(in.Spec, "==")
	if pinned.MatchString(v) {
		return "@" + v
	}
	return ""
}
