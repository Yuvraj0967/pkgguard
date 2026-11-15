package pkgguard

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Engine turns a shell command into a Decision.
type Engine struct {
	Cfg      Config
	Registry Registry     // nil when offline
	Malware  MalwareIndex // nil when offline or OSV is disabled
	Reviewer Reviewer     // nil when no Anthropic key is configured
	Now      func() time.Time
	// Approvals are human overrides (dashboard / API); see approvals.go. May be nil.
	Approvals *Approvals

	blockAt, warnAt Severity
}

// NewEngine wires the default network-backed checks according to cfg.
func NewEngine(cfg Config) (*Engine, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	e := &Engine{Cfg: cfg, Now: time.Now}
	e.Approvals = NewApprovals(cfg.ApprovalsFile, nil)
	e.blockAt, _ = ParseSeverity(cfg.BlockAt)
	e.warnAt, _ = ParseSeverity(cfg.WarnAt)
	if !cfg.Offline {
		e.Registry = NewHTTPRegistry()
		if !cfg.DisableOSV {
			e.Malware = NewOSV()
		}
		if cfg.AnthropicAPIKey != "" {
			e.Reviewer = NewClaudeReviewer(cfg.AnthropicAPIKey, cfg.ReviewerModel)
		}
	}
	return e, nil
}

// applyApproval drops findings below critical for a package a human approved, and
// leaves a note so the decision stays explainable. Critical findings stay.
func applyApproval(in Intent, fs []Finding) []Finding {
	var kept []Finding
	cleared := 0
	for _, f := range fs {
		if f.Severity >= SevCritical {
			kept = append(kept, f)
		} else if f.Severity >= SevMedium {
			cleared++
		} else {
			kept = append(kept, f)
		}
	}
	if cleared > 0 {
		kept = append(kept, Finding{ID: "approved", Severity: SevInfo, Package: in.Name,
			Message: fmt.Sprintf("a human approved this package; %d finding(s) below critical were cleared", cleared)})
	}
	return kept
}

// maxDeps bounds how many direct dependencies of one package are checked.
const maxDeps = 30

// lowDownloads is the weekly download count below which a lookalike of a popular package is suspicious.
const lowDownloads = 2000

// Analyze parses cmd and checks every package it would install.
func (e *Engine) Analyze(ctx context.Context, cmd string) Decision {
	if e.blockAt == 0 && e.warnAt == 0 { // engine built as a literal in tests
		e.blockAt, _ = ParseSeverity(e.Cfg.BlockAt)
		e.warnAt, _ = ParseSeverity(e.Cfg.WarnAt)
	}
	parsed := ParseCommand(cmd)
	d := Decision{Command: trim(cmd, 500), Intents: parsed.Installs, Findings: append([]Finding(nil), parsed.Findings...)}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	seen := map[string]bool{}
	for _, in := range parsed.Installs {
		if seen[in.key()] {
			continue
		}
		seen[in.key()] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(in Intent) {
			defer wg.Done()
			defer func() { <-sem }()
			fs := e.checkIntent(ctx, in)
			if e.Approvals.Has(in.Ecosystem, in.Name) {
				fs = applyApproval(in, fs)
			}
			mu.Lock()
			d.Findings = append(d.Findings, fs...)
			mu.Unlock()
		}(in)
	}
	wg.Wait()

	sort.SliceStable(d.Findings, func(i, j int) bool { return d.Findings[i].Severity > d.Findings[j].Severity })
	d.Action = ActionAllow
	switch m := d.maxSeverity(); {
	case len(d.Findings) == 0:
	case m >= e.blockAt:
		d.Action = ActionBlock
	case m >= e.warnAt:
		d.Action = ActionWarn
	}
	if e.Cfg.Mode == "monitor" && d.Action == ActionBlock {
		d.Action = ActionWarn
	}
	return d
}

func (e *Engine) checkIntent(ctx context.Context, in Intent) []Finding {
	var fs []Finding
	add := func(id string, sev Severity, msg string, hint string, ev ...string) {
		fs = append(fs, Finding{ID: id, Severity: sev, Package: in.Name, Message: msg, Hint: hint, Evidence: ev})
	}
	if in.Name == "(project dependencies)" {
		// only the registry override matters here
		e.checkRegistries(in, add)
		return fs
	}
	if nameIn(e.Cfg.Allow, in.Ecosystem, in.Name) {
		return nil
	}
	if nameIn(e.Cfg.Deny, in.Ecosystem, in.Name) {
		add("denylist", SevCritical, "package is on this gateway's deny list", "")
		return fs
	}
	e.checkRegistries(in, add)

	switch in.Source {
	case SourceGit:
		add("source-git", SevHigh, "installs from a git repository; the registry cannot vouch for it and its build/prepare scripts run on install", "install the published release from the registry, or ask the user to approve this source")
		return fs
	case SourceURL:
		add("source-url", SevHigh, "installs from an arbitrary URL; the archive cannot be checked before it runs", "install the published release from the registry, or ask the user to approve this source")
		return fs
	case SourcePath:
		add("source-path", SevInfo, "installs from a local path", "")
		return fs
	}

	// Name-only checks (work offline).
	typo, typoDist := typosquatMatch(in.Ecosystem, in.Name)

	if e.Registry == nil && e.Malware == nil {
		if typo != "" && typoDist == 1 {
			add("typosquat", SevMedium, fmt.Sprintf("name is one edit away from the popular package %q", typo), "check the spelling; offline mode cannot confirm", "similar to "+typo)
		}
		return fs
	}

	// Registry first: OSV must be asked about the exact version that would be
	// installed. A name-only query returns advisories for every version, and a
	// legitimate package with one compromised release (debug, chalk) would be
	// condemned forever.
	var info *PackageInfo
	var infoErr error
	if e.Registry != nil && hasRegistryClient(in.Ecosystem) && len(in.Registries) == 0 {
		info, infoErr = e.Registry.Lookup(ctx, in.Ecosystem, in.Name, in.Spec)
	}
	ver := in.Spec
	if info != nil && info.Version != "" {
		ver = info.Version
	}
	var malIDs []string
	var malErr error
	if e.Malware != nil && (info == nil || info.Exists) {
		malIDs, malErr = e.Malware.Malware(ctx, in.Ecosystem, in.Name, ver)
	}

	failSev := SevMedium
	if e.Cfg.FailClosed {
		failSev = SevHigh
	}
	if malErr != nil {
		add("lookup-failed", failSev, "could not ask OSV about this package: "+trim(malErr.Error(), 120), "")
	}
	if len(malIDs) > 0 {
		if looseVersion.MatchString(ver) {
			add("known-malware", SevCritical, fmt.Sprintf("version %s is listed as malware in OSV", ver), "", malIDs...)
		} else {
			add("malware-advisory", SevMedium, "OSV lists malware for some version of this package; the version to be installed could not be pinned down", "pin an exact version and retry", malIDs...)
		}
	}
	if infoErr != nil {
		add("lookup-failed", failSev, "could not read the registry entry: "+trim(infoErr.Error(), 120), "")
	}
	if info == nil {
		if typo != "" && typoDist == 1 && infoErr != nil {
			add("typosquat", SevMedium, fmt.Sprintf("name is one edit away from the popular package %q", typo), "check the spelling", "similar to "+typo)
		}
		return fs
	}

	now := e.Now()
	if !info.Exists {
		msg := fmt.Sprintf("does not exist on %s. AI models often invent plausible package names, and attackers register them later (\"slopsquatting\")", in.Ecosystem)
		hint := "ask the user which package is meant"
		if typo != "" {
			hint = fmt.Sprintf("did you mean %q?", typo)
		}
		add("phantom-package", SevHigh, msg, hint)
		return fs
	}
	if info.VersionMissing {
		add("version-not-found", SevMedium, fmt.Sprintf("version %s does not exist in the registry", info.Version), "")
	}

	// A typosquat candidate is only worrying when the package is also new or unused.
	if typo != "" {
		young := !info.Created.IsZero() && now.Sub(info.Created) < 30*24*time.Hour
		edits := "one edit"
		if typoDist == 2 {
			edits = "two edits"
		}
		switch {
		case young:
			add("typosquat", SevHigh, fmt.Sprintf("name is %s away from the popular package %q and was first published %s ago", edits, typo, humanAge(now.Sub(info.Created))), fmt.Sprintf("did you mean %q?", typo), "similar to "+typo)
		default:
			dl, derr := e.Registry.WeeklyDownloads(ctx, in.Ecosystem, in.Name)
			switch {
			case derr == nil && dl < lowDownloads:
				add("typosquat", SevMedium, fmt.Sprintf("name is %s away from the popular package %q and only %d people downloaded it last week", edits, typo, dl), fmt.Sprintf("did you mean %q?", typo), "similar to "+typo)
			case typoDist == 1:
				add("typosquat", SevLow, fmt.Sprintf("name is close to the popular package %q (an established package, so probably legitimate)", typo), "", "similar to "+typo)
			}
		}
	}

	// Waiting period for brand-new versions.
	if minAge := e.Cfg.minAge(); minAge > 0 && !info.VersionPublished.IsZero() {
		age := now.Sub(info.VersionPublished)
		if age < time.Duration(minAge)*time.Hour {
			hint := "wait, or pin an older version"
			if older := info.OlderThan(time.Duration(minAge)*time.Hour, now); older != "" {
				hint = fmt.Sprintf("newest version older than %dh is %s", minAge, older)
			}
			add("too-new", SevHigh, fmt.Sprintf("version %s was published %s ago; most malicious releases are caught within a day", info.Version, humanAge(age)), hint)
		}
	}

	// Install-time code.
	hasInstall := len(info.Scripts) > 0 && (info.Scripts["preinstall"] != "" || info.Scripts["install"] != "" || info.Scripts["postinstall"] != "") || info.GypFile
	if hasInstall {
		var names []string
		for _, k := range []string{"preinstall", "install", "postinstall"} {
			if s, ok := info.Scripts[k]; ok {
				names = append(names, fmt.Sprintf("%s: %s", k, trim(s, 100)))
			}
		}
		if info.GypFile {
			names = append(names, "binding.gyp (node-gyp runs at install)")
		}
		sev := SevLow
		if !info.Created.IsZero() && now.Sub(info.Created) < 7*24*time.Hour {
			sev = SevHigh
		}
		msg := "runs code at install time"
		if sev == SevHigh {
			msg = "is under a week old and runs code at install time"
		}
		add("install-script", sev, msg, "", names...)
	}

	// Direct dependencies: the part of the tree a one-package check never sees.
	if *e.Cfg.CheckDependencies && in.Ecosystem == "npm" && len(info.Dependencies) > 0 {
		fs = append(fs, e.checkDependencies(ctx, in, info)...)
	}

	// Install-time code: read the hook files once (in memory, never run), then
	// run the static rules, then ask Claude about what is left.
	if in.Ecosystem == "npm" && hasInstall && e.Registry != nil {
		files, err := e.Registry.Evidence(ctx, in.Ecosystem, info)
		if err != nil {
			add("evidence-unavailable", SevLow, "could not read the install-time files: "+trim(err.Error(), 100), "")
		}
		static := ScanInstallCode(in.Name, info.Scripts, files)
		fs = append(fs, static...)
		if e.Reviewer != nil && (len(files) > 0 || len(info.Scripts) > 0) {
			if vf := e.review(ctx, in, info, files); vf != nil {
				fs = append(fs, *vf)
			}
		}
	}
	return fs
}

func maxOf(fs []Finding) Severity {
	m := SevInfo
	for _, f := range fs {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

func (e *Engine) checkRegistries(in Intent, add func(id string, sev Severity, msg, hint string, ev ...string)) {
	for _, r := range in.Registries {
		h := registryHost(r)
		if h == "" || e.Cfg.registryAllowed(h) {
			continue
		}
		sev, id := SevHigh, "custom-registry"
		msg := "points the package manager at a registry outside the allowed list (" + h + ")"
		if in.ExtraIndex {
			id = "extra-index"
			msg = "adds an extra package index (" + h + "); pip will take the highest version from any index, which is how dependency-confusion attacks work"
		}
		add(id, sev, msg, "use the default registry, or add the host to allowed_registries", r)
	}
}

func (e *Engine) checkDependencies(ctx context.Context, in Intent, info *PackageInfo) []Finding {
	deps := info.Dependencies
	if len(deps) > maxDeps {
		deps = deps[:maxDeps]
	}
	var mu sync.Mutex
	var fs []Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, dep := range deps {
		wg.Add(1)
		sem <- struct{}{}
		go func(dep string) {
			defer wg.Done()
			defer func() { <-sem }()
			var local []Finding
			if e.Registry == nil {
				return
			}
			di, err := e.Registry.Lookup(ctx, "npm", dep, "")
			if err != nil {
				return
			}
			if !di.Exists {
				local = append(local, Finding{ID: "dependency-phantom", Severity: SevHigh, Package: in.Name,
					Message:  fmt.Sprintf("depends on %q, which is not on the public registry; whoever registers that name gets code execution in your install", dep),
					Evidence: []string{dep}})
			} else if e.Malware != nil {
				// asked about the resolved (newest) version, not the name, so one bad old release does not condemn a package
				if ids, err := e.Malware.Malware(ctx, "npm", dep, di.Version); err == nil && len(ids) > 0 {
					local = append(local, Finding{ID: "dependency-malware", Severity: SevCritical, Package: in.Name,
						Message: fmt.Sprintf("depends on %s@%s, which OSV lists as malware", dep, di.Version), Evidence: ids})
				}
			}
			if len(local) > 0 {
				mu.Lock()
				fs = append(fs, local...)
				mu.Unlock()
			}
		}(dep)
	}
	wg.Wait()
	return fs
}

func (e *Engine) review(ctx context.Context, in Intent, info *PackageInfo, files []EvidenceFile) *Finding {
	bundle := BuildBundle(in.Name, info.Version, info.Scripts, files)
	v, err := e.Reviewer.Review(ctx, in.Name, bundle)
	if err != nil {
		return &Finding{ID: "review-skipped", Severity: SevInfo, Package: in.Name, Message: "Claude review failed: " + trim(err.Error(), 100)}
	}
	if !v.Verified && v.Verdict == "unverified" {
		return &Finding{ID: "review-unverified", Severity: SevInfo, Package: in.Name, Message: "Claude flagged this but cited no real line, so the claim was discarded"}
	}
	var ev []string
	for _, c := range v.Citations {
		ev = append(ev, fmt.Sprintf("%s:%d %s", c.File, c.Line, trim(bundle.Rows[c.File][c.Line-1], 120)))
	}
	switch v.Verdict {
	case "malicious":
		return &Finding{ID: "claude-review", Severity: SevCritical, Package: in.Name, Message: "Claude judged the install code malicious: " + v.Summary, Evidence: ev}
	case "suspicious":
		sev := SevMedium
		if v.Confidence >= 0.6 {
			sev = SevHigh
		}
		return &Finding{ID: "claude-review", Severity: sev, Package: in.Name, Message: fmt.Sprintf("Claude judged the install code suspicious (confidence %.2f): %s", v.Confidence, v.Summary), Evidence: ev}
	default:
		return &Finding{ID: "claude-review", Severity: SevInfo, Package: in.Name, Message: "Claude reviewed the install code and found nothing malicious: " + v.Summary}
	}
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.0f h", d.Hours())
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// hasRegistryClient reports which ecosystems have a registry lookup (existence, age, downloads).
func hasRegistryClient(eco string) bool {
	switch eco {
	case "npm", "pypi", "crates.io", "rubygems":
		return true
	}
	return false
}
