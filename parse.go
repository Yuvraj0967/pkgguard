package pkgguard

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// SourceKind says where a package spec points.
type SourceKind string

const (
	SourceRegistry SourceKind = "registry"
	SourceGit      SourceKind = "git"
	SourceURL      SourceKind = "url"
	SourcePath     SourceKind = "path"
)

// Intent is one package an install command would fetch or run.
type Intent struct {
	Manager    string     `json:"manager"`   // npm, pnpm, yarn, bun, pip, uv, pipx, poetry, cargo, go, gem
	Ecosystem  string     `json:"ecosystem"` // npm, pypi, crates.io, go, rubygems
	Name       string     `json:"name"`
	Spec       string     `json:"spec,omitempty"` // version, range or tag as typed
	Source     SourceKind `json:"source"`
	Run        bool       `json:"run,omitempty"`         // npx / dlx / uvx: fetch and execute at once
	Registries []string   `json:"registries,omitempty"`  // registry or index URLs given on the command line
	ExtraIndex bool       `json:"extra_index,omitempty"` // pip --extra-index-url (dependency-confusion vector)
	Raw        string     `json:"raw"`                   // the shell segment it came from
	Resolved   string     `json:"resolved,omitempty"`    // lockfile entries: where the lockfile says the archive lives
}

func (i Intent) key() string {
	return i.Ecosystem + "|" + normalizeName(i.Ecosystem, i.Name) + "|" + i.Spec + "|" + string(i.Source)
}

// Parsed is everything the parser found in one command string.
type Parsed struct {
	Installs []Intent
	Findings []Finding // command-level findings (pipe to shell, requirements files, ...)
}

type segment struct {
	words []string
	sep   string // operator that follows this segment: ; && || | & or ""
}

// splitSegments tokenises a shell command into segments and words. It is a
// pragmatic splitter, not a shell: it understands quotes, escapes, the
// operators ; && || | & and newlines, and drops redirections.
func splitSegments(cmd string) []segment {
	var segs []segment
	var words []string
	var cur strings.Builder
	have := false // a word is in progress (so "" counts)
	flushWord := func() {
		if have {
			words = append(words, cur.String())
		}
		cur.Reset()
		have = false
	}
	endSeg := func(sep string) {
		flushWord()
		if len(words) > 0 || sep != "" {
			segs = append(segs, segment{words: stripRedirects(words), sep: sep})
		}
		words = nil
	}
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\'':
			have = true
			for i++; i < len(rs) && rs[i] != '\''; i++ {
				cur.WriteRune(rs[i])
			}
		case c == '"':
			have = true
			for i++; i < len(rs) && rs[i] != '"'; i++ {
				if rs[i] == '\\' && i+1 < len(rs) && strings.ContainsRune("\"\\$`", rs[i+1]) {
					i++
				}
				cur.WriteRune(rs[i])
			}
		case c == '\\' && i+1 < len(rs):
			have = true
			i++
			if rs[i] != '\n' { // line continuation
				cur.WriteRune(rs[i])
			}
		case c == ' ' || c == '\t' || c == '\r':
			flushWord()
		case c == '\n' || c == ';':
			endSeg(";")
		case c == '&' && i+1 < len(rs) && rs[i+1] == '&':
			i++
			endSeg("&&")
		case c == '|' && i+1 < len(rs) && rs[i+1] == '|':
			i++
			endSeg("||")
		case c == '|':
			endSeg("|")
		case c == '&' && (cur.Len() > 0 && strings.HasSuffix(cur.String(), ">")): // 2>&1
			cur.WriteRune(c)
			have = true
		case c == '&':
			endSeg("&")
		default:
			cur.WriteRune(c)
			have = true
		}
	}
	endSeg("")
	return segs
}

var redirRe = regexp.MustCompile(`^\d*(>>?|<)(&\d+)?`)

func stripRedirects(words []string) []string {
	var out []string
	for i := 0; i < len(words); i++ {
		w := words[i]
		if m := redirRe.FindString(w); m != "" {
			if m == w && !strings.Contains(w, "&") { // bare ">" takes the next word as its target
				i++
			}
			continue
		}
		out = append(out, w)
	}
	return out
}

var envAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func baseCmd(w string) string {
	w = strings.ReplaceAll(w, "\\", "/")
	w = path.Base(w)
	w = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(w, ".cmd"), ".exe"), ".ps1")
	return strings.ToLower(w)
}

// stripWrappers removes sudo/env/time/VAR=x prefixes and returns the rest.
func stripWrappers(words []string) []string {
	for len(words) > 0 {
		w := words[0]
		switch {
		case envAssign.MatchString(w):
			words = words[1:]
		case baseCmd(w) == "sudo" || baseCmd(w) == "doas":
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				if words[0] == "-u" || words[0] == "-g" {
					words = words[min(2, len(words)):]
				} else {
					words = words[1:]
				}
			}
		case baseCmd(w) == "env" || baseCmd(w) == "time" || baseCmd(w) == "nohup" || baseCmd(w) == "command" || baseCmd(w) == "exec" || baseCmd(w) == "nice":
			words = words[1:]
			for len(words) > 0 && (strings.HasPrefix(words[0], "-") || envAssign.MatchString(words[0])) {
				words = words[1:]
			}
		default:
			return words
		}
	}
	return words
}

var (
	shellNames    = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true}
	interpreters  = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "python": true, "python3": true, "node": true, "perl": true, "ruby": true, "powershell": true, "pwsh": true, "iex": true}
	fetchers      = map[string]bool{"curl": true, "wget": true, "iwr": true, "invoke-webrequest": true}
	subshellFetch = regexp.MustCompile(`(?i)(\$\(|<\(|` + "`" + `)\s*(curl|wget)\b`)
)

// ParseCommand extracts package installs and command-level risks from a shell command.
func ParseCommand(cmd string) Parsed {
	var out Parsed
	parseInto(cmd, 0, &out)
	return out
}

func parseInto(cmd string, depth int, out *Parsed) {
	if depth > 3 || strings.TrimSpace(cmd) == "" {
		return
	}
	segs := splitSegments(cmd)
	for i, s := range segs {
		words := stripWrappers(s.words)
		if len(words) == 0 {
			continue
		}
		raw := strings.Join(s.words, " ")
		cmdName := baseCmd(words[0])

		// curl ... | sh
		if fetchers[cmdName] && s.sep == "|" && i+1 < len(segs) {
			next := stripWrappers(segs[i+1].words)
			if len(next) > 0 && interpreters[baseCmd(next[0])] {
				out.Findings = append(out.Findings, Finding{
					ID: "pipe-to-shell", Severity: SevHigh,
					Message:  "downloads a script and pipes it straight into an interpreter; nothing can inspect it first",
					Evidence: []string{trim(raw+" | "+strings.Join(segs[i+1].words, " "), 200)},
					Hint:     "download the script to a file, read it, then run it",
				})
			}
			continue
		}

		// sh -c "<script>"  (recurse; also catches sh -c "$(curl ...)")
		if shellNames[cmdName] {
			for j := 1; j+1 < len(words); j++ {
				if words[j] == "-c" || (strings.HasPrefix(words[j], "-") && strings.HasSuffix(words[j], "c") && !strings.HasPrefix(words[j], "--")) {
					script := words[j+1]
					if subshellFetch.MatchString(script) {
						out.Findings = append(out.Findings, Finding{
							ID: "pipe-to-shell", Severity: SevHigh,
							Message:  "runs a script fetched on the fly with curl/wget; nothing can inspect it first",
							Evidence: []string{trim(raw, 200)},
							Hint:     "download the script to a file, read it, then run it",
						})
					}
					parseInto(script, depth+1, out)
					break
				}
			}
			continue
		}

		switch cmdName {
		case "npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx":
			parseJS(cmdName, words[1:], raw, out)
		case "pip", "pip3", "uv", "uvx", "pipx", "poetry", "python", "python3", "py":
			parsePy(cmdName, words[1:], raw, out)
		case "cargo":
			parseCargo(words[1:], raw, out)
		case "go":
			parseGo(words[1:], raw, out)
		case "gem":
			parseGem(words[1:], raw, out)
		}
	}
}

// ---- argument helpers -------------------------------------------------------

// scanArgs splits args into positionals and registry URLs. valueFlags consume the
// next word; registryFlags additionally record it as a registry/index URL.
func scanArgs(args []string, valueFlags, registryFlags map[string]bool) (pos []string, regs []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		if valueFlags[name] || registryFlags[name] {
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
			flags[name] = val
			if registryFlags[name] {
				regs = append(regs, val)
			}
			continue
		}
		flags[name] = ""
	}
	return
}

func set(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---- JavaScript ---------------------------------------------------------------

var (
	npmInstall = set("install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add", "install-test", "it", "link", "ln")
	npmExec    = set("exec", "x")
	npmCreate  = set("create", "init", "innit")
	jsValue    = set("--prefix", "--tag", "-w", "--workspace", "--cache", "--userconfig", "--save-prefix", "--before", "--omit", "--include", "--loglevel", "--otp", "--scope", "-C", "--filter", "-F", "--dir", "--store-dir", "--reporter", "--cwd", "--modules-folder", "--cache-folder", "--config", "-c", "-p", "--package", "--call", "--shell")
	jsRegistry = set("--registry")
)

func parseJS(mgr string, args []string, raw string, out *Parsed) {
	run := false
	sub := ""
	rest := args
	switch mgr {
	case "npx", "pnpx", "bunx":
		run = true
	default:
		// skip leading global flags to find the subcommand
		for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return
		}
		sub = strings.ToLower(rest[0])
		rest = rest[1:]
		// "yarn global add x", "pnpm -g add x", "pnpm dlx x"
		if mgr == "yarn" && sub == "global" && len(rest) > 0 {
			sub, rest = strings.ToLower(rest[0]), rest[1:]
		}
	}
	create := false
	switch {
	case run:
	case mgr == "npm" && npmInstall[sub], mgr == "pnpm" && (sub == "add" || sub == "install" || sub == "i"),
		mgr == "yarn" && sub == "add", mgr == "bun" && (sub == "add" || sub == "a" || sub == "install" || sub == "i"):
	case (mgr == "npm" && npmExec[sub]) || (mgr == "pnpm" && sub == "dlx") || (mgr == "yarn" && sub == "dlx") || (mgr == "bun" && sub == "x"):
		run = true
	case (mgr != "bun" && npmCreate[sub]) || (mgr == "bun" && sub == "create"):
		run, create = true, true
	default:
		return
	}
	pos, regs, flags := scanArgs(rest, jsValue, jsRegistry)
	if run {
		// `npx -p pkg cmd` : the package is the -p value; otherwise the first positional is it.
		var pkgs []string
		if v := firstNonEmpty(flags["--package"], flags["-p"]); v != "" {
			pkgs = append(pkgs, v)
		} else if len(pos) > 0 {
			pkgs = append(pkgs, pos[0])
		}
		pos = pkgs
	}
	for _, p := range pos {
		in := Intent{Manager: mgr, Ecosystem: "npm", Run: run, Registries: regs, Raw: raw}
		if create {
			p = createName(p)
		}
		in.Name, in.Spec, in.Source = parseNpmSpec(p)
		if in.Name == "" && in.Source == SourceRegistry {
			continue
		}
		out.Installs = append(out.Installs, in)
	}
	if len(pos) == 0 && len(regs) > 0 { // `npm install --registry http://evil` with no package still matters
		out.Installs = append(out.Installs, Intent{Manager: mgr, Ecosystem: "npm", Source: SourcePath, Name: "(project dependencies)", Registries: regs, Raw: raw})
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// createName maps `npm create vite` to its real package, create-vite.
func createName(p string) string {
	switch {
	case strings.HasPrefix(p, "@"):
		scope, rest, ok := strings.Cut(p, "/")
		if !ok {
			return scope + "/create"
		}
		return scope + "/create-" + rest
	default:
		name, ver, ok := strings.Cut(p, "@")
		if ok {
			return "create-" + name + "@" + ver
		}
		return "create-" + p
	}
}

var ghShorthand = regexp.MustCompile(`^[A-Za-z0-9][\w.-]*/[\w.-]+(#.*)?$`)

func parseNpmSpec(s string) (name, spec string, src SourceKind) {
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "git+"), strings.HasPrefix(low, "git://"), strings.HasPrefix(low, "git@"),
		strings.HasPrefix(low, "github:"), strings.HasPrefix(low, "gitlab:"), strings.HasPrefix(low, "bitbucket:"),
		strings.HasSuffix(strings.SplitN(low, "#", 2)[0], ".git"):
		return s, "", SourceGit
	case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
		return s, "", SourceURL
	case strings.HasPrefix(low, "file:"), strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"), strings.HasPrefix(s, "/"),
		strings.HasPrefix(s, "~"), strings.HasPrefix(s, "."), strings.HasSuffix(low, ".tgz"), strings.HasSuffix(low, ".tar.gz"), strings.HasPrefix(low, "link:"), strings.HasPrefix(low, "workspace:"):
		return s, "", SourcePath
	case !strings.HasPrefix(s, "@") && ghShorthand.MatchString(s):
		return s, "", SourceGit
	}
	if strings.HasPrefix(low, "npm:") { // alias: foo@npm:real@1.0.0 handled below; bare npm:real@1
		s = s[4:]
	}
	var n, v string
	if strings.HasPrefix(s, "@") {
		idx := strings.Index(s[1:], "@")
		if idx < 0 {
			n = s
		} else {
			n, v = s[:idx+1], s[idx+2:]
		}
	} else {
		n, v, _ = strings.Cut(s, "@")
	}
	if strings.HasPrefix(strings.ToLower(v), "npm:") { // name@npm:real@1.0.0 -> real
		return parseNpmSpec(v[4:])
	}
	if strings.Contains(v, "://") || strings.HasPrefix(v, "git+") || strings.HasPrefix(strings.ToLower(v), "github:") {
		return n, v, SourceURL
	}
	return n, v, SourceRegistry
}

// ---- Python ---------------------------------------------------------------------

var (
	pyValue = set("-c", "--constraint", "-f", "--find-links", "--target", "-t", "--prefix", "--root", "--python", "-p", "--platform", "--python-version",
		"--implementation", "--abi", "--proxy", "--cert", "--trusted-host", "--src", "--no-binary", "--only-binary", "--group", "--resolution", "--python-preference", "--project", "--directory", "--cache-dir", "--config-file", "--with-requirements", "--extra", "--tag", "--suffix", "--spec")
	pyRegistry = set("-i", "--index-url", "--extra-index-url", "--index", "--default-index", "--index-strategy-url")
	pySpecFlag = set("--with", "--from", "--editable", "-e", "--with-editable")
	reqFlag    = set("-r", "--requirement")
)

func parsePy(cmdName string, args []string, raw string, out *Parsed) {
	mgr := cmdName
	var rest []string
	run := false
	switch cmdName {
	case "python", "python3", "py":
		// python -m pip install ... / python -m uv pip install ...
		i := 0
		for i < len(args) && args[i] != "-m" {
			i++
		}
		if i+1 >= len(args) {
			return
		}
		mod := args[i+1]
		rest = args[i+2:]
		switch mod {
		case "pip":
			mgr = "pip"
		case "uv":
			mgr = "uv"
		case "pipx":
			mgr = "pipx"
		default:
			return
		}
		parsePyManager(mgr, rest, raw, out)
		return
	case "pip", "pip3":
		mgr = "pip"
	case "uvx":
		parsePySpecs("uv", args, raw, out, true)
		return
	}
	parsePyManager(mgr, args, raw, out)
	_ = run
}

func parsePyManager(mgr string, args []string, raw string, out *Parsed) {
	// find subcommand (first non-flag word)
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		i++
	}
	if i >= len(args) {
		return
	}
	sub := strings.ToLower(args[i])
	rest := args[i+1:]
	switch mgr {
	case "pip":
		if sub != "install" {
			return
		}
		parsePySpecs("pip", rest, raw, out, false)
	case "uv":
		switch sub {
		case "pip":
			if len(rest) > 0 && strings.ToLower(rest[0]) == "install" {
				parsePySpecs("uv", rest[1:], raw, out, false)
			}
		case "add":
			parsePySpecs("uv", rest, raw, out, false)
		case "tool":
			if len(rest) > 0 {
				switch strings.ToLower(rest[0]) {
				case "install":
					parsePySpecs("uv", rest[1:], raw, out, false)
				case "run":
					parsePySpecs("uv", rest[1:], raw, out, true)
				}
			}
		case "run":
			// `uv run --with pkg cmd` fetches pkg
			parsePySpecs("uv", withOnly(rest), raw, out, false)
		}
	case "pipx":
		switch sub {
		case "install", "inject":
			parsePySpecs("pipx", rest, raw, out, false)
		case "run":
			parsePySpecs("pipx", rest, raw, out, true)
		}
	case "poetry":
		if sub == "add" {
			parsePySpecs("poetry", rest, raw, out, false)
		}
	}
}

// withOnly keeps only the --with / --with-editable pairs of a `uv run` command.
func withOnly(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--with" && i+1 < len(args) {
			out = append(out, args[i+1])
			i++
		} else if strings.HasPrefix(args[i], "--with=") {
			out = append(out, args[i][len("--with="):])
		}
	}
	return out
}

func parsePySpecs(mgr string, args []string, raw string, out *Parsed, run bool) {
	vf := map[string]bool{}
	for k := range pyValue {
		vf[k] = true
	}
	for k := range pySpecFlag {
		vf[k] = true
	}
	for k := range reqFlag {
		vf[k] = true
	}
	pos, regs, flags := scanArgs(args, vf, pyRegistry)
	_, extra := flags["--extra-index-url"]
	var specs []string
	for _, f := range []string{"--with", "--from"} {
		if v := flags[f]; v != "" {
			specs = append(specs, v)
		}
	}
	if run && len(specs) == 0 && len(pos) > 0 {
		specs = append(specs, pos[0]) // the tool itself
	} else if !run {
		for i := 0; i < len(pos); i++ { // unquoted PEP 508 direct reference: name @ url
			if i+2 < len(pos) && pos[i+1] == "@" {
				specs = append(specs, pos[i]+" @ "+pos[i+2])
				i += 2
				continue
			}
			specs = append(specs, pos[i])
		}
	}
	if v := firstNonEmpty(flags["-e"], flags["--editable"]); v != "" {
		out.Findings = append(out.Findings, Finding{ID: "editable-install", Severity: SevInfo, Message: "editable install of " + v + " (local path, not checked)"})
	}
	if v := firstNonEmpty(flags["-r"], flags["--requirement"]); v != "" {
		out.Findings = append(out.Findings, Finding{ID: "requirements-file", Severity: SevInfo,
			Message: "installs everything in requirements file " + v + ", which is not read here; run `pkgguard audit -deep FILE` on it first"})
	}
	for _, s := range specs {
		name, spec, src := parsePySpec(s)
		if name == "" {
			continue
		}
		out.Installs = append(out.Installs, Intent{Manager: mgr, Ecosystem: "pypi", Name: name, Spec: spec, Source: src, Run: run, Registries: regs, ExtraIndex: extra, Raw: raw})
	}
	if len(specs) == 0 && len(regs) > 0 {
		out.Installs = append(out.Installs, Intent{Manager: mgr, Ecosystem: "pypi", Name: "(project dependencies)", Source: SourcePath, Registries: regs, ExtraIndex: extra, Raw: raw})
	}
}

var pySplit = regexp.MustCompile(`[=<>!~;\s@\[]`)

func parsePySpec(s string) (name, spec string, src SourceKind) {
	if n, u, ok := strings.Cut(s, " @ "); ok { // PEP 508 direct reference
		if strings.HasPrefix(strings.ToLower(u), "git+") {
			return strings.TrimSpace(n), strings.TrimSpace(u), SourceGit
		}
		return strings.TrimSpace(n), strings.TrimSpace(u), SourceURL
	}
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "git+"), strings.HasPrefix(low, "git://"):
		return s, "", SourceGit
	case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
		return s, "", SourceURL
	case s == ".", strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"), strings.HasPrefix(s, "/"), strings.HasPrefix(s, "~"),
		strings.HasSuffix(low, ".whl"), strings.HasSuffix(low, ".tar.gz"), strings.HasSuffix(low, ".zip"), strings.HasPrefix(low, "file:"):
		return s, "", SourcePath
	}
	loc := pySplit.FindStringIndex(s)
	if loc == nil {
		return s, "", SourceRegistry
	}
	name = strings.TrimSpace(s[:loc[0]])
	rest := strings.TrimSpace(s[loc[0]:])
	if strings.HasPrefix(rest, "@") { // name @ https://...
		return name, strings.TrimSpace(rest[1:]), SourceURL
	}
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end >= 0 {
			rest = strings.TrimSpace(rest[end+1:])
		}
	}
	if strings.HasPrefix(rest, "@") {
		return name, strings.TrimSpace(rest[1:]), SourceURL
	}
	return name, strings.TrimLeft(rest, " "), SourceRegistry
}

// ---- Rust / Go / Ruby --------------------------------------------------------------

func parseCargo(args []string, raw string, out *Parsed) {
	if len(args) == 0 {
		return
	}
	sub := strings.ToLower(args[0])
	if sub != "add" && sub != "install" {
		return
	}
	pos, regs, flags := scanArgs(args[1:], set("--vers", "--version", "--features", "-F", "--rename", "--package", "-p", "--manifest-path", "--root", "--bin", "--example", "--branch", "--tag", "--rev", "--target", "--path", "--git"), set("--registry", "--index"))
	_, git := flags["--git"]
	for _, p := range pos {
		name, spec, _ := strings.Cut(p, "@")
		src := SourceRegistry
		if git {
			src, name = SourceGit, p
		}
		if v := flags["--path"]; v != "" {
			src = SourcePath
		}
		out.Installs = append(out.Installs, Intent{Manager: "cargo", Ecosystem: "crates.io", Name: name, Spec: firstNonEmpty(spec, flags["--vers"], flags["--version"]), Source: src, Run: sub == "install", Registries: regs, Raw: raw})
	}
	if git && len(pos) == 0 {
		out.Installs = append(out.Installs, Intent{Manager: "cargo", Ecosystem: "crates.io", Name: flags["--git"], Source: SourceGit, Raw: raw})
	}
}

func parseGo(args []string, raw string, out *Parsed) {
	if len(args) == 0 || (args[0] != "get" && args[0] != "install") {
		return
	}
	pos, _, _ := scanArgs(args[1:], set("-C", "-tags", "-o", "-ldflags", "-gcflags", "-mod"), nil)
	for _, p := range pos {
		if p == "./..." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, ".") {
			continue
		}
		name, spec, _ := strings.Cut(p, "@")
		out.Installs = append(out.Installs, Intent{Manager: "go", Ecosystem: "go", Name: name, Spec: spec, Source: SourceRegistry, Run: args[0] == "install", Raw: raw})
	}
}

func parseGem(args []string, raw string, out *Parsed) {
	if len(args) == 0 || args[0] != "install" {
		return
	}
	pos, regs, flags := scanArgs(args[1:], set("-v", "--version", "--install-dir", "-i", "--bindir", "-n", "--platform"), set("-s", "--source", "--clear-sources"))
	for _, p := range pos {
		src := SourceRegistry
		if strings.HasSuffix(p, ".gem") || strings.HasPrefix(p, "./") {
			src = SourcePath
		}
		out.Installs = append(out.Installs, Intent{Manager: "gem", Ecosystem: "rubygems", Name: p, Spec: firstNonEmpty(flags["-v"], flags["--version"]), Source: src, Registries: regs, Raw: raw})
	}
}

// registryHost returns the host of a registry URL as typed on a command line.
func registryHost(u string) string {
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return strings.ToLower(p.Hostname())
}
