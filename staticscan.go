package pkgguard

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The static scanner reads install-time code (manifest scripts and the files
// they run) and looks for the behaviours install-time malware shares:
// collecting secrets or the environment, sending them out, downloading and
// running code, hiding what the code does, and persisting. It needs no model
// and no key, so the guard is useful without Claude; Claude is the second
// opinion for what rules cannot settle.
//
// Nothing here executes the code. Rules are deliberately narrow: network
// access or a downloaded binary alone is normal for a native addon, so a rule
// fires on a *combination* (environment + network sink, secret path + network
// sink, download + execute) or on an unmistakable signature.

type scanRule struct {
	id       string
	re       *regexp.Regexp
	category string
}

var (
	// categories
	catEnvDump   = "env-dump"
	catNetwork   = "network"
	catSecret    = "secret-path"
	catRemote    = "remote-exec"
	catObfus     = "obfuscation"
	catPersist   = "persistence"
	catRevShell  = "reverse-shell"
	catBadHost   = "exfil-host"
	catRawIP     = "raw-ip"
	catInjection = "reviewer-injection"
)

var scanRules = []scanRule{
	// whole-environment collection (a spread into spawn env is normal, so it is not matched)
	{"stringify-env", regexp.MustCompile(`(?i)JSON\.stringify\(\s*process\.env|Object\.(keys|values|entries)\(\s*process\.env|os\.environ\b[^\n]{0,40}(json|dumps|items|copy|dict)|\bprintenv\b|\benv\s*\|\s*(curl|nc|base64)|\bset\s*\|\s*(curl|nc)`), catEnvDump},
	{"host-profile", regexp.MustCompile(`(?i)os\.(hostname|userInfo|networkInterfaces)\(\).{0,200}(post|request|fetch|send)|(hostname|username).{0,120}(webhook|collaborator|oast|interact\.sh)`), catEnvDump},

	// network sinks
	{"network-call", regexp.MustCompile(`(?i)https?\.(request|get)\(|\bfetch\(|\baxios[.(]|XMLHttpRequest|net\.(connect|Socket)|require\(['"](https?|net|dgram|tls)['"]\)|\bcurl\b|\bwget\b|Invoke-WebRequest|\bnslookup\b|dns\.(lookup|resolve)|requests\.(get|post)|urllib\.request|socket\.socket`), catNetwork},

	// known drop / exfil / tunnel hosts
	{"exfil-host", regexp.MustCompile(`(?i)webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|burpcollaborator|oast\.(pro|live|site|online|fun|me)|interact\.sh|canarytokens|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|transfer\.sh|pastebin\.com/raw|ipfs\.io/ipfs|\.pagekite\.me|serveo\.net|localhost\.run`), catBadHost},
	{"raw-ip", regexp.MustCompile(`https?://(\d{1,3}\.){3}\d{1,3}\b|['"](\d{1,3}\.){3}\d{1,3}['"]\s*,\s*\d{2,5}`), catRawIP},

	// secrets
	{"secret-path", regexp.MustCompile(`(?i)\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.npmrc\b|\.git-credentials|\.docker[/\\]config|\.kube[/\\]config|\.netrc\b|\.pypirc|wallet\.dat|Login Data|Local State|keychain|\.config[/\\](gcloud|gh)|/etc/(passwd|shadow)|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET|169\.254\.169\.254|metadata\.google\.internal`), catSecret},

	// download and run
	{"pipe-to-shell", regexp.MustCompile(`(?i)(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b|powershell[^\n]{0,80}(-enc|-e\s|-encodedcommand|iex|downloadstring)|\biex\s*\(|certutil[^\n]{0,60}-urlcache`), catRemote},
	{"download-exec", regexp.MustCompile(`(?i)(exec|execSync|spawn|spawnSync|system|popen)\([^)\n]{0,160}(curl|wget|powershell|bash|/bin/sh|cmd\.exe)[^)\n]{0,160}(http|\|)`), catRemote},
	{"eval-remote", regexp.MustCompile(`(?i)\beval\(\s*(await\s+)?(fetch|axios|https?\.)|new\s+Function\([^)]{0,100}(res|data|body|response)|vm\.(runIn\w+|Script)\(`), catRemote},

	// obfuscation
	{"base64-blob", regexp.MustCompile(`[A-Za-z0-9+/]{300,}={0,2}`), catObfus},
	{"decode-exec", regexp.MustCompile(`(?i)(eval|Function|exec|execSync)\(\s*(Buffer\.from|atob)\(|Buffer\.from\([^)]{20,}['"]\s*,\s*['"](base64|hex)['"]\)\s*\.toString|base64\s+(-d|--decode)\s*\|`), catObfus},
	{"charcode-array", regexp.MustCompile(`String\.fromCharCode\([^)]{40,}\)|(\\x[0-9a-fA-F]{2}){12,}|(\\u[0-9a-fA-F]{4}){10,}`), catObfus},
	{"js-obfuscator", regexp.MustCompile(`_0x[0-9a-f]{4,6}\b.{0,40}_0x[0-9a-f]{4,6}\b`), catObfus},

	// persistence
	{"persistence", regexp.MustCompile(`(?i)\.(bashrc|zshrc|profile|bash_profile)\b|crontab|/etc/cron|systemctl\s+(enable|--user)|LaunchAgents|LaunchDaemons|schtasks|CurrentVersion[/\\]Run|Start Menu[/\\]Programs[/\\]Startup|authorized_keys`), catPersist},

	// reverse shells
	{"reverse-shell", regexp.MustCompile(`(?i)/dev/tcp/|\bnc(at)?\b[^\n]{0,40}\s-e\s|bash\s+-i\s*>&|sh\s+-i\s*<&|socket\.(connect|create_connection)\([^)]*\)[^\n]{0,200}(spawn|exec|pty)|spawn\(\s*['"](/bin/)?(ba)?sh['"][^\n]{0,200}(pipe|socket)`), catRevShell},

	// text aimed at a reviewer rather than a machine
	{"reviewer-injection", regexp.MustCompile(`(?i)ignore (all )?(previous|prior|above) (instructions|prompts)|(this|the) package (is|has been) (audited|verified|reviewed|safe)|(ai|llm|automated) (reviewer|scanner|analyst)|do not (flag|report|block)|mark (this|it) as (benign|safe)`), catInjection},
}

// ScanInstallCode scans install-time scripts and files, returning findings
// for the package. Findings cite "file:line text" evidence.
func ScanInstallCode(pkg string, scripts map[string]string, files []EvidenceFile) []Finding {
	type hit struct {
		rule scanRule
		ev   string
	}
	hits := map[string]map[string]hit{} // file -> category -> first hit (also per-rule below)
	byRule := map[string][]string{}     // rule id -> evidence (across files)

	scan := func(file, text string) {
		lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		for _, r := range scanRules {
			for i, l := range lines {
				if r.re.MatchString(l) {
					ev := fmt.Sprintf("%s:%d %s", file, i+1, trim(strings.TrimSpace(l), 140))
					if hits[file] == nil {
						hits[file] = map[string]hit{}
					}
					if _, ok := hits[file][r.category]; !ok {
						hits[file][r.category] = hit{r, ev}
					}
					byRule[r.id] = append(byRule[r.id], ev)
					break
				}
			}
		}
	}
	var keys []string
	for k := range scripts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var manifest strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&manifest, "scripts.%s = %s\n", k, scripts[k])
	}
	if manifest.Len() > 0 {
		scan("package.json", manifest.String())
	}
	for _, f := range files {
		scan(f.Path, f.Content)
	}

	var out []Finding
	add := func(id string, sev Severity, msg string, ev []string) {
		out = append(out, Finding{ID: id, Severity: sev, Package: pkg, Message: msg, Evidence: dedupe(ev, 4)})
	}
	first := func(rules ...string) []string {
		var ev []string
		for _, r := range rules {
			ev = append(ev, byRule[r]...)
		}
		return ev
	}
	has := func(cat string, file string) bool { _, ok := hits[file][cat]; return ok }

	// Per-file combinations: the sink and the secret must be in the same file (or the manifest line).
	for file := range hits {
		net := has(catNetwork, file) || has(catBadHost, file) || has(catRawIP, file)
		if has(catEnvDump, file) && net {
			add("install-exfil-env", SevCritical, "install-time code serialises the environment and sends it over the network (credential theft)", first("stringify-env", "host-profile", "exfil-host", "raw-ip", "network-call"))
		}
		if has(catSecret, file) && net {
			add("install-exfil-secrets", SevCritical, "install-time code reads credential files or cloud metadata and talks to the network", first("secret-path", "exfil-host", "raw-ip", "network-call"))
		}
	}
	if len(byRule["pipe-to-shell"]) > 0 || len(byRule["download-exec"]) > 0 || len(byRule["eval-remote"]) > 0 {
		add("install-remote-exec", SevCritical, "install-time code downloads something and executes it", first("pipe-to-shell", "download-exec", "eval-remote"))
	}
	if len(byRule["reverse-shell"]) > 0 {
		add("install-reverse-shell", SevCritical, "install-time code opens a reverse shell", first("reverse-shell"))
	}
	if len(byRule["decode-exec"]) > 0 {
		add("install-obfuscated-exec", SevHigh, "install-time code decodes a hidden payload and runs it", first("decode-exec", "base64-blob", "charcode-array"))
	}
	if len(byRule["js-obfuscator"]) > 0 || (len(byRule["base64-blob"]) > 0 && len(byRule["network-call"]) > 0) || len(byRule["charcode-array"]) > 0 {
		add("install-obfuscation", SevHigh, "install-time code is obfuscated; legitimate install scripts have no reason to hide what they do", first("js-obfuscator", "charcode-array", "base64-blob"))
	}
	if len(byRule["persistence"]) > 0 && (len(byRule["network-call"]) > 0 || len(byRule["secret-path"]) == 0) {
		sev := SevHigh
		if len(byRule["network-call"]) == 0 {
			sev = SevMedium
		}
		add("install-persistence", sev, "install-time code writes itself into shell profiles, cron, startup items or authorized_keys", first("persistence"))
	}
	if len(byRule["exfil-host"]) > 0 {
		add("install-exfil-host", SevHigh, "install-time code contacts a disposable collection or tunnel host (webhook/requestbin/collaborator/tunnel)", first("exfil-host"))
	}
	if len(byRule["raw-ip"]) > 0 && len(byRule["exfil-host"]) == 0 {
		add("install-raw-ip", SevMedium, "install-time code contacts a raw IP address", first("raw-ip"))
	}
	if len(byRule["reviewer-injection"]) > 0 {
		add("reviewer-injection", SevHigh, "package text is addressed to an AI or human reviewer (\"this package is safe\", \"ignore previous instructions\"); real code does not do that", first("reviewer-injection"))
	}
	return out
}

func dedupe(in []string, n int) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
			if len(out) == n {
				break
			}
		}
	}
	return out
}
