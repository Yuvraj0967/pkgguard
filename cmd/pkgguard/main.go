// Command pkgguard is the command line for the pkgguard Bifrost plugin: it runs
// the same checks without a gateway.
//
//	pkgguard check "npm install expresss"
//	pkgguard audit [-deep] [file...]
//	pkgguard bench
//	pkgguard demo
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkgguard/pkgguard"
)

func usage() {
	fmt.Fprintln(os.Stderr, `pkgguard - guard what AI agents install (a Bifrost gateway plugin; this is its command line)

usage:
  pkgguard check [flags] "<shell command>"   check one install command
  pkgguard audit [flags] [file...]           audit package-lock.json, package.json, requirements.txt
                                             (no file: whatever is in the current directory)
  pkgguard bench [-json] [-v]                run the built-in red-team benchmark (offline, deterministic)
  pkgguard demo [-dashboard] [-pause 1s]     scripted agent session through the real Bifrost core
  pkgguard proxy -upstream URL [-listen ADDR] [-dashboard ADDR]
                                             guard any OpenAI-compatible endpoint, e.g. a stock Bifrost,
                                             with no plugin loading (see README, "Standard install")
  pkgguard agent -model M "task"             a small real coding agent (real model via any OpenAI-compatible
                                             endpoint); dry run by default, -exec runs commands in a temp dir

flags (check, audit):
  -offline        never contact registries, OSV or Claude (local rules only)
  -json           print machine-readable output
  -config FILE    plugin config JSON (the same object as in Bifrost's config.json)
  -monitor        report only; never "block"
  -deep           (audit) also run registry, install-script and Claude checks on up to 100 packages

environment:
  ANTHROPIC_API_KEY   enables the Claude reviewer for flagged npm packages

exit status: 0 allow/clean, 1 warn, 2 block/problems found, 3 error`)
}

type common struct {
	offline, asJSON, monitor *bool
	cfgPath                  *string
}

func addCommon(fs *flag.FlagSet) common {
	fs.Usage = usage
	return common{
		offline: fs.Bool("offline", false, ""),
		asJSON:  fs.Bool("json", false, ""),
		monitor: fs.Bool("monitor", false, ""),
		cfgPath: fs.String("config", "", ""),
	}
}

func (c common) engine() *pkgguard.Engine {
	e, err := pkgguard.NewEngine(c.config())
	if err != nil {
		fail("%v", err)
	}
	return e
}

func (c common) config() pkgguard.Config {
	var cfg pkgguard.Config
	if *c.cfgPath != "" {
		b, err := os.ReadFile(*c.cfgPath)
		if err == nil {
			err = json.Unmarshal(b, &cfg)
		}
		if err != nil {
			fail("config: %v", err)
		}
	}
	cfg.Offline = cfg.Offline || *c.offline
	if *c.monitor {
		cfg.Mode = "monitor"
	}
	return cfg
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(3)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(3)
	}
	switch os.Args[1] {
	case "check":
		runCheck(os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	case "demo":
		runDemo(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	case "agent":
		runAgent(os.Args[2:])
	default:
		usage()
		os.Exit(3)
	}
}

func printFindings(fs []pkgguard.Finding) {
	for _, f := range fs {
		pkg := ""
		if f.Package != "" {
			pkg = f.Package + ": "
		}
		fmt.Printf("  [%-8s] %-22s %s%s\n", f.Severity, f.ID, pkg, f.Message)
		for _, ev := range f.Evidence {
			fmt.Printf("               > %s\n", ev)
		}
		if f.Hint != "" {
			fmt.Printf("               hint: %s\n", f.Hint)
		}
	}
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	c := addCommon(fs)
	fs.Parse(args)
	if fs.NArg() == 0 {
		usage()
		os.Exit(3)
	}
	e := c.engine()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d := e.Analyze(ctx, strings.Join(fs.Args(), " "))

	if *c.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(d)
	} else {
		fmt.Printf("command : %s\n", d.Command)
		for _, in := range d.Intents {
			v := ""
			if in.Spec != "" {
				v = "@" + in.Spec
			}
			fmt.Printf("installs: %s %s%s\n", in.Ecosystem, in.Name, v)
		}
		fmt.Printf("verdict : %s\n", strings.ToUpper(string(d.Action)))
		printFindings(d.Findings)
	}
	switch d.Action {
	case pkgguard.ActionBlock:
		os.Exit(2)
	case pkgguard.ActionWarn:
		os.Exit(1)
	}
}

func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	c := addCommon(fs)
	deep := fs.Bool("deep", false, "")
	fs.Parse(args)

	files := fs.Args()
	if len(files) == 0 {
		for _, n := range []string{"package-lock.json", "package.json", "requirements.txt"} {
			if _, err := os.Stat(n); err == nil {
				files = append(files, n)
			}
		}
	}
	if len(files) == 0 {
		fail("no package-lock.json, package.json or requirements.txt here; pass a file")
	}
	var intents []pkgguard.Intent
	var notes []pkgguard.Finding
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fail("%v", err)
		}
		var in []pkgguard.Intent
		switch base := strings.ToLower(filepath.Base(f)); {
		case base == "package-lock.json" || base == "npm-shrinkwrap.json":
			in, err = pkgguard.ParsePackageLock(b)
		case base == "package.json":
			in, err = pkgguard.ParsePackageJSON(b)
		case strings.HasSuffix(base, ".txt"):
			var n []pkgguard.Finding
			in, n = pkgguard.ParseRequirements(string(b))
			notes = append(notes, n...)
		default:
			fail("don't know how to read %s (supported: package-lock.json, package.json, requirements*.txt)", f)
		}
		if err != nil {
			fail("%v", err)
		}
		intents = append(intents, in...)
	}
	e := c.engine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rep := e.Audit(ctx, intents, pkgguard.AuditOptions{Deep: *deep})
	rep.Findings = append(rep.Findings, notes...)

	if *c.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	} else {
		fmt.Printf("audited %s: %d packages", strings.Join(files, ", "), rep.Scanned)
		if *deep {
			fmt.Printf(" (%d checked in depth", rep.Deep)
			if rep.Truncated {
				fmt.Print(", more were skipped: raise the limit or audit fewer files")
			}
			fmt.Print(")")
		}
		fmt.Println()
		if len(rep.Findings) == 0 {
			fmt.Println("no problems found")
		} else {
			printFindings(rep.Findings)
		}
		if !*deep {
			fmt.Println("(fast mode: pinned versions checked against OSV and lockfile sources; add -deep for registry, install-script and Claude checks)")
		}
	}
	if rep.Worst() >= pkgguard.SevHigh {
		os.Exit(2)
	}
	if rep.Worst() >= pkgguard.SevMedium {
		os.Exit(1)
	}
}
