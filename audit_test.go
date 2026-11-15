package pkgguard

import (
	"context"
	"testing"
)

const lockV3 = `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/express": {"version": "4.19.2", "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz"},
    "node_modules/chalk": {"version": "5.6.1", "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"},
    "node_modules/express/node_modules/debug": {"version": "2.6.9", "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"},
    "node_modules/@scope/helper": {"version": "1.0.0", "resolved": "https://evil.example/helper-1.0.0.tgz"},
    "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/someone/gitdep.git#abc123"},
    "node_modules/mylib": {"resolved": "packages/mylib", "link": true}
  }
}`

func TestParsePackageLock(t *testing.T) {
	in, err := ParsePackageLock([]byte(lockV3))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Intent{}
	for _, i := range in {
		got[i.Name] = i
	}
	if len(in) != 5 { // root and the workspace link are skipped
		t.Fatalf("want 5 packages, got %d: %v", len(in), names(Parsed{Installs: in}))
	}
	if got["debug"].Spec != "2.6.9" { // nested node_modules resolves to the innermost name
		t.Fatalf("nested package: %+v", got["debug"])
	}
	if got["@scope/helper"].Source != SourceURL || got["gitdep"].Source != SourceGit || got["express"].Source != SourceRegistry {
		t.Fatalf("sources wrong: %+v", got)
	}
}

func TestParsePackageLockV1(t *testing.T) {
	in, err := ParsePackageLock([]byte(`{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","dependencies":{"b":{"version":"2.0.0"}}}}}`))
	if err != nil || len(in) != 2 {
		t.Fatalf("%v %+v", err, in)
	}
}

func TestParseRequirements(t *testing.T) {
	in, notes := ParseRequirements(`
# comment
requests==2.31.0   # pinned
flask>=2.0; python_version >= "3.9"
numpy[extra]==1.26.0 --hash=sha256:abc
git+https://github.com/a/b.git#egg=b
-r other.txt
--extra-index-url https://pypi.evil.example/simple
-e ./local
`)
	got := names(Parsed{Installs: in})
	want := map[string]bool{"pypi:requests@==2.31.0": true, "pypi:flask@>=2.0": true, "pypi:numpy@==1.26.0": true}
	for _, g := range got {
		delete(want, g)
	}
	if len(want) != 0 {
		t.Fatalf("missing %v in %v", want, got)
	}
	var extra, git bool
	for _, i := range in {
		extra = extra || (i.ExtraIndex && len(i.Registries) == 1)
		git = git || i.Source == SourceGit
	}
	if !extra || !git || len(notes) != 1 || notes[0].ID != "requirements-include" {
		t.Fatalf("extra=%v git=%v notes=%+v", extra, git, notes)
	}
}

func TestAuditFindsMalwareAndPoisonedLockfile(t *testing.T) {
	in, _ := ParsePackageLock([]byte(lockV3))
	reg := &fakeRegistry{}
	mal := fakeMalware{"npm|chalk@5.6.1": {"MAL-2025-3"}}
	rep := newTestEngine(Config{}, reg, mal, nil).Audit(context.Background(), in, AuditOptions{})

	if rep.Scanned != 5 {
		t.Fatalf("scanned %d", rep.Scanned)
	}
	byID := map[string]Finding{}
	for _, f := range rep.Findings {
		byID[f.ID+"|"+f.Package] = f
	}
	if f, ok := byID["known-malware|chalk@5.6.1"]; !ok || f.Severity != SevCritical || f.Evidence[0] != "MAL-2025-3" {
		t.Fatalf("pinned malware not reported: %+v", rep.Findings)
	}
	if _, ok := byID["source-url|@scope/helper@1.0.0"]; !ok {
		t.Fatalf("foreign resolved URL not flagged: %+v", rep.Findings)
	}
	if _, ok := byID["source-git|gitdep@1.0.0"]; !ok {
		t.Fatalf("git source not flagged: %+v", rep.Findings)
	}
	if rep.Worst() != SevCritical {
		t.Fatalf("worst = %s", rep.Worst())
	}
	for _, f := range rep.Findings {
		if f.Package == "express@4.19.2" {
			t.Fatalf("clean package got a finding: %+v", f)
		}
	}
}

func TestAuditCleanLockfile(t *testing.T) {
	in, _ := ParsePackageLock([]byte(`{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.19.2","resolved":"https://registry.npmjs.org/express/-/express-4.19.2.tgz"}}}`))
	rep := newTestEngine(Config{}, &fakeRegistry{}, fakeMalware{}, nil).Audit(context.Background(), in, AuditOptions{})
	if len(rep.Findings) != 0 || rep.Worst() != SevInfo {
		t.Fatalf("a clean lockfile must audit clean: %+v", rep.Findings)
	}
}

func TestAuditDeepRunsPerPackageChecks(t *testing.T) {
	in := []Intent{{Manager: "pip", Ecosystem: "pypi", Name: "flask-made-up-thing", Spec: "==1.0", Source: SourceRegistry}}
	reg := &fakeRegistry{} // the package does not exist
	rep := newTestEngine(Config{}, reg, fakeMalware{}, nil).Audit(context.Background(), in, AuditOptions{Deep: true})
	if rep.Deep != 1 || rep.Worst() < SevHigh {
		t.Fatalf("deep audit should flag the phantom package: %+v", rep)
	}
	fast := newTestEngine(Config{}, reg, fakeMalware{}, nil).Audit(context.Background(), in, AuditOptions{})
	if len(fast.Findings) != 0 {
		t.Fatalf("fast mode does not look at the registry: %+v", fast.Findings)
	}
}

func TestAuditDeepHonoursLimit(t *testing.T) {
	var in []Intent
	for i := 0; i < 5; i++ {
		in = append(in, Intent{Ecosystem: "npm", Name: string(rune('a'+i)) + "pkg", Spec: "1.0.0", Source: SourceRegistry})
	}
	rep := newTestEngine(Config{}, &fakeRegistry{}, fakeMalware{}, nil).Audit(context.Background(), in, AuditOptions{Deep: true, DeepLimit: 2})
	if rep.Deep != 2 || !rep.Truncated {
		t.Fatalf("deep=%d truncated=%v", rep.Deep, rep.Truncated)
	}
}
