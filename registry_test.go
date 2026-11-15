package pkgguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestHTTPRegistryNPM(t *testing.T) {
	tarball := makeTarball(t, map[string]string{
		"package.json": `{"name":"pretty-logs"}`,
		"setup.js":     "line1\nline2\n",
		"unrelated.js": "x",
	})
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pretty-logs":
			json.NewEncoder(w).Encode(map[string]any{
				"dist-tags": map[string]string{"latest": "1.2.0", "next": "2.0.0-rc.1"},
				"time": map[string]string{"created": "2026-11-10T00:00:00.000Z", "1.1.0": "2026-11-10T00:00:00.000Z",
					"1.2.0": "2026-11-15T10:00:00.000Z", "2.0.0-rc.1": "2026-11-14T00:00:00.000Z"},
				"versions": map[string]any{
					"1.1.0":      map[string]any{},
					"2.0.0-rc.1": map[string]any{},
					"1.2.0": map[string]any{
						"scripts":      map[string]string{"postinstall": "node setup.js", "test": "jest"},
						"dependencies": map[string]string{"chalk": "^5", "abc": "1"},
						"dist":         map[string]string{"tarball": srv.URL + "/tgz/pretty-logs.tgz"},
					},
				},
			})
		case "/tgz/pretty-logs.tgz":
			w.Write(tarball)
		case "/@scope/pkg":
			json.NewEncoder(w).Encode(map[string]any{"dist-tags": map[string]string{"latest": "1.0.0"}, "time": map[string]string{"1.0.0": "2020-01-01T00:00:00.000Z"}, "versions": map[string]any{"1.0.0": map[string]any{}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := NewHTTPRegistry()
	r.NPMBase = srv.URL
	r.AllowInsecureTarballs = true

	info, err := r.Lookup(context.Background(), "npm", "pretty-logs", "")
	if err != nil || !info.Exists {
		t.Fatalf("lookup: %v %+v", err, info)
	}
	if info.Version != "1.2.0" || info.Scripts["postinstall"] != "node setup.js" || info.Scripts["test"] != "" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if got := strings.Join(info.Dependencies, ","); got != "abc,chalk" {
		t.Fatalf("deps: %s", got)
	}
	if info.Created.IsZero() || info.VersionPublished.IsZero() {
		t.Fatalf("times missing: %+v", info)
	}
	// newest *stable* version older than 24h, relative to a fixed "now"
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	if got := info.OlderThan(24*time.Hour, now); got != "1.1.0" {
		t.Fatalf("OlderThan: %q", got)
	}

	// exact, missing version and dist-tag
	if i, _ := r.Lookup(context.Background(), "npm", "pretty-logs", "1.1.0"); i.Version != "1.1.0" || i.VersionMissing {
		t.Fatalf("exact: %+v", i)
	}
	if i, _ := r.Lookup(context.Background(), "npm", "pretty-logs", "9.9.9"); !i.VersionMissing {
		t.Fatalf("missing version not flagged: %+v", i)
	}
	if i, _ := r.Lookup(context.Background(), "npm", "pretty-logs", "next"); i.Version != "2.0.0-rc.1" {
		t.Fatalf("dist-tag: %+v", i)
	}
	// absent package and scoped name
	if i, err := r.Lookup(context.Background(), "npm", "nope-nope", ""); err != nil || i.Exists {
		t.Fatalf("absent: %v %+v", err, i)
	}
	if i, err := r.Lookup(context.Background(), "npm", "@scope/pkg", ""); err != nil || !i.Exists {
		t.Fatalf("scoped: %v %+v", err, i)
	}

	// tarball evidence: only the file the install script names
	files, err := r.Evidence(context.Background(), "npm", info)
	if err != nil || len(files) != 1 || files[0].Path != "setup.js" || files[0].Content != "line1\nline2\n" {
		t.Fatalf("evidence: %v %+v", err, files)
	}
}

func TestHTTPRegistryPyPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pypi/requests/json" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]string{"version": "2.32.0"},
			"releases": map[string]any{
				"2.31.0": []map[string]string{{"upload_time_iso_8601": "2023-05-22T15:12:44.175040Z"}},
				"2.32.0": []map[string]string{{"upload_time_iso_8601": "2026-11-15T09:00:00.000000Z"}},
			},
		})
	}))
	defer srv.Close()
	r := NewHTTPRegistry()
	r.PyPIBase = srv.URL
	i, err := r.Lookup(context.Background(), "pypi", "requests", "")
	if err != nil || i.Version != "2.32.0" || i.VersionPublished.Year() != 2026 || i.Created.Year() != 2023 {
		t.Fatalf("%v %+v", err, i)
	}
	if i, _ := r.Lookup(context.Background(), "pypi", "requests", "==2.31.0"); i.Version != "2.31.0" {
		t.Fatalf("pinned: %+v", i)
	}
	if i, _ := r.Lookup(context.Background(), "pypi", "reqeusts", ""); i.Exists {
		t.Fatalf("absent package reported as existing")
	}
}

func TestOSVOnlyMalwareIDs(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotBody)
		w.Write([]byte(`{"vulns":[{"id":"GHSA-xxxx"},{"id":"MAL-2026-777"}]}`))
	}))
	defer srv.Close()
	o := NewOSV()
	o.Base = srv.URL
	ids, err := o.Malware(context.Background(), "npm", "evil", "1.0.0")
	if err != nil || len(ids) != 1 || ids[0] != "MAL-2026-777" {
		t.Fatalf("%v %v", err, ids)
	}
	// only name, ecosystem and version are sent
	pkg := gotBody["package"].(map[string]any)
	if pkg["name"] != "evil" || pkg["ecosystem"] != "npm" || gotBody["version"] != "1.0.0" || len(gotBody) != 2 {
		t.Fatalf("unexpected OSV request: %v", gotBody)
	}
}

func TestClaudeReviewerRequestAndValidation(t *testing.T) {
	var req map[string]any
	var apiKey, version string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey, version = r.Header.Get("x-api-key"), r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &req)
		reply := "Here is my verdict:\n" + `{"verdict":"malicious","confidence":0.95,"summary":"posts env to raw IP","citations":[{"file":"setup.js","line":3,"why":"POST"},{"file":"setup.js","line":50,"why":"made up"}]}`
		json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": reply}}})
	}))
	defer srv.Close()

	c := NewClaudeReviewer("sk-test", "claude-sonnet-5-5")
	c.Base = srv.URL
	bundle := BuildBundle("pretty-logs", "1.0.0", map[string]string{"postinstall": "node setup.js"}, evilSetup)
	v, err := c.Review(context.Background(), "pretty-logs", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if apiKey != "sk-test" || version == "" || req["model"] != "claude-sonnet-5-5" {
		t.Fatalf("bad request headers/model: %q %q %v", apiKey, version, req["model"])
	}
	// the package text reaches the model inside a delimited block, after the instructions
	msg := req["messages"].([]any)[0].(map[string]any)["content"].(string)
	if !strings.Contains(msg, "<package_code>") || !strings.Contains(msg, "203.0.113.9") || !strings.Contains(req["system"].(string), "untrusted DATA") {
		t.Fatalf("prompt layout wrong:\n%s", msg)
	}
	// the fabricated citation was dropped by code, the real one kept
	if v.Verdict != "malicious" || !v.Verified || len(v.Citations) != 1 || v.Citations[0].Line != 3 {
		t.Fatalf("validation: %+v", v)
	}
}

func TestParseVerdictRejectsGarbage(t *testing.T) {
	if _, err := parseVerdict("no json here"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := parseVerdict("{not json}"); err == nil {
		t.Fatal("expected error")
	}
}

func TestBundleSplitsMinifiedLines(t *testing.T) {
	long := strings.Repeat("a", 700)
	b := BuildBundle("p", "1", nil, []EvidenceFile{{Path: "x.js", Content: long}})
	if n := len(b.Rows["x.js"]); n != 3 {
		t.Fatalf("700-char line should split into 3 citable rows, got %d", n)
	}
}
