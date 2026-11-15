package pkgguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPRegistryCratesAndGems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/crates/serde":
			json.NewEncoder(w).Encode(map[string]any{
				"crate": map[string]any{"max_stable_version": "1.0.200", "created_at": "2015-01-01T00:00:00Z", "recent_downloads": 130000},
				"versions": []map[string]any{
					{"num": "1.0.200", "created_at": "2026-10-01T00:00:00Z"},
					{"num": "1.0.199", "created_at": "2026-09-01T00:00:00Z", "yanked": true},
				},
			})
		case "/api/v1/versions/rails.json":
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": "8.0.0.rc1", "created_at": "2026-11-01T00:00:00.000Z", "prerelease": true},
				{"number": "7.1.0", "created_at": "2026-10-01T00:00:00.000Z"},
				{"number": "7.0.0", "created_at": "2022-01-01T00:00:00.000Z"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	r := NewHTTPRegistry()
	r.CratesBase, r.GemsBase = srv.URL, srv.URL

	c, err := r.Lookup(context.Background(), "crates.io", "serde", "")
	if err != nil || !c.Exists || c.Version != "1.0.200" || c.Created.Year() != 2015 || len(c.Versions) != 1 {
		t.Fatalf("crates: %v %+v", err, c)
	}
	if i, _ := r.Lookup(context.Background(), "crates.io", "nope-nope", ""); i.Exists {
		t.Fatal("absent crate reported as existing")
	}
	if dl, err := r.WeeklyDownloads(context.Background(), "crates.io", "serde"); err != nil || dl != 10000 {
		t.Fatalf("crate downloads: %d %v", dl, err)
	}
	g, err := r.Lookup(context.Background(), "rubygems", "rails", "")
	if err != nil || !g.Exists || g.Version != "7.1.0" || g.Created.Year() != 2022 {
		t.Fatalf("rubygems: %v %+v", err, g)
	}
	if g, _ := r.Lookup(context.Background(), "rubygems", "rails", "7.0.0"); g.Version != "7.0.0" {
		t.Fatalf("pinned gem: %+v", g)
	}
	if g, _ := r.Lookup(context.Background(), "rubygems", "rails", "9.9.9"); !g.VersionMissing {
		t.Fatalf("missing gem version not flagged: %+v", g)
	}
	if i, _ := r.Lookup(context.Background(), "rubygems", "no-such-gem", ""); i.Exists {
		t.Fatal("absent gem reported as existing")
	}
}
