package pkgguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dashPlugin(t *testing.T, mal fakeMalware) *Plugin {
	t.Helper()
	reg := &fakeRegistry{pkgs: map[string]*PackageInfo{
		"npm|express":  established("4.19.2"),
		"npm|evil-pkg": established("1.0.0"),
	}}
	e := newTestEngine(Config{DashboardAddr: "127.0.0.1:0", DashboardToken: "secrettoken"}, reg, mal, nil)
	e.Approvals = NewApprovals("", func() time.Time { return testNow })
	p, err := NewPlugin(e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Cleanup() })
	return p
}

func get(t *testing.T, p *Plugin, path, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", p.DashboardURL()+strings.TrimPrefix(path, "/"), nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestDashboardAuthAndPage(t *testing.T) {
	p := dashPlugin(t, fakeMalware{})
	if code, body := get(t, p, "/", ""); code != 200 || !strings.Contains(body, "pkgguard") {
		t.Fatalf("page should load without a token (it asks for one): %d", code)
	}
	for _, path := range []string{"/api/events", "/api/stats", "/api/approvals"} {
		if code, _ := get(t, p, path, ""); code != 401 {
			t.Errorf("%s without token: want 401, got %d", path, code)
		}
		if code, _ := get(t, p, path, "wrong"); code != 401 {
			t.Errorf("%s with a wrong token: want 401, got %d", path, code)
		}
		if code, _ := get(t, p, path, "secrettoken"); code != 200 {
			t.Errorf("%s with the token: want 200, got %d", path, code)
		}
	}
}

func TestDashboardRejectsForeignHost(t *testing.T) {
	p := dashPlugin(t, fakeMalware{})
	req, _ := http.NewRequest("GET", p.DashboardURL()+"api/stats", nil)
	req.Host = "attacker.example:80" // DNS rebinding: the browser thinks it is talking to attacker.example
	req.Header.Set("Authorization", "Bearer secrettoken")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("foreign Host header must be refused, got %d", resp.StatusCode)
	}
}

func TestDashboardShowsEventsAndStats(t *testing.T) {
	p := dashPlugin(t, fakeMalware{})
	p.PostLLMHook(bctx(), chatResponse("", toolCall("bash", "npm i made-up-thing"), toolCall("bash", "npm i express")), nil)

	_, body := get(t, p, "/api/events", "secrettoken")
	var evs []Event
	if err := json.Unmarshal([]byte(body), &evs); err != nil || len(evs) != 2 || evs[0].ID != 1 || evs[1].ID != 2 {
		t.Fatalf("events: %v %s", err, body)
	}
	_, body = get(t, p, "/api/stats", "secrettoken")
	var s Stats
	json.Unmarshal([]byte(body), &s)
	if s.Total != 2 || s.Blocked != 1 || s.Allowed != 1 || len(s.TopRules) == 0 || s.TopRules[0].Name != "phantom-package" {
		t.Fatalf("stats: %+v", s)
	}
}

func post(t *testing.T, p *Plugin, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", p.DashboardURL()+strings.TrimPrefix(path, "/"), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secrettoken")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestApprovalClearsHighButNotCritical(t *testing.T) {
	p := dashPlugin(t, fakeMalware{"npm|evil-pkg": {"MAL-1"}})
	ctx := context.Background()

	// a phantom package is high severity: blocked, then approvable
	if d := p.Engine().Analyze(ctx, "npm i made-up-thing"); d.Action != ActionBlock {
		t.Fatalf("want block first, got %s", d.Action)
	}
	if code, _ := post(t, p, "/api/approve", `{"package":"made-up-thing","hours":1}`); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	d := p.Engine().Analyze(ctx, "npm i made-up-thing")
	if d.Action != ActionAllow || !has(d, "approved") {
		t.Fatalf("approved package should go through with a note: %s %v", d.Action, ids(d))
	}

	// known malware is critical: approving it must not unblock it
	post(t, p, "/api/approve", `{"package":"evil-pkg"}`)
	if d := p.Engine().Analyze(ctx, "npm i evil-pkg"); d.Action != ActionBlock || !has(d, "known-malware") {
		t.Fatalf("critical findings must survive approval: %s %v", d.Action, ids(d))
	}

	// revoking brings the block back
	req, _ := http.NewRequest("DELETE", p.DashboardURL()+"api/approve?package=made-up-thing", nil)
	req.Header.Set("Authorization", "Bearer secrettoken")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("revoke: %v", err)
	}
	if d := p.Engine().Analyze(ctx, "npm i made-up-thing"); d.Action != ActionBlock {
		t.Fatalf("revoked approval should block again, got %s", d.Action)
	}
	if code, _ := post(t, p, "/api/approve", `{}`); code != 400 {
		t.Fatalf("empty approve should be rejected, got %d", code)
	}
}

func TestApprovalExpiresAndPersists(t *testing.T) {
	now := testNow
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "approvals.json")
	a := NewApprovals(path, clock)
	a.Add("npm", "thing", "me", "ok", time.Hour)
	if !a.Has("npm", "thing") || a.Has("pypi", "thing") {
		t.Fatal("approval is per ecosystem")
	}
	// survives a restart
	if b := NewApprovals(path, clock); !b.Has("npm", "thing") {
		t.Fatal("approval lost on reload")
	}
	now = now.Add(2 * time.Hour)
	if a.Has("npm", "thing") || len(a.List()) != 0 {
		t.Fatal("approval should have expired")
	}
	// any-ecosystem approval
	a.Add("", "anywhere", "me", "", time.Hour)
	if !a.Has("npm", "anywhere") || !a.Has("pypi", "Anywhere") {
		t.Fatal("empty ecosystem should approve everywhere")
	}
}

func TestDashboardLiveEvents(t *testing.T) {
	p := dashPlugin(t, fakeMalware{})
	ch, cancel := p.subscribe()
	defer cancel()
	p.PostLLMHook(bctx(), chatResponse("", toolCall("bash", "npm i made-up-thing")), nil)
	select {
	case ev := <-ch:
		if ev.Decision.Action != ActionBlock {
			t.Fatalf("unexpected event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no live event delivered")
	}
}

func TestDashboardMustNotBeExposedWithoutToken(t *testing.T) {
	e := newTestEngine(Config{DashboardAddr: "0.0.0.0:0"}, &fakeRegistry{}, fakeMalware{}, nil)
	if _, err := NewPlugin(e); err == nil {
		t.Fatal("a non-loopback dashboard without an explicit token must be refused")
	}
}

func TestBlockedMessageMentionsDashboard(t *testing.T) {
	p := dashPlugin(t, fakeMalware{})
	out, _, _ := p.PostLLMHook(bctx(), chatResponse("", toolCall("bash", "npm i made-up-thing")), nil)
	text := *out.ChatResponse.Choices[0].Message.Content.ContentStr
	if !strings.Contains(text, p.DashboardURL()) {
		t.Fatalf("the agent should be told a human can approve:\n%s", text)
	}
}
