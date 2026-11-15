package pkgguard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed dashboard.html
var dashboardHTML []byte

// Bifrost routes plugin HTTP hooks only for routes it already serves (its 404
// handler bypasses them), so a plugin cannot add /pkgguard to the gateway's own
// port. The dashboard therefore runs as a small separate listener, loopback by
// default, started by the plugin and shut down in Cleanup.

// Stats summarises the audit trail.
type Stats struct {
	Total    int            `json:"total"`
	Allowed  int            `json:"allowed"`
	Warned   int            `json:"warned"`
	Blocked  int            `json:"blocked"`
	TopRules []RuleCount    `json:"top_rules"`
	TopPkgs  []RuleCount    `json:"top_packages"`
	ByAction map[string]int `json:"by_action"`
	Since    time.Time      `json:"since"`
}

// RuleCount is a name with a count.
type RuleCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func topN(m map[string]int, n int) []RuleCount {
	var out []RuleCount
	for k, v := range m {
		out = append(out, RuleCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Stats computes statistics over the events currently held in memory.
func (p *Plugin) Stats() Stats {
	evs := p.Events()
	s := Stats{ByAction: map[string]int{}, Total: len(evs)}
	rules, pkgs := map[string]int{}, map[string]int{}
	for i, ev := range evs {
		if i == 0 {
			s.Since = ev.Time
		}
		s.ByAction[string(ev.Decision.Action)]++
		switch ev.Decision.Action {
		case ActionBlock:
			s.Blocked++
		case ActionWarn:
			s.Warned++
		default:
			s.Allowed++
		}
		if ev.Decision.Action != ActionAllow {
			for _, f := range ev.Decision.Findings {
				if f.Severity >= SevMedium {
					rules[f.ID]++
					if f.Package != "" {
						pkgs[f.Package]++
					}
				}
			}
		}
	}
	s.TopRules, s.TopPkgs = topN(rules, 6), topN(pkgs, 6)
	return s
}

type dashboard struct {
	p     *Plugin
	token string
	srv   *http.Server
	url   string
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// startDashboard starts the dashboard listener described by the config.
func (p *Plugin) startDashboard() error {
	cfg := p.engine.Cfg
	if cfg.DashboardAddr == "" {
		return nil
	}
	if !isLoopbackAddr(cfg.DashboardAddr) && cfg.DashboardToken == "" {
		return fmt.Errorf("pkgguard: dashboard_addr %q is not loopback; set dashboard_token explicitly", cfg.DashboardAddr)
	}
	token := cfg.DashboardToken
	generated := false
	if token == "" {
		token, generated = newToken(), true
	}
	ln, err := net.Listen("tcp", cfg.DashboardAddr)
	if err != nil {
		return fmt.Errorf("pkgguard: dashboard: %w", err)
	}
	d := &dashboard{p: p, token: token}
	d.url = "http://" + ln.Addr().String() + "/"
	d.srv = &http.Server{Handler: d.handler(ln.Addr().String()), ReadHeaderTimeout: 10 * time.Second}
	p.dash = d
	go func() { _ = d.srv.Serve(ln) }()
	if generated {
		fmt.Fprintf(os.Stderr, "pkgguard dashboard: %s#token=%s\n", d.url, token)
	} else {
		fmt.Fprintf(os.Stderr, "pkgguard dashboard: %s (token from config)\n", d.url)
	}
	return nil
}

// DashboardURL returns the dashboard address ("" when disabled).
func (p *Plugin) DashboardURL() string {
	if p.dash == nil {
		return ""
	}
	return p.dash.url
}

// DashboardToken returns the active dashboard token ("" when disabled).
func (p *Plugin) DashboardToken() string {
	if p.dash == nil {
		return ""
	}
	return p.dash.token
}

func (d *dashboard) stop() {
	if d.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = d.srv.Shutdown(ctx)
	}
}

func (d *dashboard) authed(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.URL.Query().Get("token") // EventSource cannot set headers
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(d.token)) == 1
}

// handler builds the routes. listenAddr is used to reject foreign Host headers
// (DNS-rebinding protection) when the listener is loopback.
func (d *dashboard) handler(listenAddr string) http.Handler {
	mux := http.NewServeMux()
	loop := isLoopbackAddr(listenAddr)
	_, port, _ := net.SplitHostPort(listenAddr)

	api := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !d.authed(r) {
				http.Error(w, `{"error":"missing or wrong token"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			h(w, r)
		}
	}
	writeJSON := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(dashboardHTML)
	})
	mux.HandleFunc("GET /api/events", api(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		evs := d.p.Events()
		if limit > 0 && len(evs) > limit {
			evs = evs[len(evs)-limit:]
		}
		writeJSON(w, evs)
	}))
	mux.HandleFunc("GET /api/stats", api(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, d.p.Stats()) }))
	mux.HandleFunc("GET /api/approvals", api(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, d.p.engine.Approvals.List()) }))
	mux.HandleFunc("POST /api/approve", api(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ecosystem string `json:"ecosystem"`
			Package   string `json:"package"`
			Reason    string `json:"reason"`
			Hours     int    `json:"hours"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || strings.TrimSpace(req.Package) == "" {
			http.Error(w, `{"error":"need {\"package\": \"name\"}"}`, http.StatusBadRequest)
			return
		}
		hours := req.Hours
		if hours <= 0 || hours > 24*30 {
			hours = 24
		}
		ap := d.p.engine.Approvals.Add(req.Ecosystem, strings.TrimSpace(req.Package), "dashboard", trim(req.Reason, 200), time.Duration(hours)*time.Hour)
		writeJSON(w, map[string]any{"approved": ap, "note": "findings below critical are cleared; known malware, malicious install code and the deny list cannot be approved here"})
	}))
	mux.HandleFunc("DELETE /api/approve", api(func(w http.ResponseWriter, r *http.Request) {
		ok := d.p.engine.Approvals.Remove(r.URL.Query().Get("ecosystem"), r.URL.Query().Get("package"))
		writeJSON(w, map[string]bool{"removed": ok})
	}))
	mux.HandleFunc("GET /api/stream", func(w http.ResponseWriter, r *http.Request) {
		if !d.authed(r) {
			http.Error(w, "missing or wrong token", http.StatusUnauthorized)
			return
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		ch, cancel := d.p.subscribe()
		defer cancel()
		fmt.Fprint(w, ": connected\n\n")
		fl.Flush()
		ping := time.NewTicker(20 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case ev := <-ch:
				b, _ := json.Marshal(ev)
				fmt.Fprintf(w, "data: %s\n\n", b)
				fl.Flush()
			case <-ping.C:
				fmt.Fprint(w, ": ping\n\n")
				fl.Flush()
			}
		}
	})

	// Host check: a page on another origin that rebinds its DNS name to 127.0.0.1 must not reach this API.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loop {
			h := strings.ToLower(r.Host)
			if h != "127.0.0.1:"+port && h != "localhost:"+port && h != "[::1]:"+port {
				http.Error(w, "bad host", http.StatusForbidden)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
