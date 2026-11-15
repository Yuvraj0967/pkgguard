package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/pkgguard/pkgguard"
)

// runProxy runs pkgguard as an OpenAI-compatible reverse proxy in front of a
// stock Bifrost. No plugin loading is involved: it works with the default
// Bifrost install (Docker, npx, binary).
func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	c := addCommon(fs)
	listen := fs.String("listen", "127.0.0.1:8089", "")
	upstream := fs.String("upstream", "", "")
	dash := fs.String("dashboard", "", "")
	fs.Parse(args)
	if *upstream == "" {
		fail("proxy: -upstream is required, e.g. -upstream http://127.0.0.1:8080")
	}
	u, err := url.Parse(*upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		fail("proxy: bad -upstream %q", *upstream)
	}
	cfg := c.config()
	if *dash != "" {
		cfg.DashboardAddr = *dash
	}
	e, err := pkgguard.NewEngine(cfg)
	if err != nil {
		fail("%v", err)
	}
	p, err := pkgguard.NewPlugin(e)
	if err != nil {
		fail("%v", err)
	}
	defer p.Cleanup()

	srv := &http.Server{Addr: *listen, Handler: p.ProxyHandler(u), ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "pkgguard proxy: %s -> %s (mode: %s)\n", *listen, u, e.Cfg.Mode)
	fmt.Fprintf(os.Stderr, "point your agent's OpenAI base URL at http://%s/v1 instead of the gateway\n", *listen)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fail("proxy: %v", err)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
