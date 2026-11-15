package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The loop is tested against a stand-in OpenAI-compatible server. That is a
// test of the loop's mechanics only; the genuine run uses a real model.
func TestAgentLoopFeedsBlockBackToModel(t *testing.T) {
	var seen [][]map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []map[string]any `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		seen = append(seen, req.Messages)
		var msg map[string]any
		switch len(seen) {
		case 1: // the gateway removed the call and explained why
			msg = map[string]any{"role": "assistant", "content": "Installing.\n\n[pkgguard] BLOCKED: no such package"}
		case 2: // the model recovers
			msg = map[string]any{"role": "assistant", "content": "", "tool_calls": []any{map[string]any{
				"id": "c1", "type": "function", "function": map[string]any{"name": "bash", "arguments": `{"command":"pip install flask-jwt-extended"}`}}}}
		default:
			msg = map[string]any{"role": "assistant", "content": "Done."}
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": msg}}})
	}))
	defer srv.Close()

	var out bytes.Buffer
	a := &agentCfg{base: srv.URL, model: "m", maxTurns: 6, timeout: time.Second, client: srv.Client(), out: &out}
	n, err := a.Run(context.Background(), "add auth")
	if err != nil || n != 1 {
		t.Fatalf("interventions=%d err=%v\n%s", n, err, out.String())
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 model calls, got %d", len(seen))
	}
	// the second request must carry the explanation back to the model
	last := seen[1][len(seen[1])-1]
	if last["role"] != "user" || !strings.Contains(last["content"].(string), "safety gateway stopped") {
		t.Fatalf("the model was not told: %+v", last)
	}
	// the third carries the (dry-run) tool result for the recovered call
	tool := seen[2][len(seen[2])-1]
	if tool["role"] != "tool" || tool["tool_call_id"] != "c1" || !strings.Contains(tool["content"].(string), "dry run") {
		t.Fatalf("tool result missing: %+v", tool)
	}
	if !strings.Contains(out.String(), "$ pip install flask-jwt-extended") {
		t.Fatalf("transcript:\n%s", out.String())
	}
}

func TestAgentReportsGatewayErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"no provider configured"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	a := &agentCfg{base: srv.URL, model: "m", maxTurns: 2, timeout: time.Second, client: srv.Client(), out: &bytes.Buffer{}}
	if _, err := a.Run(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("want an HTTP 400 error, got %v", err)
	}
}

func TestAgentRetriesRateLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			http.Error(w, `{"error":"quota"}`, http.StatusTooManyRequests)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "ok"}}}})
	}))
	defer srv.Close()
	var out bytes.Buffer
	a := &agentCfg{base: srv.URL, model: "m", maxTurns: 2, timeout: time.Second, retryWait: time.Millisecond, client: srv.Client(), out: &out}
	if _, err := a.Run(context.Background(), "x"); err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if !strings.Contains(out.String(), "HTTP 429; waiting") {
		t.Fatalf("the wait should be visible:\n%s", out.String())
	}
}
