package pkgguard

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// upstream plays Bifrost (or any OpenAI-compatible gateway).
func fakeUpstream(t *testing.T, command string) *httptest.Server {
	t.Helper()
	args, _ := json.Marshal(map[string]string{"command": command})
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if stream, _ := req["stream"].(bool); stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			half := len(args) / 2
			ev := func(delta string, finish string) {
				fmt.Fprintf(w, "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":%s,\"finish_reason\":%s}]}\n\n", delta, finish)
				fl.Flush()
			}
			ev(`{"role":"assistant","content":"Installing."}`, "null")
			j1, _ := json.Marshal(string(args[:half]))
			j2, _ := json.Marshal(string(args[half:]))
			ev(`{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":`+string(j1)+`}}]}`, "null")
			ev(`{"tool_calls":[{"index":0,"function":{"arguments":`+string(j2)+`}}]}`, "null")
			ev(`{}`, `"tool_calls"`)
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var out io.Writer = w
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			out = gz
		}
		json.NewEncoder(out).Encode(map[string]any{
			"id": "c1", "object": "chat.completion", "model": "m", "created": 1700000000,
			"usage": map[string]any{"total_tokens": 42},
			"choices": []any{map[string]any{"index": 0, "finish_reason": "tool_calls", "message": map[string]any{
				"role": "assistant", "content": "Installing.",
				"tool_calls": []any{map[string]any{"id": "call_1", "type": "function", "function": map[string]any{"name": "bash", "arguments": string(args)}}},
			}}},
		})
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"data":[{"id":"m"}]}`) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func proxyFor(t *testing.T, p *Plugin, up *httptest.Server) *httptest.Server {
	t.Helper()
	u, _ := url.Parse(up.URL)
	srv := httptest.NewServer(p.ProxyHandler(u))
	t.Cleanup(srv.Close)
	return srv
}

func chat(t *testing.T, base string, stream bool) (*http.Response, string) {
	t.Helper()
	body := fmt.Sprintf(`{"model":"m","stream":%v,"messages":[{"role":"user","content":"hi"}]}`, stream)
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestProxyBlocksNonStreamedToolCall(t *testing.T) {
	p := testPlugin(t, Config{})
	px := proxyFor(t, p, fakeUpstream(t, "npm install totally-invented-lib"))
	resp, body := chat(t, px.URL, false)

	var out struct {
		Usage   map[string]any `json:"usage"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   string `json:"content"`
				ToolCalls []any  `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	c := out.Choices[0]
	if len(c.Message.ToolCalls) != 0 || c.FinishReason != "stop" || !strings.Contains(c.Message.Content, "[pkgguard] BLOCKED") || !strings.HasPrefix(c.Message.Content, "Installing.") {
		t.Fatalf("not rewritten: %s", body)
	}
	if out.Usage["total_tokens"].(float64) != 42 { // unrelated fields survive the rewrite
		t.Fatalf("usage lost: %s", body)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("Content-Length %d does not match body %d", resp.ContentLength, len(body))
	}
}

func TestProxyAllowsSafeToolCallUnchanged(t *testing.T) {
	p := testPlugin(t, Config{})
	px := proxyFor(t, p, fakeUpstream(t, "npm install express"))
	_, body := chat(t, px.URL, false)
	if !strings.Contains(body, `"tool_calls"`) || strings.Contains(body, "pkgguard") {
		t.Fatalf("a safe install must pass through untouched: %s", body)
	}
}

func parseSSE(body string) (text string, finish string, tools []string, events int) {
	for _, block := range strings.Split(body, "\n\n") {
		if !strings.HasPrefix(block, "data: ") || strings.Contains(block, "[DONE]") {
			continue
		}
		events++
		var e struct {
			Choices []struct {
				FinishReason *string `json:"finish_reason"`
				Delta        struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		json.Unmarshal([]byte(strings.TrimPrefix(block, "data: ")), &e)
		for _, c := range e.Choices {
			if c.Delta.Content != nil {
				text += *c.Delta.Content
			}
			if c.FinishReason != nil {
				finish = *c.FinishReason
			}
			for _, tc := range c.Delta.ToolCalls {
				tools = append(tools, tc.Function.Arguments)
			}
		}
	}
	return
}

func TestProxyBlocksStreamedToolCall(t *testing.T) {
	p := testPlugin(t, Config{})
	px := proxyFor(t, p, fakeUpstream(t, "npm install totally-invented-lib"))
	_, body := chat(t, px.URL, true)
	text, finish, tools, events := parseSSE(body)
	if len(tools) != 0 {
		t.Fatalf("a blocked call must never reach the client: %v\n%s", tools, body)
	}
	if !strings.Contains(text, "Installing.") || !strings.Contains(text, "[pkgguard] BLOCKED") || finish != "stop" {
		t.Fatalf("text=%q finish=%q\n%s", text, finish, body)
	}
	if events != 2 { // the first text chunk and the final one; both fragment chunks were withheld
		t.Fatalf("expected 2 data events, got %d:\n%s", events, body)
	}
	if !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("stream terminator lost:\n%s", body)
	}
}

func TestProxyReassemblesAllowedStreamedCall(t *testing.T) {
	p := testPlugin(t, Config{})
	px := proxyFor(t, p, fakeUpstream(t, "npm install express"))
	_, body := chat(t, px.URL, true)
	_, finish, tools, _ := parseSSE(body)
	if len(tools) != 1 || tools[0] != `{"command":"npm install express"}` || finish != "tool_calls" {
		t.Fatalf("tools=%v finish=%q\n%s", tools, finish, body)
	}
}

func TestProxyForwardsOtherPathsUntouched(t *testing.T) {
	p := testPlugin(t, Config{})
	px := proxyFor(t, p, fakeUpstream(t, "npm install totally-invented-lib"))
	resp, err := http.Get(px.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != `{"data":[{"id":"m"}]}` {
		t.Fatalf("got %s", b)
	}
}

// Gateways often compress responses; the proxy must still be able to read and rewrite them.
func TestProxyHandlesGzippedUpstream(t *testing.T) {
	p := testPlugin(t, Config{})
	px := proxyFor(t, p, fakeUpstream(t, "npm install totally-invented-lib"))
	req, _ := http.NewRequest("POST", px.URL+"/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("Accept-Encoding", "gzip, br") // a client that asks for compression
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "[pkgguard] BLOCKED") {
		t.Fatalf("a compressed upstream response was not rewritten: %q", b)
	}
}
