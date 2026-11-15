package pkgguard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Proxy mode.
//
// Bifrost loads Go plugins only in a dynamically linked build, which is not the
// default install. Proxy mode needs no plugin loading at all: pkgguard runs as
// a small OpenAI-compatible reverse proxy in front of any Bifrost (or any
// OpenAI-compatible endpoint), points the agent at the proxy instead of the
// gateway, and applies the same engine to every chat-completion response,
// streamed or not:
//
//	agent --> pkgguard proxy (:8089) --> Bifrost (:8080) --> providers
//
// Everything else is forwarded untouched. Only /chat/completions responses
// (OpenAI format, which Bifrost serves under /v1 and /openai/v1) are inspected.

// ProxyHandler returns a reverse proxy to upstream that guards chat-completion tool calls.
func (p *Plugin) ProxyHandler(upstream *url.URL) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	director := rp.Director
	rp.Director = func(r *http.Request) {
		director(r)
		r.Host = upstream.Host
		// Drop the client's Accept-Encoding: Go's transport then negotiates gzip itself and
		// decodes it transparently, so the bodies this proxy rewrites are always plain.
		r.Header.Del("Accept-Encoding")
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK || !strings.HasSuffix(resp.Request.URL.Path, "/chat/completions") {
			return nil
		}
		ct := resp.Header.Get("Content-Type")
		ctx := resp.Request.Context()
		switch {
		case strings.HasPrefix(ct, "text/event-stream"):
			resp.Body = p.guardSSE(ctx, resp.Body)
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
		case strings.Contains(ct, "json"):
			b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			if err != nil {
				return err
			}
			out := p.guardChatJSON(ctx, b)
			resp.Body = io.NopCloser(bytes.NewReader(out))
			resp.ContentLength = int64(len(out))
			resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
		}
		return nil
	}
	return rp
}

func decodeMap(b []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // keep numbers exactly as the upstream wrote them
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, false
	}
	return m, true
}

// guardCalls checks OpenAI-format tool calls and returns the ones to keep plus notices for the agent.
func (p *Plugin) guardCalls(ctx context.Context, calls []any) (kept []any, notices []string) {
	for _, c := range calls {
		cm, _ := c.(map[string]any)
		fn, _ := cm["function"].(map[string]any)
		name, _ := fn["name"].(string)
		args, _ := fn["arguments"].(string)
		d := p.analyzeArgs(ctx, name, args)
		if d != nil && d.Action != ActionAllow {
			notices = append(notices, p.notice(d))
			if p.enforcing(d) {
				continue
			}
		}
		kept = append(kept, c)
	}
	return kept, notices
}

// guardChatJSON rewrites a non-streamed chat-completion response.
func (p *Plugin) guardChatJSON(ctx context.Context, body []byte) []byte {
	root, ok := decodeMap(body)
	if !ok {
		return body
	}
	choices, _ := root["choices"].([]any)
	changed := false
	for _, c := range choices {
		ch, _ := c.(map[string]any)
		msg, _ := ch["message"].(map[string]any)
		calls, _ := msg["tool_calls"].([]any)
		if len(calls) == 0 {
			continue
		}
		kept, notices := p.guardCalls(ctx, calls)
		if len(notices) == 0 {
			continue
		}
		changed = true
		text := strings.Join(notices, "\n\n")
		if s, ok := msg["content"].(string); ok && s != "" {
			text = s + "\n\n" + text
		}
		msg["content"] = text
		if len(kept) == 0 {
			delete(msg, "tool_calls")
			if fr, _ := ch["finish_reason"].(string); fr == "tool_calls" {
				ch["finish_reason"] = "stop"
			}
		} else {
			msg["tool_calls"] = kept
		}
	}
	if !changed {
		return body
	}
	out, err := json.Marshal(root)
	if err != nil {
		return body
	}
	return out
}

type proxyAcc struct {
	id, typ any
	name    string
	args    strings.Builder
}

// guardSSE returns a reader of the same event stream with tool calls withheld
// until complete, then emitted whole (allowed) or replaced by the explanation (blocked).
func (p *Plugin) guardSSE(ctx context.Context, upstream io.ReadCloser) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer upstream.Close()
		br := bufio.NewReaderSize(upstream, 64<<10)
		state := map[int]map[int]*proxyAcc{} // choice -> tool index -> call
		var event []string
		flush := func() error {
			if len(event) == 0 {
				return nil
			}
			out := p.guardEvent(ctx, event, state)
			event = nil
			if out == nil {
				return nil
			}
			_, err := pw.Write(out)
			return err
		}
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				trimmed := strings.TrimRight(line, "\r\n")
				if trimmed == "" {
					if ferr := flush(); ferr != nil {
						pw.CloseWithError(ferr)
						return
					}
				} else {
					event = append(event, trimmed)
				}
			}
			if err != nil {
				_ = flush()
				if err == io.EOF {
					pw.Close()
				} else {
					pw.CloseWithError(err)
				}
				return
			}
		}
	}()
	return pr
}

// guardEvent processes one SSE event (its lines, without the blank terminator) and returns the bytes to send, or nil to drop it.
func (p *Plugin) guardEvent(ctx context.Context, lines []string, state map[int]map[int]*proxyAcc) []byte {
	raw := func() []byte { return []byte(strings.Join(lines, "\n") + "\n\n") }
	var data string
	for _, l := range lines {
		if strings.HasPrefix(l, "data:") {
			data = strings.TrimSpace(strings.TrimPrefix(l, "data:"))
		}
	}
	if data == "" || data == "[DONE]" {
		return raw()
	}
	root, ok := decodeMap(([]byte)(data))
	if !ok {
		return raw()
	}
	choices, _ := root["choices"].([]any)
	if len(choices) == 0 {
		return raw()
	}
	sawTool := false
	for _, c := range choices {
		ch, _ := c.(map[string]any)
		idx := 0
		if n, ok := ch["index"].(json.Number); ok {
			i, _ := n.Int64()
			idx = int(i)
		}
		delta, _ := ch["delta"].(map[string]any)
		if tcs, _ := delta["tool_calls"].([]any); len(tcs) > 0 {
			sawTool = true
			calls := state[idx]
			if calls == nil {
				calls = map[int]*proxyAcc{}
				state[idx] = calls
			}
			for _, t := range tcs {
				tm, _ := t.(map[string]any)
				ti := 0
				if n, ok := tm["index"].(json.Number); ok {
					i, _ := n.Int64()
					ti = int(i)
				}
				a := calls[ti]
				if a == nil {
					a = &proxyAcc{}
					calls[ti] = a
				}
				if v, ok := tm["id"]; ok && v != nil {
					a.id = v
				}
				if v, ok := tm["type"]; ok && v != nil {
					a.typ = v
				}
				fn, _ := tm["function"].(map[string]any)
				if n, _ := fn["name"].(string); n != "" {
					a.name = n
				}
				if s, _ := fn["arguments"].(string); s != "" {
					a.args.WriteString(s)
				}
			}
			delete(delta, "tool_calls") // withheld until the call is complete
		}
		if fr, ok := ch["finish_reason"].(string); ok && fr != "" && len(state[idx]) > 0 {
			sawTool = true
			p.finishSSEChoice(ctx, ch, state[idx])
			delete(state, idx)
		}
	}
	if !sawTool {
		return raw()
	}
	// drop an event that only carried withheld fragments
	if _, hasUsage := root["usage"]; !hasUsage || root["usage"] == nil {
		empty := true
		for _, c := range choices {
			ch, _ := c.(map[string]any)
			if fr, _ := ch["finish_reason"].(string); fr != "" {
				empty = false
			}
			if d, _ := ch["delta"].(map[string]any); len(d) > 0 {
				for k, v := range d {
					if v != nil && v != "" && k != "tool_calls" {
						empty = false
					}
				}
			}
		}
		if empty {
			return nil
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return raw()
	}
	return append(append([]byte("data: "), out...), '\n', '\n')
}

func (p *Plugin) finishSSEChoice(ctx context.Context, ch map[string]any, calls map[int]*proxyAcc) {
	var idxs []int
	for k := range calls {
		idxs = append(idxs, k)
	}
	sort.Ints(idxs)
	var raw []any
	for _, k := range idxs {
		a := calls[k]
		typ := a.typ
		if typ == nil {
			typ = "function"
		}
		raw = append(raw, map[string]any{
			"index": k, "id": a.id, "type": typ,
			"function": map[string]any{"name": a.name, "arguments": a.args.String()},
		})
	}
	kept, notices := p.guardCalls(ctx, raw)
	delta, _ := ch["delta"].(map[string]any)
	if delta == nil {
		delta = map[string]any{}
		ch["delta"] = delta
	}
	for i, k := range kept {
		k.(map[string]any)["index"] = i
	}
	if len(kept) > 0 {
		delta["tool_calls"] = kept
	}
	if len(notices) > 0 {
		text := strings.Join(notices, "\n\n")
		if s, ok := delta["content"].(string); ok && s != "" {
			text = s + "\n\n" + text
		}
		delta["content"] = text
	}
	if len(kept) == 0 {
		ch["finish_reason"] = "stop"
	}
}
