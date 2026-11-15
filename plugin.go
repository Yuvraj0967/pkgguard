package pkgguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// PluginName is the name Bifrost registers the plugin under.
const PluginName = "pkgguard"

// Plugin is the Bifrost plugin. It implements schemas.LLMPlugin (inspects the
// tool calls a model returns) and schemas.MCPPlugin (inspects tool executions
// passing through Bifrost's MCP gateway).
type Plugin struct {
	engine *Engine

	mu      sync.Mutex
	events  []Event
	audit   *os.File
	nextID  int
	subs    map[chan Event]struct{}
	dash    *dashboard
	streams sync.Map // stream key -> *streamState (see stream.go)
}

var (
	_ schemas.LLMPlugin = (*Plugin)(nil)
	_ schemas.MCPPlugin = (*Plugin)(nil)
)

// Event is one audited decision.
type Event struct {
	ID       int       `json:"id"`
	Time     time.Time `json:"time"`
	Surface  string    `json:"surface"` // "llm-response" or "mcp-tool"
	Tool     string    `json:"tool"`
	Decision Decision  `json:"decision"`
}

const maxEvents = 500

// Init builds a plugin from Bifrost's loosely typed config value.
func Init(config any) (*Plugin, error) {
	cfg, err := ConfigFromAny(config)
	if err != nil {
		return nil, err
	}
	e, err := NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	return NewPlugin(e)
}

// NewPlugin wraps an engine (tests inject fakes through the engine).
func NewPlugin(e *Engine) (*Plugin, error) {
	p := &Plugin{engine: e, subs: map[chan Event]struct{}{}}
	if e.Cfg.AuditLog != "" {
		f, err := os.OpenFile(e.Cfg.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("pkgguard: audit log: %w", err)
		}
		p.audit = f
	}
	if err := p.startDashboard(); err != nil {
		_ = p.Cleanup()
		return nil, err
	}
	return p, nil
}

// Engine exposes the engine (used by the CLI and tests).
func (p *Plugin) Engine() *Engine { return p.engine }

// Events returns a copy of the recent audited decisions, oldest first.
func (p *Plugin) Events() []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Event(nil), p.events...)
}

func (p *Plugin) record(surface, tool string, d Decision) {
	p.mu.Lock()
	p.nextID++
	ev := Event{ID: p.nextID, Time: time.Now().UTC(), Surface: surface, Tool: tool, Decision: d}
	p.events = append(p.events, ev)
	if len(p.events) > maxEvents {
		p.events = p.events[len(p.events)-maxEvents:]
	}
	if p.audit != nil {
		if b, err := json.Marshal(ev); err == nil {
			_, _ = p.audit.Write(append(b, '\n'))
		}
	}
	for ch := range p.subs {
		select {
		case ch <- ev:
		default: // a slow dashboard tab must never stall the gateway
		}
	}
	p.mu.Unlock()
}

// subscribe returns a channel of future events and a cancel function.
func (p *Plugin) subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	p.mu.Lock()
	p.subs[ch] = struct{}{}
	p.mu.Unlock()
	return ch, func() {
		p.mu.Lock()
		delete(p.subs, ch)
		p.mu.Unlock()
	}
}

// notice is the text an agent reads when a command is blocked or warned about.
func (p *Plugin) notice(d *Decision) string {
	msg := d.Message()
	if msg != "" && d.Action == ActionBlock && p.dash != nil {
		msg += "\nA human can approve a specific package at the pkgguard dashboard (" + p.dash.url + "); do not try to work around the block."
	}
	return msg
}

// GetName implements schemas.BasePlugin.
func (p *Plugin) GetName() string { return PluginName }

// Cleanup implements schemas.BasePlugin.
func (p *Plugin) Cleanup() error {
	if p.dash != nil {
		p.dash.stop()
		p.dash = nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.audit != nil {
		err := p.audit.Close()
		p.audit = nil
		return err
	}
	return nil
}

// analyzeArgs looks for install commands in a tool call's arguments. It returns
// the worst decision across all string values, or nil when nothing relevant is there.
func (p *Plugin) analyzeArgs(ctx context.Context, tool, args string) *Decision {
	if p.engine.Cfg.ignoresTool(tool) {
		return nil
	}
	var worst *Decision
	for _, cmd := range stringValues(args) {
		if !mightInstall(cmd) {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		d := p.engine.Analyze(cctx, cmd)
		cancel()
		if len(d.Intents) == 0 && len(d.Findings) == 0 {
			continue
		}
		p.record("tool-call", tool, d)
		if worst == nil || rank(d.Action) > rank(worst.Action) {
			dd := d
			worst = &dd
		}
	}
	return worst
}

func rank(a Action) int {
	switch a {
	case ActionBlock:
		return 2
	case ActionWarn:
		return 1
	}
	return 0
}

// mightInstall is a cheap pre-filter so ordinary tool arguments cost nothing.
func mightInstall(s string) bool {
	l := strings.ToLower(s)
	for _, k := range []string{"npm", "npx", "pnpm", "yarn", "bun", "pip", "uv", "pipx", "poetry", "cargo", "go ", "gem ", "curl", "wget", "iwr", "invoke-webrequest"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// stringValues returns every string found in a JSON document (or the raw text if it is not JSON).
func stringValues(args string) []string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(args), &v); err != nil {
		return []string{args}
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, i := range t {
				walk(i)
			}
		case map[string]any:
			for _, i := range t {
				walk(i)
			}
		}
	}
	walk(v)
	return out
}

func strp(s string) *string { return &s }

func (p *Plugin) blockedError(d *Decision) *schemas.BifrostError {
	code := http.StatusForbidden
	f := false
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &code,
		Type:           strp("pkgguard_blocked"),
		Error:          &schemas.ErrorField{Type: strp("pkgguard_blocked"), Code: strp("package_blocked"), Message: p.notice(d)},
		AllowFallbacks: &f, // another provider would return the same tool call
	}
}

// ---- schemas.LLMPlugin ------------------------------------------------------------

// PreRequestHook implements schemas.LLMPlugin (nothing to route).
func (p *Plugin) PreRequestHook(_ *schemas.BifrostContext, _ *schemas.BifrostRequest) error {
	return nil
}

// PreLLMHook implements schemas.LLMPlugin (the guard works on responses).
func (p *Plugin) PreLLMHook(_ *schemas.BifrostContext, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	return req, nil, nil
}

// PostLLMHook implements schemas.LLMPlugin. It inspects the tool calls in the
// model's response. A blocked call is removed from the response and replaced by
// an explanation in the assistant text, so the agent reads why and picks
// another way instead of running the install.
//
// Streaming responses are not inspected (their tool-call arguments arrive in
// fragments after the first bytes have already reached the client); use the MCP
// gateway path or non-streaming requests for enforcement.
func (p *Plugin) PostLLMHook(ctx *schemas.BifrostContext, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	if resp == nil || bifrostErr != nil {
		return resp, bifrostErr, nil
	}
	if resp.ChatResponse != nil {
		p.guardChat(ctx, resp.ChatResponse)
	}
	if resp.ResponsesResponse != nil {
		p.guardResponses(ctx, resp.ResponsesResponse)
	}
	return resp, bifrostErr, nil
}

func (p *Plugin) enforcing(d *Decision) bool {
	return d != nil && d.Action == ActionBlock && p.engine.Cfg.Mode == "enforce"
}

func (p *Plugin) guardChat(ctx context.Context, r *schemas.BifrostChatResponse) {
	for ci := range r.Choices {
		choice := &r.Choices[ci]
		if choice.ChatNonStreamResponseChoice == nil || choice.Message == nil || choice.Message.ChatAssistantMessage == nil {
			continue
		}
		msg := choice.Message
		var kept []schemas.ChatAssistantMessageToolCall
		var notices []string
		for _, tc := range msg.ToolCalls {
			name := ""
			if tc.Function.Name != nil {
				name = *tc.Function.Name
			}
			d := p.analyzeArgs(ctx, name, tc.Function.Arguments)
			if d != nil && d.Action != ActionAllow {
				if p.enforcing(d) {
					notices = append(notices, p.notice(d))
					continue
				}
				notices = append(notices, p.notice(d))
			}
			kept = append(kept, tc)
		}
		if len(notices) == 0 {
			continue
		}
		removed := len(msg.ToolCalls) - len(kept)
		msg.ToolCalls = kept
		text := strings.Join(notices, "\n\n")
		if msg.Content == nil {
			msg.Content = &schemas.ChatMessageContent{}
		}
		switch {
		case msg.Content.ContentStr != nil:
			msg.Content.ContentStr = strp(*msg.Content.ContentStr + "\n\n" + text)
		case len(msg.Content.ContentBlocks) > 0:
			t := schemas.ChatContentBlockTypeText
			msg.Content.ContentBlocks = append(msg.Content.ContentBlocks, schemas.ChatContentBlock{Type: t, Text: strp(text)})
		default:
			msg.Content.ContentStr = strp(text)
		}
		if removed > 0 && len(kept) == 0 {
			choice.FinishReason = strp("stop")
		}
	}
}

func (p *Plugin) guardResponses(ctx context.Context, r *schemas.BifrostResponsesResponse) {
	for i := range r.Output {
		item := &r.Output[i]
		if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeFunctionCall || item.ResponsesToolMessage == nil {
			continue
		}
		name, args := "", ""
		if item.Name != nil {
			name = *item.Name
		}
		if item.Arguments != nil {
			args = *item.Arguments
		}
		d := p.analyzeArgs(ctx, name, args)
		if !p.enforcing(d) {
			continue
		}
		// Replace the call with an assistant message that explains the block.
		t := schemas.ResponsesMessageTypeMessage
		role := schemas.ResponsesInputMessageRoleAssistant
		*item = schemas.ResponsesMessage{
			ID:      item.ID,
			Type:    &t,
			Role:    &role,
			Content: &schemas.ResponsesMessageContent{ContentStr: strp(p.notice(d))},
		}
	}
}

// PostLLMHook is the only LLM hook that does work; the rest are no-ops above.

// ---- schemas.MCPPlugin ----------------------------------------------------------------

// PreMCPHook implements schemas.MCPPlugin. Tool executions that pass through
// Bifrost's MCP gateway are checked before they reach the MCP server; a blocked
// install short-circuits with a 403-style error the agent can read.
func (p *Plugin) PreMCPHook(ctx *schemas.BifrostContext, req *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if req == nil {
		return req, nil, nil
	}
	if req.RequestType != schemas.MCPRequestTypeChatToolCall && req.RequestType != schemas.MCPRequestTypeResponsesToolCall {
		return req, nil, nil
	}
	args, _ := req.GetToolArguments().(string)
	if args == "" {
		if sp, ok := req.GetToolArguments().(*string); ok && sp != nil {
			args = *sp
		}
	}
	d := p.analyzeArgs(ctx, req.GetToolName(), args)
	if p.enforcing(d) {
		return req, &schemas.MCPPluginShortCircuit{Error: p.blockedError(d)}, nil
	}
	return req, nil, nil
}

// PostMCPHook implements schemas.MCPPlugin (nothing to do after execution).
func (p *Plugin) PostMCPHook(_ *schemas.BifrostContext, resp *schemas.BifrostMCPResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}
