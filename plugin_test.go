package pkgguard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func testPlugin(t *testing.T, cfg Config) *Plugin {
	t.Helper()
	reg := &fakeRegistry{pkgs: map[string]*PackageInfo{"npm|express": established("4.19.2")}}
	p, err := NewPlugin(newTestEngine(cfg, reg, fakeMalware{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func bctx() *schemas.BifrostContext {
	return schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
}

func toolCall(name, command string) schemas.ChatAssistantMessageToolCall {
	args, _ := json.Marshal(map[string]string{"command": command})
	id := "call_" + name
	typ := "function"
	return schemas.ChatAssistantMessageToolCall{ID: &id, Type: &typ, Function: schemas.ChatAssistantMessageToolCallFunction{Name: &name, Arguments: string(args)}}
}

func chatResponse(text string, calls ...schemas.ChatAssistantMessageToolCall) *schemas.BifrostResponse {
	finish := "tool_calls"
	return &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
		Choices: []schemas.BifrostResponseChoice{{
			FinishReason: &finish,
			ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{Message: &schemas.ChatMessage{
				Role:                 schemas.ChatMessageRoleAssistant,
				Content:              &schemas.ChatMessageContent{ContentStr: &text},
				ChatAssistantMessage: &schemas.ChatAssistantMessage{ToolCalls: calls},
			}},
		}},
	}}
}

func TestPostLLMHookRemovesBlockedToolCall(t *testing.T) {
	p := testPlugin(t, Config{})
	resp := chatResponse("Installing now.", toolCall("bash", "npm install expresss-auth-helper"), toolCall("bash", "npm install express"))
	out, berr, err := p.PostLLMHook(bctx(), resp, nil)
	if err != nil || berr != nil {
		t.Fatal(err, berr)
	}
	ch := out.ChatResponse.Choices[0]
	calls := ch.Message.ToolCalls
	if len(calls) != 1 || !strings.Contains(calls[0].Function.Arguments, "npm install express") {
		t.Fatalf("expected only the safe call to survive: %+v", calls)
	}
	text := *ch.Message.Content.ContentStr
	if !strings.Contains(text, "[pkgguard] BLOCKED") || !strings.Contains(text, "expresss-auth-helper") || !strings.HasPrefix(text, "Installing now.") {
		t.Fatalf("explanation missing:\n%s", text)
	}
	if *ch.FinishReason != "tool_calls" { // one call left, the agent still has work to run
		t.Fatalf("finish reason should stay tool_calls, got %s", *ch.FinishReason)
	}
	if evs := p.Events(); len(evs) != 2 || evs[0].Decision.Action != ActionBlock || evs[1].Decision.Action != ActionAllow {
		t.Fatalf("audit trail wrong: %+v", evs)
	}
}

func TestPostLLMHookStopsWhenAllCallsBlocked(t *testing.T) {
	p := testPlugin(t, Config{})
	resp := chatResponse("", toolCall("bash", "npm i totally-invented-lib"))
	out, _, _ := p.PostLLMHook(bctx(), resp, nil)
	ch := out.ChatResponse.Choices[0]
	if len(ch.Message.ToolCalls) != 0 || *ch.FinishReason != "stop" {
		t.Fatalf("calls=%d finish=%s", len(ch.Message.ToolCalls), *ch.FinishReason)
	}
}

func TestPostLLMHookMonitorModeKeepsCallAndWarns(t *testing.T) {
	p := testPlugin(t, Config{Mode: "monitor"})
	resp := chatResponse("ok", toolCall("bash", "npm i totally-invented-lib"))
	out, _, _ := p.PostLLMHook(bctx(), resp, nil)
	ch := out.ChatResponse.Choices[0]
	if len(ch.Message.ToolCalls) != 1 || !strings.Contains(*ch.Message.Content.ContentStr, "WARNING") {
		t.Fatalf("monitor mode should keep the call and warn: %+v", ch.Message)
	}
}

func TestPostLLMHookLeavesOrdinaryCallsAlone(t *testing.T) {
	p := testPlugin(t, Config{})
	resp := chatResponse("listing", toolCall("bash", "ls -la && git status"), toolCall("write_file", "npm install made-up-lib-in-a-readme"))
	out, _, _ := p.PostLLMHook(bctx(), resp, nil)
	ch := out.ChatResponse.Choices[0]
	if len(ch.Message.ToolCalls) != 2 || *ch.Message.Content.ContentStr != "listing" {
		t.Fatalf("ordinary calls must pass untouched: %+v", ch.Message)
	}
	if len(p.Events()) != 0 {
		t.Fatalf("nothing should be audited: %+v", p.Events())
	}
}

func TestPostLLMHookResponsesAPI(t *testing.T) {
	p := testPlugin(t, Config{})
	typ := schemas.ResponsesMessageTypeFunctionCall
	name, args := "shell", `{"command":"pip install reqeusts-oauth-plus"}`
	resp := &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{
		{Type: &typ, ResponsesToolMessage: &schemas.ResponsesToolMessage{Name: &name, Arguments: &args}},
	}}}
	out, _, _ := p.PostLLMHook(bctx(), resp, nil)
	item := out.ResponsesResponse.Output[0]
	if *item.Type != schemas.ResponsesMessageTypeMessage || item.ResponsesToolMessage != nil || !strings.Contains(*item.Content.ContentStr, "BLOCKED") {
		t.Fatalf("function_call should become an explanatory message: %+v", item)
	}
}

func TestPreMCPHookShortCircuits(t *testing.T) {
	p := testPlugin(t, Config{})
	name := "run_shell"
	args := `{"command":"npm install github:someone/thing"}`
	req := &schemas.BifrostMCPRequest{
		RequestType:                  schemas.MCPRequestTypeChatToolCall,
		ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &name, Arguments: args}},
	}
	_, sc, err := p.PreMCPHook(bctx(), req)
	if err != nil || sc == nil || sc.Error == nil {
		t.Fatalf("expected short-circuit error: %v %+v", err, sc)
	}
	if *sc.Error.StatusCode != 403 || !strings.Contains(sc.Error.Error.Message, "source-git") && !strings.Contains(sc.Error.Error.Message, "git repository") {
		t.Fatalf("bad error: %+v", sc.Error.Error)
	}
	// a harmless tool call goes through
	args2 := `{"command":"npm install express"}`
	req.ChatAssistantMessageToolCall.Function.Arguments = args2
	if _, sc, _ := p.PreMCPHook(bctx(), req); sc != nil {
		t.Fatalf("safe call was short-circuited: %+v", sc)
	}
	// non-execute requests are ignored
	if _, sc, _ := p.PreMCPHook(bctx(), &schemas.BifrostMCPRequest{RequestType: schemas.MCPRequestTypeListTools}); sc != nil {
		t.Fatal("list_tools must be ignored")
	}
}

func TestAuditLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	p := testPlugin(t, Config{AuditLog: path})
	p.PostLLMHook(bctx(), chatResponse("", toolCall("bash", "npm i nope-not-real")), nil)
	if err := p.Cleanup(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), `"action":"block"`) || !strings.Contains(string(b), "phantom-package") {
		t.Fatalf("audit log: %v %s", err, b)
	}
}

func TestInitFromBifrostConfigMap(t *testing.T) {
	// Bifrost hands plugins their config as a loosely typed map.
	p, err := Init(map[string]any{"mode": "monitor", "offline": true, "block_at": "critical", "min_age_hours": 0, "deny": []any{"event-stream"}})
	if err != nil {
		t.Fatal(err)
	}
	c := p.Engine().Cfg
	if c.Mode != "monitor" || !c.Offline || c.BlockAt != "critical" || c.minAge() != 0 || len(c.Deny) != 1 {
		t.Fatalf("%+v", c)
	}
	if p.Engine().Registry != nil {
		t.Fatal("offline plugin must not build network clients")
	}
	if _, err := Init(map[string]any{"mode": "bogus"}); err == nil {
		t.Fatal("bad mode should be rejected")
	}
	if _, err := Init(map[string]any{"block_at": "nuclear"}); err == nil {
		t.Fatal("bad severity should be rejected")
	}
	if _, err := Init(nil); err != nil { // default config
		t.Fatal(err)
	}
}
