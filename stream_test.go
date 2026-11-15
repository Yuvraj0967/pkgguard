package pkgguard

import (
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func chunk(id string, d schemas.ChatStreamResponseChoiceDelta, finish *string) *schemas.BifrostStreamChunk {
	return &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: id, Object: "chat.completion.chunk",
		Choices: []schemas.BifrostResponseChoice{{
			Index: 0, FinishReason: finish,
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &d},
		}},
	}}
}

func tcDelta(index uint16, id, name, args string) schemas.ChatStreamResponseChoiceDelta {
	d := schemas.ChatAssistantMessageToolCall{Index: index, Function: schemas.ChatAssistantMessageToolCallFunction{Arguments: args}}
	if id != "" {
		d.ID = &id
	}
	if name != "" {
		d.Function.Name = &name
	}
	return schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{d}}
}

// replay feeds chunks through the hook and returns what a client would receive.
func replay(t *testing.T, p *Plugin, chunks []*schemas.BifrostStreamChunk) []*schemas.BifrostStreamChunk {
	t.Helper()
	var out []*schemas.BifrostStreamChunk
	ctx := bctx()
	for _, c := range chunks {
		got, err := p.HTTPTransportStreamChunkHook(ctx, &schemas.HTTPRequest{}, c)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			out = append(out, got)
		}
	}
	return out
}

func streamOf(id, command string) []*schemas.BifrostStreamChunk {
	half := len(command) / 2
	role, text, stop := "assistant", "Installing it now.", "tool_calls"
	return []*schemas.BifrostStreamChunk{
		chunk(id, schemas.ChatStreamResponseChoiceDelta{Role: &role}, nil),
		chunk(id, schemas.ChatStreamResponseChoiceDelta{Content: &text}, nil),
		// the call arrives in fragments of one JSON document
		chunk(id, tcDelta(0, "call_1", "bash", `{"command":"`+command[:half]), nil),
		chunk(id, tcDelta(0, "", "", command[half:]+`"}`), nil),
		chunk(id, schemas.ChatStreamResponseChoiceDelta{}, &stop),
	}
}

func TestStreamBlocksFragmentedToolCall(t *testing.T) {
	p := testPlugin(t, Config{})
	out := replay(t, p, streamOf("cmpl-1", "npm install totally-invented-lib"))

	var text strings.Builder
	var finish string
	for _, c := range out {
		for _, ch := range c.BifrostChatResponse.Choices {
			if ch.Delta != nil {
				if len(ch.Delta.ToolCalls) > 0 {
					t.Fatalf("a blocked tool call must never reach the client: %+v", ch.Delta.ToolCalls)
				}
				if ch.Delta.Content != nil {
					text.WriteString(*ch.Delta.Content)
				}
			}
			if ch.FinishReason != nil {
				finish = *ch.FinishReason
			}
		}
	}
	if !strings.Contains(text.String(), "Installing it now.") || !strings.Contains(text.String(), "[pkgguard] BLOCKED") || !strings.Contains(text.String(), "totally-invented-lib") {
		t.Fatalf("client should read the original text and the explanation:\n%s", text.String())
	}
	if finish != "stop" {
		t.Fatalf("finish_reason should become stop, got %q", finish)
	}
	if len(out) != 3 { // role, text, final (the two fragment chunks were withheld)
		t.Fatalf("expected the fragment chunks to be dropped, client got %d chunks", len(out))
	}
}

func TestStreamAllowedCallIsReassembledInFinalChunk(t *testing.T) {
	p := testPlugin(t, Config{})
	out := replay(t, p, streamOf("cmpl-2", "npm install express"))
	last := out[len(out)-1].BifrostChatResponse.Choices[0]
	if len(last.Delta.ToolCalls) != 1 {
		t.Fatalf("final chunk should carry the whole call: %+v", last.Delta)
	}
	tc := last.Delta.ToolCalls[0]
	if *tc.ID != "call_1" || *tc.Function.Name != "bash" || tc.Function.Arguments != `{"command":"npm install express"}` {
		t.Fatalf("call not reassembled faithfully: %+v", tc)
	}
	if *last.FinishReason != "tool_calls" {
		t.Fatalf("finish_reason must stay tool_calls, got %s", *last.FinishReason)
	}
}

func TestStreamMonitorModeStillDelivers(t *testing.T) {
	p := testPlugin(t, Config{Mode: "monitor"})
	out := replay(t, p, streamOf("cmpl-3", "npm install totally-invented-lib"))
	last := out[len(out)-1].BifrostChatResponse.Choices[0]
	if len(last.Delta.ToolCalls) != 1 || !strings.Contains(*last.Delta.Content, "WARNING") || *last.FinishReason != "tool_calls" {
		t.Fatalf("monitor mode should deliver the call with a warning: %+v / %v", last.Delta, *last.FinishReason)
	}
}

func TestStreamPlainTextIsUntouched(t *testing.T) {
	p := testPlugin(t, Config{})
	role, a, b, stop := "assistant", "Hello ", "world", "stop"
	in := []*schemas.BifrostStreamChunk{
		chunk("cmpl-4", schemas.ChatStreamResponseChoiceDelta{Role: &role, Content: &a}, nil),
		chunk("cmpl-4", schemas.ChatStreamResponseChoiceDelta{Content: &b}, nil),
		chunk("cmpl-4", schemas.ChatStreamResponseChoiceDelta{}, &stop),
	}
	out := replay(t, p, in)
	if len(out) != 3 || out[0] != in[0] || out[2] != in[2] {
		t.Fatalf("text-only streams must pass through unchanged, got %d chunks", len(out))
	}
	n := 0
	p.streams.Range(func(_, _ any) bool { n++; return true })
	if n != 0 {
		t.Fatalf("no state should be kept for text-only streams, found %d", n)
	}
}

func TestStreamTwoParallelCallsOneBlocked(t *testing.T) {
	p := testPlugin(t, Config{})
	stop := "tool_calls"
	in := []*schemas.BifrostStreamChunk{
		chunk("cmpl-5", tcDelta(0, "c0", "bash", `{"command":"npm install totally-invented-lib"}`), nil),
		chunk("cmpl-5", tcDelta(1, "c1", "bash", `{"command":"npm install express"}`), nil),
		chunk("cmpl-5", schemas.ChatStreamResponseChoiceDelta{}, &stop),
	}
	out := replay(t, p, in)
	last := out[len(out)-1].BifrostChatResponse.Choices[0]
	if len(last.Delta.ToolCalls) != 1 || !strings.Contains(last.Delta.ToolCalls[0].Function.Arguments, "npm install express") || last.Delta.ToolCalls[0].Index != 0 {
		t.Fatalf("only the safe call should remain, re-indexed from 0: %+v", last.Delta.ToolCalls)
	}
	if *last.FinishReason != "tool_calls" || !strings.Contains(*last.Delta.Content, "BLOCKED") {
		t.Fatalf("one call survives so the stream still finishes with tool_calls: %v %v", *last.FinishReason, last.Delta.Content)
	}
}

func TestStreamStateIsReleasedAfterFinish(t *testing.T) {
	p := testPlugin(t, Config{})
	replay(t, p, streamOf("cmpl-6", "npm install express"))
	n := 0
	p.streams.Range(func(_, _ any) bool { n++; return true })
	if n != 0 {
		t.Fatalf("stream state leaked: %d entries", n)
	}
}
