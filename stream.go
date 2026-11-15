package pkgguard

import (
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

var _ schemas.HTTPTransportPlugin = (*Plugin)(nil)

// Streaming enforcement.
//
// In a streamed chat completion the tool call arrives as fragments: the name
// and the first piece of the arguments in one chunk, the rest of the JSON in
// later chunks. By the time the command is complete the first fragments have
// already reached the client, so a response hook cannot take it back.
// HTTPTransportStreamChunkHook can: it sees every chunk before the client does
// and may drop or rewrite it. pkgguard withholds the tool-call fragments,
// reassembles each call, and when the choice finishes either
//
//   - emits the complete tool call in the final chunk (allowed), or
//   - drops it and puts the explanation in the final chunk's text (blocked),
//     setting finish_reason to "stop" when no call is left.
//
// Cost: the client receives tool calls at the end of the stream instead of
// token by token. Text is not delayed. If a stream dies before its
// finish_reason arrives, the withheld calls are never emitted (fail closed).
// Only chat-completion streams are handled; Responses-API streams are not.

type toolAcc struct {
	id, typ *string
	name    *string
	args    strings.Builder
}

type streamState struct {
	mu      sync.Mutex
	seen    time.Time
	choices map[int]map[uint16]*toolAcc // choice index -> tool index -> call
}

const streamStateTTL = 15 * time.Minute

func (p *Plugin) streamKey(ctx *schemas.BifrostContext, chunk *schemas.BifrostStreamChunk) string {
	if ctx != nil {
		if id, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string); ok && id != "" {
			return "req:" + id
		}
	}
	if chunk.BifrostChatResponse != nil && chunk.BifrostChatResponse.ID != "" {
		return "cmpl:" + chunk.BifrostChatResponse.ID
	}
	return ""
}

func (p *Plugin) stateFor(key string) *streamState {
	now := time.Now()
	v, _ := p.streams.LoadOrStore(key, &streamState{seen: now, choices: map[int]map[uint16]*toolAcc{}})
	st := v.(*streamState)
	st.mu.Lock()
	st.seen = now
	st.mu.Unlock()
	// opportunistic sweep of abandoned streams
	p.streams.Range(func(k, v any) bool {
		o := v.(*streamState)
		o.mu.Lock()
		stale := now.Sub(o.seen) > streamStateTTL
		o.mu.Unlock()
		if stale {
			p.streams.Delete(k)
		}
		return true
	})
	return st
}

func deltaEmpty(d *schemas.ChatStreamResponseChoiceDelta) bool {
	if d == nil {
		return true
	}
	return d.Role == nil && (d.Content == nil || *d.Content == "") && d.Refusal == nil && d.Audio == nil &&
		(d.Reasoning == nil || *d.Reasoning == "") && len(d.ReasoningDetails) == 0 && len(d.ToolCalls) == 0 &&
		len(d.Images) == 0 && len(d.Annotations) == 0 && len(d.ExtraContent) == 0 && len(d.Context) == 0
}

// HTTPTransportStreamChunkHook implements schemas.HTTPTransportPlugin.
func (p *Plugin) HTTPTransportStreamChunkHook(ctx *schemas.BifrostContext, _ *schemas.HTTPRequest, chunk *schemas.BifrostStreamChunk) (*schemas.BifrostStreamChunk, error) {
	if chunk == nil || chunk.BifrostChatResponse == nil || chunk.BifrostError != nil {
		return chunk, nil
	}
	r := chunk.BifrostChatResponse
	key := p.streamKey(ctx, chunk)
	if key == "" {
		return chunk, nil
	}
	hasTool := false
	for i := range r.Choices {
		c := &r.Choices[i]
		if c.ChatStreamResponseChoice != nil && c.Delta != nil && len(c.Delta.ToolCalls) > 0 {
			hasTool = true
		}
	}
	// Only streams that carry tool calls need state; plain text passes straight through.
	if !hasTool {
		if _, ok := p.streams.Load(key); !ok {
			return chunk, nil
		}
	}
	st := p.stateFor(key)
	st.mu.Lock()
	defer st.mu.Unlock()

	finished := false
	for i := range r.Choices {
		c := &r.Choices[i]
		if c.ChatStreamResponseChoice == nil || c.Delta == nil {
			if c.FinishReason != nil {
				finished = finished || p.finishChoice(ctx, st, c)
			}
			continue
		}
		if len(c.Delta.ToolCalls) > 0 {
			calls := st.choices[c.Index]
			if calls == nil {
				calls = map[uint16]*toolAcc{}
				st.choices[c.Index] = calls
			}
			for _, tc := range c.Delta.ToolCalls {
				a := calls[tc.Index]
				if a == nil {
					a = &toolAcc{}
					calls[tc.Index] = a
				}
				if tc.ID != nil {
					a.id = tc.ID
				}
				if tc.Type != nil {
					a.typ = tc.Type
				}
				if tc.Function.Name != nil && *tc.Function.Name != "" {
					a.name = tc.Function.Name
				}
				a.args.WriteString(tc.Function.Arguments)
			}
			c.Delta.ToolCalls = nil // withheld until the call is complete
		}
		if c.FinishReason != nil {
			finished = finished || p.finishChoice(ctx, st, c)
		}
	}
	if finished {
		p.streams.Delete(key)
	}

	// Drop a chunk that only carried withheld tool-call fragments.
	if r.Usage == nil {
		empty := true
		for i := range r.Choices {
			c := &r.Choices[i]
			if c.FinishReason != nil || (c.ChatStreamResponseChoice != nil && !deltaEmpty(c.Delta)) {
				empty = false
			}
		}
		if empty && hasTool {
			return nil, nil
		}
	}
	return chunk, nil
}

// finishChoice runs when a choice reports its finish_reason: it analyses the
// reassembled calls and rewrites the final chunk. It reports whether the choice had state.
func (p *Plugin) finishChoice(ctx *schemas.BifrostContext, st *streamState, c *schemas.BifrostResponseChoice) bool {
	calls := st.choices[c.Index]
	if len(calls) == 0 {
		return false
	}
	delete(st.choices, c.Index)
	if c.ChatStreamResponseChoice == nil {
		c.ChatStreamResponseChoice = &schemas.ChatStreamResponseChoice{}
	}
	if c.Delta == nil {
		c.Delta = &schemas.ChatStreamResponseChoiceDelta{}
	}
	// stable order by tool index
	var idxs []int
	for k := range calls {
		idxs = append(idxs, int(k))
	}
	for i := 1; i < len(idxs); i++ {
		for j := i; j > 0 && idxs[j] < idxs[j-1]; j-- {
			idxs[j], idxs[j-1] = idxs[j-1], idxs[j]
		}
	}
	var kept []schemas.ChatAssistantMessageToolCall
	var notices []string
	for _, k := range idxs {
		a := calls[uint16(k)]
		name := ""
		if a.name != nil {
			name = *a.name
		}
		args := a.args.String()
		d := p.analyzeArgs(ctx, name, args)
		if d != nil && d.Action != ActionAllow {
			notices = append(notices, p.notice(d))
			if p.enforcing(d) {
				continue
			}
		}
		kept = append(kept, schemas.ChatAssistantMessageToolCall{
			Index: uint16(len(kept)), ID: a.id, Type: a.typ,
			Function: schemas.ChatAssistantMessageToolCallFunction{Name: a.name, Arguments: args},
		})
	}
	c.Delta.ToolCalls = kept
	if len(notices) > 0 {
		text := strings.Join(notices, "\n\n")
		if c.Delta.Content != nil && *c.Delta.Content != "" {
			text = *c.Delta.Content + "\n\n" + text
		}
		c.Delta.Content = strp(text)
	}
	if len(kept) == 0 && c.FinishReason != nil {
		c.FinishReason = strp("stop")
	}
	return true
}

// ---- the rest of schemas.HTTPTransportPlugin: nothing to do ------------------------------

// HTTPTransportPreAuthHook implements schemas.HTTPTransportPlugin (no-op).
func (p *Plugin) HTTPTransportPreAuthHook(*schemas.BifrostContext, *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}

// HTTPTransportPreHook implements schemas.HTTPTransportPlugin (no-op).
func (p *Plugin) HTTPTransportPreHook(*schemas.BifrostContext, *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}

// HTTPTransportPostHook implements schemas.HTTPTransportPlugin (no-op).
func (p *Plugin) HTTPTransportPostHook(*schemas.BifrostContext, *schemas.HTTPRequest, *schemas.HTTPResponse) error {
	return nil
}

// HTTPTransportResponseHeadersHook implements schemas.HTTPTransportPlugin (no-op).
func (p *Plugin) HTTPTransportResponseHeadersHook(*schemas.BifrostContext, *schemas.HTTPRequest, *schemas.HTTPResponseMetadata) error {
	return nil
}
