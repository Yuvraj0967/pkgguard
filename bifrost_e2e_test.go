package pkgguard

import (
	"context"
	"strings"
	"testing"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// e2eAccount is the minimal schemas.Account Bifrost needs (same shape as the
// account in Bifrost's own plugin tests, e.g. plugins/mocker).
type e2eAccount struct{}

func (e2eAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.OpenAI}, nil
}

func (e2eAccount) GetKeysForProvider(context.Context, schemas.ModelProvider) ([]schemas.Key, error) {
	return []schemas.Key{{Value: *schemas.NewSecretVar("dummy-key"), Models: []string{"gpt-4o"}, Weight: 1}}, nil
}

func (e2eAccount) GetConfigForProvider(schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	return &schemas.ProviderConfig{NetworkConfig: schemas.DefaultNetworkConfig, ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize}, nil
}

// fakeModel is an LLMPlugin that plays the provider: it short-circuits every
// request with a canned assistant reply, so no real model or key is needed.
type fakeModel struct {
	reply func() *schemas.BifrostResponse
}

func (fakeModel) GetName() string                                                       { return "fake-model" }
func (fakeModel) Cleanup() error                                                        { return nil }
func (fakeModel) PreRequestHook(*schemas.BifrostContext, *schemas.BifrostRequest) error { return nil }
func (f fakeModel) PreLLMHook(_ *schemas.BifrostContext, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	return req, &schemas.LLMPluginShortCircuit{Response: f.reply()}, nil
}
func (fakeModel) PostLLMHook(_ *schemas.BifrostContext, r *schemas.BifrostResponse, e *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	return r, e, nil
}

func runThroughBifrost(t *testing.T, p *Plugin, reply func() *schemas.BifrostResponse) *schemas.BifrostChatResponse {
	t.Helper()
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	client, err := bifrost.Init(ctx, schemas.BifrostConfig{
		Account: e2eAccount{},
		// pkgguard first: its PostLLMHook runs last, after the "model" answered.
		LLMPlugins: []schemas.LLMPlugin{p, fakeModel{reply: reply}},
		Logger:     bifrost.NewDefaultLogger(schemas.LogLevelError),
	})
	if err != nil {
		t.Fatalf("bifrost.Init: %v", err)
	}
	defer client.Shutdown()

	resp, berr := client.ChatCompletionRequest(ctx, &schemas.BifrostChatRequest{
		Provider: schemas.OpenAI,
		Model:    "gpt-4o",
		Input: []schemas.ChatMessage{{
			Role:    schemas.ChatMessageRoleUser,
			Content: &schemas.ChatMessageContent{ContentStr: bifrost.Ptr("add auth to the flask app")},
		}},
	})
	if berr != nil {
		t.Fatalf("request failed: %+v", berr.Error)
	}
	return resp
}

func TestBifrostCoreBlocksHallucinatedInstall(t *testing.T) {
	p := testPlugin(t, Config{})
	resp := runThroughBifrost(t, p, func() *schemas.BifrostResponse {
		return chatResponse("I'll install the helper.", toolCall("bash", "pip install flask-jwt-auth-helper-pro && python app.py"))
	})
	ch := resp.Choices[0]
	if len(ch.Message.ToolCalls) != 0 {
		t.Fatalf("the install must not reach the agent: %+v", ch.Message.ToolCalls)
	}
	text := *ch.Message.Content.ContentStr
	if !strings.Contains(text, "BLOCKED") || !strings.Contains(text, "flask-jwt-auth-helper-pro") || !strings.Contains(text, "slopsquatting") {
		t.Fatalf("agent-facing explanation missing:\n%s", text)
	}
	if evs := p.Events(); len(evs) != 1 || evs[0].Decision.Action != ActionBlock {
		t.Fatalf("audit: %+v", evs)
	}
}

func TestBifrostCoreAllowsNormalWork(t *testing.T) {
	p := testPlugin(t, Config{})
	resp := runThroughBifrost(t, p, func() *schemas.BifrostResponse {
		return chatResponse("Installing.", toolCall("bash", "npm install express"))
	})
	if calls := resp.Choices[0].Message.ToolCalls; len(calls) != 1 {
		t.Fatalf("a legitimate install must pass through: %+v", calls)
	}
}
