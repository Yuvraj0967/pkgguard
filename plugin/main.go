// Command plugin builds pkgguard as a Bifrost native plugin (.so).
//
//	go build -buildmode=plugin -o pkgguard.so ./plugin
//
// Bifrost loads native plugins by looking up exported package-level functions
// (Init, GetName, PreLLMHook, PostLLMHook, PreMCPHook, PostMCPHook, Cleanup),
// the same contract as examples/plugins/multi-interface in the Bifrost repo.
// Go's plugin mode is only available on Linux and macOS.
package main

import (
	"fmt"
	"sync"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/pkgguard/pkgguard"
)

var (
	mu sync.RWMutex
	pg *pkgguard.Plugin
)

func instance() *pkgguard.Plugin {
	mu.RLock()
	defer mu.RUnlock()
	return pg
}

// Init is called by Bifrost with the plugin's "config" object from config.json.
func Init(config any) error {
	p, err := pkgguard.Init(config)
	if err != nil {
		return err
	}
	mu.Lock()
	pg = p
	mu.Unlock()
	return nil
}

// GetName returns the plugin's system name.
func GetName() string { return pkgguard.PluginName }

// Cleanup flushes the audit log.
func Cleanup() error {
	if p := instance(); p != nil {
		return p.Cleanup()
	}
	return nil
}

// PreRequestHook is a no-op (the guard works on responses).
func PreRequestHook(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) error { return nil }

// PreLLMHook is a no-op.
func PreLLMHook(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	return req, nil, nil
}

// PostLLMHook removes blocked install tool calls from model responses.
func PostLLMHook(ctx *schemas.BifrostContext, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	p := instance()
	if p == nil {
		return resp, bifrostErr, fmt.Errorf("pkgguard: not initialised")
	}
	return p.PostLLMHook(ctx, resp, bifrostErr)
}

// PreMCPHook blocks unsafe installs in MCP tool executions.
func PreMCPHook(ctx *schemas.BifrostContext, req *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	p := instance()
	if p == nil {
		return req, nil, fmt.Errorf("pkgguard: not initialised")
	}
	return p.PreMCPHook(ctx, req)
}

// PostMCPHook is a no-op.
func PostMCPHook(ctx *schemas.BifrostContext, resp *schemas.BifrostMCPResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}

// HTTPTransportPreAuthHook is a no-op.
func HTTPTransportPreAuthHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}

// HTTPTransportPreHook is a no-op.
func HTTPTransportPreHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}

// HTTPTransportPostHook is a no-op.
func HTTPTransportPostHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	return nil
}

// HTTPTransportResponseHeadersHook is a no-op.
func HTTPTransportResponseHeadersHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponseMetadata) error {
	return nil
}

// HTTPTransportStreamChunkHook enforces the policy on streamed tool calls (see stream.go).
func HTTPTransportStreamChunkHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest, chunk *schemas.BifrostStreamChunk) (*schemas.BifrostStreamChunk, error) {
	p := instance()
	if p == nil {
		return chunk, nil
	}
	return p.HTTPTransportStreamChunkHook(ctx, req, chunk)
}

func main() {}
