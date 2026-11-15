package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// pkgguard agent is a small, real coding-agent loop: it sends a task to any
// OpenAI-compatible endpoint (a Bifrost gateway, or pkgguard's proxy in front
// of one), lets the model call a `bash` tool, and feeds results back. It exists
// so the protection can be shown with a real model making real decisions, not a
// scripted stand-in.
//
// By default commands are NOT executed (dry run). -exec runs allowed commands
// in a throwaway temp directory; only use it on a machine you are happy to
// install packages on.

type agentMsg map[string]any

type agentCfg struct {
	base, model, key string
	maxTurns         int
	exec             bool
	timeout          time.Duration
	retryWait        time.Duration // base wait before retrying a rate-limited (429) or overloaded (503) call
	client           *http.Client
	out              io.Writer
}

const agentSystem = `You are a coding agent working in a fresh empty project directory. You have one tool, bash, to run shell commands.
The environment has only the language runtimes (node, npm, python, pip); no project dependencies are installed yet.
Do the user's task. Install any library you need with the package manager (npm, pip) before using it. Be brief.`

var bashTool = map[string]any{
	"type": "function",
	"function": map[string]any{
		"name":        "bash",
		"description": "Run a shell command in the project directory and return its output.",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"command": map[string]any{"type": "string"}},
			"required":   []string{"command"},
		},
	},
}

func (a *agentCfg) chat(ctx context.Context, msgs []agentMsg) (agentMsg, error) {
	body, _ := json.Marshal(map[string]any{"model": a.model, "messages": msgs, "tools": []any{bashTool}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.base, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.key != "" {
		req.Header.Set("Authorization", "Bearer "+a.key)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 400)])))
	}
	var out struct {
		Choices []struct {
			Message agentMsg `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return nil, fmt.Errorf("unexpected response: %s", strings.TrimSpace(string(raw[:min(len(raw), 400)])))
	}
	return out.Choices[0].Message, nil
}

func (a *agentCfg) run(command, dir string) string {
	if !a.exec {
		return "(dry run: the command was not executed)"
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	sh := "bash"
	if _, err := exec.LookPath(sh); err != nil {
		sh = "sh"
	}
	c := exec.CommandContext(ctx, sh, "-c", command)
	c.Dir = dir
	b, err := c.CombinedOutput()
	s := string(b)
	if len(s) > 4000 {
		s = s[:4000] + "\n...(truncated)"
	}
	if err != nil {
		s += "\n(exit: " + err.Error() + ")"
	}
	return s
}

// chatRetry retries rate-limited or overloaded calls with a growing wait, the way any
// real client of a metered model API has to.
func (a *agentCfg) chatRetry(ctx context.Context, msgs []agentMsg) (agentMsg, error) {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		var m agentMsg
		m, err = a.chat(ctx, msgs)
		if err == nil || !(strings.HasPrefix(err.Error(), "HTTP 429") || strings.HasPrefix(err.Error(), "HTTP 503")) {
			return m, err
		}
		wait := a.retryWait * time.Duration(attempt+1)
		fmt.Fprintf(a.out, "  (%s; waiting %s then retrying)\n", strings.SplitN(err.Error(), ":", 2)[0], wait)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, err
}

// Run executes the loop and returns the number of pkgguard interventions the model saw.
func (a *agentCfg) Run(ctx context.Context, task string) (interventions int, err error) {
	dir := ""
	if a.exec {
		dir, err = os.MkdirTemp("", "pkgguard-agent-")
		if err != nil {
			return 0, err
		}
		defer os.RemoveAll(dir)
	}
	msgs := []agentMsg{{"role": "system", "content": agentSystem}, {"role": "user", "content": task}}
	fmt.Fprintf(a.out, "task: %s\n\n", task)
	for turn := 0; turn < a.maxTurns; turn++ {
		msg, err := a.chatRetry(ctx, msgs)
		if err != nil {
			return interventions, err
		}
		content, _ := msg["content"].(string)
		calls, _ := msg["tool_calls"].([]any)
		assistant := agentMsg{"role": "assistant", "content": content}
		if len(calls) > 0 {
			assistant["tool_calls"] = calls
		}
		msgs = append(msgs, assistant)
		if content != "" {
			fmt.Fprintf(a.out, "model: %s\n", strings.ReplaceAll(strings.TrimSpace(content), "\n", "\n       "))
		}
		if len(calls) == 0 {
			if strings.Contains(content, "[pkgguard]") && interventions < 4 {
				// The gateway removed the model's tool call and explained why. A real harness
				// shows the model that explanation so it can choose another way.
				interventions++
				fmt.Fprintf(a.out, "\n--- pkgguard stopped that action; the model is told and tries again (%d) ---\n\n", interventions)
				msgs = append(msgs, agentMsg{"role": "user", "content": "The safety gateway stopped your last action (see above). Choose a different, safe approach, or explain what you need from me."})
				continue
			}
			return interventions, nil
		}
		for _, c := range calls {
			cm, _ := c.(map[string]any)
			fn, _ := cm["function"].(map[string]any)
			var args struct {
				Command string `json:"command"`
			}
			_ = json.Unmarshal([]byte(fmt.Sprint(fn["arguments"])), &args)
			id, _ := cm["id"].(string)
			fmt.Fprintf(a.out, "  $ %s\n", args.Command)
			res := a.run(args.Command, dir)
			if a.exec {
				fmt.Fprintf(a.out, "    %s\n", strings.ReplaceAll(strings.TrimSpace(trimTo(res, 300)), "\n", "\n    "))
			}
			msgs = append(msgs, agentMsg{"role": "tool", "tool_call_id": id, "content": res})
		}
	}
	fmt.Fprintln(a.out, "(stopped: turn limit reached)")
	return interventions, nil
}

func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	base := fs.String("base", "http://127.0.0.1:8089/v1", "OpenAI-compatible base URL (pkgguard proxy, or a gateway)")
	model := fs.String("model", "", "model name as the gateway knows it, e.g. anthropic/claude-sonnet-5-5")
	keyEnv := fs.String("key-env", "", "environment variable holding an API key to send as a Bearer token (optional; Bifrost holds provider keys itself)")
	turns := fs.Int("turns", 8, "maximum model turns")
	doExec := fs.Bool("exec", false, "actually run the model's commands in a temp directory (default: dry run)")
	fs.Usage = usage
	fs.Parse(args)
	if *model == "" || fs.NArg() == 0 {
		fail(`agent: need -model and a task, e.g. pkgguard agent -model anthropic/claude-sonnet-5-5 "add JWT auth to my Flask app"`)
	}
	a := &agentCfg{base: *base, model: *model, maxTurns: *turns, exec: *doExec, timeout: 90 * time.Second, retryWait: 20 * time.Second,
		client: &http.Client{Timeout: 3 * time.Minute}, out: os.Stdout}
	if *keyEnv != "" {
		a.key = os.Getenv(*keyEnv)
	}
	if *doExec {
		fmt.Fprintln(os.Stderr, "WARNING: -exec runs the model's commands for real (in a throwaway temp directory).")
	}
	n, err := a.Run(context.Background(), strings.Join(fs.Args(), " "))
	if err != nil {
		fail("agent: %v", err)
	}
	fmt.Printf("\ndone (%d pkgguard intervention(s) seen by the model)\n", n)
}
